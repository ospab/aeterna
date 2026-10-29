/*
 * TCP — Transmission Control Protocol (RFC 793 / RFC 9293, client-oriented)
 *
 * Small but real implementation:
 *   - 3-way handshake with MSS option (SYN → SYN-ACK → ACK)
 *   - send buffer of unacknowledged bytes; transmission limited by the
 *     peer's receive window; retransmission of the oldest unacked segment
 *     on timeout (exponential back-off)
 *   - in-order receive into a ring buffer; out-of-order / duplicate data
 *     is answered with a (duplicate) ACK so the peer retransmits quickly;
 *     window updates are sent when the application drains the buffer
 *   - teardown in both directions (FIN-WAIT-1/2, CLOSE-WAIT, LAST-ACK)
 *   - RST handling
 *
 * Connection table: up to MAX_CONNS simultaneous connections.
 *
 * Concurrency: all public entry points hold a `super::BusyGuard`, so the NIC
 * interrupt handler never processes segments while this code is manipulating
 * the connection table; the blocking loops poll the NIC themselves.
 *
 * API:
 *   tcp_connect(dst_ip, dst_port) -> Result<usize, TcpError>
 *   tcp_listen(port) -> Result<usize, TcpError>
 *   tcp_accept(listener_id, timeout) -> Result<usize, TcpError>
 *   tcp_send(conn, data) -> Result<usize, TcpError>
 *   tcp_recv(conn, buf, timeout) -> Result<usize, TcpError>   (Ok(0) = EOF)
 *   tcp_close(conn)
 *   handle_tcp(payload, src_ip)                                (from IPv4)
 */

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

// ─── TCP header constants ─────────────────────────────────────────────────
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

// ─── Limits / timers (PIT ticks, 100 Hz) ─────────────────────────────────
const MAX_CONNS: usize = 16;
const RX_BUF_SIZE: usize = 16384;
const TX_BUF_SIZE: usize = 16384;
const OUR_MSS: usize = 1460;             // advertised in SYN (1500 - 40)
const DEFAULT_PEER_MSS: usize = 536;     // RFC 9293 default if no MSS option
const RTO_INITIAL: u64 = 100;            // 1 s
const RTO_MAX: u64 = 800;                // 8 s
const MAX_RETRIES: u32 = 8;
const CONNECT_TIMEOUT_TICKS: u64 = 1000; // 10 s
const CLOSE_TIMEOUT_TICKS: u64 = 300;    // 3 s
const SEND_TIMEOUT_TICKS: u64 = 3000;    // 30 s without progress

// ─── Connection state (RFC 793) ───────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

impl TcpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Closed      => "CLOSED",
            TcpState::Listen      => "LISTEN",
            TcpState::SynSent     => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECV",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1    => "FIN_WAIT1",
            TcpState::FinWait2    => "FIN_WAIT2",
            TcpState::CloseWait   => "CLOSE_WAIT",
            TcpState::LastAck     => "LAST_ACK",
            TcpState::TimeWait    => "TIME_WAIT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    ConnectionRefused,
    ConnectionReset,
    TimedOut,
    NotConnected,
    InvalidConn,
    NoFreeSlots,
    WouldBlock,
}

impl TcpError {
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpError::ConnectionRefused => "Connection refused",
            TcpError::ConnectionReset   => "Connection reset by peer",
            TcpError::TimedOut          => "Connection timed out",
            TcpError::NotConnected      => "Not connected",
            TcpError::InvalidConn       => "Invalid connection",
            TcpError::NoFreeSlots       => "No free connection slots",
            TcpError::WouldBlock        => "Would block",
        }
    }
}

// ─── Ring buffer for received data ────────────────────────────────────────
struct RxRing {
    buf: [u8; RX_BUF_SIZE],
    head: usize, // write position
    tail: usize, // read position
    len:  usize,
}

impl RxRing {
    const fn new() -> Self {
        RxRing { buf: [0; RX_BUF_SIZE], head: 0, tail: 0, len: 0 }
    }

    fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(RX_BUF_SIZE - self.len);
        for i in 0..n {
            self.buf[self.head] = data[i];
            self.head = (self.head + 1) % RX_BUF_SIZE;
        }
        self.len += n;
        n
    }

    fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        for i in 0..n {
            out[i] = self.buf[self.tail];
            self.tail = (self.tail + 1) % RX_BUF_SIZE;
        }
        self.len -= n;
        n
    }

    fn available(&self) -> usize { self.len }
    fn free_space(&self) -> usize { RX_BUF_SIZE - self.len }
}

// ─── TCP Connection Block ─────────────────────────────────────────────────
struct TcpConn {
    state:       TcpState,
    local_port:  u16,
    remote_port: u16,
    remote_ip:   [u8; 4],
    // Send sequence space
    snd_una:     u32, // oldest unacknowledged
    snd_nxt:     u32, // next seq to send
    snd_iss:     u32, // initial send sequence
    snd_wnd:     u32, // peer's receive window
    peer_mss:    usize,
    fin_sent:    bool, // our FIN occupies seq number snd_nxt-1
    // Receive sequence space
    rcv_nxt:     u32,
    rcv_irs:     u32,
    last_adv_wnd: usize,
    rx_ring:     RxRing,
    // Unacknowledged outgoing bytes, starting at snd_una
    txq:         [u8; TX_BUF_SIZE],
    txq_len:     usize,
    // Retransmission
    last_tx_tick: u64,
    rto:         u64,
    retries:     u32,
    // Listener: pending SYN (for Listen state)
    accept_ready: bool,
    accept_ip:    [u8; 4],
    accept_port:  u16,
    accept_irs:   u32,
    accept_mss:   usize,
}

impl TcpConn {
    const fn new() -> Self {
        TcpConn {
            state: TcpState::Closed,
            local_port: 0,
            remote_port: 0,
            remote_ip: [0; 4],
            snd_una: 0,
            snd_nxt: 0,
            snd_iss: 0,
            snd_wnd: 0,
            peer_mss: DEFAULT_PEER_MSS,
            fin_sent: false,
            rcv_nxt: 0,
            rcv_irs: 0,
            last_adv_wnd: RX_BUF_SIZE,
            rx_ring: RxRing::new(),
            txq: [0; TX_BUF_SIZE],
            txq_len: 0,
            last_tx_tick: 0,
            rto: RTO_INITIAL,
            retries: 0,
            accept_ready: false,
            accept_ip: [0; 4],
            accept_port: 0,
            accept_irs: 0,
            accept_mss: DEFAULT_PEER_MSS,
        }
    }

    fn reset(&mut self) {
        // Field-wise reset: avoids building a 32 KiB temporary on the stack.
        self.state = TcpState::Closed;
        self.local_port = 0;
        self.remote_port = 0;
        self.remote_ip = [0; 4];
        self.snd_una = 0;
        self.snd_nxt = 0;
        self.snd_iss = 0;
        self.snd_wnd = 0;
        self.peer_mss = DEFAULT_PEER_MSS;
        self.fin_sent = false;
        self.rcv_nxt = 0;
        self.rcv_irs = 0;
        self.last_adv_wnd = RX_BUF_SIZE;
        self.rx_ring.head = 0;
        self.rx_ring.tail = 0;
        self.rx_ring.len = 0;
        self.txq_len = 0;
        self.last_tx_tick = 0;
        self.rto = RTO_INITIAL;
        self.retries = 0;
        self.accept_ready = false;
        self.accept_ip = [0; 4];
        self.accept_port = 0;
        self.accept_irs = 0;
        self.accept_mss = DEFAULT_PEER_MSS;
    }

    fn adv_window(&self) -> u16 {
        self.rx_ring.free_space().min(u16::MAX as usize) as u16
    }

    /// Bytes in flight (sent, not yet acknowledged), excluding SYN/FIN.
    fn in_flight(&self) -> usize { self.txq_len }
}

// ─── Global connection table ──────────────────────────────────────────────
// Single-core kernel; the IRQ path is excluded via BusyGuard (see header).
static mut CONNS: [TcpConn; MAX_CONNS] = {
    const INIT: TcpConn = TcpConn::new();
    [INIT; MAX_CONNS]
};

static ISS_COUNTER: AtomicU32 = AtomicU32::new(0x10000);
static EPHEMERAL_PORT: AtomicU32 = AtomicU32::new(0);

fn next_iss() -> u32 {
    let tsc = unsafe { core::arch::x86_64::_rdtsc() } as u32;
    ISS_COUNTER.fetch_add(64000, Ordering::Relaxed) ^ tsc
}

fn next_ephemeral_port() -> u16 {
    // Start at a TSC-derived offset so ports are not reused across reboots.
    if EPHEMERAL_PORT.load(Ordering::Relaxed) == 0 {
        let tsc = unsafe { core::arch::x86_64::_rdtsc() } as u32;
        let _ = EPHEMERAL_PORT.compare_exchange(0, (tsc % 16384) | 1, Ordering::Relaxed, Ordering::Relaxed);
    }
    loop {
        let p = EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed);
        let port = (49152 + (p % 16384)) as u16;
        let in_use = unsafe { CONNS.iter().any(|c| c.state != TcpState::Closed && c.local_port == port) };
        if !in_use { return port; }
    }
}

fn now_ticks() -> u64 {
    crate::arch::x86_64::idt::timer_ticks()
}

/// a < b in sequence space
fn seq_lt(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) < 0 }
fn seq_le(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) <= 0 }

fn alloc_conn() -> Option<usize> {
    unsafe { (0..MAX_CONNS).find(|&i| CONNS[i].state == TcpState::Closed) }
}

fn find_conn(local_port: u16, remote_ip: [u8; 4], remote_port: u16) -> Option<usize> {
    unsafe {
        (0..MAX_CONNS).find(|&i| {
            let c = &CONNS[i];
            c.state != TcpState::Closed && c.state != TcpState::Listen
                && c.local_port == local_port
                && c.remote_ip == remote_ip
                && c.remote_port == remote_port
        })
    }
}

fn find_listener(local_port: u16) -> Option<usize> {
    unsafe {
        (0..MAX_CONNS).find(|&i| CONNS[i].state == TcpState::Listen && CONNS[i].local_port == local_port)
    }
}

// ─── TCP segment builder ──────────────────────────────────────────────────

/// Build and send a TCP segment. SYN segments carry an MSS option.
fn send_tcp_segment(
    dst_ip:   [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq:      u32,
    ack:      u32,
    flags:    u8,
    window:   u16,
    payload:  &[u8],
) {
    let opt_len = if flags & TCP_SYN != 0 { 4 } else { 0 };
    let header_len = 20 + opt_len;
    let total_len = header_len + payload.len();
    if total_len > 1480 { return; }

    let mut seg = [0u8; 1480];
    seg[0..2].copy_from_slice(&src_port.to_be_bytes());
    seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[8..12].copy_from_slice(&ack.to_be_bytes());
    seg[12] = ((header_len / 4) as u8) << 4;
    seg[13] = flags;
    seg[14..16].copy_from_slice(&window.to_be_bytes());
    if opt_len > 0 {
        seg[20] = 2; // MSS
        seg[21] = 4;
        seg[22..24].copy_from_slice(&(OUR_MSS as u16).to_be_bytes());
    }
    seg[header_len..total_len].copy_from_slice(payload);

    let src_ip = unsafe { super::OUR_IP };
    let cksum = tcp_checksum(&src_ip, &dst_ip, &seg[..total_len]);
    seg[16] = (cksum >> 8) as u8;
    seg[17] = (cksum & 0xFF) as u8;

    super::ipv4::send_ipv4(6, dst_ip, &seg[..total_len]);
}

/// TCP checksum with pseudo-header
fn tcp_checksum(src: &[u8; 4], dst: &[u8; 4], segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += 6u32;
    sum += segment.len() as u32;
    let mut i = 0;
    while i + 1 < segment.len() {
        sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
        i += 2;
    }
    if i < segment.len() {
        sum += (segment[i] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Parse the MSS option from a SYN's option bytes.
fn parse_mss(opts: &[u8]) -> usize {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,
            1 => i += 1,
            kind => {
                if i + 1 >= opts.len() { break; }
                let len = opts[i + 1] as usize;
                if len < 2 || i + len > opts.len() { break; }
                if kind == 2 && len == 4 {
                    let mss = u16::from_be_bytes([opts[i + 2], opts[i + 3]]) as usize;
                    return mss.clamp(64, OUR_MSS);
                }
                i += len;
            }
        }
    }
    DEFAULT_PEER_MSS
}

/// Send a bare ACK carrying our current window.
unsafe fn send_ack(c: &mut TcpConn) {
    let wnd = c.adv_window();
    c.last_adv_wnd = wnd as usize;
    send_tcp_segment(c.remote_ip, c.local_port, c.remote_port,
        c.snd_nxt, c.rcv_nxt, TCP_ACK, wnd, &[]);
}

/// Transmit queued-but-unsent bytes as far as the peer's window allows.
unsafe fn output(c: &mut TcpConn) {
    loop {
        let sent = c.snd_nxt.wrapping_sub(c.snd_una) as usize; // bytes already sent from txq
        let sent = sent.min(c.txq_len);
        if sent >= c.txq_len { return; }
        let wnd = (c.snd_wnd as usize).max(if sent == 0 { 1 } else { 0 }); // allow a 1-byte probe on zero window
        if sent >= wnd { return; }
        let n = (c.txq_len - sent).min(c.peer_mss).min(wnd - sent);
        if n == 0 { return; }
        let wnd_adv = c.adv_window();
        let seq = c.snd_nxt;
        let mut tmp = [0u8; OUR_MSS];
        tmp[..n].copy_from_slice(&c.txq[sent..sent + n]);
        send_tcp_segment(c.remote_ip, c.local_port, c.remote_port,
            seq, c.rcv_nxt, TCP_PSH | TCP_ACK, wnd_adv, &tmp[..n]);
        if sent == 0 { c.last_tx_tick = now_ticks(); }
        c.snd_nxt = c.snd_nxt.wrapping_add(n as u32);
    }
}

/// Retransmit the oldest unacknowledged segment (or SYN / FIN) if its timer expired.
/// Returns false if the connection was given up.
unsafe fn check_retransmit(c: &mut TcpConn) -> bool {
    let outstanding = c.snd_una != c.snd_nxt;
    if !outstanding { return true; }
    if now_ticks().wrapping_sub(c.last_tx_tick) < c.rto { return true; }
    if c.retries >= MAX_RETRIES {
        c.state = TcpState::Closed;
        return false;
    }
    c.retries += 1;
    c.rto = (c.rto * 2).min(RTO_MAX);
    c.last_tx_tick = now_ticks();

    match c.state {
        TcpState::SynSent => {
            send_tcp_segment(c.remote_ip, c.local_port, c.remote_port,
                c.snd_iss, 0, TCP_SYN, c.adv_window(), &[]);
        }
        TcpState::SynReceived => {
            send_tcp_segment(c.remote_ip, c.local_port, c.remote_port,
                c.snd_iss, c.rcv_nxt, TCP_SYN | TCP_ACK, c.adv_window(), &[]);
        }
        _ => {
            if c.txq_len > 0 {
                // Go back to snd_una and resend the first segment.
                let n = c.txq_len.min(c.peer_mss);
                let mut tmp = [0u8; OUR_MSS];
                tmp[..n].copy_from_slice(&c.txq[..n]);
                send_tcp_segment(c.remote_ip, c.local_port, c.remote_port,
                    c.snd_una, c.rcv_nxt, TCP_PSH | TCP_ACK, c.adv_window(), &tmp[..n]);
            } else if c.fin_sent {
                // Only the FIN is outstanding.
                send_tcp_segment(c.remote_ip, c.local_port, c.remote_port,
                    c.snd_nxt.wrapping_sub(1), c.rcv_nxt, TCP_FIN | TCP_ACK, c.adv_window(), &[]);
            }
        }
    }
    true
}

/// Process an acknowledgment number for a synchronized connection.
unsafe fn process_ack(c: &mut TcpConn, ack: u32, window: u16) {
    if seq_lt(c.snd_una, ack) && seq_le(ack, c.snd_nxt) {
        let mut acked = ack.wrapping_sub(c.snd_una) as usize;
        // The FIN (if sent) is the last sequence number and is not in txq.
        if c.fin_sent && ack == c.snd_nxt { acked = acked.saturating_sub(1); }
        let acked = acked.min(c.txq_len);
        if acked > 0 {
            c.txq.copy_within(acked..c.txq_len, 0);
            c.txq_len -= acked;
        }
        c.snd_una = ack;
        c.retries = 0;
        c.rto = RTO_INITIAL;
        c.last_tx_tick = now_ticks();
    }
    if seq_le(c.snd_una, ack) {
        c.snd_wnd = window as u32;
    }
}

// ─── Incoming packet handler (called from IPv4 dispatcher) ────────────────

/// Handle an incoming TCP segment. Called from ipv4::handle_ipv4().
pub fn handle_tcp(data: &[u8], src_ip: [u8; 4]) {
    if data.len() < 20 { return; }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num  = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num  = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_off = ((data[12] >> 4) as usize) * 4;
    let flags    = data[13];
    let window   = u16::from_be_bytes([data[14], data[15]]);

    if data_off < 20 || data_off > data.len() { return; }
    let opts = &data[20..data_off];
    let payload = &data[data_off..];

    let is_syn = flags & TCP_SYN != 0;
    let is_ack = flags & TCP_ACK != 0;
    let is_fin = flags & TCP_FIN != 0;
    let is_rst = flags & TCP_RST != 0;

    // 1. Existing connection
    if let Some(idx) = find_conn(dst_port, src_ip, src_port) {
        unsafe { handle_conn_segment(idx, seq_num, ack_num, flags, window, opts, payload); }
        return;
    }

    // 2. SYN to a listener (passive open)
    if is_syn && !is_ack && !is_rst {
        if let Some(lis) = find_listener(dst_port) {
            unsafe {
                let l = &mut CONNS[lis];
                l.accept_ready = true;
                l.accept_ip    = src_ip;
                l.accept_port  = src_port;
                l.accept_irs   = seq_num;
                l.accept_mss   = parse_mss(opts);
            }
            return;
        }
    }

    // 3. No matching connection — answer with RST (never RST a RST)
    if !is_rst {
        let (rst_seq, rst_ack, rst_flags) = if is_ack {
            (ack_num, 0u32, TCP_RST)
        } else {
            let seg_len = payload.len() as u32
                + if is_syn { 1 } else { 0 }
                + if is_fin { 1 } else { 0 };
            (0u32, seq_num.wrapping_add(seg_len), TCP_RST | TCP_ACK)
        };
        send_tcp_segment(src_ip, dst_port, src_port, rst_seq, rst_ack, rst_flags, 0, &[]);
    }
}

/// Accept in-order payload (and FIN) into the receive buffer.
/// Returns true if a FIN was consumed.
unsafe fn receive_data(c: &mut TcpConn, seq: u32, payload: &[u8], is_fin: bool) -> bool {
    let mut need_ack = false;
    let mut seq = seq;
    let mut data = payload;

    // Trim bytes we already have (retransmission overlapping rcv_nxt).
    if !data.is_empty() && seq_lt(seq, c.rcv_nxt) {
        let dup = c.rcv_nxt.wrapping_sub(seq) as usize;
        if dup >= data.len() {
            data = &[];
            need_ack = true; // pure duplicate: re-ACK
        } else {
            data = &data[dup..];
        }
        seq = c.rcv_nxt;
    }

    if !data.is_empty() {
        if seq == c.rcv_nxt {
            let written = c.rx_ring.write(data);
            c.rcv_nxt = c.rcv_nxt.wrapping_add(written as u32);
            if written < data.len() {
                // Buffer full: the peer will retransmit the rest.
                send_ack(c);
                return false;
            }
        }
        // In order or not, ACK it (out-of-order → duplicate ACK).
        need_ack = true;
    }

    let fin_now = is_fin && seq.wrapping_add(data.len() as u32) == c.rcv_nxt;
    if fin_now {
        c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
        need_ack = true;
    }
    if need_ack { send_ack(c); }
    fin_now
}

/// Process a segment for an existing connection.
unsafe fn handle_conn_segment(
    idx: usize,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    opts: &[u8],
    payload: &[u8],
) {
    let c = &mut CONNS[idx];

    let is_syn = flags & TCP_SYN != 0;
    let is_ack = flags & TCP_ACK != 0;
    let is_fin = flags & TCP_FIN != 0;
    let is_rst = flags & TCP_RST != 0;

    if is_rst {
        // In SYN-SENT a RST is only valid if it acknowledges our SYN.
        if c.state == TcpState::SynSent && !(is_ack && ack == c.snd_nxt) { return; }
        c.state = TcpState::Closed;
        return;
    }

    match c.state {
        TcpState::SynSent => {
            if is_syn && is_ack {
                if ack == c.snd_nxt {
                    c.rcv_irs = seq;
                    c.rcv_nxt = seq.wrapping_add(1);
                    c.snd_una = ack;
                    c.snd_wnd = window as u32;
                    c.peer_mss = parse_mss(opts);
                    c.retries = 0;
                    c.rto = RTO_INITIAL;
                    c.state = TcpState::Established;
                    send_ack(c);
                } else {
                    send_tcp_segment(c.remote_ip, c.local_port, c.remote_port,
                        ack, 0, TCP_RST, 0, &[]);
                }
            }
        }

        TcpState::SynReceived => {
            if is_ack && ack == c.snd_nxt {
                c.snd_una = ack;
                c.snd_wnd = window as u32;
                c.retries = 0;
                c.rto = RTO_INITIAL;
                c.state = TcpState::Established;
                if receive_data(c, seq, payload, is_fin) {
                    c.state = TcpState::CloseWait;
                }
            }
        }

        TcpState::Established | TcpState::CloseWait => {
            if is_syn {
                // Retransmitted SYN-ACK (our ACK was lost): re-ACK.
                send_ack(c);
                return;
            }
            if is_ack { process_ack(c, ack, window); }
            if c.state == TcpState::Established {
                if receive_data(c, seq, payload, is_fin) {
                    c.state = TcpState::CloseWait;
                }
            }
            output(c);
        }

        TcpState::FinWait1 | TcpState::FinWait2 => {
            if is_ack { process_ack(c, ack, window); }
            let fin_acked = c.fin_sent && c.snd_una == c.snd_nxt;
            if c.state == TcpState::FinWait1 && fin_acked {
                c.state = TcpState::FinWait2;
            }
            // We may still receive data after our FIN (half-close).
            if receive_data(c, seq, payload, is_fin) {
                // Peer's FIN received (normal or simultaneous close).
                c.state = TcpState::TimeWait;
            } else {
                output(c);
            }
        }

        TcpState::LastAck => {
            if is_ack { process_ack(c, ack, window); }
            if c.snd_una == c.snd_nxt {
                c.state = TcpState::Closed;
            }
        }

        TcpState::TimeWait => {
            // Peer retransmitted its FIN: our ACK was lost.
            if is_fin { send_ack(c); }
        }

        _ => {}
    }
}

// ─── Public API ───────────────────────────────────────────────────────────

fn wait_tick() {
    unsafe { core::arch::asm!("sti; hlt", options(nostack)); }
}

/// Active open: connect to dst_ip:dst_port. Blocks until established or timeout.
pub fn tcp_connect(dst_ip: [u8; 4], dst_port: u16) -> Result<usize, TcpError> {
    let _g = super::BusyGuard::new();
    let idx = alloc_conn().ok_or(TcpError::NoFreeSlots)?;
    let local_port = next_ephemeral_port();
    let iss = next_iss();

    unsafe {
        let c = &mut CONNS[idx];
        c.reset();
        c.state = TcpState::SynSent;
        c.local_port = local_port;
        c.remote_port = dst_port;
        c.remote_ip = dst_ip;
        c.snd_iss = iss;
        c.snd_una = iss;
        c.snd_nxt = iss.wrapping_add(1); // SYN consumes one seq
        c.last_tx_tick = now_ticks();
        send_tcp_segment(dst_ip, local_port, dst_port, iss, 0, TCP_SYN, c.adv_window(), &[]);
    }

    let deadline = now_ticks() + CONNECT_TIMEOUT_TICKS;
    loop {
        super::poll_rx();
        unsafe {
            let c = &mut CONNS[idx];
            match c.state {
                TcpState::Established | TcpState::CloseWait => return Ok(idx),
                TcpState::Closed => { c.reset(); return Err(TcpError::ConnectionRefused); }
                _ => {}
            }
            if now_ticks() >= deadline {
                c.reset();
                return Err(TcpError::TimedOut);
            }
            check_retransmit(c);
        }
        wait_tick();
    }
}

/// Passive open: listen on a port. Returns listener connection ID.
pub fn tcp_listen(port: u16) -> Result<usize, TcpError> {
    let _g = super::BusyGuard::new();
    if find_listener(port).is_some() { return Err(TcpError::NoFreeSlots); }
    let idx = alloc_conn().ok_or(TcpError::NoFreeSlots)?;
    unsafe {
        let c = &mut CONNS[idx];
        c.reset();
        c.state = TcpState::Listen;
        c.local_port = port;
    }
    Ok(idx)
}

/// Accept an incoming connection on a listener. Blocks until a SYN arrives
/// and the handshake completes. Returns a NEW connection ID (listener stays open).
pub fn tcp_accept(listener: usize, timeout_ticks: u64) -> Result<usize, TcpError> {
    let _g = super::BusyGuard::new();
    if listener >= MAX_CONNS { return Err(TcpError::InvalidConn); }
    unsafe {
        if CONNS[listener].state != TcpState::Listen {
            return Err(TcpError::InvalidConn);
        }
    }

    let deadline = now_ticks() + timeout_ticks;
    loop {
        super::poll_rx();

        let ready = unsafe { CONNS[listener].accept_ready };
        if ready {
            let idx = alloc_conn().ok_or(TcpError::NoFreeSlots)?;
            let iss = next_iss();
            unsafe {
                let l = &mut CONNS[listener];
                let client_ip   = l.accept_ip;
                let client_port = l.accept_port;
                let client_irs  = l.accept_irs;
                let client_mss  = l.accept_mss;
                let listen_port = l.local_port;
                l.accept_ready = false;

                let c = &mut CONNS[idx];
                c.reset();
                c.state = TcpState::SynReceived;
                c.local_port = listen_port;
                c.remote_port = client_port;
                c.remote_ip = client_ip;
                c.snd_iss = iss;
                c.snd_una = iss;
                c.snd_nxt = iss.wrapping_add(1);
                c.rcv_irs = client_irs;
                c.rcv_nxt = client_irs.wrapping_add(1);
                c.peer_mss = client_mss;
                c.last_tx_tick = now_ticks();
                send_tcp_segment(client_ip, listen_port, client_port,
                    iss, c.rcv_nxt, TCP_SYN | TCP_ACK, c.adv_window(), &[]);
            }

            let hs_deadline = now_ticks() + CONNECT_TIMEOUT_TICKS;
            loop {
                super::poll_rx();
                unsafe {
                    let c = &mut CONNS[idx];
                    match c.state {
                        TcpState::Established | TcpState::CloseWait => return Ok(idx),
                        TcpState::Closed => { c.reset(); return Err(TcpError::ConnectionReset); }
                        _ => {}
                    }
                    if now_ticks() >= hs_deadline {
                        c.reset();
                        return Err(TcpError::TimedOut);
                    }
                    check_retransmit(c);
                }
                wait_tick();
            }
        }

        if now_ticks() >= deadline {
            return Err(TcpError::TimedOut);
        }
        wait_tick();
    }
}

/// Send data on an established connection. Blocks until all bytes are queued
/// (not necessarily acknowledged). Returns bytes queued.
pub fn tcp_send(conn: usize, data: &[u8]) -> Result<usize, TcpError> {
    let _g = super::BusyGuard::new();
    if conn >= MAX_CONNS { return Err(TcpError::InvalidConn); }

    let mut queued = 0usize;
    let mut last_progress = now_ticks();
    while queued < data.len() {
        unsafe {
            let c = &mut CONNS[conn];
            match c.state {
                TcpState::Established | TcpState::CloseWait => {}
                TcpState::Closed => {
                    return if queued > 0 { Ok(queued) } else { Err(TcpError::ConnectionReset) };
                }
                _ => return Err(TcpError::NotConnected),
            }

            let space = TX_BUF_SIZE - c.txq_len;
            if space > 0 {
                let n = space.min(data.len() - queued);
                let start = c.txq_len;
                c.txq[start..start + n].copy_from_slice(&data[queued..queued + n]);
                c.txq_len += n;
                queued += n;
                last_progress = now_ticks();
            }
            output(c);
            if queued >= data.len() { break; }
            if !check_retransmit(c) { return Err(TcpError::TimedOut); }
        }
        if now_ticks().wrapping_sub(last_progress) > SEND_TIMEOUT_TICKS {
            return if queued > 0 { Ok(queued) } else { Err(TcpError::TimedOut) };
        }
        super::poll_rx();
        wait_tick();
    }
    Ok(queued)
}

/// Receive data. Returns Ok(n>0) with data, Ok(0) at end of stream (peer
/// closed and everything read), or Err(TimedOut) if nothing arrived in time.
pub fn tcp_recv(conn: usize, buf: &mut [u8], timeout_ticks: u64) -> Result<usize, TcpError> {
    let _g = super::BusyGuard::new();
    if conn >= MAX_CONNS { return Err(TcpError::InvalidConn); }
    if buf.is_empty() { return Ok(0); }

    let deadline = now_ticks() + timeout_ticks;
    loop {
        super::poll_rx();

        unsafe {
            let c = &mut CONNS[conn];

            let n = c.rx_ring.read(buf);
            if n > 0 {
                maybe_window_update(c);
                return Ok(n);
            }

            match c.state {
                TcpState::Established | TcpState::SynReceived
                | TcpState::FinWait1 | TcpState::FinWait2 => {}
                TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait => return Ok(0),
                TcpState::Closed => return Err(TcpError::ConnectionReset),
                _ => return Err(TcpError::NotConnected),
            }

            if !check_retransmit(c) { return Err(TcpError::TimedOut); }
            output(c);
        }

        if now_ticks() >= deadline { return Err(TcpError::TimedOut); }
        wait_tick();
    }
}

/// After the application consumed data, tell the peer if the window grew a lot.
unsafe fn maybe_window_update(c: &mut TcpConn) {
    let free = c.rx_ring.free_space();
    if c.state == TcpState::Established
        && free >= c.last_adv_wnd + 2 * OUR_MSS.min(RX_BUF_SIZE / 4)
    {
        send_ack(c);
    }
}

/// Non-blocking receive — returns WouldBlock if no data.
pub fn tcp_recv_nb(conn: usize, buf: &mut [u8]) -> Result<usize, TcpError> {
    let _g = super::BusyGuard::new();
    if conn >= MAX_CONNS { return Err(TcpError::InvalidConn); }

    super::poll_rx();
    unsafe {
        let c = &mut CONNS[conn];
        let n = c.rx_ring.read(buf);
        if n == 0 {
            return match c.state {
                TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait => Ok(0),
                TcpState::Closed => Err(TcpError::ConnectionReset),
                _ => Err(TcpError::WouldBlock),
            };
        }
        maybe_window_update(c);
        Ok(n)
    }
}

/// Returns the number of connections in non-Closed state.
pub fn active_connection_count() -> usize {
    unsafe { CONNS.iter().filter(|c| c.state != TcpState::Closed).count() }
}

/// Close a connection gracefully: flush queued data, send FIN, wait briefly
/// for the peer to acknowledge, then release the slot.
pub fn tcp_close(conn: usize) {
    let _g = super::BusyGuard::new();
    if conn >= MAX_CONNS { return; }

    unsafe {
        let c = &mut CONNS[conn];
        let next = match c.state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait   => TcpState::LastAck,
            _ => { c.reset(); return; }
        };

        let deadline = now_ticks() + CLOSE_TIMEOUT_TICKS;

        // Push out remaining data first (bounded by the close timeout).
        while c.txq_len > 0 && now_ticks() < deadline
            && (c.state == TcpState::Established || c.state == TcpState::CloseWait)
        {
            output(c);
            if !check_retransmit(c) { break; }
            super::poll_rx();
            wait_tick();
        }
        let next = if c.state == TcpState::CloseWait { TcpState::LastAck } else { next };
        if c.state != TcpState::Established && c.state != TcpState::CloseWait {
            c.reset();
            return;
        }

        // FIN goes after all data that was sent.
        let fin_seq = c.snd_una.wrapping_add(c.txq_len as u32);
        c.snd_nxt = fin_seq.wrapping_add(1);
        c.fin_sent = true;
        c.state = next;
        c.last_tx_tick = now_ticks();
        send_tcp_segment(c.remote_ip, c.local_port, c.remote_port,
            fin_seq, c.rcv_nxt, TCP_FIN | TCP_ACK, c.adv_window(), &[]);

        while now_ticks() < deadline {
            super::poll_rx();
            match c.state {
                TcpState::Closed | TcpState::TimeWait => break,
                TcpState::FinWait2 => {
                    // Our FIN is acknowledged; the peer's FIN may never come
                    // (we don't need it — nothing more will be read).
                    break;
                }
                _ => {}
            }
            if !check_retransmit(c) { break; }
            wait_tick();
        }
        c.reset();
    }
}

/// Get the state of a connection (for display/diagnostics).
pub fn conn_state(conn: usize) -> TcpState {
    if conn >= MAX_CONNS { return TcpState::Closed; }
    unsafe { CONNS[conn].state }
}

/// Get info about a connection for netstat-like display.
pub fn conn_info(conn: usize) -> Option<(TcpState, u16, [u8; 4], u16)> {
    if conn >= MAX_CONNS { return None; }
    unsafe {
        let c = &CONNS[conn];
        if c.state == TcpState::Closed { return None; }
        Some((c.state, c.local_port, c.remote_ip, c.remote_port))
    }
}

/// Number of bytes available to read on a connection.
pub fn available(conn: usize) -> usize {
    if conn >= MAX_CONNS { return 0; }
    unsafe { CONNS[conn].rx_ring.available() }
}

/// Bytes queued for sending but not yet acknowledged.
pub fn unacked(conn: usize) -> usize {
    if conn >= MAX_CONNS { return 0; }
    unsafe { CONNS[conn].in_flight() }
}

/// Return a snapshot of all active connections for display.
/// Fills `out` with (state, local_port, remote_ip, remote_port), returns count.
pub fn active_connections(out: &mut [(TcpState, u16, [u8; 4], u16)]) -> usize {
    let mut n = 0;
    unsafe {
        for i in 0..MAX_CONNS {
            if n >= out.len() { break; }
            if CONNS[i].state != TcpState::Closed {
                out[n] = (CONNS[i].state, CONNS[i].local_port, CONNS[i].remote_ip, CONNS[i].remote_port);
                n += 1;
            }
        }
    }
    n
}
