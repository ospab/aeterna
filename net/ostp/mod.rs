/*
 * OSTP — native client for the stealth tunnel protocol (https://github.com/ospab/ostp)
 *
 * The protocol itself is `ostp-core` (sans-IO, no_std + alloc). This module is
 * the glue the kernel provides:
 *
 *   - platform hooks for ostp-core: monotonic clock, wall clock, RDRAND entropy;
 *   - transports: OSTP over UDP (kernel UDP/IPv4; datagrams for our local port
 *     are queued by `net::udp`, see `wants` / `on_udp`) and UoT, the same
 *     packets over a plain TCP connection with 2-byte length prefixes (kernel
 *     TCP). TLS / WebSocket-upgrade links are not supported;
 *   - a driver that polls the NIC, feeds datagrams to the `ProtocolMachine`,
 *     ticks its timers and sends what it emits;
 *   - a kernel thread ("ostp-pump") that keeps an established session alive
 *     while no command runs (ticks, keepalive pings) and reconnects with
 *     back-off when the server stops answering.
 *
 * Operations on the established tunnel: ping, UDP relay (`dns`), TCP relay (`get`).
 */

extern crate alloc;

pub mod config;
pub mod dnsq;
pub mod rng;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Mutex;

use ostp_core::bytes::Bytes;
use ostp_core::crypto::{derive_all_secrets, NoiseRole};
use ostp_core::framing::{PaddingStrategy, TrafficProfile};
use ostp_core::protocol::{OstpEvent, OstpState, ProtocolAction, ProtocolConfig, ProtocolMachine};
use ostp_core::relay::{data_chunks, RelayMessage};
use ostp_core::sys;

/// OSTP's default datagram budget (same as the desktop client's `mtu`).
const MTU: usize = 1140;
const TICK_NS: u64 = 2_000_000;
const MAX_QUEUED: usize = 256;
const KEEPALIVE_NS: u64 = 10_000_000_000;
const DEAD_AFTER_NS: u64 = 40_000_000_000;

const STREAM_CTRL: u16 = 0;
const STREAM_UDP: u16 = 1;
const STREAM_TCP: u16 = 2;

// ─── Platform hooks ──────────────────────────────────────────────────────────

fn hook_monotonic_ns() -> u64 {
    crate::time::monotonic_ns()
}
fn hook_unix_secs() -> u64 {
    crate::time::unix_secs().max(0) as u64
}
fn hook_random(b: &mut [u8]) {
    rng::fill(b)
}

static HOOKS_SET: AtomicBool = AtomicBool::new(false);

fn ensure_hooks() {
    if !HOOKS_SET.swap(true, Ordering::AcqRel) {
        sys::install(sys::Hooks {
            monotonic_ns: hook_monotonic_ns,
            unix_secs: hook_unix_secs,
            fill_random: hook_random,
        });
    }
}

/// Run `f` with interrupts off. The NIC IRQ polls the stack and reaches
/// `on_udp`, so every task-side use of `RXQ` must not be interruptible.
fn irq_off<T>(f: impl FnOnce() -> T) -> T {
    let flags: u64;
    unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags) };
    let r = f();
    if flags & 0x200 != 0 {
        unsafe { core::arch::asm!("sti") };
    }
    r
}

// ─── UDP receive queue (filled by net::udp) ──────────────────────────────────

static LOCAL_PORT: AtomicU16 = AtomicU16::new(0);
static RXQ: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

/// `net::udp` asks this for every incoming datagram: is it ours?
pub fn wants(dst_port: u16) -> bool {
    let p = LOCAL_PORT.load(Ordering::Relaxed);
    p != 0 && p == dst_port
}

/// Called by `net::udp` with the UDP payload of a datagram for our port.
pub fn on_udp(payload: &[u8]) {
    irq_off(|| {
        let mut q = RXQ.lock();
        if q.len() < MAX_QUEUED {
            q.push_back(payload.to_vec());
        }
    });
}

/// Lock without ever spinning on a holder that was preempted: the pump thread
/// may hold a lock when the timer switches away from it, and a spinning waiter
/// that is not itself preemptible would never let it finish. Yield instead.
fn lock_yield<T>(m: &Mutex<T>) -> spin::MutexGuard<'_, T> {
    loop {
        if let Some(g) = m.try_lock() {
            return g;
        }
        crate::core::scheduler::sys_yield();
    }
}

fn rx_pop() -> Option<Vec<u8>> {
    irq_off(|| RXQ.lock().pop_front())
}

fn rx_clear() {
    irq_off(|| RXQ.lock().clear());
}

// ─── Connection parameters, events ───────────────────────────────────────────

#[derive(Clone)]
pub struct ConnParams {
    pub ip: [u8; 4],
    pub port: u16,
    pub key: String,
    /// UoT (OSTP over plain TCP) instead of UDP.
    pub tcp: bool,
}

static PARAMS: Mutex<Option<ConnParams>> = Mutex::new(None);
/// The user wants a session (set by `connect`, cleared by `close`): the pump
/// thread reconnects while this is set.
static WANT: AtomicBool = AtomicBool::new(false);
static EVENTS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

fn event(s: String) {
    irq_off(|| {
        let mut e = EVENTS.lock();
        if e.len() >= 6 {
            e.pop_front();
        }
        e.push_back(format!("[{} s] {}", crate::time::monotonic_ns() / 1_000_000_000, s));
    });
}

pub fn recent_events() -> Vec<String> {
    irq_off(|| EVENTS.lock().iter().cloned().collect())
}

// ─── Tunnel state ────────────────────────────────────────────────────────────

enum Transport {
    Udp { local_port: u16 },
    Tcp { conn: usize, acc: Vec<u8> },
}

struct Tunnel {
    machine: ProtocolMachine,
    tr: Transport,
    server_ip: [u8; 4],
    server_port: u16,
    started_ns: u64,
    last_tick_ns: u64,
    last_rx_ns: u64,
    last_ping_ns: u64,
    broken: bool,
    tx_dgrams: u64,
    rx_dgrams: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    /// Relay messages delivered by the machine, waiting for the current operation.
    app_q: VecDeque<(u16, Vec<u8>)>,
}

static TUNNEL: Mutex<Option<Tunnel>> = Mutex::new(None);

pub struct Status {
    pub server: String,
    pub transport: &'static str,
    pub state: &'static str,
    pub uptime_ms: u64,
    pub tx_dgrams: u64,
    pub rx_dgrams: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub in_flight: usize,
    pub cwnd_packets: usize,
    pub idle_ms: u64,
}

fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

pub fn is_connected() -> bool {
    matches!(lock_yield(&TUNNEL).as_ref(), Some(t) if t.machine.state() == OstpState::Established && !t.broken)
}

/// Whether a session is wanted (even if currently reconnecting).
pub fn wanted() -> bool {
    WANT.load(Ordering::Relaxed)
}

pub fn status() -> Option<Status> {
    let g = TUNNEL.try_lock()?;
    let t = g.as_ref()?;
    let state = match t.machine.state() {
        OstpState::Init => "init",
        OstpState::Handshaking => "handshaking",
        OstpState::Established => "established",
        OstpState::Closing => "closing",
        OstpState::Closed => "closed",
    };
    let now = crate::time::monotonic_ns();
    Some(Status {
        server: format!("{}:{}", fmt_ip(t.server_ip), t.server_port),
        transport: if matches!(t.tr, Transport::Tcp { .. }) { "uot (tcp)" } else { "udp" },
        state,
        uptime_ms: now.saturating_sub(t.started_ns) / 1_000_000,
        tx_dgrams: t.tx_dgrams,
        rx_dgrams: t.rx_dgrams,
        tx_bytes: t.tx_bytes,
        rx_bytes: t.rx_bytes,
        in_flight: t.machine.in_flight_count(),
        cwnd_packets: t.machine.cwnd_packets(),
        idle_ms: now.saturating_sub(t.last_rx_ns) / 1_000_000,
    })
}

impl Tunnel {
    fn send(&mut self, frame: &[u8]) {
        self.tx_dgrams += 1;
        self.tx_bytes += frame.len() as u64;
        match &self.tr {
            Transport::Udp { local_port } => {
                crate::net::udp::send_udp(self.server_ip, *local_port, self.server_port, frame)
            }
            Transport::Tcp { conn, .. } => {
                let mut buf = Vec::with_capacity(2 + frame.len());
                buf.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                buf.extend_from_slice(frame);
                let mut off = 0;
                let mut spins = 0;
                while off < buf.len() {
                    match crate::net::tcp::tcp_send(*conn, &buf[off..]) {
                        Ok(0) => {
                            spins += 1;
                            if spins > 2000 {
                                self.broken = true;
                                return;
                            }
                            crate::core::scheduler::sys_yield();
                        }
                        Ok(n) => off += n,
                        Err(_) => {
                            self.broken = true;
                            return;
                        }
                    }
                }
            }
        }
    }

    fn act(&mut self, a: ProtocolAction) {
        match a {
            ProtocolAction::SendDatagram(f) => self.send(&f),
            ProtocolAction::DeliverApp(sid, p) => {
                if self.app_q.len() < 4096 {
                    self.app_q.push_back((sid, p.to_vec()));
                }
            }
            ProtocolAction::Multiple(v) => {
                for x in v {
                    self.act(x);
                }
            }
            ProtocolAction::HandshakePayload(..) | ProtocolAction::Noop => {}
        }
    }

    fn event(&mut self, e: OstpEvent) -> Result<(), String> {
        match self.machine.on_event(e) {
            Ok(a) => {
                self.act(a);
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Datagrams that arrived since the last call (UDP queue, or TCP frames).
    fn recv_datagrams(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        match &mut self.tr {
            Transport::Udp { .. } => {
                while let Some(d) = rx_pop() {
                    out.push(d);
                }
            }
            Transport::Tcp { conn, acc } => {
                let mut buf = [0u8; 2048];
                loop {
                    match crate::net::tcp::tcp_recv_nb(*conn, &mut buf) {
                        Ok(0) => {
                            self.broken = true;
                            break;
                        }
                        Ok(n) => acc.extend_from_slice(&buf[..n]),
                        Err(crate::net::tcp::TcpError::WouldBlock) => break,
                        Err(_) => {
                            self.broken = true;
                            break;
                        }
                    }
                }
                while acc.len() >= 2 {
                    let len = u16::from_be_bytes([acc[0], acc[1]]) as usize;
                    if acc.len() < 2 + len {
                        break;
                    }
                    out.push(acc[2..2 + len].to_vec());
                    acc.drain(..2 + len);
                }
            }
        }
        out
    }

    /// Feed arrived datagrams to the machine and run its timers.
    fn pump(&mut self) {
        for d in self.recv_datagrams() {
            self.rx_dgrams += 1;
            self.rx_bytes += d.len() as u64;
            self.last_rx_ns = crate::time::monotonic_ns();
            // A datagram that fails to authenticate is dropped like on any UDP path.
            let _ = self.event(OstpEvent::Inbound(Bytes::from(d)));
        }
        let now = crate::time::monotonic_ns();
        if now.saturating_sub(self.last_tick_ns) >= TICK_NS {
            self.last_tick_ns = now;
            let _ = self.event(OstpEvent::Tick);
        }
    }

    fn send_relay(&mut self, stream: u16, m: RelayMessage) -> Result<(), String> {
        self.event(OstpEvent::Outbound(stream, Bytes::from(m.encode())))
    }

    /// Wait up to `timeout_ms` for a relay message on `stream` for which `f`
    /// returns `Some`. Other messages are discarded.
    fn wait<T>(
        &mut self,
        stream: u16,
        timeout_ms: u64,
        mut f: impl FnMut(RelayMessage) -> Option<T>,
    ) -> Result<T, String> {
        let deadline = crate::time::monotonic_ns() + timeout_ms * 1_000_000;
        loop {
            if crate::arch::x86_64::keyboard::interrupt_pending() {
                return Err("interrupted".to_string());
            }
            crate::net::poll_rx();
            self.pump();
            if self.broken {
                return Err("connection lost".to_string());
            }
            while let Some((sid, raw)) = self.app_q.pop_front() {
                if sid != stream {
                    continue;
                }
                if let Ok(m) = RelayMessage::decode(&raw) {
                    if let Some(v) = f(m) {
                        return Ok(v);
                    }
                }
            }
            if crate::time::monotonic_ns() >= deadline {
                return Err("timeout".to_string());
            }
            crate::core::scheduler::sys_yield();
        }
    }

    /// Background upkeep: keepalive pings and dead-session detection.
    fn dead(&mut self) -> bool {
        let now = crate::time::monotonic_ns();
        if now.saturating_sub(self.last_ping_ns) >= KEEPALIVE_NS {
            self.last_ping_ns = now;
            let _ = self.send_relay(STREAM_CTRL, RelayMessage::Ping(now));
        }
        self.app_q.clear();
        self.broken
            || self.machine.state() != OstpState::Established
            || now.saturating_sub(self.last_rx_ns) > DEAD_AFTER_NS
    }
}

// ─── Establishing a session ──────────────────────────────────────────────────

fn establish(p: &ConnParams) -> Result<(Tunnel, u64), String> {
    ensure_hooks();
    let key = p.key.as_bytes();
    let secrets = derive_all_secrets(key);
    let session_id = rng::u32();

    // Handshake payload: unix seconds | session id | access key (see ostp-client).
    let mut hp = Vec::with_capacity(12 + key.len());
    hp.extend_from_slice(&sys::unix_secs().to_be_bytes());
    hp.extend_from_slice(&session_id.to_be_bytes());
    hp.extend_from_slice(key);

    let mut machine = ProtocolMachine::new(ProtocolConfig {
        role: NoiseRole::Initiator,
        psk: secrets.psk,
        session_id,
        handshake_payload: hp,
        padding_strategy: PaddingStrategy::Profile(TrafficProfile::HttpsBurst),
        obfuscation_key: secrets.obfuscation_key,
        max_reorder: 16384,
        max_reorder_buffer: 8192,
        ack_delay_ms: 5,
        rto_ms: 100,
        max_retries: 8,
        max_sent_history: 32768,
        handshake_pad_min: secrets.handshake_pad_min,
        handshake_pad_max: secrets.handshake_pad_max,
        mtu: MTU,
        max_padding: MTU.saturating_sub(48).max(256),
    })
    .map_err(|e| e.to_string())?;
    // UoT rides TCP: no timer-driven resends (TCP over TCP).
    machine.set_reliable_carrier(p.tcp);

    // ARP-warm the path so the first datagram is not lost to resolution.
    let (our, mask, gw) = unsafe { (crate::net::OUR_IP, crate::net::SUBNET_MASK, crate::net::GATEWAY_IP) };
    let on_link = (0..4).all(|i| p.ip[i] & mask[i] == our[i] & mask[i]);
    let nh = if on_link { p.ip } else { gw };
    if crate::net::arp::cache_lookup(nh).is_none() {
        crate::net::arp::send_request(nh);
        let end = crate::time::monotonic_ns() + 300_000_000;
        while crate::time::monotonic_ns() < end {
            crate::net::poll_rx();
            if crate::net::arp::cache_lookup(nh).is_some() {
                break;
            }
            crate::core::scheduler::sys_yield();
        }
    }

    let tr = if p.tcp {
        let conn = crate::net::tcp::tcp_connect(p.ip, p.port)
            .map_err(|_| "TCP connect failed (refused, unreachable or timed out)".to_string())?;
        Transport::Tcp { conn, acc: Vec::new() }
    } else {
        let local_port = 49152 + (rng::u32() % 16000) as u16;
        rx_clear();
        LOCAL_PORT.store(local_port, Ordering::Relaxed);
        Transport::Udp { local_port }
    };

    let now = crate::time::monotonic_ns();
    let mut t = Tunnel {
        machine,
        tr,
        server_ip: p.ip,
        server_port: p.port,
        started_ns: now,
        last_tick_ns: now,
        last_rx_ns: now,
        last_ping_ns: now,
        broken: false,
        tx_dgrams: 0,
        rx_dgrams: 0,
        tx_bytes: 0,
        rx_bytes: 0,
        app_q: VecDeque::new(),
    };

    let fail = |t: &mut Tunnel, msg: &str| -> Result<(Tunnel, u64), String> {
        if let Transport::Tcp { conn, .. } = &t.tr {
            crate::net::tcp::tcp_close(*conn);
        } else {
            LOCAL_PORT.store(0, Ordering::Relaxed);
        }
        Err(msg.to_string())
    };

    let frame = match t.machine.on_event(OstpEvent::Start).map_err(|e| e.to_string())? {
        ProtocolAction::SendDatagram(f) => f,
        _ => return fail(&mut t, "protocol did not emit a handshake datagram"),
    };

    let (attempts, window_ns) = if p.tcp { (1, 8_000_000_000u64) } else { (6, 800_000_000u64) };
    let start = crate::time::monotonic_ns();
    let mut established = false;
    'attempts: for _ in 0..attempts {
        t.send(&frame);
        let end = crate::time::monotonic_ns() + window_ns;
        while crate::time::monotonic_ns() < end {
            if crate::arch::x86_64::keyboard::interrupt_pending() {
                return fail(&mut t, "interrupted");
            }
            crate::net::poll_rx();
            for d in t.recv_datagrams() {
                t.rx_dgrams += 1;
                t.rx_bytes += d.len() as u64;
                if t.machine.on_event(OstpEvent::Inbound(Bytes::from(d))).is_ok()
                    && t.machine.state() == OstpState::Established
                {
                    established = true;
                    break 'attempts;
                }
            }
            if t.broken {
                break 'attempts;
            }
            crate::core::scheduler::sys_yield();
        }
    }
    if !established {
        return fail(
            &mut t,
            "handshake failed: no valid reply from the server (wrong key, clock skew, or unreachable)",
        );
    }
    let hs_us = crate::time::monotonic_ns().saturating_sub(start) / 1000;
    let now = crate::time::monotonic_ns();
    t.last_tick_ns = now;
    t.last_rx_ns = now;
    t.last_ping_ns = now;
    Ok((t, hs_us))
}

fn drop_tunnel(mut t: Tunnel) {
    let _ = t.event(OstpEvent::Close);
    if let Transport::Tcp { conn, .. } = &t.tr {
        crate::net::tcp::tcp_close(*conn);
    }
}

/// Open a session (handshake, then the caller usually pings). Returns the
/// handshake time in microseconds. The session is kept alive and re-established
/// by the pump thread until [`close`].
pub fn connect(p: ConnParams) -> Result<u64, String> {
    if !crate::net::is_up() {
        return Err("network is down".to_string());
    }
    if !rng::usable() {
        return Err("this CPU has no RDRAND (QEMU: use -cpu max); pass --weak-rng to use the kernel's fallback RNG".to_string());
    }
    close();
    let (t, us) = establish(&p)?;
    *lock_yield(&TUNNEL) = Some(t);
    *lock_yield(&PARAMS) = Some(p);
    WANT.store(true, Ordering::Release);
    event("connected".to_string());
    start_pump();
    Ok(us)
}

pub fn close() {
    WANT.store(false, Ordering::Release);
    if let Some(t) = lock_yield(&TUNNEL).take() {
        drop_tunnel(t);
    }
    LOCAL_PORT.store(0, Ordering::Relaxed);
    rx_clear();
}

// ─── Pump thread ─────────────────────────────────────────────────────────────

static PUMP_STARTED: AtomicBool = AtomicBool::new(false);

/// The pump thread is experimental: with it the shell hung right after the first
/// `connect` in QEMU (see the phase-2 report). Off until that is understood;
/// without it the session is driven by the commands and re-established on demand.
const PUMP_ENABLED: bool = false;

fn start_pump() {
    if !PUMP_ENABLED || PUMP_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    const STACK: usize = 256 * 1024;
    let stack: &'static mut [u8] = alloc::boxed::Box::leak(alloc::vec![0u8; STACK].into_boxed_slice());
    let top = (stack.as_ptr() as u64 + STACK as u64) & !0xF;
    let ok = crate::core::scheduler::spawn_named(
        "ostp-pump",
        crate::core::scheduler::Priority::Normal,
        pump_main as usize as u64,
        top - 8,
        0,
        &[],
    );
    crate::arch::x86_64::serial::write_str(if ok.is_some() { "[ostp] pump spawned
" } else { "[ostp] pump spawn failed
" });
    if ok.is_none() {
        PUMP_STARTED.store(false, Ordering::Release);
        event("could not start the pump thread (no keepalive)".to_string());
    }
}

/// Drive an established session from the console's idle loop (no thread): keepalives
/// and retransmits at most every 50 ms; a dead session is dropped and the next ostp
/// command reconnects. Never blocks: skips if a command holds the tunnel.
pub fn idle_poll() {
    static LAST_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    if !WANT.load(Ordering::Acquire) {
        return;
    }
    let now = crate::time::monotonic_ns();
    if now.wrapping_sub(LAST_NS.load(Ordering::Relaxed)) < 50_000_000 {
        return;
    }
    LAST_NS.store(now, Ordering::Relaxed);
    if let Some(mut g) = TUNNEL.try_lock() {
        let mut dead = false;
        if let Some(t) = g.as_mut() {
            crate::net::poll_rx();
            t.pump();
            dead = t.dead();
        }
        if dead {
            if let Some(old) = g.take() {
                drop_tunnel(old);
            }
            event("session lost; the next ostp command reconnects".to_string());
        }
    }
}

extern "C" fn pump_main() -> ! {
    let mut backoff_s: u64 = 2;
    let mut next_try_ns: u64 = 0;
    loop {
        // Sleep one timer tick. The shell is the Idle task (slot 0): a Ready
        // Normal task would starve it, so this thread is Waiting almost always.
        unsafe {
            core::arch::asm!("cli");
            crate::core::scheduler::park(crate::arch::x86_64::idt::timer_ticks() + 1);
            core::arch::asm!("sti");
        }
        if !WANT.load(Ordering::Acquire) {
            continue;
        }
        let mut lost = false;
        let mut have = false;
        if let Some(mut g) = TUNNEL.try_lock() {
            let mut is_dead = false;
            if let Some(t) = g.as_mut() {
                have = true;
                crate::net::poll_rx();
                t.pump();
                is_dead = t.dead();
            }
            if is_dead {
                lost = true;
                if let Some(old) = g.take() {
                    drop_tunnel(old);
                }
            }
        } else {
            have = true; // a command is using it
        }
        if lost {
            event("session lost, reconnecting".to_string());
            next_try_ns = 0;
            backoff_s = 2;
        }
        if !have && WANT.load(Ordering::Acquire) {
            let now = crate::time::monotonic_ns();
            if now >= next_try_ns {
                let p = lock_yield(&PARAMS).clone();
                if let Some(p) = p {
                    match establish(&p) {
                        Ok((t, _)) => {
                            if WANT.load(Ordering::Acquire) {
                                *lock_yield(&TUNNEL) = Some(t);
                                event("reconnected".to_string());
                                backoff_s = 2;
                            } else {
                                drop_tunnel(t);
                            }
                        }
                        Err(e) => {
                            event(format!("reconnect failed: {} (retry in {} s)", e, backoff_s));
                            next_try_ns = crate::time::monotonic_ns() + backoff_s * 1_000_000_000;
                            backoff_s = (backoff_s * 2).min(30);
                        }
                    }
                }
            }
        }
    }
}

// ─── Operations on the tunnel ────────────────────────────────────────────────

fn with_tunnel<T>(f: impl FnOnce(&mut Tunnel) -> Result<T, String>) -> Result<T, String> {
    let mut g = lock_yield(&TUNNEL);
    let t = g.as_mut().ok_or_else(|| {
        if WANT.load(Ordering::Relaxed) {
            "session is being re-established, try again in a moment".to_string()
        } else {
            "not connected (ostp connect)".to_string()
        }
    })?;
    if t.machine.state() != OstpState::Established {
        return Err("session is not established".to_string());
    }
    f(t)
}

/// Relay ping through the tunnel; round-trip time in microseconds.
pub fn ping() -> Result<u64, String> {
    with_tunnel(|t| {
        let ts = crate::time::monotonic_ns();
        t.send_relay(STREAM_CTRL, RelayMessage::Ping(ts))?;
        t.wait(STREAM_CTRL, 3000, |m| match m {
            RelayMessage::Pong(x) if x == ts => Some(()),
            _ => None,
        })?;
        Ok(crate::time::monotonic_ns().saturating_sub(ts) / 1000)
    })
}

/// Resolve `name` with a DNS query sent through the tunnel (UDP relay) to
/// `resolver` ("ip:port"). Returns the A records and the query time in µs.
pub fn dns(name: &str, resolver: &str) -> Result<(Vec<[u8; 4]>, u64), String> {
    let id = rng::u32() as u16;
    let q = dnsq::build_query(id, name).ok_or_else(|| "bad host name".to_string())?;
    with_tunnel(|t| {
        t.send_relay(STREAM_UDP, RelayMessage::UdpAssociate)?;
        t.wait(STREAM_UDP, 3000, |m| matches!(m, RelayMessage::ConnectOk).then_some(()))
            .map_err(|e| format!("UDP associate not acknowledged by the server ({})", e))?;
        let t0 = crate::time::monotonic_ns();
        t.send_relay(STREAM_UDP, RelayMessage::UdpData(resolver.to_string(), q))?;
        let res = t
            .wait(STREAM_UDP, 4000, |m| match m {
                RelayMessage::UdpData(_, data) => dnsq::parse_a(&data, id)
                    .map(|r| r.map_err(|rc| format!("DNS error (rcode {})", rc))),
                RelayMessage::Error(e) => Some(Err(e)),
                _ => None,
            })
            .map_err(|e| format!("no DNS reply through the tunnel ({})", e))?;
        let rtt = crate::time::monotonic_ns().saturating_sub(t0) / 1000;
        let _ = t.send_relay(STREAM_UDP, RelayMessage::Close);
        res.map(|v| (v, rtt))
    })
}

/// Open a TCP connection to `target` ("host:port") through the tunnel, send
/// `request`, and hand every received byte to `sink` until the remote closes,
/// `max_bytes` arrived or the stream is idle for `idle_ms`.
/// Returns the number of bytes received.
pub fn tcp_exchange(
    target: &str,
    request: &[u8],
    max_bytes: usize,
    idle_ms: u64,
    sink: &mut dyn FnMut(&[u8]),
) -> Result<usize, String> {
    with_tunnel(|t| {
        t.send_relay(STREAM_TCP, RelayMessage::Connect(target.to_string()))?;
        t.wait(STREAM_TCP, 8000, |m| match m {
            RelayMessage::ConnectOk => Some(Ok(())),
            RelayMessage::Error(e) => Some(Err(e)),
            _ => None,
        })?
        .map_err(|e| format!("connect failed: {}", e))?;

        let max_payload = t.machine.max_payload();
        for chunk in data_chunks(request, max_payload) {
            t.send_relay(STREAM_TCP, RelayMessage::Data(chunk.to_vec()))?;
        }

        let mut got = 0usize;
        loop {
            match t.wait(STREAM_TCP, idle_ms, |m| Some(m)) {
                Ok(RelayMessage::Data(d)) => {
                    got += d.len();
                    sink(&d);
                    if got >= max_bytes {
                        break;
                    }
                }
                Ok(RelayMessage::Close) | Ok(RelayMessage::Error(_)) => break,
                Ok(_) => {}
                Err(e) if e == "timeout" => break,
                Err(e) => return Err(e),
            }
        }
        let _ = t.send_relay(STREAM_TCP, RelayMessage::Close);
        Ok(got)
    })
}
