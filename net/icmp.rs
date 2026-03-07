/*
 * ICMP — Internet Control Message Protocol
 * Handles Echo Reply (for receiving pong) and sends Echo Request (ping).
 *
 * The ping state machine uses atomics so that the IRQ-driven RX path
 * (`handle_icmp`) can store results that the polling sender reads.
 *
 * RTT is measured with the TSC (µs precision).
 */

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

const ICMP_ECHO_REPLY: u8    = 0;
const ICMP_ECHO_REQUEST: u8  = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;

// Ping state: shared between sender (send_ping_sized) and IRQ receiver (handle_icmp).
static PING_WAITING:  AtomicBool = AtomicBool::new(false);
static PING_RECEIVED: AtomicBool = AtomicBool::new(false);
static PING_SEQ:      AtomicU64  = AtomicU64::new(0);
// TSC stamp (µs absolute) captured when the echo-request was sent.
static PING_SEND_US:  AtomicU64  = AtomicU64::new(0);
// RTT result in *microseconds*.
static PING_RTT_US:   AtomicU64  = AtomicU64::new(0);
// TTL from the IP header of the echo-reply.
static PING_TTL:      AtomicU8   = AtomicU8::new(0);
// Total ICMP payload bytes in the echo-reply (data[8..]).
static PING_REPLY_BYTES: AtomicU64 = AtomicU64::new(0);
// Source IP of the replier (packed as u32 big-endian).
static PING_SRC_IP: AtomicU32 = AtomicU32::new(0);
// True when reply was ICMP Time Exceeded (type 11) rather than Echo Reply.
static PING_IS_TTL_EXCEEDED: AtomicBool = AtomicBool::new(false);

/// Ping reply data returned by `poll_reply()` / `wait_reply()`.
#[derive(Clone, Copy, Debug)]
pub struct PingReply {
    pub seq:    u16,
    pub rtt_us: u64,
    pub ttl:    u8,
    /// Total bytes received (IP header 20 + ICMP header 8 + payload).
    pub nbytes: u64,
    /// IPv4 address of the host that sent the reply.
    pub src_ip: [u8; 4],
    /// True if reply was an ICMP Time Exceeded (type 11) rather than Echo Reply.
    pub is_ttl_exceeded: bool,
}

/// Handle incoming ICMP packet.
/// Called from `ipv4::handle_ipv4` with the ICMP payload, source IP, and IP-layer TTL.
pub fn handle_icmp(data: &[u8], src_ip: [u8; 4], ttl: u8) {
    if data.len() < 8 { return; }

    let icmp_type = data[0];

    match icmp_type {
        ICMP_ECHO_REPLY => {
            crate::arch::x86_64::serial::write_str("[ICMP] Echo Reply received\r\n");
            if PING_WAITING.load(Ordering::Acquire) {
                let seq = u16::from_be_bytes([data[6], data[7]]);
                // TSC-based RTT: now_us - send_us  (sub-millisecond precision)
                let now_us  = crate::arch::x86_64::tsc::tsc_stamp_us();
                let sent_us = PING_SEND_US.load(Ordering::Relaxed);
                let rtt_us  = now_us.saturating_sub(sent_us);
                PING_RTT_US.store(rtt_us, Ordering::Relaxed);
                PING_SEQ.store(seq as u64, Ordering::Relaxed);
                PING_TTL.store(ttl, Ordering::Relaxed);
                // Total reply bytes = 20 (IP header) + ICMP data length
                PING_REPLY_BYTES.store((20 + data.len()) as u64, Ordering::Relaxed);
                // Store replier's IP and mark as echo reply
                let packed_ip = u32::from_be_bytes(src_ip);
                PING_SRC_IP.store(packed_ip, Ordering::Relaxed);
                PING_IS_TTL_EXCEEDED.store(false, Ordering::Relaxed);
                PING_RECEIVED.store(true, Ordering::Release);
                PING_WAITING.store(false, Ordering::Relaxed);
            }
        }
        ICMP_TIME_EXCEEDED => {
            // Time Exceeded (type 11): a router dropped our packet due to TTL=0.
            // The ICMP payload contains: 4 bytes unused + original IP header (20 B)
            // + first 8 bytes of the original datagram (ICMP header with our seq).
            // Layout: data[0]=11, [1]=code, [2-3]=cksum, [4-7]=unused,
            //         [8..28]=original IP hdr, [28..36]=original ICMP hdr
            crate::arch::x86_64::serial::write_str("[ICMP] Time Exceeded received\r\n");
            if PING_WAITING.load(Ordering::Acquire) && data.len() >= 36 {
                // Extract original ICMP seq from inner datagram (offset 28+6 = 34)
                let _seq = u16::from_be_bytes([data[34], data[35]]);
                let now_us  = crate::arch::x86_64::tsc::tsc_stamp_us();
                let sent_us = PING_SEND_US.load(Ordering::Relaxed);
                let rtt_us  = now_us.saturating_sub(sent_us);
                PING_RTT_US.store(rtt_us, Ordering::Relaxed);
                PING_SEQ.store(_seq as u64, Ordering::Relaxed);
                PING_TTL.store(ttl, Ordering::Relaxed);
                PING_REPLY_BYTES.store(0, Ordering::Relaxed);
                let packed_ip = u32::from_be_bytes(src_ip);
                PING_SRC_IP.store(packed_ip, Ordering::Relaxed);
                PING_IS_TTL_EXCEEDED.store(true, Ordering::Relaxed);
                PING_RECEIVED.store(true, Ordering::Release);
                PING_WAITING.store(false, Ordering::Relaxed);
            }
        }
        ICMP_ECHO_REQUEST => {
            send_echo_reply(src_ip, data);
        }
        _ => {}
    }
}

/// Send ICMP echo request with `payload_size` bytes of pattern data.
///
/// Total ICMP packet = 8 (header) + `payload_size`.
/// Linux default: payload_size = 56 → total ICMP = 64 → IP packet = 84 bytes.
pub fn send_ping_sized(dst_ip: [u8; 4], seq: u16, payload_size: usize) {
    // Cap to prevent overflowing the 1500-byte Ethernet MTU
    // IP header = 20, ICMP header = 8 → max payload = 1500 - 14 (eth) - 20 - 8 = 1458
    let payload_size = payload_size.min(1458);
    let icmp_len = 8 + payload_size;

    let mut pkt = [0u8; 1480];

    pkt[0] = ICMP_ECHO_REQUEST;
    pkt[1] = 0; // code
    pkt[2] = 0; // checksum (filled below)
    pkt[3] = 0;
    pkt[4] = 0xAE; // identifier hi
    pkt[5] = 0x01; // identifier lo
    let sq = seq.to_be_bytes();
    pkt[6] = sq[0];
    pkt[7] = sq[1];

    // Fill payload with repeating pattern (matches Linux ping behaviour)
    for i in 0..payload_size {
        pkt[8 + i] = (i as u8) & 0xFF;
    }

    let cksum = super::ipv4::checksum(&pkt[..icmp_len]);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xFF) as u8;

    // Mark waiting — TSC µs timestamp for sub-millisecond RTT measurement
    PING_RECEIVED.store(false, Ordering::Relaxed);
    PING_WAITING.store(true, Ordering::Release);
    PING_SEND_US.store(crate::arch::x86_64::tsc::tsc_stamp_us(), Ordering::Relaxed);

    super::ipv4::send_ipv4(1, dst_ip, &pkt[..icmp_len]);
}

/// Legacy 56-byte-payload variant (keeps existing callers happy).
pub fn send_ping(dst_ip: [u8; 4], seq: u16) {
    send_ping_sized(dst_ip, seq, 56);
}

/// Send an ICMP echo request with a custom IP TTL — used by traceroute.
///
/// The TTL causes the packet to expire at intermediate routers, which will
/// respond with ICMP Time Exceeded (type 11).  The reply (whether Echo Reply
/// or Time Exceeded) is returned by `poll_reply()` / `wait_reply_us()`.
pub fn send_ping_ttl(dst_ip: [u8; 4], seq: u16, ttl: u8) {
    let payload_size = 40; // small payload sufficient for traceroute
    let icmp_len = 8 + payload_size;

    let mut pkt = [0u8; 64];
    pkt[0] = ICMP_ECHO_REQUEST;
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 0;
    pkt[4] = 0xAE;
    pkt[5] = 0x01;
    let sq = seq.to_be_bytes();
    pkt[6] = sq[0];
    pkt[7] = sq[1];
    for i in 0..payload_size {
        pkt[8 + i] = (i as u8) & 0xFF;
    }
    let cksum = super::ipv4::checksum(&pkt[..icmp_len]);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xFF) as u8;

    PING_RECEIVED.store(false, Ordering::Relaxed);
    PING_WAITING.store(true, Ordering::Release);
    PING_SEND_US.store(crate::arch::x86_64::tsc::tsc_stamp_us(), Ordering::Relaxed);

    super::ipv4::send_ipv4_ttl(1, dst_ip, &pkt[..icmp_len], ttl);
}

/// Non-blocking check for ping reply. Polls NIC and returns immediately.
pub fn poll_reply() -> Option<PingReply> {
    super::poll_rx();
    if PING_RECEIVED.load(Ordering::Acquire) {
        let raw_ip = PING_SRC_IP.load(Ordering::Relaxed).to_be_bytes();
        return Some(PingReply {
            seq:             PING_SEQ.load(Ordering::Relaxed) as u16,
            rtt_us:          PING_RTT_US.load(Ordering::Relaxed),
            ttl:             PING_TTL.load(Ordering::Relaxed),
            nbytes:          PING_REPLY_BYTES.load(Ordering::Relaxed),
            src_ip:          raw_ip,
            is_ttl_exceeded: PING_IS_TTL_EXCEEDED.load(Ordering::Relaxed),
        });
    }
    None
}

/// Cancel an in-progress wait (called on Ctrl+C or timeout).
pub fn cancel_wait() {
    PING_WAITING.store(false, Ordering::Relaxed);
    PING_RECEIVED.store(false, Ordering::Relaxed);
}

/// Blocking wait for ping reply with TSC-based timeout.
///
/// `timeout_us` is in **microseconds** (e.g. 3_000_000 = 3 s).
/// Returns `Some(PingReply)` or `None` on timeout.
pub fn wait_reply_us(timeout_us: u64) -> Option<PingReply> {
    let start_us = crate::arch::x86_64::tsc::tsc_stamp_us();
    loop {
        if let Some(r) = poll_reply() { return Some(r); }

        let elapsed_us = crate::arch::x86_64::tsc::tsc_stamp_us().saturating_sub(start_us);
        if elapsed_us >= timeout_us {
            PING_WAITING.store(false, Ordering::Relaxed);
            return None;
        }

        // Sleep until next interrupt (NIC IRQ / APIC 1 ms timer).
        crate::core::scheduler::sys_yield();
    }
}

/// Legacy API: timeout in 100 Hz PIT ticks → converts to µs internally.
pub fn wait_reply(timeout_ticks: u64) -> Option<PingReply> {
    wait_reply_us(timeout_ticks.saturating_mul(10_000))
}

/// Reply to an Echo Request (we are being pinged).
fn send_echo_reply(dst_ip: [u8; 4], request: &[u8]) {
    let len = request.len().min(1480);
    let mut pkt = [0u8; 1480];
    pkt[..len].copy_from_slice(&request[..len]);

    pkt[0] = ICMP_ECHO_REPLY;
    pkt[2] = 0;
    pkt[3] = 0;
    let cksum = super::ipv4::checksum(&pkt[..len]);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xFF) as u8;

    super::ipv4::send_ipv4(1, dst_ip, &pkt[..len]);
}
