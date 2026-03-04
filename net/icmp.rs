/*
 * ICMP — Internet Control Message Protocol
 * Handles Echo Reply (for receiving pong) and sends Echo Request (ping).
 */

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const ICMP_ECHO_REPLY: u8   = 0;
const ICMP_ECHO_REQUEST: u8 = 8;

// Ping state: shared between sender and receiver
static PING_WAITING:  AtomicBool = AtomicBool::new(false);
static PING_RECEIVED: AtomicBool = AtomicBool::new(false);
static PING_SEQ:      AtomicU64  = AtomicU64::new(0);
// TSC stamp (µs absolute) captured when the echo-request was sent.
static PING_SEND_US:  AtomicU64  = AtomicU64::new(0);
// RTT result in *microseconds*.
static PING_RTT_US:   AtomicU64  = AtomicU64::new(0);
#[allow(dead_code)]
static mut PING_TTL: u8 = 0;

/// Handle incoming ICMP packet
pub fn handle_icmp(data: &[u8], src_ip: [u8; 4]) {
    if data.len() < 8 { return; }

    let icmp_type = data[0];
    let _code = data[1];

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
                PING_RECEIVED.store(true, Ordering::Release);
                PING_WAITING.store(false, Ordering::Relaxed);
            }
        }
        ICMP_ECHO_REQUEST => {
            // Reply to ping (we are being pinged)
            send_echo_reply(src_ip, data);
        }
        _ => {}
    }
}

/// Send ICMP echo request (ping)
pub fn send_ping(dst_ip: [u8; 4], seq: u16) {
    let mut pkt = [0u8; 64];

    // ICMP type: Echo Request
    pkt[0] = ICMP_ECHO_REQUEST;
    // Code: 0
    pkt[1] = 0;
    // Checksum (filled later)
    pkt[2] = 0;
    pkt[3] = 0;
    // Identifier
    pkt[4] = 0xAE;
    pkt[5] = 0x01;
    // Sequence number
    let sq = seq.to_be_bytes();
    pkt[6] = sq[0];
    pkt[7] = sq[1];

    // Payload: fill with pattern
    for i in 8..64 {
        pkt[i] = (i as u8) & 0xFF;
    }

    // Checksum
    let cksum = super::ipv4::checksum(&pkt[..64]);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xFF) as u8;

    // Mark waiting — use TSC µs timestamp for sub-millisecond RTT measurement
    PING_RECEIVED.store(false, Ordering::Relaxed);
    PING_WAITING.store(true, Ordering::Release);
    PING_SEND_US.store(crate::arch::x86_64::tsc::tsc_stamp_us(), Ordering::Relaxed);

    // Send via IPv4
    super::ipv4::send_ipv4(1, dst_ip, &pkt[..64]);
}

/// Non-blocking check for ping reply. Polls NIC and returns immediately.
/// Returns `Some((seq, rtt_us))` where rtt_us is RTT in **microseconds**.
pub fn poll_reply() -> Option<(u16, u64)> {
    super::poll_rx();
    if PING_RECEIVED.load(Ordering::Acquire) {
        let seq    = PING_SEQ.load(Ordering::Relaxed) as u16;
        let rtt_us = PING_RTT_US.load(Ordering::Relaxed);
        return Some((seq, rtt_us));
    }
    None
}

/// Cancel an in-progress wait (called on Ctrl+C)
pub fn cancel_wait() {
    PING_WAITING.store(false, Ordering::Relaxed);
    PING_RECEIVED.store(false, Ordering::Relaxed);
}

/// Wait for ping reply. Returns `Some((seq, rtt_us))` or `None` on timeout/cancel.
/// The wait loop wakes on *any* interrupt (NIC IRQ, APIC timer, PIT tick) via `hlt`,
/// then immediately calls `poll_reply()` — so latency is bounded by NIC IRQ latency,
/// not by the 10 ms PIT period.
pub fn wait_reply(timeout_ticks: u64) -> Option<(u16, u64)> {
    // Convert timeout from legacy 100 Hz ticks to microseconds.
    let timeout_us  = timeout_ticks.saturating_mul(10_000);
    let start_us    = crate::arch::x86_64::tsc::tsc_stamp_us();
    loop {
        // poll_reply() calls poll_rx() internally
        if let Some(r) = poll_reply() { return Some(r); }

        let elapsed_us = crate::arch::x86_64::tsc::tsc_stamp_us().saturating_sub(start_us);
        if elapsed_us >= timeout_us {
            PING_WAITING.store(false, Ordering::Relaxed);
            return None;
        }

        // Sleep until next interrupt.  The NIC IRQ (or APIC 1 ms timer) will
        // wake us; we immediately re-check instead of waiting for the next
        // 10 ms PIT tick.  This brings localhost RTT from ~10 ms to <1 ms.
        crate::core::scheduler::sys_yield();
    }
}

/// Reply to an Echo Request
fn send_echo_reply(dst_ip: [u8; 4], request: &[u8]) {
    let len = request.len().min(1480);
    let mut pkt = [0u8; 1480];
    pkt[..len].copy_from_slice(&request[..len]);

    // Change type to Echo Reply
    pkt[0] = ICMP_ECHO_REPLY;
    // Recompute checksum
    pkt[2] = 0;
    pkt[3] = 0;
    let cksum = super::ipv4::checksum(&pkt[..len]);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xFF) as u8;

    super::ipv4::send_ipv4(1, dst_ip, &pkt[..len]);
}
