/*
 * DHCP Client — Dynamic Host Configuration Protocol (RFC 2131)
 *
 * Full 4-step handshake on bare metal:
 *   1. DISCOVER  → broadcast (0.0.0.0 → 255.255.255.255)
 *   2. OFFER     ← server provides IP/mask/gateway/DNS
 *   3. REQUEST   → confirm the offered lease
 *   4. ACK       ← server confirms; configuration is active
 *
 * No QEMU/SLIRP assumptions.  Works with any RFC 2131 server.
 */

use core::sync::atomic::{AtomicBool, Ordering};

// ─── DHCP constants ───────────────────────────────────────────────────────
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

const BOOTREQUEST: u8 = 1;
const BOOTREPLY:   u8 = 2;

// DHCP message types (option 53)
const DHCPDISCOVER: u8 = 1;
const DHCPOFFER:    u8 = 2;
const DHCPREQUEST:  u8 = 3;
const DHCPACK:      u8 = 5;
const DHCPNAK:      u8 = 6;

// ─── Parsed DHCP offer / ACK ─────────────────────────────────────────────
#[derive(Clone, Copy, Debug)]
pub struct DhcpLease {
    pub your_ip:    [u8; 4],
    pub subnet:     [u8; 4],
    pub gateway:    [u8; 4],
    pub dns:        [u8; 4],
    pub server_ip:  [u8; 4],
    pub lease_secs: u32,
}

impl DhcpLease {
    const fn empty() -> Self {
        DhcpLease {
            your_ip:   [0; 4],
            subnet:    [255, 255, 255, 0],
            gateway:   [0; 4],
            dns:       [0; 4],
            server_ip: [0; 4],
            lease_secs: 0,
        }
    }
}

// ─── RX buffer — written by UDP handler, read by dhcp code ───────────────
static mut DHCP_RX_BUF: [u8; 576] = [0; 576];
static mut DHCP_RX_LEN: usize = 0;
static DHCP_RX_READY: AtomicBool = AtomicBool::new(false);

/// Called from UDP dispatch when dst_port == 68
pub fn handle_dhcp_udp(data: &[u8]) {
    if data.len() < 240 { return; }
    let copy = data.len().min(576);
    unsafe {
        DHCP_RX_BUF[..copy].copy_from_slice(&data[..copy]);
        DHCP_RX_LEN = copy;
    }
    DHCP_RX_READY.store(true, Ordering::Release);
}

// ─── Unique transaction ID derived from MAC ──────────────────────────────
fn xid_from_mac(mac: [u8; 6]) -> u32 {
    // Cheap hash of MAC + timer ticks for uniqueness
    let t = crate::arch::x86_64::idt::timer_ticks() as u32;
    u32::from_be_bytes([mac[2] ^ (t as u8), mac[3], mac[4], mac[5]])
}

// ─── Build DHCP packet (BOOTP + options) ─────────────────────────────────
fn build_dhcp(
    msg_type: u8,
    xid: u32,
    mac: [u8; 6],
    requested_ip: Option<[u8; 4]>,
    server_ip: Option<[u8; 4]>,
    buf: &mut [u8; 576],
) -> usize {
    // Zero entire buffer
    for b in buf.iter_mut() { *b = 0; }

    buf[0] = BOOTREQUEST;  // op
    buf[1] = 1;            // htype = Ethernet
    buf[2] = 6;            // hlen  = MAC length
    buf[3] = 0;            // hops

    // Transaction ID
    let x = xid.to_be_bytes();
    buf[4..8].copy_from_slice(&x);

    // secs = 0, flags = 0x8000 (broadcast)
    buf[10] = 0x80;

    // chaddr (client hardware address)
    buf[28..34].copy_from_slice(&mac);

    // Magic cookie (offset 236)
    buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    // Options start at 240
    let mut pos = 240;

    // Option 53: DHCP Message Type
    buf[pos] = 53; buf[pos+1] = 1; buf[pos+2] = msg_type;
    pos += 3;

    // Option 50: Requested IP Address (in REQUEST)
    if let Some(ip) = requested_ip {
        buf[pos] = 50; buf[pos+1] = 4;
        buf[pos+2..pos+6].copy_from_slice(&ip);
        pos += 6;
    }

    // Option 54: Server Identifier (in REQUEST)
    if let Some(srv) = server_ip {
        buf[pos] = 54; buf[pos+1] = 4;
        buf[pos+2..pos+6].copy_from_slice(&srv);
        pos += 6;
    }

    // Option 55: Parameter Request List
    buf[pos] = 55; buf[pos+1] = 4;
    buf[pos+2] = 1;   // Subnet Mask
    buf[pos+3] = 3;   // Router
    buf[pos+4] = 6;   // DNS
    buf[pos+5] = 51;  // Lease Time
    pos += 6;

    // Option 255: End
    buf[pos] = 255;
    pos += 1;

    pos
}

// ─── Parse DHCP reply (OFFER or ACK) ─────────────────────────────────────
fn parse_dhcp_reply(data: &[u8], expected_xid: u32) -> Option<(u8, DhcpLease)> {
    if data.len() < 240 { return None; }

    // op must be BOOTREPLY
    if data[0] != BOOTREPLY { return None; }

    // Check xid
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if xid != expected_xid { return None; }

    let mut lease = DhcpLease::empty();
    lease.your_ip = [data[16], data[17], data[18], data[19]];
    lease.server_ip = [data[20], data[21], data[22], data[23]];

    // Verify magic cookie
    if data[236..240] != DHCP_MAGIC_COOKIE { return None; }

    // Parse options
    let mut msg_type: u8 = 0;
    let mut i = 240;
    while i < data.len() {
        let opt = data[i];
        if opt == 255 { break; }    // End
        if opt == 0  { i += 1; continue; } // Padding
        if i + 1 >= data.len() { break; }
        let len = data[i+1] as usize;
        if i + 2 + len > data.len() { break; }
        let val = &data[i+2..i+2+len];

        match opt {
            53 if len >= 1 => msg_type = val[0],
            1  if len >= 4 => lease.subnet = [val[0], val[1], val[2], val[3]],
            3  if len >= 4 => lease.gateway = [val[0], val[1], val[2], val[3]],
            6  if len >= 4 => lease.dns = [val[0], val[1], val[2], val[3]],
            51 if len >= 4 => {
                lease.lease_secs = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
            }
            54 if len >= 4 => {
                // Server identifier overrides siaddr if present
                lease.server_ip = [val[0], val[1], val[2], val[3]];
            }
            _ => {}
        }

        i += 2 + len;
    }

    if msg_type == 0 { return None; }
    Some((msg_type, lease))
}

// ─── Send raw DHCP packet (bypassing normal IPv4 — source IP is 0.0.0.0) ─
fn send_dhcp_raw(mac: [u8; 6], payload: &[u8], payload_len: usize) {
    // Build: UDP header + payload
    let udp_len = 8 + payload_len;
    let ip_total = 20 + udp_len;
    let frame_total = 14 + ip_total;

    if frame_total > 1514 { return; }

    let mut frame = [0u8; 1514];

    // ── Ethernet header ──
    // Destination: broadcast
    frame[0..6].copy_from_slice(&[0xFF; 6]);
    // Source: our MAC
    frame[6..12].copy_from_slice(&mac);
    // EtherType: IPv4
    frame[12] = 0x08; frame[13] = 0x00;

    // ── IPv4 header (offset 14) ──
    let ip = &mut frame[14..];
    ip[0] = 0x45;                          // Version 4, IHL 5
    ip[1] = 0x00;                          // DSCP/ECN
    let tl = (ip_total as u16).to_be_bytes();
    ip[2] = tl[0]; ip[3] = tl[1];
    ip[4] = 0; ip[5] = 0;                 // Identification
    ip[6] = 0; ip[7] = 0;                 // Flags + frag offset
    ip[8] = 64;                            // TTL
    ip[9] = 17;                            // Protocol: UDP
    ip[10] = 0; ip[11] = 0;               // Checksum (computed below)
    // Source: 0.0.0.0
    ip[12] = 0; ip[13] = 0; ip[14] = 0; ip[15] = 0;
    // Destination: 255.255.255.255
    ip[16] = 255; ip[17] = 255; ip[18] = 255; ip[19] = 255;

    // IP checksum
    let cksum = super::ipv4::checksum(&ip[..20]);
    ip[10] = (cksum >> 8) as u8;
    ip[11] = (cksum & 0xFF) as u8;

    // ── UDP header (offset 34) ──
    let udp = &mut frame[34..];
    let sp = DHCP_CLIENT_PORT.to_be_bytes();
    udp[0] = sp[0]; udp[1] = sp[1];
    let dp = DHCP_SERVER_PORT.to_be_bytes();
    udp[2] = dp[0]; udp[3] = dp[1];
    let ul = (udp_len as u16).to_be_bytes();
    udp[4] = ul[0]; udp[5] = ul[1];
    udp[6] = 0; udp[7] = 0;               // Checksum disabled

    // ── DHCP payload ──
    frame[42..42+payload_len].copy_from_slice(&payload[..payload_len]);

    let send_len = if frame_total < 60 { 60 } else { frame_total };
    super::send_raw(&frame, send_len);
}

// ─── Wait for DHCP reply ─────────────────────────────────────────────────
fn wait_dhcp_reply(xid: u32, timeout_ticks: u64) -> Option<(u8, DhcpLease)> {
    DHCP_RX_READY.store(false, Ordering::Release);
    let start = crate::arch::x86_64::idt::timer_ticks();
    loop {
        super::poll_rx();
        if DHCP_RX_READY.load(Ordering::Acquire) {
            DHCP_RX_READY.store(false, Ordering::Release);
            let len = unsafe { DHCP_RX_LEN };
            let data = unsafe { &DHCP_RX_BUF[..len] };
            if let Some(result) = parse_dhcp_reply(data, xid) {
                return Some(result);
            }
        }
        let now = crate::arch::x86_64::idt::timer_ticks();
        if now.saturating_sub(start) >= timeout_ticks { return None; }
        unsafe { core::arch::asm!("hlt"); }
    }
}

// ─── Public API ──────────────────────────────────────────────────────────

/// Run full DHCP handshake.  Returns a lease or None on failure.
///
/// Tries up to 3 DISCOVER rounds with exponential backoff (2s, 4s, 8s).
/// Fully bare-metal: no QEMU / VM assumptions.
pub fn discover(mac: [u8; 6]) -> Option<DhcpLease> {
    let serial = crate::arch::x86_64::serial::write_str;
    let xid = xid_from_mac(mac);
    let mut pkt = [0u8; 576];

    for attempt in 0u8..3 {
        let timeout = 200u64 << attempt; // 2s, 4s, 8s at 100Hz

        serial("[DHCP] DISCOVER (attempt ");
        serial_dec(attempt as u64 + 1);
        serial("/3)...\r\n");

        let len = build_dhcp(DHCPDISCOVER, xid, mac, None, None, &mut pkt);
        send_dhcp_raw(mac, &pkt, len);

        // Wait for OFFER
        let offer = match wait_dhcp_reply(xid, timeout) {
            Some((DHCPOFFER, lease)) => lease,
            Some((typ, _)) => {
                serial("[DHCP] unexpected msg type in OFFER phase: ");
                serial_dec(typ as u64);
                serial("\r\n");
                continue;
            }
            None => {
                serial("[DHCP] DISCOVER timeout\r\n");
                continue;
            }
        };

        serial("[DHCP] OFFER: IP ");
        serial_ip(offer.your_ip);
        serial(" GW ");
        serial_ip(offer.gateway);
        serial(" DNS ");
        serial_ip(offer.dns);
        serial(" Lease ");
        serial_dec(offer.lease_secs as u64);
        serial("s\r\n");

        // Send REQUEST
        let len = build_dhcp(
            DHCPREQUEST, xid, mac,
            Some(offer.your_ip),
            Some(offer.server_ip),
            &mut pkt,
        );
        send_dhcp_raw(mac, &pkt, len);

        // Wait for ACK
        match wait_dhcp_reply(xid, timeout) {
            Some((DHCPACK, ack_lease)) => {
                serial("[DHCP] ACK: IP ");
                serial_ip(ack_lease.your_ip);
                serial("\r\n");
                return Some(ack_lease);
            }
            Some((DHCPNAK, _)) => {
                serial("[DHCP] NAK — server rejected request\r\n");
                continue;
            }
            Some((typ, _)) => {
                serial("[DHCP] unexpected msg type in ACK phase: ");
                serial_dec(typ as u64);
                serial("\r\n");
                continue;
            }
            None => {
                serial("[DHCP] REQUEST timeout\r\n");
                continue;
            }
        }
    }

    serial("[DHCP] Failed after 3 attempts\r\n");
    None
}

// ─── Serial helpers ──────────────────────────────────────────────────────
fn serial_ip(ip: [u8; 4]) {
    for i in 0..4 {
        serial_dec(ip[i] as u64);
        if i < 3 { crate::arch::x86_64::serial::write_byte(b'.'); }
    }
}

fn serial_dec(mut n: u64) {
    if n == 0 {
        crate::arch::x86_64::serial::write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for k in (0..i).rev() {
        crate::arch::x86_64::serial::write_byte(buf[k]);
    }
}
