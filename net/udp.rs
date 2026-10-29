/*
 * UDP — User Datagram Protocol
 *
 * Dispatches incoming packets to:
 *   - DHCP client (dst_port 68)
 *   - DNS resolver (dynamic ephemeral port)
 *   - Generic listener (SNTP and future protocols)
 */


// Generic UDP receive buffer (used by SNTP and other one-shot listeners)
static UDP_RX: super::Mailbox<512> = super::Mailbox::new("UDP.rx");

/// Handle incoming UDP packet (IPv4 payload)
pub fn handle_udp(data: &[u8], _src_ip: [u8; 4]) {
    if data.len() < 8 { return; }

    let _src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port  = u16::from_be_bytes([data[2], data[3]]);
    let length    = u16::from_be_bytes([data[4], data[5]]) as usize;

    if length < 8 || data.len() < length { return; }

    let payload = &data[8..length];

    // ── Route to specific protocol handlers ──

    // DHCP client listens on port 68
    if dst_port == 68 {
        super::dhcp::handle_dhcp_udp(payload);
        return;
    }

    // OSTP tunnel client (its datagrams are larger than the generic 512-byte slot)
    if super::ostp::wants(dst_port) {
        super::ostp::on_udp(payload);
        return;
    }

    // DNS resolver listens on its current ephemeral source port
    let dns_port = super::dns::current_src_port();
    if dns_port != 0 && dst_port == dns_port {
        super::dns::handle_dns_udp(payload);
        return;
    }

    // Generic listener (SNTP, etc.)
    let listen = UDP_RX.port();
    if dst_port == listen || listen == 0 {
        UDP_RX.put(payload, dst_port);
    }
}

/// Send a UDP packet
pub fn send_udp(dst_ip: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) {
    let udp_len = 8 + payload.len();
    if udp_len > 1460 { return; }

    let mut pkt = [0u8; 1468];

    // Source port
    let sp = src_port.to_be_bytes();
    pkt[0] = sp[0];
    pkt[1] = sp[1];

    // Destination port
    let dp = dst_port.to_be_bytes();
    pkt[2] = dp[0];
    pkt[3] = dp[1];

    // Length
    let len = (udp_len as u16).to_be_bytes();
    pkt[4] = len[0];
    pkt[5] = len[1];

    // Checksum (0 = disabled for UDP)
    pkt[6] = 0;
    pkt[7] = 0;

    // Payload
    pkt[8..8 + payload.len()].copy_from_slice(payload);

    // Listen for reply on src_port
    UDP_RX.set_port(src_port);
    UDP_RX.clear();

    super::ipv4::send_ipv4(17, dst_ip, &pkt[..udp_len]);
}

/// Wait for a UDP packet on the listening port. Returns payload or None.
pub fn wait_rx(timeout_ticks: u64) -> Option<alloc::vec::Vec<u8>> {
    let start = crate::arch::x86_64::idt::timer_ticks();
    loop {
        super::poll_rx();

        if let Some(pkt) = UDP_RX.take() {
            return Some(pkt);
        }

        let now = crate::arch::x86_64::idt::timer_ticks();
        if now.saturating_sub(start) >= timeout_ticks {
            return None;
        }

        unsafe { core::arch::asm!("hlt"); }
    }
}
