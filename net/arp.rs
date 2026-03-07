/*
 * ARP - Address Resolution Protocol
 * Resolve IPv4 addresses to MAC addresses.
 * Handles ARP requests and replies.
 */

const ARP_HW_ETHERNET: u16 = 1;
const ARP_PROTO_IPV4: u16  = 0x0800;
const ARP_OP_REQUEST: u16  = 1;
const ARP_OP_REPLY: u16    = 2;

// ─── ARP Cache (16 entries) ─────────────────────────────────────────────
const CACHE_SIZE: usize = 16;
/// Entries older than 30 s (3000 ticks at 100 Hz) are considered stale.
const ARP_TTL_TICKS: u64 = 3000;

// (valid, ip, mac, timestamp)
static mut ARP_CACHE: [(bool, [u8; 4], [u8; 6], u64); CACHE_SIZE] =
    [(false, [0; 4], [0; 6], 0); CACHE_SIZE];
static mut CACHE_NEXT: usize = 0;

/// Look up a MAC from the ARP cache. Returns Some(mac) if found and entry is fresh.
pub fn cache_lookup(ip: [u8; 4]) -> Option<[u8; 6]> {
    let now = crate::arch::x86_64::idt::timer_ticks();
    unsafe {
        for i in 0..CACHE_SIZE {
            if ARP_CACHE[i].0 && ARP_CACHE[i].1 == ip {
                if now.wrapping_sub(ARP_CACHE[i].3) < ARP_TTL_TICKS {
                    return Some(ARP_CACHE[i].2);
                } else {
                    // Expired — invalidate the entry
                    ARP_CACHE[i].0 = false;
                }
            }
        }
    }
    None
}

/// Insert or update a cache entry, resetting its TTL.
pub fn cache_update(ip: [u8; 4], mac: [u8; 6]) {
    let now = crate::arch::x86_64::idt::timer_ticks();
    unsafe {
        // Update existing entry if present
        for i in 0..CACHE_SIZE {
            if ARP_CACHE[i].0 && ARP_CACHE[i].1 == ip {
                ARP_CACHE[i].2 = mac;
                ARP_CACHE[i].3 = now;
                return;
            }
        }
        // Insert into next free slot (circular)
        let slot = CACHE_NEXT % CACHE_SIZE;
        ARP_CACHE[slot] = (true, ip, mac, now);
        CACHE_NEXT += 1;
    }
}

/// Dump ARP cache to serial for diagnostics
pub fn cache_dump() {
    let s = crate::arch::x86_64::serial::write_str;
    let now = crate::arch::x86_64::idt::timer_ticks();
    s("[ARP] Cache:\r\n");
    unsafe {
        let mut any = false;
        for i in 0..CACHE_SIZE {
            if ARP_CACHE[i].0 {
                let age = now.wrapping_sub(ARP_CACHE[i].3);
                if age < ARP_TTL_TICKS {
                    s("  ");
                    serial_ip(ARP_CACHE[i].1);
                    s(" -> ");
                    serial_mac(ARP_CACHE[i].2);
                    s("\r\n");
                    any = true;
                }
            }
        }
        if !any { s("  (empty)\r\n"); }
    }
}

/// Expose cache entries for netstat display (returns count, skips expired entries)
pub fn cache_entries(out: &mut [([u8;4],[u8;6]); 16]) -> usize {
    let now = crate::arch::x86_64::idt::timer_ticks();
    let mut n = 0;
    unsafe {
        for i in 0..CACHE_SIZE {
            if ARP_CACHE[i].0 && n < 16 && now.wrapping_sub(ARP_CACHE[i].3) < ARP_TTL_TICKS {
                out[n] = (ARP_CACHE[i].1, ARP_CACHE[i].2);
                n += 1;
            }
        }
    }
    n
}

/// Handle an incoming ARP packet (Ethernet payload)
pub fn handle_arp(data: &[u8]) {
    if data.len() < 28 { return; }

    let hw_type = u16::from_be_bytes([data[0], data[1]]);
    let proto   = u16::from_be_bytes([data[2], data[3]]);
    let opcode  = u16::from_be_bytes([data[6], data[7]]);

    if hw_type != ARP_HW_ETHERNET || proto != ARP_PROTO_IPV4 { return; }

    let mut sender_mac = [0u8; 6];
    let mut sender_ip  = [0u8; 4];
    let mut target_ip  = [0u8; 4];

    sender_mac.copy_from_slice(&data[8..14]);
    sender_ip.copy_from_slice(&data[14..18]);
    target_ip.copy_from_slice(&data[24..28]);

    let our_ip = unsafe { super::OUR_IP };

    match opcode {
        ARP_OP_REQUEST => {
            // Someone is asking for our MAC
            if target_ip == our_ip {
                send_reply(sender_mac, sender_ip);
            }
        }
        ARP_OP_REPLY => {
            // Someone responded to our ARP request
            crate::arch::x86_64::serial::write_str("[ARP] Reply from ");
            serial_ip(sender_ip);
            crate::arch::x86_64::serial::write_str(" MAC ");
            serial_mac(sender_mac);
            crate::arch::x86_64::serial::write_str("\r\n");
            // Store in cache (for any IP)
            cache_update(sender_ip, sender_mac);
            // Check if this is the gateway
            let gw_ip = unsafe { super::GATEWAY_IP };
            if sender_ip == gw_ip {
                unsafe { super::GATEWAY_MAC = sender_mac; }
                crate::arch::x86_64::serial::write_str("[ARP] Gateway MAC updated\r\n");
            }
        }
        _ => {}
    }
}

/// Send an ARP request for an IP address
pub fn send_request(target_ip: [u8; 4]) {
    let our_mac = unsafe { super::OUR_MAC };
    let our_ip  = unsafe { super::OUR_IP };

    let mut pkt = [0u8; 28];

    // Hardware type: Ethernet
    pkt[0..2].copy_from_slice(&ARP_HW_ETHERNET.to_be_bytes());
    // Protocol type: IPv4
    pkt[2..4].copy_from_slice(&ARP_PROTO_IPV4.to_be_bytes());
    // Hardware size: 6, Protocol size: 4
    pkt[4] = 6;
    pkt[5] = 4;
    // Opcode: request
    pkt[6..8].copy_from_slice(&ARP_OP_REQUEST.to_be_bytes());
    // Sender MAC
    pkt[8..14].copy_from_slice(&our_mac);
    // Sender IP
    pkt[14..18].copy_from_slice(&our_ip);
    // Target MAC (zero for request)
    pkt[18..24].copy_from_slice(&[0u8; 6]);
    // Target IP
    pkt[24..28].copy_from_slice(&target_ip);

    // Send via Ethernet (broadcast)
    super::ethernet::send_frame([0xFF; 6], super::ethernet::ETHERTYPE_ARP, &pkt);
}

/// Send an ARP reply
fn send_reply(dst_mac: [u8; 6], dst_ip: [u8; 4]) {
    let our_mac = unsafe { super::OUR_MAC };
    let our_ip  = unsafe { super::OUR_IP };

    let mut pkt = [0u8; 28];

    pkt[0..2].copy_from_slice(&ARP_HW_ETHERNET.to_be_bytes());
    pkt[2..4].copy_from_slice(&ARP_PROTO_IPV4.to_be_bytes());
    pkt[4] = 6;
    pkt[5] = 4;
    pkt[6..8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    pkt[8..14].copy_from_slice(&our_mac);
    pkt[14..18].copy_from_slice(&our_ip);
    pkt[18..24].copy_from_slice(&dst_mac);
    pkt[24..28].copy_from_slice(&dst_ip);

    super::ethernet::send_frame(dst_mac, super::ethernet::ETHERTYPE_ARP, &pkt);
}

fn serial_ip(ip: [u8; 4]) {
    for i in 0..4 {
        serial_dec_u8(ip[i]);
        if i < 3 { crate::arch::x86_64::serial::write_byte(b'.'); }
    }
}

fn serial_mac(mac: [u8; 6]) {
    let hex = b"0123456789ABCDEF";
    for i in 0..6 {
        crate::arch::x86_64::serial::write_byte(hex[(mac[i] >> 4) as usize]);
        crate::arch::x86_64::serial::write_byte(hex[(mac[i] & 0xF) as usize]);
        if i < 5 { crate::arch::x86_64::serial::write_byte(b':'); }
    }
}

fn serial_dec_u8(mut v: u8) {
    if v >= 100 { crate::arch::x86_64::serial::write_byte(b'0' + v / 100); v %= 100; crate::arch::x86_64::serial::write_byte(b'0' + v / 10); v %= 10; }
    else if v >= 10 { crate::arch::x86_64::serial::write_byte(b'0' + v / 10); v %= 10; }
    crate::arch::x86_64::serial::write_byte(b'0' + v);
}
