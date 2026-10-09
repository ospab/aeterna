/*
 * axon/net_tools — Network & disk commands: netstat, ping, df
 *
 * Self-contained logical unit.  Contacts the kernel net stack through
 * crate::userspace::net::* and the filesystem through crate::fs::*.
 *
 * All timer-based deadlines are calibrated for PIT at 100 Hz (10 ms/tick).
 */

extern crate alloc;
use alloc::format;

use crate::arch::x86_64::framebuffer;

const FG: u32     = 0x00FFFFFF;
const FG_OK: u32  = 0x0000FF00;
const FG_ERR: u32 = 0x00FF4444;
const FG_DIM: u32 = 0x00AAAAAA;
const FG_HL: u32  = 0x00FFCC00;
const BG: u32     = 0x00000000;

fn puts(s: &str)  { framebuffer::draw_string(s, FG, BG); }
fn ok(s: &str)    { framebuffer::draw_string(s, FG_OK, BG); }
fn err(s: &str)   { framebuffer::draw_string(s, FG_ERR, BG); }
fn dim(s: &str)   { framebuffer::draw_string(s, FG_DIM, BG); }
fn hl(s: &str)    { framebuffer::draw_string(s, FG_HL, BG); }

fn check_ctrl_c() -> bool {
    // Ctrl+C is flagged by the keyboard IRQ (shared API; the shell clears it)
    crate::arch::x86_64::keyboard::interrupt_pending()
}

fn put_usize(mut n: usize) {
    if n == 0 { puts("0"); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    for k in (0..i).rev() { framebuffer::draw_char(buf[k] as char, FG, BG); }
}

/// Inline hex nibble table
const HEX: [u8; 16] = *b"0123456789abcdef";

fn draw_mac(mac: &[u8; 6]) {
    for i in 0..6 {
        framebuffer::draw_char(HEX[(mac[i] >> 4) as usize] as char, FG, BG);
        framebuffer::draw_char(HEX[(mac[i] & 0xF) as usize] as char, FG, BG);
        if i < 5 { puts(":"); }
    }
}

fn draw_mac_dim(mac: &[u8; 6]) {
    for i in 0..6 {
        framebuffer::draw_char(HEX[(mac[i] >> 4) as usize] as char, FG_DIM, BG);
        framebuffer::draw_char(HEX[(mac[i] & 0xF) as usize] as char, FG_DIM, BG);
        if i < 5 { puts(":"); }
    }
}

// ─── netstat ─────────────────────────────────────────────────────────────────

pub fn cmd_netstat(_args: &str) {
    use crate::net;

    if !net::is_up() {
        err("netstat: no network interface is up\n");
        return;
    }

    // Interface table
    hl("  Interface    MAC                  IP              Status    RX        TX\n");
    dim("  -------------------------------------------------------------------------\n");

    let mac = unsafe { net::OUR_MAC };
    let ip  = unsafe { net::OUR_IP };
    let rx  = net::rx_packets();
    let tx  = net::tx_packets();
    let nic = net::nic_name();

    puts("  ");
    puts(nic);
    for _ in 0..(13usize.saturating_sub(nic.len())) { puts(" "); }

    draw_mac(&mac);
    puts("  ");

    let ip_s = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    puts(&ip_s);
    for _ in 0..(16usize.saturating_sub(ip_s.len())) { puts(" "); }

    if net::link_up() {
        ok("Up");
    } else {
        err("Down");
    }
    puts("      ");
    let rx_s = format!("{}", rx);
    puts(&rx_s);
    for _ in 0..(10usize.saturating_sub(rx_s.len())) { puts(" "); }
    puts(&format!("{}", tx));
    puts("\n");

    // ARP cache
    let gw      = unsafe { net::GATEWAY_IP };
    let gw_mac  = unsafe { net::GATEWAY_MAC };
    puts("\n");
    hl("  ARP Cache:\n");
    dim("  IP              MAC\n");
    dim("  -------------------------------------\n");

    let mut cache = [([0u8; 4], [0u8; 6]); 16];
    let n = net::arp::cache_entries(&mut cache);
    for i in 0..n {
        let (cip, cmac) = cache[i];
        let ip_s = format!("  {}.{}.{}.{}", cip[0], cip[1], cip[2], cip[3]);
        puts(&ip_s);
        for _ in 0..(18usize.saturating_sub(ip_s.len())) { puts(" "); }
        draw_mac_dim(&cmac);
        puts("\n");
    }
    if n == 0 {
        dim("  (no fresh entries)\n");
    }
    if gw != [0, 0, 0, 0] {
        puts(&format!("  default gateway {}.{}.{}.{}  ", gw[0], gw[1], gw[2], gw[3]));
        if gw_mac == [0xFF; 6] {
            err("unresolved\n");
        } else {
            draw_mac_dim(&gw_mac);
            puts("\n");
        }
    }

    // TCP connection table (real entries from the stack)
    puts("\n");
    hl("  Active TCP connections:\n");
    dim("  Proto  Local Address          Foreign Address        State\n");
    let mut conns = [(net::tcp::TcpState::Closed, 0u16, [0u8; 4], 0u16); 16];
    let cn = net::tcp::active_connections(&mut conns);
    for i in 0..cn {
        let (st, lport, rip, rport) = conns[i];
        let local = if st == net::tcp::TcpState::Listen {
            format!("0.0.0.0:{}", lport)
        } else {
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], lport)
        };
        let remote = if st == net::tcp::TcpState::Listen {
            alloc::string::String::from("0.0.0.0:*")
        } else {
            format!("{}.{}.{}.{}:{}", rip[0], rip[1], rip[2], rip[3], rport)
        };
        puts(&format!("  tcp    {:<22} {:<22} {}\n", local, remote, st.as_str()));
    }
    if cn == 0 {
        dim("  (none)\n");
    }
}

// ─── ping ────────────────────────────────────────────────────────────────────
//
// A fully self-contained ICMP ping inside axon, separate from the terminal
// built-in.  All timeouts calibrated for PIT at 100 Hz (10 ms/tick):
//   3 s reply window  = 300 ticks
//   1 s inter-packet  = 100 ticks

pub fn cmd_ping(args: &str) {
    let args = args.trim();
    if args.is_empty() {
        err("ping: missing host\n");
        dim("Usage: ping [-c N] [-i secs] <host|ip>\n");
        dim("  Example: ping 8.8.8.8\n");
        dim("  Example: ping -c 3 localhost\n");
        return;
    }

    // Parse args: [-c N] [-i secs] <host|ip>
    let mut count      = 4usize;
    let mut target     = "";
    let mut iticks     = 100u64; // 1 s at 100 Hz
    let mut words_iter = args.split_whitespace().peekable();
    while let Some(w) = words_iter.next() {
        match w {
            "-c" => {
                if let Some(v) = words_iter.next() {
                    count = v.parse::<usize>().unwrap_or(4).max(1);
                }
            }
            "-i" => {
                if let Some(v) = words_iter.next() {
                    if let Ok(f) = v.parse::<f32>() {
                        iticks = (f * 100.0) as u64;
                    }
                }
            }
            _ if w.starts_with('-') => {
                err("ping: unknown option: "); err(w); err("\n");
                return;
            }
            _ => { target = w; }
        }
    }
    if target.is_empty() {
        err("ping: missing destination\n");
        return;
    }

    // Resolve: IPv4 literal first, then /etc/hosts
    let ip = match crate::userspace::net::resolver::parse_ipv4(target) {
        Some(ip) => ip,
        None => match crate::userspace::net::resolver::resolve_host(target) {
            Ok(ip) => {
                ok("Resolved "); puts(target); ok(" -> ");
                puts(&alloc::format!("{}.{}.{}.{}\n", ip[0], ip[1], ip[2], ip[3]));
                ip
            }
            Err(e) => {
                err("ping: cannot resolve "); err(target);
                err(": "); err(e.as_str()); err("\n");
                return;
            }
        },
    };

    if !crate::userspace::net::is_up() {
        err("ping: network is down\n");
        return;
    }

    ok("PING "); puts(target); ok(" 56(84) bytes of data\n");

    // Ensure ARP is warm for the target (send a gratuitous ARP first)
    crate::userspace::net::arp::send_request(ip);
    let arp_deadline = crate::arch::x86_64::idt::timer_ticks() + 30; // 300 ms
    while crate::arch::x86_64::idt::timer_ticks() < arp_deadline {
        crate::userspace::net::poll_rx();
        if crate::userspace::net::arp::cache_lookup(ip).is_some() { break; }
        crate::core::scheduler::sys_yield();
    }

    let mut received = 0usize;
    let mut total_rtt_us = 0u64;
    let mut min_rtt_us = u64::MAX;
    let mut max_rtt_us = 0u64;
    for seq in 1..=count {
        crate::userspace::net::icmp::send_ping(ip, seq as u16);

        // Wait up to 3 s for matching echo-reply (seq/src filtering in ICMP layer).
        let reply = crate::userspace::net::icmp::wait_reply_us(3_000_000);

        match reply {
            Some(r) => {
                received += 1;
                let rtt_us = r.rtt_us;
                let display_ms = if rtt_us < 1000 { 1 } else { rtt_us / 1000 };
                min_rtt_us = core::cmp::min(min_rtt_us, rtt_us);
                max_rtt_us = core::cmp::max(max_rtt_us, rtt_us);
                total_rtt_us = total_rtt_us.saturating_add(rtt_us);

                ok(&format!("{} bytes from {}.{}.{}.{}: icmp_seq={} ttl={} time={}ms\n",
                    r.nbytes,
                    r.src_ip[0], r.src_ip[1], r.src_ip[2], r.src_ip[3],
                    r.seq,
                    r.ttl,
                    display_ms));
            }
            None => {
                err("Request timeout for icmp_seq=");
                err(&format!("{}\n", seq));
            }
        }

        // inter-ping delay (default 1 s = 100 ticks @ 100 Hz; overridden by -i)
        if seq < count {
            let wait = crate::arch::x86_64::idt::timer_ticks() + iticks;
            while crate::arch::x86_64::idt::timer_ticks() < wait {
                crate::userspace::net::poll_rx();
                unsafe { core::arch::asm!("hlt"); }
            }
        }
    }

    puts("\n");
    dim(&format!("--- {} ping statistics ---\n", target));
    let lost = count - received;
    let loss_pct = if count > 0 { lost * 100 / count } else { 0 };
    dim(&format!("{} packets transmitted, {} received, {}% packet loss\n",
        count, received, loss_pct));
    if received > 0 {
        let avg_rtt_us = total_rtt_us / received as u64;
        dim(&format!(
            "rtt min/avg/max = {}/{}/{} ms\n",
            core::cmp::max(1, min_rtt_us / 1000),
            core::cmp::max(1, avg_rtt_us / 1000),
            core::cmp::max(1, max_rtt_us / 1000)
        ));
    }
}

// ─── df ──────────────────────────────────────────────────────────────────────

pub fn cmd_df(_args: &str) {
    hl("  Filesystem      1K-blocks   Used  Available  Use%  Mounted on\n");
    dim("  ---------------------------------------------------------------\n");

    // RamFS usage
    let node_count = crate::fs::node_count();
    let ramfs_used_kb = (node_count * 256) / 1024;
    let heap_total_kb = if crate::mm::heap::is_initialized() {
        let (used, free) = crate::mm::heap::stats();
        (used + free) / 1024
    } else { 131072 }; // 128 MiB default

    puts("  ramfs           ");
    put_usize(heap_total_kb); puts("  ");
    put_usize(ramfs_used_kb); puts("  ");
    put_usize(heap_total_kb.saturating_sub(ramfs_used_kb));
    puts("  ");
    if heap_total_kb > 0 {
        put_usize(ramfs_used_kb * 100 / heap_total_kb);
    } else { puts("0"); }
    puts("%  /\n");

    // Physical disk(s)
    let disk_count = crate::drivers::disk_count();
    for i in 0..disk_count {
        if let Some(info) = crate::drivers::disk_info(i) {
            let disk_kb = info.size_mb as usize * 1024;
            let raw = crate::fs::disk_sync::last_snapshot_bytes();
            let used_kb = if raw > 0 { raw / 1024 } else { 0 };
            puts("  disk");
            put_usize(i);
            puts("          ");
            put_usize(disk_kb); puts("  ");
            put_usize(used_kb); puts("  ");
            put_usize(disk_kb.saturating_sub(used_kb));
            puts("  ");
            if disk_kb > 0 {
                put_usize(used_kb * 100 / disk_kb);
            } else { puts("0"); }
            puts("%  /dev/disk");
            put_usize(i);
            puts("\n");
        }
    }
}

// ─── traceroute ───────────────────────────────────────────────────────────────
//
// ICMP-based traceroute: sends Echo Requests with incrementing IP TTL values.
// Each router that drops the packet due to TTL=0 replies with ICMP Time
// Exceeded (type 11), revealing the route.
//
// In QEMU user-mode networking intermediate hops silently drop the expired
// packets (the virtual NAT does not forward Time Exceeded replies back), so
// those hops will show "* * *" — the same behaviour as any NATted environment.

pub fn cmd_traceroute(args: &str) {
    let args = args.trim();
    if args.is_empty() {
        err("traceroute: missing host\n");
        dim("Usage: traceroute [-m max_hops] [-w secs] <host|ip>\n");
        dim("  Example: traceroute 8.8.8.8\n");
        return;
    }

    // ── Argument parsing ─────────────────────────────────────────────────────
    let mut max_hops: u8  = 30;
    let mut timeout_us    = 3_000_000u64; // 3 s per hop
    let mut target        = "";
    let mut words         = args.split_whitespace().peekable();

    while let Some(w) = words.next() {
        match w {
            "-m" => {
                if let Some(v) = words.next() {
                    max_hops = v.parse::<u8>().unwrap_or(30).max(1);
                }
            }
            "-w" => {
                if let Some(v) = words.next() {
                    if let Ok(secs) = v.parse::<u32>() {
                        timeout_us = secs as u64 * 1_000_000;
                    }
                }
            }
            _ if w.starts_with('-') => {
                err("traceroute: unknown option: "); err(w); err("\n");
                return;
            }
            _ => { target = w; }
        }
    }
    if target.is_empty() {
        err("traceroute: missing destination\n");
        return;
    }

    // ── Resolve destination ───────────────────────────────────────────────────
    let dst_ip = match crate::userspace::net::resolver::parse_ipv4(target) {
        Some(ip) => ip,
        None => match crate::userspace::net::resolver::resolve_host(target) {
            Ok(ip) => {
                ok("Resolved "); puts(target); ok(" -> ");
                puts(&format!("{}.{}.{}.{}\n", ip[0], ip[1], ip[2], ip[3]));
                ip
            }
            Err(e) => {
                err("traceroute: cannot resolve "); err(target);
                err(": "); err(e.as_str()); err("\n");
                return;
            }
        },
    };

    if !crate::userspace::net::is_up() {
        err("traceroute: network is down\n");
        return;
    }

    // ── Warm up ARP for the destination / gateway ─────────────────────────────
    crate::userspace::net::arp::send_request(dst_ip);
    let arp_dl = crate::arch::x86_64::idt::timer_ticks() + 30;
    while crate::arch::x86_64::idt::timer_ticks() < arp_dl {
        crate::userspace::net::poll_rx();
        crate::core::scheduler::sys_yield();
        if crate::userspace::net::arp::cache_lookup(dst_ip).is_some() { break; }
    }

    // ── Header ────────────────────────────────────────────────────────────────
    hl("traceroute to ");
    puts(target);
    hl(&format!(" ({}.{}.{}.{})", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]));
    puts(&format!(", {} hops max\n", max_hops));

    // ── Probe loop ────────────────────────────────────────────────────────────
    for ttl in 1u8..=max_hops {
        // Print hop number (right-aligned, 2 chars)
        if ttl < 10 { puts(" "); }
        put_usize(ttl as usize);
        puts("  ");

        // Send 3 probes per hop (classic traceroute behaviour)
        let mut any_reply = false;
        let mut reached   = false;
        let mut last_src  = [0u8; 4];

        for probe in 0u16..3 {
            let seq = (ttl as u16) * 10 + probe;
            crate::userspace::net::icmp::send_ping_ttl(dst_ip, seq, ttl);

            // Wait for reply with TSC-based timeout
            let start = crate::arch::x86_64::tsc::tsc_stamp_us();
            let mut reply = None;
            loop {
                reply = crate::userspace::net::icmp::poll_reply();
                if reply.is_some() { break; }
                let elapsed = crate::arch::x86_64::tsc::tsc_stamp_us()
                    .saturating_sub(start);
                if elapsed >= timeout_us {
                    crate::userspace::net::icmp::cancel_wait();
                    break;
                }
                crate::core::scheduler::sys_yield();
            }

            match reply {
                Some(r) => {
                    any_reply = true;
                    last_src  = r.src_ip;
                    let rtt_ms = if r.rtt_us < 1000 { 1 } else { r.rtt_us / 1000 };
                    puts(&format!("{} ms  ", rtt_ms));
                    if !r.is_ttl_exceeded {
                        // Echo Reply from destination: we've arrived
                        reached = true;
                    }
                }
                None => {
                    puts("*  ");
                }
            }
        }

        // Print replier's IP (nothing for pure timeouts)
        if any_reply {
            let ip_s = format!("{}.{}.{}.{}", last_src[0], last_src[1], last_src[2], last_src[3]);
            ok(&format!(" {}\n", ip_s));
        } else {
            puts("(no reply)\n");
        }

        // Destination reached — stop probing
        if reached { break; }

        // Ctrl+C bail-out
        if check_ctrl_c() {
            puts("^C\n");
            break;
        }
    }
}

// ─── ip addr / ip link / ip route ────────────────────────────────────────────

fn put_ip(ip: [u8; 4]) {
    puts(&format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
}

fn subnet_prefix_len(mask: [u8; 4]) -> u8 {
    mask.iter().map(|b| b.count_ones() as u8).sum()
}

fn ip_broadcast(ip: [u8; 4], mask: [u8; 4]) -> [u8; 4] {
    [ip[0] | !mask[0], ip[1] | !mask[1], ip[2] | !mask[2], ip[3] | !mask[3]]
}

fn ip_network(ip: [u8; 4], mask: [u8; 4]) -> [u8; 4] {
    [ip[0] & mask[0], ip[1] & mask[1], ip[2] & mask[2], ip[3] & mask[3]]
}

pub fn cmd_ip_show(args: &str) {
    use crate::net;

    if !net::is_up() {
        err("ip: network not available\n");
        return;
    }
    let sub = args.split_whitespace().next().unwrap_or("");
    match sub {
        "" | "a" | "addr" | "address" => cmd_ip_show_addr(),
        "l" | "link" => cmd_ip_show_link(),
        "r" | "route" => cmd_ip_show_route(),
        _ => {
            err("ip: unknown subcommand\n");
            dim("Usage: ip {a[ddr] | l[ink] | r[oute]}\n");
        }
    }
}

/// Interface name used for the single physical NIC.
const IFNAME: &str = "eth0";

/// `lo` is real: ipv4::send_ipv4 delivers 127.0.0.0/8 (and our own address)
/// locally without touching the NIC. It has no packet counters of its own.
fn show_lo(with_addr: bool) {
    dim("1: lo: <LOOPBACK,UP> mtu 65536 (software loopback in the IPv4 layer)\n");
    if with_addr {
        dim("    inet 127.0.0.1/8 scope host lo\n");
    }
}

fn show_eth_header(up: bool) {
    use crate::net;
    puts("2: ");
    hl(IFNAME);
    puts(": <BROADCAST,MULTICAST");
    if up { ok(",UP,LOWER_UP"); } else { err(",NO-CARRIER"); }
    puts("> mtu 1500 state ");
    if up { ok("UP"); } else { err("DOWN"); }
    puts("\n");
    dim("    driver: ");
    dim(net::nic_model());
    dim("\n");
}

fn cmd_ip_show_addr() {
    use crate::net;
    let ip   = unsafe { net::OUR_IP };
    let mask = unsafe { net::SUBNET_MASK };
    let mac  = unsafe { net::OUR_MAC };
    let up   = net::link_up();
    let plen = subnet_prefix_len(mask);
    let brd  = ip_broadcast(ip, mask);

    show_lo(true);
    puts("\n");
    show_eth_header(up);
    puts("    link/ether ");
    draw_mac(&mac);
    puts(" brd ff:ff:ff:ff:ff:ff\n");
    puts("    inet ");
    put_ip(ip);
    puts(&format!("/{} brd ", plen));
    put_ip(brd);
    puts(" scope global ");
    puts(IFNAME);
    if ip[0] == 169 && ip[1] == 254 {
        err("  (link-local fallback: DHCP failed)");
    }
    puts("\n");
}

fn cmd_ip_show_link() {
    use crate::net;
    let mac = unsafe { net::OUR_MAC };
    let up  = net::link_up();

    show_lo(false);
    puts("\n");
    show_eth_header(up);
    puts("    link/ether ");
    draw_mac(&mac);
    puts(" brd ff:ff:ff:ff:ff:ff\n");
    puts(&format!("    RX: packets={} bytes={}\n", net::rx_packets(), net::rx_bytes()));
    puts(&format!("    TX: packets={} bytes={}\n", net::tx_packets(), net::tx_bytes()));
}

fn cmd_ip_show_route() {
    use crate::net;
    let ip   = unsafe { net::OUR_IP };
    let gw   = unsafe { net::GATEWAY_IP };
    let mask = unsafe { net::SUBNET_MASK };
    let plen = subnet_prefix_len(mask);
    let net_addr = ip_network(ip, mask);

    if gw != [0, 0, 0, 0] {
        puts("default via ");
        put_ip(gw);
        puts(" dev ");
        puts(IFNAME);
        puts("\n");
    }
    put_ip(net_addr);
    puts(&format!("/{} dev {} proto kernel scope link src ", plen, IFNAME));
    put_ip(ip);
    puts("\n");
    puts("127.0.0.0/8 dev lo scope host\n");
}

// ─── nslookup ─────────────────────────────────────────────────────────────────

pub fn cmd_nslookup(args: &str) {
    let args = args.trim();
    if args.is_empty() {
        err("nslookup: missing hostname\n");
        dim("Usage: nslookup <hostname|ip>\n");
        return;
    }

    if !crate::userspace::net::is_up() {
        err("nslookup: network is down\n");
        return;
    }

    use crate::userspace::net::{dns, resolver};
    let name = args.split_whitespace().next().unwrap_or(args);
    let fmt_ip = |ip: [u8; 4]| format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);

    if let Some(ip) = resolver::parse_ipv4(name) {
        // Reverse (PTR) lookups are not implemented.
        puts(&format!("Name:  {}\nAddress: {}\n", name, fmt_ip(ip)));
        dim("(IP literal; reverse PTR lookup is not supported)\n");
        return;
    }

    // /etc/hosts first, like resolve_host() does.
    if let Some(ip) = resolver::hosts_lookup(name) {
        dim("Source:    /etc/hosts\n\n");
        puts(&format!("Name:  {}\n", name));
        ok(&format!("Address: {}\n", fmt_ip(ip)));
        return;
    }

    match dns::query(name) {
        Ok(a) => {
            if a.cached {
                dim("Server:    (local cache)\n\n");
            } else {
                dim(&format!("Server:    {}\n", fmt_ip(a.server)));
                dim(&format!("Address:  {}#53\n\n", fmt_ip(a.server)));
            }
            dim("Non-authoritative answer:\n");
            puts(&format!("Name:  {}\n", name));
            ok(&format!("Address: {}\n", fmt_ip(a.ip)));
        }
        Err(e) => {
            match e {
                dns::DnsError::NxDomain { server } | dns::DnsError::NoAddress { server } => {
                    dim(&format!("Server:    {}\n\n", fmt_ip(server)));
                }
                dns::DnsError::NoResponse => {
                    let mut srv = [[0u8; 4]; 6];
                    let n = dns::servers(&mut srv);
                    let mut list = alloc::string::String::new();
                    for i in 0..n {
                        if i > 0 { list.push_str(", "); }
                        list.push_str(&fmt_ip(srv[i]));
                    }
                    dim(&format!("Tried:    {}\n\n", list));
                }
                _ => {}
            }
            err(&format!("nslookup: can't resolve '{}': {}\n", name, e.as_str()));
        }
    }
}

// ─── curl — HTTP/1.x over real TCP ───────────────────────────────────────────

/// Decode HTTP/1.1 chunked transfer encoding.
fn decode_chunked(data: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        // find CRLF terminating the chunk-size line
        let mut lf = pos;
        while lf + 1 < data.len() && !(data[lf] == b'\r' && data[lf + 1] == b'\n') {
            lf += 1;
        }
        if lf + 1 >= data.len() { break; }
        let hex_s = core::str::from_utf8(&data[pos..lf]).unwrap_or("0");
        let hex_s = hex_s.split(';').next().unwrap_or("0").trim();
        let chunk_size = usize::from_str_radix(hex_s, 16).unwrap_or(0);
        pos = lf + 2; // skip chunk-size CRLF
        if chunk_size == 0 { break; } // terminal chunk
        let take = chunk_size.min(data.len().saturating_sub(pos));
        out.extend_from_slice(&data[pos..pos + take]);
        pos += take + 2; // skip data + trailing CRLF
    }
    out
}

/// Upper bound on a buffered HTTP response.
const MAX_RESPONSE: usize = 512 * 1024;

/// True once `acc` holds a complete HTTP response (by Content-Length, the
/// final chunk, or headers-only for HEAD / bodiless statuses). Used to stop
/// reading without waiting for the server to close the connection.
fn http_response_complete(acc: &[u8], head_only: bool) -> bool {
    let sep = match acc.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i,
        None => return false,
    };
    let body_len = acc.len() - (sep + 4);
    let hdr = core::str::from_utf8(&acc[..sep]).unwrap_or("");
    let mut status = 0u16;
    let mut content_len: Option<usize> = None;
    let mut chunked = false;
    for (i, line) in hdr.split("\r\n").enumerate() {
        if i == 0 {
            status = line.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        } else if let Some(col) = line.find(':') {
            let (k, v) = (line[..col].trim(), line[col + 1..].trim());
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }
    if head_only || status == 204 || status == 304 || (100..200).contains(&status) {
        return true;
    }
    if chunked {
        return acc.ends_with(b"\r\n0\r\n\r\n") || (body_len == 5 && acc.ends_with(b"0\r\n\r\n"));
    }
    match content_len {
        Some(cl) => body_len >= cl,
        None => false, // read until the server closes
    }
}

/// Write response bytes to the framebuffer (printable + common whitespace).
fn print_http_bytes(data: &[u8], color: u32) {
    for &b in data {
        if b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t' {
            framebuffer::draw_char(b as char, color, BG);
        }
    }
}

pub fn cmd_curl(args: &str) {
    use alloc::string::String;
    use alloc::vec::Vec;

    let args = args.trim();
    if args.is_empty() {
        err("curl: missing URL\n");
        dim("Usage: curl [-IiLvs] [-H hdr] [-X method] [-d data] <URL>\n");
        dim("  -I / --head      HEAD request — print headers only\n");
        dim("  -i / --include   Include response headers in output\n");
        dim("  -v / --verbose   Verbose (show request + response)\n");
        dim("  -L / --location  Follow redirects\n");
        dim("  -H hdr           Add custom request header\n");
        dim("  -X method        Override HTTP method\n");
        dim("  -d data          POST data\n");
        return;
    }

    if !crate::userspace::net::is_up() { err("curl: network is down\n"); return; }

    // ── Parse flags ───────────────────────────────────────────────────────────
    let mut head_only   = false; // -I / --head
    let mut inc_hdrs    = false; // -i / --include
    let mut verbose     = false; // -v / --verbose
    let mut silent      = false; // -s / --silent
    let mut follow      = false; // -L / --location
    let mut method_ovrd = "";
    let mut post_data   = "";
    let mut out_file    = "";
    let mut url_raw     = "";
    let mut extra: Vec<&str> = Vec::new();
    {
        let mut it = args.split_ascii_whitespace();
        while let Some(tok) = it.next() {
            match tok {
                "-I" | "--head"      => head_only   = true,
                "-i" | "--include"   => inc_hdrs    = true,
                "-v" | "--verbose"   => verbose     = true,
                "-s" | "--silent"    => silent      = true,
                "-L" | "--location"  => follow      = true,
                "-H" | "--header"    => { extra.push(it.next().unwrap_or("")); }
                "-X" | "--request"   => { method_ovrd = it.next().unwrap_or(""); }
                "-d" | "--data"      => { post_data  = it.next().unwrap_or(""); }
                "-o" | "--output"    => { out_file = it.next().unwrap_or(""); }
                _ if !tok.starts_with('-') => url_raw = tok,
                _ => {}
            }
        }
    }
    if url_raw.is_empty() { err("curl: missing URL\n"); return; }

    let http_method = if !method_ovrd.is_empty() { method_ovrd }
        else if head_only { "HEAD" }
        else if !post_data.is_empty() { "POST" }
        else { "GET" };

    // ── Redirect loop ─────────────────────────────────────────────────────────
    let mut cur_url = String::from(url_raw);
    'redir: for _depth in 0..=10usize {

        // ── Parse URL into owned components ────────────────────────────────
        let (use_tls, host, port, path): (bool, String, u16, String) = {
            let s: &str = &cur_url;
            let (tls, rest) = if s.starts_with("https://") {
                (true,  &s[8..])
            } else if s.starts_with("http://") {
                (false, &s[7..])
            } else {
                (false, s)
            };
            let dflt = if tls { 443u16 } else { 80u16 };
            let (hp, p) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None    => (rest, "/"),
            };
            let (h, po) = match hp.rfind(':') {
                Some(c) => (&hp[..c], hp[c+1..].parse::<u16>().unwrap_or(dflt)),
                None    => (hp, dflt),
            };
            (tls, String::from(h), po, String::from(p))
        };

        // ── Resolve ──────────────────────────────────────────────────────────
        let ip = match crate::userspace::net::resolver::resolve_host(&host) {
            Ok(ip) => ip,
            Err(e) => {
                err("curl: cannot resolve '"); err(&host);
                err("': "); err(e.as_str()); err("\n");
                return;
            }
        };

        if verbose {
            dim(&format!("* Trying {}.{}.{}.{}:{} ...\n",
                ip[0], ip[1], ip[2], ip[3], port));
        }

        // ── Build HTTP/1.1 request ────────────────────────────────────────────
        let mut req = String::with_capacity(256);
        req.push_str(http_method); req.push(' ');
        req.push_str(&path); req.push_str(" HTTP/1.1\r\n");
        req.push_str("Host: "); req.push_str(&host); req.push_str("\r\n");
        req.push_str("User-Agent: curl/8.0.0 (AETERNA)\r\n");
        req.push_str("Accept: */*\r\n");
        req.push_str("Connection: close\r\n");
        for h in &extra {
            if !h.is_empty() { req.push_str(h); req.push_str("\r\n"); }
        }
        if !post_data.is_empty() {
            req.push_str(&format!(
                "Content-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\n",
                post_data.len()));
        }
        req.push_str("\r\n");
        if !post_data.is_empty() { req.push_str(post_data); }

        if verbose {
            for line in req.lines() { dim("> "); puts(line); puts("\n"); }
            dim(">\n");
        }

        // ── Connect, send, and receive the full response ─────────────────────
        let raw: Vec<u8> = 'conn: {
            if use_tls {
                let mut tls = match crate::userspace::net::tls::connect(ip, port, &host) {
                    Ok(c)  => c,
                    Err(e) => { err("curl: TLS failed: "); err(e); err("\n"); return; }
                };
                if verbose { dim("* SSL connection established\n"); }
                if tls.send(req.as_bytes()).is_err() {
                    err("curl: TLS send failed\n"); tls.close(); return;
                }
                let mut acc: Vec<u8> = Vec::with_capacity(8192);
                let mut buf = [0u8; 4096];
                loop {
                    if check_ctrl_c() { dim("\n[interrupted]\n"); tls.close(); return; }
                    match tls.recv(&mut buf, 1000) {
                        Ok(0)  => break,
                        Ok(n)  => acc.extend_from_slice(&buf[..n]),
                        Err(e) => {
                            if !silent { err("curl: "); err(e); err(" (response may be incomplete)\n"); }
                            break;
                        }
                    }
                    if http_response_complete(&acc, head_only) { break; }
                    if acc.len() > MAX_RESPONSE {
                        if !silent { err("curl: response truncated at 512 KiB\n"); }
                        break;
                    }
                }
                tls.close();
                break 'conn acc;
            } else {
                let conn = match crate::userspace::net::tcp::tcp_connect(ip, port) {
                    Ok(c)  => c,
                    Err(e) => { err("curl: connect failed: "); err(e.as_str()); err("\n"); return; }
                };
                if crate::userspace::net::tcp::tcp_send(conn, req.as_bytes()).is_err() {
                    err("curl: send failed\n");
                    crate::userspace::net::tcp::tcp_close(conn);
                    return;
                }
                let mut acc: Vec<u8> = Vec::with_capacity(8192);
                let mut buf = [0u8; 2048];
                loop {
                    if check_ctrl_c() {
                        dim("\n[interrupted]\n");
                        crate::userspace::net::tcp::tcp_close(conn);
                        return;
                    }
                    match crate::userspace::net::tcp::tcp_recv(conn, &mut buf, 1000) {
                        Ok(0) => break,
                        Ok(n) => acc.extend_from_slice(&buf[..n]),
                        Err(e) => {
                            if !silent { err("curl: recv: "); err(e.as_str()); err(" (response may be incomplete)\n"); }
                            break;
                        }
                    }
                    if http_response_complete(&acc, head_only) { break; }
                    if acc.len() > MAX_RESPONSE {
                        if !silent { err("curl: response truncated at 512 KiB\n"); }
                        break;
                    }
                }
                crate::userspace::net::tcp::tcp_close(conn);
                break 'conn acc;
            }
        };

        if raw.is_empty() {
            if !silent { err("curl: empty response\n"); }
            return;
        }

        // ── Split headers / body at the first \r\n\r\n ───────────────────────
        let sep_pos = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(i) => i,
            None    => { print_http_bytes(&raw, FG); return; }
        };
        let hdr_bytes = &raw[..sep_pos];
        let body_raw  = &raw[sep_pos + 4..];

        // ── Parse status line + key headers ──────────────────────────────────
        let hdr_str = core::str::from_utf8(hdr_bytes).unwrap_or("");
        let mut status_code: u16 = 0;
        let mut status_text      = "";
        let mut is_chunked       = false;
        let mut redirect_url: Option<String> = None;

        for (idx, raw_line) in hdr_str.split('\n').enumerate() {
            let line = raw_line.trim_end_matches('\r');
            if idx == 0 {
                status_text = line;
                let mut parts = line.splitn(3, ' ');
                let _ = parts.next(); // "HTTP/x.y"
                if let Some(c) = parts.next() {
                    status_code = c.trim().parse().unwrap_or(0);
                }
            } else if let Some(col) = line.find(':') {
                let key = line[..col].trim();
                let val = line[col + 1..].trim();
                if key.eq_ignore_ascii_case("transfer-encoding")
                    && val.eq_ignore_ascii_case("chunked")
                {
                    is_chunked = true;
                } else if key.eq_ignore_ascii_case("location") {
                    redirect_url = Some(String::from(val));
                }
            }
        }

        if verbose {
            for raw_line in hdr_str.split('\n') {
                let line = raw_line.trim_end_matches('\r');
                dim("< "); puts(line); puts("\n");
            }
            dim("<\n");
        }

        // ── Follow redirect (3xx) ─────────────────────────────────────────────
        if follow && (300..=399).contains(&status_code) {
            if let Some(loc) = redirect_url {
                if !silent {
                    dim(&format!("* Following {} redirect to {}\n", status_code, &loc));
                }
                cur_url = if loc.starts_with("http://") || loc.starts_with("https://") {
                    loc
                } else {
                    let scheme = if use_tls { "https" } else { "http" };
                    format!("{}://{}{}", scheme, &host, &loc)
                };
                continue 'redir;
            }
        }

        // ── Decode body ───────────────────────────────────────────────────────
        let body = if is_chunked {
            decode_chunked(body_raw)
        } else {
            body_raw.to_vec()
        };

        // ── Display based on mode ─────────────────────────────────────────────
        if head_only {
            // -I: status line + headers, no body
            puts(status_text); puts("\n");
            for raw_line in hdr_str.split('\n').skip(1) {
                let line = raw_line.trim_end_matches('\r');
                if line.is_empty() { break; }
                puts(line); puts("\n");
            }
        } else if !out_file.is_empty() {
            let path = crate::userspace::plum::resolve_path(out_file);
            if crate::fs::write_file(&path, &body) {
                if !silent { ok(&format!("curl: saved {} bytes to {} (HTTP {})\n", body.len(), path, status_code)); }
            } else {
                err(&format!("curl: cannot write {}\n", path));
            }
            break 'redir;
        } else if inc_hdrs {
            // -i: headers + body
            print_http_bytes(hdr_bytes, FG_DIM);
            puts("\r\n\r\n");
            print_http_bytes(&body, FG);
        } else if verbose {
            // -v: request+response headers already shown, just print body
            print_http_bytes(&body, FG);
        } else {
            // default: body only (like real curl)
            print_http_bytes(&body, FG);
        }

        if !silent { puts("\n"); }
        break 'redir;
    }
}
