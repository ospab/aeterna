/*
 * axon/net_tools — Network & disk commands: netstat, ping, df
 *
 * Self-contained logical unit.  Contacts the kernel net stack through
 * crate::net::* and the filesystem through crate::fs::*.
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
    while let Some(ch) = crate::arch::x86_64::keyboard::try_read_key() {
        if ch == '\x03' { return true; }
    }
    false
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
        puts("  Gateway ");
        puts(&format!("{}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]));
        puts("  ");
        draw_mac_dim(&gw_mac);
        puts("\n");
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
    let ip = match crate::net::resolver::parse_ipv4(target) {
        Some(ip) => ip,
        None => match crate::net::resolver::resolve_host(target) {
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

    if !crate::net::is_up() {
        err("ping: network is down\n");
        return;
    }

    ok("PING "); puts(target); ok(" 56(84) bytes of data\n");

    // Ensure ARP is warm for the target (send a gratuitous ARP first)
    crate::net::arp::send_request(ip);
    let arp_deadline = crate::arch::x86_64::idt::timer_ticks() + 30; // 300 ms
    while crate::arch::x86_64::idt::timer_ticks() < arp_deadline {
        crate::net::poll_rx();
        if crate::net::arp::cache_lookup(ip).is_some() { break; }
        crate::core::scheduler::sys_yield();
    }

    let mut received = 0usize;
    for seq in 1..=count {
        crate::net::icmp::send_ping(ip, seq as u16);

        // Wait up to 3 s (300 ticks @ 100 Hz) for ICMP echo reply
        let mut reply = None;
        let deadline = crate::arch::x86_64::idt::timer_ticks() + 300;
        while crate::arch::x86_64::idt::timer_ticks() < deadline {
            reply = crate::net::icmp::poll_reply();
            if reply.is_some() { break; }
            unsafe { core::arch::asm!("hlt"); }
        }
        if reply.is_none() {
            crate::net::icmp::cancel_wait();
        }

        match reply {
            Some(r) => {
                received += 1;
                let rtt_us = r.rtt_us;
                let display_ms = if rtt_us < 1000 { 1 } else { rtt_us / 1000 };
                ok("64 bytes from "); puts(target);
                puts(&format!(": icmp_seq={} ttl={} time={}ms\n", seq, r.ttl, display_ms));
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
                crate::net::poll_rx();
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
}

// ─── df ──────────────────────────────────────────────────────────────────────

pub fn cmd_df(_args: &str) {
    hl("  Filesystem      1K-blocks   Used  Available  Use%  Mounted on\n");
    dim("  ---------------------------------------------------------------\n");

    // RamFS usage
    let node_count = crate::fs::ramfs::node_count();
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
    let dst_ip = match crate::net::resolver::parse_ipv4(target) {
        Some(ip) => ip,
        None => match crate::net::resolver::resolve_host(target) {
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

    if !crate::net::is_up() {
        err("traceroute: network is down\n");
        return;
    }

    // ── Warm up ARP for the destination / gateway ─────────────────────────────
    crate::net::arp::send_request(dst_ip);
    let arp_dl = crate::arch::x86_64::idt::timer_ticks() + 30;
    while crate::arch::x86_64::idt::timer_ticks() < arp_dl {
        crate::net::poll_rx();
        crate::core::scheduler::sys_yield();
        if crate::net::arp::cache_lookup(dst_ip).is_some() { break; }
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
            crate::net::icmp::send_ping_ttl(dst_ip, seq, ttl);

            // Wait for reply with TSC-based timeout
            let start = crate::arch::x86_64::tsc::tsc_stamp_us();
            let mut reply = None;
            loop {
                reply = crate::net::icmp::poll_reply();
                if reply.is_some() { break; }
                let elapsed = crate::arch::x86_64::tsc::tsc_stamp_us()
                    .saturating_sub(start);
                if elapsed >= timeout_us {
                    crate::net::icmp::cancel_wait();
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

fn cmd_ip_show_addr() {
    use crate::net;
    let ip   = unsafe { net::OUR_IP };
    let mask = unsafe { net::SUBNET_MASK };
    let mac  = unsafe { net::OUR_MAC };
    let nic  = net::nic_name();
    let up   = net::link_up();
    let plen = subnet_prefix_len(mask);
    let brd  = ip_broadcast(ip, mask);
    let rx_p = net::rx_packets();
    let tx_p = net::tx_packets();

    // Loopback
    dim("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n");
    dim("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n");
    dim("    inet 127.0.0.1/8 scope host lo\n\n");

    // NIC
    puts("2: ");
    hl(nic);
    puts(": <BROADCAST,MULTICAST,");
    if up { ok("UP,LOWER_UP"); } else { err("NO-CARRIER"); }
    puts("> mtu 1500 state ");
    if up { ok("UP"); } else { err("DOWN"); }
    puts("\n");
    puts("    link/ether ");
    draw_mac(&mac);
    puts(" brd ff:ff:ff:ff:ff:ff\n");
    puts("    inet ");
    put_ip(ip);
    puts(&format!("/{} brd ", plen));
    put_ip(brd);
    puts(" scope global ");
    puts(nic);
    puts("\n");
    puts("    RX: ");
    put_usize(rx_p as usize);
    puts(" pkts  TX: ");
    put_usize(tx_p as usize);
    puts(" pkts\n");
}

fn cmd_ip_show_link() {
    use crate::net;
    let mac = unsafe { net::OUR_MAC };
    let nic = net::nic_name();
    let up  = net::link_up();
    let rx  = net::rx_packets();
    let tx  = net::tx_packets();
    let rxb = net::rx_bytes();
    let txb = net::tx_bytes();

    dim("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n");
    dim("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n\n");

    puts("2: ");
    hl(nic);
    puts(": <BROADCAST,MULTICAST,");
    if up { ok("UP,LOWER_UP"); } else { err("NO-CARRIER"); }
    puts("> mtu 1500 state ");
    if up { ok("UP"); } else { err("DOWN"); }
    puts("\n");
    puts("    link/ether ");
    draw_mac(&mac);
    puts(" brd ff:ff:ff:ff:ff:ff\n");
    puts(&format!("    RX: packets={} bytes={}\n", rx, rxb));
    puts(&format!("    TX: packets={} bytes={}\n", tx, txb));
}

fn cmd_ip_show_route() {
    use crate::net;
    let ip   = unsafe { net::OUR_IP };
    let gw   = unsafe { net::GATEWAY_IP };
    let mask = unsafe { net::SUBNET_MASK };
    let nic  = net::nic_name();
    let plen = subnet_prefix_len(mask);
    let net_addr = ip_network(ip, mask);

    puts("default via ");
    put_ip(gw);
    puts(" dev ");
    puts(nic);
    puts("\n");
    put_ip(net_addr);
    puts(&format!("/{} dev ", plen));
    puts(nic);
    puts(" proto kernel scope link src ");
    put_ip(ip);
    puts("\n");
    puts("127.0.0.0/8 dev lo scope host\n");
}

// ─── curl — HTTP/1.0 over real TCP ───────────────────────────────────────────

pub fn cmd_curl(args: &str) {
    let args = args.trim();
    if args.is_empty() {
        err("curl: missing URL\n");
        dim("Usage: curl http://<host>[:port][/path]\n");
        dim("       curl http://example.com/\n");
        return;
    }

    if !crate::net::is_up() {
        err("curl: network is down\n");
        return;
    }

    // Handle scheme
    if args.starts_with("https://") {
        err("curl: HTTPS (TLS) is not supported — use http://\n");
        dim("  Example: curl http://example.com/\n");
        return;
    }

    // Strip optional "http://"
    let rest = if args.starts_with("http://") { &args[7..] } else { args };

    // Split hostport from path
    let (hostport, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None        => (rest, "/"),
    };

    // Split host from optional port
    let (host_str, port) = match hostport.rfind(':') {
        Some(c) => {
            let p = hostport[c+1..].parse::<u16>().unwrap_or(80);
            (&hostport[..c], p)
        }
        None => (hostport, 80u16),
    };

    // Resolve hostname → IPv4
    let ip = match crate::net::resolver::resolve_host(host_str) {
        Ok(ip)  => ip,
        Err(e)  => {
            err("curl: cannot resolve '");
            err(host_str);
            err("': ");
            err(e.as_str());
            err("\n");
            return;
        }
    };

    dim(&format!("Connecting to {}:{} ({})\n", host_str, port,
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])));

    // TCP connect
    let conn = match crate::net::tcp::tcp_connect(ip, port) {
        Ok(c)  => c,
        Err(e) => {
            err("curl: connect failed: ");
            err(e.as_str());
            err("\n");
            return;
        }
    };

    ok("Connected.\n");

    // Send HTTP/1.0 GET
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: AETERNA/1.1\r\nConnection: close\r\n\r\n",
        path, host_str
    );
    if let Err(e) = crate::net::tcp::tcp_send(conn, req.as_bytes()) {
        err("curl: send failed: ");
        err(e.as_str());
        err("\n");
        crate::net::tcp::tcp_close(conn);
        return;
    }

    // Receive HTTP response and display it
    let mut total_bytes = 0usize;
    let mut buf = [0u8; 512];
    // Track last 4 received bytes to detect end-of-headers (\r\n\r\n)
    let mut tail4 = [0u8; 4];
    let mut headers_done = false;

    loop {
        if check_ctrl_c() { dim("\n[interrupted]\n"); break; }

        match crate::net::tcp::tcp_recv(conn, &mut buf, 200) {
            Ok(0) => break, // connection closed
            Ok(n) => {
                total_bytes += n;
                let data = &buf[..n];

                for &b in data {
                    // Update sliding 4-byte window to detect \r\n\r\n
                    if !headers_done {
                        tail4[0] = tail4[1];
                        tail4[1] = tail4[2];
                        tail4[2] = tail4[3];
                        tail4[3] = b;
                        if &tail4 == b"\r\n\r\n" { headers_done = true; }
                        // Print header line in dim colour
                        if b >= 0x20 || b == b'\n' || b == b'\r' {
                            framebuffer::draw_char(b as char, FG_DIM, BG);
                        }
                    } else {
                        // Print body in normal colour
                        if b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t' {
                            framebuffer::draw_char(b as char, FG, BG);
                        }
                    }
                }
            }
            Err(crate::net::tcp::TcpError::TimedOut)
            | Err(crate::net::tcp::TcpError::WouldBlock) => break,
            Err(e) => {
                err("\ncurl: recv error: ");
                err(e.as_str());
                err("\n");
                break;
            }
        }
    }

    crate::net::tcp::tcp_close(conn);
    puts("\n");
    dim(&format!("[{} bytes received]\n", total_bytes));
}
