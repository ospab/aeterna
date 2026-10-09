/*
 * ostp — OSTP tunnel client (native, see net/ostp)
 *
 *   ostp connect [--weak-rng] <ostp://KEY@HOST:PORT | HOST[:PORT] KEY>
 *   ostp status
 *   ostp ping [-c N]
 *   ostp dns <name> [resolver]        resolve through the tunnel (default 1.1.1.1:53)
 *   ostp get <host[:port]> [path]     HTTP/1.0 GET through the tunnel
 *   ostp close
 */

extern crate alloc;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::net::ostp;
use crate::userspace::plum::io;

const DEFAULT_PORT: u16 = 50000;

fn usage() {
    io::out("usage:\n");
    io::out("  ostp connect [--weak-rng] <ostp://KEY@HOST:PORT | HOST[:PORT] KEY>\n");
    io::out("  ostp status\n");
    io::out("  ostp ping [-c N]\n");
    io::out("  ostp dns <name> [resolver-ip[:port]]\n");
    io::out("  ostp get <host[:port]> [path]\n");
    io::out("  ostp close\n");
}

fn fmt_us(us: u64) -> String {
    format!("{}.{:03} ms", us / 1000, us % 1000)
}

fn ip_str(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

pub fn run(args: &str) {
    let mut words = args.split_whitespace();
    match words.next() {
        Some("connect") => connect(words.collect()),
        Some("status") => status(),
        Some("ping") => ping(words.collect()),
        Some("dns") => dns(words.collect()),
        Some("get") => get(words.collect()),
        Some("close") => {
            ostp::close();
            io::out("ostp: session closed\n");
        }
        _ => usage(),
    }
}

fn connect(args: Vec<&str>) {
    let mut weak = false;
    let mut rest: Vec<&str> = Vec::new();
    for a in args {
        if a == "--weak-rng" {
            weak = true;
        } else {
            rest.push(a);
        }
    }
    let (host, port, key): (String, u16, String) = match rest.as_slice() {
        [link] if link.starts_with("ostp://") => match ostp_core::share_link::ShareLink::parse(link) {
            Ok(l) => {
                if l.transport != ostp_core::share_link::LinkTransport::Udp || l.tls {
                    io::err("ostp: only the plain UDP transport is supported (link is uot/tls)\n");
                    return;
                }
                (l.host, l.port, l.key)
            }
            Err(e) => {
                io::err(&format!("ostp: bad link: {}\n", e));
                return;
            }
        },
        [hp, key] => {
            let (h, p) = match hp.rsplit_once(':') {
                Some((h, p)) => match p.parse::<u16>() {
                    Ok(p) => (h, p),
                    Err(_) => {
                        io::err("ostp: bad port\n");
                        return;
                    }
                },
                None => (*hp, DEFAULT_PORT),
            };
            (h.to_string(), p, key.to_string())
        }
        _ => {
            usage();
            return;
        }
    };
    let ip = match crate::net::resolver::resolve_host(&host) {
        Ok(ip) => ip,
        Err(e) => {
            io::err(&format!("ostp: cannot resolve {}: {}\n", host, e.as_str()));
            return;
        }
    };
    ostp::rng::allow_weak(weak);
    if weak && !ostp::rng::has_rdrand() {
        io::err("ostp: warning: no RDRAND, using the kernel fallback RNG (NOT secure)\n");
    }
    io::out(&format!("ostp: handshake with {}:{} ...\n", ip_str(ip), port));
    match ostp::connect(ip, port, &key) {
        Ok(us) => {
            io::out(&format!("ostp: tunnel established (handshake {})\n", fmt_us(us)));
            match ostp::ping() {
                Ok(us) => io::out(&format!("ostp: relay ping ok, rtt {}\n", fmt_us(us))),
                Err(e) => io::err(&format!("ostp: relay ping failed: {}\n", e)),
            }
        }
        Err(e) => io::err(&format!("ostp: {}\n", e)),
    }
}

fn status() {
    match ostp::status() {
        None => io::out("ostp: not connected\n"),
        Some(s) => {
            io::out(&format!("ostp: {} to {}\n", s.state, s.server));
            io::out(&format!("  uptime   {} s\n", s.uptime_ms / 1000));
            io::out(&format!("  tx       {} datagrams, {} bytes\n", s.tx_dgrams, s.tx_bytes));
            io::out(&format!("  rx       {} datagrams, {} bytes\n", s.rx_dgrams, s.rx_bytes));
            io::out(&format!("  window   {} packets, {} in flight\n", s.cwnd_packets, s.in_flight));
        }
    }
}

fn ping(args: Vec<&str>) {
    let mut count = 4usize;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if *a == "-c" {
            count = it.next().and_then(|v| v.parse().ok()).unwrap_or(4);
        }
    }
    let (mut ok, mut min, mut max, mut sum) = (0u64, u64::MAX, 0u64, 0u64);
    for i in 0..count {
        match ostp::ping() {
            Ok(us) => {
                ok += 1;
                min = min.min(us);
                max = max.max(us);
                sum += us;
                io::out(&format!("tunnel ping seq={} time={}\n", i + 1, fmt_us(us)));
            }
            Err(e) => {
                io::err(&format!("tunnel ping seq={}: {}\n", i + 1, e));
                if e == "interrupted" || e.starts_with("not connected") {
                    break;
                }
            }
        }
    }
    if ok > 0 {
        io::out(&format!(
            "{} sent, {} received; rtt min/avg/max = {}/{}/{}\n",
            count, ok, fmt_us(min), fmt_us(sum / ok), fmt_us(max)
        ));
    }
}

fn dns(args: Vec<&str>) {
    let Some(name) = args.first() else {
        usage();
        return;
    };
    let resolver = match args.get(1) {
        Some(r) if r.contains(':') => r.to_string(),
        Some(r) => format!("{}:53", r),
        None => "1.1.1.1:53".to_string(),
    };
    match ostp::dns(name, &resolver) {
        Ok((ips, us)) => {
            io::out(&format!("{} via tunnel (resolver {}), {}:\n", name, resolver, fmt_us(us)));
            if ips.is_empty() {
                io::out("  (no A records)\n");
            }
            for ip in ips {
                io::out(&format!("  {}\n", ip_str(ip)));
            }
        }
        Err(e) => io::err(&format!("ostp dns: {}\n", e)),
    }
}

fn get(args: Vec<&str>) {
    let Some(hp) = args.first() else {
        usage();
        return;
    };
    let path = args.get(1).copied().unwrap_or("/");
    let (host, target) = match hp.rsplit_once(':') {
        Some((h, _)) => (h.to_string(), hp.to_string()),
        None => (hp.to_string(), format!("{}:80", hp)),
    };
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: ospab-ostp\r\nConnection: close\r\n\r\n",
        path, host
    );
    let mut shown = 0usize;
    let mut sink = |d: &[u8]| {
        // Print the beginning of the response (headers and first bytes of the body).
        if shown < 1200 {
            let take = d.len().min(1200 - shown);
            let text = String::from_utf8_lossy(&d[..take]).replace('\r', "");
            io::out(&text);
            shown += take;
        }
    };
    match ostp::tcp_exchange(&target, req.as_bytes(), 1 << 20, 3000, &mut sink) {
        Ok(n) => io::out(&format!("\n[{} bytes received through the tunnel]\n", n)),
        Err(e) => io::err(&format!("ostp get: {}\n", e)),
    }
}
