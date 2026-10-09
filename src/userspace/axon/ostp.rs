/*
 * ostp — OSTP tunnel client (native, see net/ostp). Client side of the Linux
 * `ostp` tool: same command names, flags and wording where they make sense.
 *
 *   ostp connect [--weak-rng] [URL | HOST[:PORT] KEY]   no argument: the config
 *   ostp import <ostp://link | https://…/sub/token>     save to /etc/ostp/config.json
 *   ostp sub [update | <url>]                            subscription
 *   ostp list | use <n>                                  pick a server
 *   ostp check | links | init client | gk [-n N]
 *   ostp status | ping [-c N] | dns <name> [resolver] | get <host[:port]> [path] | close
 */

extern crate alloc;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::net::ostp::{self, config, config::Config, ConnParams};
use crate::userspace::plum::io;
use ostp_core::share_link::{LinkTransport, ShareLink};

const DEFAULT_PORT: u16 = 50000;
const TAG: &str = "[ostp]";

fn usage() {
    io::out("usage: ostp <command>\n");
    io::out("  connect [--weak-rng] [URL | HOST[:PORT] KEY]  connect (no argument: the saved server)\n");
    io::out("  import <ostp://link | https://.../sub/token>  save a link or a subscription\n");
    io::out("  sub [update | <url>]                           show / refresh / set the subscription\n");
    io::out("  list                                           servers in the config\n");
    io::out("  use <n>                                        select server n\n");
    io::out("  check                                          validate the config\n");
    io::out("  links                                          print the saved ostp:// links\n");
    io::out("  init client                                    write an empty client config\n");
    io::out("  gk [-n COUNT]                                  generate access keys\n");
    io::out("  status | ping [-c N] | close\n");
    io::out("  dns <name> [resolver-ip[:port]]                resolve through the tunnel\n");
    io::out("  get <host[:port]> [path]                       HTTP GET through the tunnel\n");
}

fn fmt_us(us: u64) -> String {
    format!("{}.{:03} ms", us / 1000, us % 1000)
}

fn ip_str(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn format_bytes(b: u64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024 * 10 && i < 3 {
        v /= 1024;
        i += 1;
    }
    format!("{} {}", v, U[i])
}

fn info(s: &str) {
    io::out(&format!("{} {}\n", TAG, s));
}
fn fail(s: &str) {
    io::err(&format!("{} {}\n", TAG, s));
}

pub fn run(args: &str) {
    let mut words = args.split_whitespace();
    match words.next() {
        Some("connect") => connect(words.collect()),
        Some("import") => import(words.collect()),
        Some("sub") => sub(words.collect()),
        Some("list") => list(),
        Some("use") => use_server(words.collect()),
        Some("check") => check(),
        Some("links") => links(),
        Some("init") => init(words.collect()),
        Some("gk") | Some("generate-key") => gk(words.collect()),
        Some("status") => status(),
        Some("ping") => ping(words.collect()),
        Some("dns") => dns(words.collect()),
        Some("get") => get(words.collect()),
        Some("close") => {
            ostp::close();
            info("session closed");
        }
        _ => usage(),
    }
}

// ─── Config helpers ──────────────────────────────────────────────────────────

fn load_config() -> Result<Config, String> {
    match config::load()? {
        Some(c) => Ok(c),
        None => Err(format!("Configuration file \"{}\" not found. Use `ostp import <url>`.", config::PATH)),
    }
}

fn link_label(l: &ShareLink) -> String {
    l.name.clone().unwrap_or_else(|| l.server())
}

fn params_for(l: &ShareLink) -> Result<ConnParams, String> {
    if l.tls {
        return Err("this link uses TLS (type=tls / tls=1): only the udp and uot (plain TCP) transports are supported".to_string());
    }
    let ip = crate::net::resolver::resolve_host(&l.host)
        .map_err(|e| format!("cannot resolve {}: {}", l.host, e.as_str()))?;
    Ok(ConnParams { ip, port: l.port, key: l.key.clone(), tcp: l.transport == LinkTransport::Uot })
}

// ─── Subscription ────────────────────────────────────────────────────────────

/// Fetch a subscription and store it (keeping the selected index when it still exists).
fn fetch_subscription(url: &str, announce: bool) -> Result<Config, String> {
    if announce {
        info("Fetching subscription...");
    }
    let body = super::net_tools::http_get(url, 256 * 1024)?;
    let text = String::from_utf8(body).map_err(|_| "Subscription Error: the response is not text".to_string())?;
    let doc = ostp_core::subscription::SubscriptionDoc::parse(&text).map_err(|e| format!("Subscription Error: {}", e))?;
    let links = doc.valid_links();
    if links.is_empty() {
        return Err("Subscription Error: no usable ostp:// links in the response".to_string());
    }
    io::out(&format!("  {} - {} link(s), refresh every {} h\n", doc.name, links.len(), doc.update_interval_hours));
    let (used, limit) = match &doc.usage {
        Some(u) => {
            let lim = u.limit_bytes.map(format_bytes).unwrap_or_else(|| "unlimited".to_string());
            io::out(&format!("  Traffic: {} of {}\n", format_bytes(u.used_bytes), lim));
            (Some(u.used_bytes), u.limit_bytes)
        }
        None => (None, None),
    };
    for (i, l) in links.iter().enumerate() {
        io::out(&format!("  [{}] {}\n", i + 1, link_label(l)));
    }
    let prev = config::load().ok().flatten();
    let selected = prev.as_ref().map(|p| p.selected).filter(|s| *s < links.len()).unwrap_or(0);
    let cfg = Config {
        subscription: Some(url.to_string()),
        name: doc.name.clone(),
        interval_h: doc.update_interval_hours,
        updated: crate::time::unix_secs().max(0) as u64,
        used,
        limit,
        selected,
        links: links.iter().map(|l| l.to_uri()).collect(),
    };
    config::save(&cfg)?;
    Ok(cfg)
}

fn import(args: Vec<&str>) {
    let Some(src) = args.first() else {
        usage();
        return;
    };
    if src.to_ascii_lowercase().starts_with("https://") || src.to_ascii_lowercase().starts_with("http://") {
        match fetch_subscription(src, true) {
            Ok(_) => {
                io::out("  Run `ostp import <url>` again to pick up server changes (or `ostp sub update`).\n");
                info(&format!("Configuration successfully imported and saved to \"{}\"", config::PATH));
            }
            Err(e) => fail(&e),
        }
        return;
    }
    info("Importing configuration from share link...");
    let link = match ShareLink::parse(src) {
        Ok(l) => l,
        Err(e) => {
            fail(&format!("Share Link Error: {}", e));
            return;
        }
    };
    let cfg = Config { interval_h: 12, links: alloc::vec![link.to_uri()], ..Default::default() };
    match config::save(&cfg) {
        Ok(()) => info(&format!("Configuration successfully imported and saved to \"{}\"", config::PATH)),
        Err(e) => fail(&e),
    }
}

fn sub(args: Vec<&str>) {
    match args.first().copied() {
        None => match load_config() {
            Ok(c) => match &c.subscription {
                Some(u) => {
                    io::out(&format!("subscription: {}\n", u));
                    io::out(&format!("  {} - {} link(s), refresh every {} h\n", c.name, c.links.len(), c.interval_h));
                    if let Some(used) = c.used {
                        let lim = c.limit.map(format_bytes).unwrap_or_else(|| "unlimited".to_string());
                        io::out(&format!("  Traffic: {} of {}\n", format_bytes(used), lim));
                    }
                }
                None => io::out("no subscription: ostp sub <https://.../sub/token>\n"),
            },
            Err(e) => fail(&e),
        },
        Some("update") => match load_config().and_then(|c| c.subscription.ok_or_else(|| "no subscription in the config".to_string())) {
            Ok(u) => match fetch_subscription(&u, true) {
                Ok(_) => info("Subscription updated."),
                Err(e) => fail(&e),
            },
            Err(e) => fail(&e),
        },
        Some(url) => import(alloc::vec![url]),
    }
}

// ─── Config commands ─────────────────────────────────────────────────────────

fn list() {
    let c = match load_config() {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    if c.links.is_empty() {
        io::out("no servers: ostp import <url>\n");
    }
    for (i, l) in c.parsed().iter().enumerate() {
        let mark = if i == c.selected { '*' } else { ' ' };
        match l {
            Ok(l) => io::out(&format!(
                "{} [{}] {}  ({}{})\n",
                mark,
                i + 1,
                link_label(l),
                if l.tls { "tls" } else { l.transport.as_str() },
                if l.tls { ", unsupported" } else { "" }
            )),
            Err(e) => io::out(&format!("{} [{}] invalid link: {}\n", mark, i + 1, e)),
        }
    }
}

fn use_server(args: Vec<&str>) {
    let mut c = match load_config() {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let n: usize = match args.first().and_then(|a| a.parse().ok()) {
        Some(n) if n >= 1 && n <= c.links.len() => n,
        _ => return fail(&format!("usage: ostp use <1..{}>", c.links.len().max(1))),
    };
    c.selected = n - 1;
    if let Err(e) = config::save(&c) {
        return fail(&e);
    }
    info(&format!("Selected server [{}] {}", n, c.current().map(|l| link_label(&l)).unwrap_or_default()));
    if ostp::wanted() {
        connect(Vec::new());
    }
}

fn check() {
    let c = match config::load() {
        Ok(Some(c)) => c,
        Ok(None) => return fail(&format!("Configuration file \"{}\" not found.", config::PATH)),
        Err(e) => return fail(&format!("Config error: {}", e)),
    };
    let parsed = c.parsed();
    if let Some((i, Err(e))) = parsed.iter().enumerate().find(|(_, r)| r.is_err()) {
        return fail(&format!("Config error: link [{}] is invalid: {}", i + 1, e));
    }
    let cur = match c.current() {
        Ok(l) => l,
        Err(e) => return fail(&format!("Config error: {}", e)),
    };
    io::out(&format!("{} Config OK: client mode\n", TAG));
    io::out(&format!("  Server: {}\n", cur.server()));
    let k: String = cur.key.chars().take(8).collect();
    io::out(&format!("  Key: {}...\n", k));
    io::out(&format!("  Transport: {}{}\n", cur.transport.as_str(), if cur.tls { " + tls (not supported in AETERNA)" } else { "" }));
    io::out(&format!("  Servers: {} (selected {})\n", c.links.len(), c.selected + 1));
    match &c.subscription {
        Some(u) => io::out(&format!("  Subscription: {} (refresh every {} h)\n", u, c.interval_h)),
        None => io::out("  Subscription: none\n"),
    }
}

fn links() {
    match load_config() {
        Ok(c) => {
            for l in &c.links {
                io::out(&format!("{}\n", l));
            }
        }
        Err(e) => fail(&e),
    }
}

fn init(args: Vec<&str>) {
    if args.first().copied() != Some("client") {
        return fail("usage: ostp init client");
    }
    if config::load().ok().flatten().is_some() {
        return fail(&format!("\"{}\" already exists", config::PATH));
    }
    match config::save(&Config { interval_h: 12, ..Default::default() }) {
        Ok(()) => info(&format!("Client config written to \"{}\". Add a server: ostp import <url>", config::PATH)),
        Err(e) => fail(&e),
    }
}

fn gk(args: Vec<&str>) {
    let mut count = 1usize;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if *a == "-n" || *a == "--count" {
            count = it.next().and_then(|v| v.parse().ok()).unwrap_or(1).clamp(1, 64);
        }
    }
    if !ostp::rng::usable() {
        return fail("no RDRAND on this CPU: refusing to generate a key from a weak RNG (QEMU: -cpu max)");
    }
    for _ in 0..count {
        let mut b = [0u8; 16];
        ostp::rng::fill(&mut b);
        let mut s = String::new();
        for x in b {
            s.push_str(&format!("{:02x}", x));
        }
        io::out(&format!("{}\n", s));
    }
}

// ─── Connection ──────────────────────────────────────────────────────────────

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
    let params: Result<ConnParams, String> = match rest.as_slice() {
        [] => {
            // The saved server; refresh a stale subscription first.
            load_config().and_then(|c| {
                if let Some(u) = &c.subscription {
                    let now = crate::time::unix_secs().max(0) as u64;
                    if c.updated != 0 && now > c.updated + c.interval_h as u64 * 3600 {
                        if fetch_subscription(u, false).is_err() {
                            info("Subscription refresh failed, using the saved servers.");
                        }
                    }
                }
                let c = load_config()?;
                let l = c.current()?;
                info(&format!("Connecting to {}...", link_label(&l)));
                params_for(&l)
            })
        }
        [link] if link.starts_with("ostp://") => {
            info("Connecting via share link...");
            ShareLink::parse(link).map_err(|e| format!("Share Link Error: {}", e)).and_then(|l| params_for(&l))
        }
        [hp, key] => {
            let (h, p) = match hp.rsplit_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().unwrap_or(DEFAULT_PORT)),
                None => (*hp, DEFAULT_PORT),
            };
            crate::net::resolver::resolve_host(h)
                .map(|ip| ConnParams { ip, port: p, key: key.to_string(), tcp: false })
                .map_err(|e| format!("cannot resolve {}: {}", h, e.as_str()))
        }
        _ => {
            usage();
            return;
        }
    };
    let params = match params {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    ostp::rng::allow_weak(weak);
    if weak && !ostp::rng::has_rdrand() {
        fail("warning: no RDRAND, using the kernel fallback RNG (NOT secure)");
    }
    info(&format!(
        "Handshake with {}:{} ({})...",
        ip_str(params.ip),
        params.port,
        if params.tcp { "uot" } else { "udp" }
    ));
    match ostp::connect(params) {
        Ok(us) => {
            info(&format!("Handshake complete (handshake {}); the session is kept alive in the background", fmt_us(us)));
            match ostp::ping() {
                Ok(us) => info(&format!("Tunnel ping ok, rtt {}", fmt_us(us))),
                Err(e) => fail(&format!("tunnel ping failed: {}", e)),
            }
        }
        Err(e) => fail(&e),
    }
}

fn status() {
    match ostp::status() {
        None => {
            if ostp::wanted() {
                io::out("ostp: reconnecting (or busy)\n");
            } else {
                io::out("ostp: not connected\n");
            }
        }
        Some(s) => {
            io::out(&format!("ostp: {} to {} via {}\n", s.state, s.server, s.transport));
            io::out(&format!("  uptime   {} s (last data from server {} ms ago)\n", s.uptime_ms / 1000, s.idle_ms));
            io::out(&format!("  tx       {} datagrams, {} bytes\n", s.tx_dgrams, s.tx_bytes));
            io::out(&format!("  rx       {} datagrams, {} bytes\n", s.rx_dgrams, s.rx_bytes));
            io::out(&format!("  window   {} packets, {} in flight\n", s.cwnd_packets, s.in_flight));
        }
    }
    for e in ostp::recent_events() {
        io::out(&format!("  event    {}\n", e));
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
