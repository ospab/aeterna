/*
 * OSTP — native client for the stealth tunnel protocol (https://github.com/ospab/ostp)
 *
 * The protocol itself is `ostp-core` (sans-IO, no_std + alloc). This module is
 * the glue the kernel provides:
 *
 *   - platform hooks for ostp-core: monotonic clock, wall clock, RDRAND entropy;
 *   - transport: OSTP's UDP mode over the kernel's UDP/IPv4 stack. Datagrams for
 *     our local port are queued by `net::udp` (see `wants` / `on_udp`);
 *   - a synchronous driver: every operation polls the NIC, feeds datagrams to the
 *     `ProtocolMachine`, ticks its timers and sends what it emits. There is no
 *     background task, so the session only makes progress while a command runs.
 *
 * Operations on the established tunnel: ping (relay Ping/Pong), UDP relay
 * (`dns`), TCP relay (`get`).
 */

extern crate alloc;

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

// ─── Transport: datagrams queued by net::udp ─────────────────────────────────

static LOCAL_PORT: AtomicU16 = AtomicU16::new(0);
static RXQ: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

/// `net::udp` asks this for every incoming datagram: is it ours?
pub fn wants(dst_port: u16) -> bool {
    let p = LOCAL_PORT.load(Ordering::Relaxed);
    p != 0 && p == dst_port
}

/// Called by `net::udp` with the UDP payload of a datagram for our port.
pub fn on_udp(payload: &[u8]) {
    let mut q = RXQ.lock();
    if q.len() < MAX_QUEUED {
        q.push_back(payload.to_vec());
    }
}

// ─── Tunnel state ────────────────────────────────────────────────────────────

struct Tunnel {
    machine: ProtocolMachine,
    server_ip: [u8; 4],
    server_port: u16,
    local_port: u16,
    started_ns: u64,
    last_tick_ns: u64,
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
    pub state: &'static str,
    pub uptime_ms: u64,
    pub tx_dgrams: u64,
    pub rx_dgrams: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub in_flight: usize,
    pub cwnd_packets: usize,
}

fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

pub fn is_connected() -> bool {
    matches!(TUNNEL.lock().as_ref(), Some(t) if t.machine.state() == OstpState::Established)
}

pub fn status() -> Option<Status> {
    let g = TUNNEL.lock();
    let t = g.as_ref()?;
    let state = match t.machine.state() {
        OstpState::Init => "init",
        OstpState::Handshaking => "handshaking",
        OstpState::Established => "established",
        OstpState::Closing => "closing",
        OstpState::Closed => "closed",
    };
    Some(Status {
        server: format!("{}:{}", fmt_ip(t.server_ip), t.server_port),
        state,
        uptime_ms: crate::time::monotonic_ns().saturating_sub(t.started_ns) / 1_000_000,
        tx_dgrams: t.tx_dgrams,
        rx_dgrams: t.rx_dgrams,
        tx_bytes: t.tx_bytes,
        rx_bytes: t.rx_bytes,
        in_flight: t.machine.in_flight_count(),
        cwnd_packets: t.machine.cwnd_packets(),
    })
}

impl Tunnel {
    fn send(&mut self, frame: &[u8]) {
        self.tx_dgrams += 1;
        self.tx_bytes += frame.len() as u64;
        crate::net::udp::send_udp(self.server_ip, self.local_port, self.server_port, frame);
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

    /// Feed queued datagrams to the machine and run its timers.
    fn pump(&mut self) {
        loop {
            let d = RXQ.lock().pop_front();
            let Some(d) = d else { break };
            self.rx_dgrams += 1;
            self.rx_bytes += d.len() as u64;
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
}

// ─── Public operations ───────────────────────────────────────────────────────

/// Open a session: UDP handshake, then one relay ping to prove the tunnel.
/// Returns the handshake round-trip time in microseconds.
pub fn connect(server_ip: [u8; 4], server_port: u16, access_key: &str) -> Result<u64, String> {
    if !crate::net::is_up() {
        return Err("network is down".to_string());
    }
    if !rng::usable() {
        return Err("this CPU has no RDRAND (QEMU: use -cpu max); pass --weak-rng to use the kernel's fallback RNG".to_string());
    }
    ensure_hooks();
    close();
    RXQ.lock().clear();

    let key = access_key.as_bytes();
    let secrets = derive_all_secrets(key);
    let session_id = rng::u32();
    let local_port = 49152 + (rng::u32() % 16000) as u16;
    LOCAL_PORT.store(local_port, Ordering::Relaxed);

    // Handshake payload: unix seconds | session id | access key (see ostp-client).
    let mut hp = Vec::with_capacity(12 + key.len());
    hp.extend_from_slice(&sys::unix_secs().to_be_bytes());
    hp.extend_from_slice(&session_id.to_be_bytes());
    hp.extend_from_slice(key);

    let machine = ProtocolMachine::new(ProtocolConfig {
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

    let now = crate::time::monotonic_ns();
    let mut t = Tunnel {
        machine,
        server_ip,
        server_port,
        local_port,
        started_ns: now,
        last_tick_ns: now,
        tx_dgrams: 0,
        rx_dgrams: 0,
        tx_bytes: 0,
        rx_bytes: 0,
        app_q: VecDeque::new(),
    };

    // ARP-warm the path so the first datagram is not lost to resolution.
    let (our, mask, gw) = unsafe { (crate::net::OUR_IP, crate::net::SUBNET_MASK, crate::net::GATEWAY_IP) };
    let on_link = (0..4).all(|i| server_ip[i] & mask[i] == our[i] & mask[i]);
    let nh = if on_link { server_ip } else { gw };
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

    let frame = match t.machine.on_event(OstpEvent::Start).map_err(|e| e.to_string())? {
        ProtocolAction::SendDatagram(f) => f,
        _ => return Err("protocol did not emit a handshake datagram".to_string()),
    };

    let start = crate::time::monotonic_ns();
    let mut established = false;
    'attempts: for _ in 0..6 {
        t.send(&frame);
        let end = crate::time::monotonic_ns() + 800_000_000;
        while crate::time::monotonic_ns() < end {
            if crate::arch::x86_64::keyboard::interrupt_pending() {
                LOCAL_PORT.store(0, Ordering::Relaxed);
                return Err("interrupted".to_string());
            }
            crate::net::poll_rx();
            let d = RXQ.lock().pop_front();
            if let Some(d) = d {
                t.rx_dgrams += 1;
                t.rx_bytes += d.len() as u64;
                if t.machine.on_event(OstpEvent::Inbound(Bytes::from(d))).is_ok()
                    && t.machine.state() == OstpState::Established
                {
                    established = true;
                    break 'attempts;
                }
            }
            crate::core::scheduler::sys_yield();
        }
    }
    if !established {
        LOCAL_PORT.store(0, Ordering::Relaxed);
        return Err("handshake failed: no valid reply from the server (wrong key, clock skew, or unreachable)".to_string());
    }
    let hs_us = crate::time::monotonic_ns().saturating_sub(start) / 1000;
    t.last_tick_ns = crate::time::monotonic_ns();
    *TUNNEL.lock() = Some(t);
    Ok(hs_us)
}

pub fn close() {
    if let Some(mut t) = TUNNEL.lock().take() {
        let _ = t.event(OstpEvent::Close);
    }
    LOCAL_PORT.store(0, Ordering::Relaxed);
    RXQ.lock().clear();
}

fn with_tunnel<T>(f: impl FnOnce(&mut Tunnel) -> Result<T, String>) -> Result<T, String> {
    let mut g = TUNNEL.lock();
    let t = g.as_mut().ok_or_else(|| "not connected (ostp connect ...)".to_string())?;
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
        let res = t.wait(STREAM_UDP, 4000, |m| match m {
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
