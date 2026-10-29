/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
VMware GuestRPC over the backdoor: the guest half of VMware Tools'
"resolutionSet", enough for autofit (the guest follows the window size).

The backdoor (port 0x5658, see vmmouse.rs) command 0x1E carries messages.
Every call has the message type in the high half of ECX:

  0 open (EBX = protocol | 0x80000000)  -> EDX high = channel, ESI/EDI = cookie
  1 send size (EBX = bytes)             2 send payload (EBX = next 4 bytes)
  3 receive size                        -> EBX = bytes, ECX high bit 1 = a message waits
  4 receive payload (EBX = 1 ack)       -> EBX = next 4 bytes
  5 receive status (EBX = 1 ack)        6 close

Two channels are used:
  RPCI ("RPCI")  guest -> host requests: "tools.capability.resolution_set 1"
  TCLO ("TCLO")  host -> guest requests: "Resolution_Set <w> <h>" (answer "OK ")

Outside VMware the port does not answer and everything here reports "absent".
*/
use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::x86_64::{serial, tsc};
use crate::core::sync::IrqSpinLock;

const MAGIC: u32 = 0x564D5868;
const PORT: u32 = 0x5658;
const CMD_MESSAGE: u32 = 30;

const T_OPEN: u32 = 0;
const T_SEND_SIZE: u32 = 1;
const T_SEND_PAYLOAD: u32 = 2;
const T_RECV_SIZE: u32 = 3;
const T_RECV_PAYLOAD: u32 = 4;
const T_RECV_STATUS: u32 = 5;
const T_CLOSE: u32 = 6;

const ST_SUCCESS: u32 = 0x0001;
const ST_DORECV: u32 = 0x0002;

const PROTO_RPCI: u32 = 0x4943_5052; // "RPCI"
const PROTO_TCLO: u32 = 0x4F4C_4354; // "TCLO"
const FLAG_COOKIE: u32 = 0x8000_0000;

const MAX_MSG: usize = 16 * 1024;

/// Poll period while the TCLO channel is open, µs.
const POLL_US: u64 = 100_000;
/// Retry period for opening the channel, µs.
const RETRY_US: u64 = 5_000_000;

#[derive(Clone, Copy)]
struct Chan {
    id: u32,
    cookie_hi: u32,
    cookie_lo: u32,
}

struct Regs { bx: u32, cx: u32, dx: u32, si: u32, di: u32 }

/// One backdoor call. `dx` carries the channel id in its high half.
#[inline(always)]
unsafe fn call(ty: u32, bx: u32, ch: &Chan) -> Regs {
    raw(bx, (ty << 16) | CMD_MESSAGE, (ch.id << 16) | PORT, ch.cookie_hi, ch.cookie_lo)
}

#[inline(always)]
unsafe fn raw(bx: u32, cx: u32, dx: u32, si: u32, di: u32) -> Regs {
    let mut eax: u32 = MAGIC;
    let mut ecx = cx;
    let mut edx = dx;
    let mut esi = si;
    let mut edi = di;
    let mut ebx = bx;
    core::arch::asm!(
        "push rbx",
        "mov ebx, {b:e}",
        "in eax, dx",
        "mov {b:e}, ebx",
        "pop rbx",
        b = inout(reg) ebx,
        inout("eax") eax,
        inout("ecx") ecx,
        inout("edx") edx,
        inout("esi") esi,
        inout("edi") edi,
        options(nomem),
    );
    let _ = eax;
    Regs { bx: ebx, cx: ecx, dx: edx, si: esi, di: edi }
}

#[inline(always)]
fn ok(r: &Regs) -> bool { (r.cx >> 16) & ST_SUCCESS != 0 }

fn open(proto: u32) -> Option<Chan> {
    let r = unsafe { raw(proto | FLAG_COOKIE, (T_OPEN << 16) | CMD_MESSAGE, PORT, 0, 0) };
    if !ok(&r) { return None; }
    Some(Chan { id: r.dx >> 16, cookie_hi: r.si, cookie_lo: r.di })
}

fn close(ch: &Chan) {
    unsafe { call(T_CLOSE, 0, ch); }
}

fn send(ch: &Chan, data: &[u8]) -> bool {
    unsafe {
        if !ok(&call(T_SEND_SIZE, data.len() as u32, ch)) { return false; }
        for chunk in data.chunks(4) {
            let mut w = [0u8; 4];
            w[..chunk.len()].copy_from_slice(chunk);
            if !ok(&call(T_SEND_PAYLOAD, u32::from_le_bytes(w), ch)) { return false; }
        }
    }
    true
}

/// Err = channel broken, Ok(None) = nothing waiting.
fn recv(ch: &Chan) -> Result<Option<Vec<u8>>, ()> {
    unsafe {
        let r = call(T_RECV_SIZE, 0, ch);
        if !ok(&r) { return Err(()); }
        if r.cx >> 16 & ST_DORECV == 0 { return Ok(None); }
        let len = r.bx as usize;
        if len > MAX_MSG { call(T_RECV_STATUS, 0, ch); return Err(()); }
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let p = call(T_RECV_PAYLOAD, ST_SUCCESS, ch);
            if !ok(&p) { return Err(()); }
            let bytes = p.bx.to_le_bytes();
            let take = (len - out.len()).min(4);
            out.extend_from_slice(&bytes[..take]);
        }
        call(T_RECV_STATUS, ST_SUCCESS, ch);
        Ok(Some(out))
    }
}

/// One request on a fresh RPCI channel; returns the reply text without the
/// leading "1 " / "0 " status, or None when it failed or was refused.
pub fn rpci(cmd: &str) -> Option<String> {
    let ch = open(PROTO_RPCI)?;
    let reply = if send(&ch, cmd.as_bytes()) { recv(&ch).ok().flatten() } else { None };
    close(&ch);
    let r = reply?;
    if r.len() >= 2 && r[0] == b'1' && r[1] == b' ' {
        Some(String::from_utf8_lossy(&r[2..]).into_owned())
    } else if r.first() == Some(&b'1') {
        Some(String::new())
    } else {
        None
    }
}

// ─── Capabilities ───────────────────────────────────────────────────────────

/// Tell the host what this guest can do. `resolution_set` is the one that
/// makes VMware send "Resolution_Set" when the window or full screen changes.
fn announce() -> (u32, u32) {
    const CAPS: [&str; 6] = [
        "tools.set.version 2147483647",
        "tools.capability.resolution_set 1",
        "tools.capability.resolution_server toolbox 1",
        "tools.capability.display_topology_set 1",
        "tools.capability.color_depth_set 1",
        "tools.capability.resolution_min 0 0",
    ];
    let (mut ok, mut bad) = (0, 0);
    for cmd in CAPS {
        serial::write_str("[DISPLAY] RPCI send: ");
        serial::write_str(cmd);
        match rpci(cmd) {
            Some(r) => { ok += 1; serial::write_str(" -> ok "); serial::write_str(&r); }
            None => { bad += 1; serial::write_str(" -> REFUSED or channel error"); }
        }
        serial::write_str("\r\n");
    }
    (ok, bad)
}

// ─── TCLO: requests from the host ───────────────────────────────────────────

struct Tclo {
    chan: Option<Chan>,
    must_send: bool,
    last: Vec<u8>,
    next_us: u64,
    failed_logged: bool,
    announce_again: bool,
    // diagnostics
    opens: u32,
    open_fails: u32,
    caps_ok: u32,
    caps_bad: u32,
    msgs: u32,
    resolutions: u32,
    last_msg: String,
    last_res: (u32, u32),
}

static TCLO: IrqSpinLock<Tclo> = IrqSpinLock::new("vmrpc", crate::core::sync::rank::DEV, Tclo {
    chan: None,
    must_send: false,
    last: Vec::new(),
    next_us: 0,
    failed_logged: false,
    announce_again: false,
    opens: 0,
    open_fails: 0,
    caps_ok: 0,
    caps_bad: 0,
    msgs: 0,
    resolutions: 0,
    last_msg: String::new(),
    last_res: (0, 0),
});

/// True when the VMware backdoor answers.
pub fn available() -> bool { super::vmclip::available() }

/// True while the host channel is open (the host can send us requests).
pub fn connected() -> bool { TCLO.lock().chan.is_some() }

fn dec(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 5 { return None; }
    let mut v = 0u32;
    for b in s.bytes() {
        if !b.is_ascii_digit() { return None; }
        v = v * 10 + (b - b'0') as u32;
    }
    Some(v)
}

/// Run the channel (rate-limited; cheap when idle). Returns a requested
/// resolution from the host. The caller applies it and calls `reply_failed`
/// if it could not; the "OK " answer is already queued.
pub fn poll() -> Option<(u32, u32)> {
    if !available() { return None; }
    let now = tsc::tsc_us();
    let mut t = TCLO.lock();
    if now < t.next_us { return None; }

    if t.chan.is_none() {
        match open(PROTO_TCLO) {
            Some(ch) => {
                serial::write_str("[DISPLAY] host channel open (autofit active)\r\n");
                t.chan = Some(ch);
                t.must_send = true;
                t.last.clear();
                t.announce_again = true;
                t.failed_logged = false;
                t.opens += 1;
            }
            None => {
                t.open_fails += 1;
                if !t.failed_logged {
                    serial::write_str("[DISPLAY] host channel unavailable (no VMware GuestRPC); autofit idle\r\n");
                    t.failed_logged = true;
                }
                t.next_us = now + RETRY_US * 6;
                return None;
            }
        }
    }
    let ch = t.chan.unwrap();

    if t.announce_again {
        t.announce_again = false;
        let (ok, bad) = announce();
        t.caps_ok += ok;
        t.caps_bad += bad;
    }
    if t.must_send {
        let last = core::mem::take(&mut t.last);
        t.must_send = false;
        if !send(&ch, &last) {
            close(&ch);
            t.chan = None;
            t.next_us = now + RETRY_US;
            serial::write_str("[DISPLAY] host channel lost (send)\r\n");
            return None;
        }
    }
    t.next_us = now + POLL_US;
    let msg = match recv(&ch) {
        Ok(Some(m)) => m,
        Ok(None) => return None,
        Err(()) => {
            close(&ch);
            t.chan = None;
            t.next_us = now + RETRY_US;
            serial::write_str("[DISPLAY] host channel lost (receive)\r\n");
            return None;
        }
    };
    t.next_us = now + 10_000; // more may follow: look again soon
    let text = String::from_utf8_lossy(&msg).into_owned();
    let text = text.trim_end_matches('\0').trim();
    let mut parts = text.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    t.msgs += 1;
    t.last_msg = String::from(text);
    serial::write_str("[DISPLAY] host says: ");
    serial::write_str(text);
    serial::write_str("\r\n");
    let mut resolution = None;
    let reply: &str = match cmd {
        "reset" => "OK ATR toolbox",
        "ping" | "Set_Option" | "ColorDepth_Set" => "OK ",
        "Capabilities_Register" => { t.announce_again = true; "OK " }
        "Resolution_Set" => {
            match (parts.next().and_then(dec), parts.next().and_then(dec)) {
                (Some(w), Some(h)) => { resolution = Some((w, h)); "OK " }
                _ => "ERROR Invalid arguments",
            }
        }
        "DisplayTopology_Set" => {
            // "DisplayTopology_Set <n> , x y w h , ..." : use the first rectangle.
            let nums: Vec<u32> = text[cmd.len()..].split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect();
            if nums.len() >= 5 { resolution = Some((nums[3], nums[4])); "OK " } else { "ERROR Invalid arguments" }
        }
        _ => "ERROR Unknown command",
    };
    if let Some(r) = resolution { t.resolutions += 1; t.last_res = r; }
    t.last = reply.as_bytes().to_vec();
    t.must_send = true;
    resolution
}

/// Make the next `poll` run at once (after `display auto`).
pub fn kick() { TCLO.lock().next_us = 0; }

/// Human-readable GuestRPC state for `display` / `display auto`.
pub fn status() -> String {
    use alloc::format;
    if !available() { return String::from("no VMware backdoor (not running under VMware)"); }
    let t = TCLO.lock();
    let mut s = format!("channel {}; opened {} time(s), open failed {}; capabilities accepted {}, refused {}; host messages {}",
        if t.chan.is_some() { "open" } else { "closed" }, t.opens, t.open_fails, t.caps_ok, t.caps_bad, t.msgs);
    if t.resolutions > 0 {
        s.push_str(&format!("; resolution requests {} (last {}x{})", t.resolutions, t.last_res.0, t.last_res.1));
    } else {
        s.push_str("; no resolution request received yet");
    }
    if !t.last_msg.is_empty() { s.push_str(&format!("; last host message: {}", t.last_msg)); }
    s
}

/// The host's last request could not be done.
pub fn reply_failed() {
    let mut t = TCLO.lock();
    t.last = b"ERROR Unable to set resolution".to_vec();
    t.must_send = true;
}
