/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

plum/account — user names, /etc/passwd, the login prompt.

There is no root and no permission model yet: an account is a name, a home directory and an
optional password that gates the console login. Every in-kernel command still runs with full
rights. Real separation comes with the capability system of stage 3 (seed, powerbox).

/etc/passwd, one account per line, written by the installer:

    name:hash:uid:home:shell
    anna:sha256$<16-byte salt, hex>$<32-byte hash, hex>:1000:/home/anna:/bin/plum
    bob::1001:/home/bob:/bin/plum            (empty hash = no password)

The hash is SHA-256 over `salt || password`, then ROUNDS more rounds of
`SHA-256(previous hash || salt || password)`. The salt comes from RDRAND, or from TSC jitter
where the CPU has no RDRAND (`random_bytes`).

/etc/login.conf:

    autologin = yes|no       # yes: log in `user` without asking
    user = anna              # account used by autologin (default: the first one)

The live system (cmdline `mode=live` / `mode=installer`) always runs as `live`, with no prompt.
A disk without /etc/passwd also runs as `live`.
*/

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::x86_64::{framebuffer, keyboard};
use super::io;

pub const PASSWD_FILE: &str = "/etc/passwd";
pub const LOGIN_CONF: &str = "/etc/login.conf";
pub const LIVE_USER: &str = "live";
pub const SCHEME: &str = "sha256";
pub const ROUNDS: u32 = 4096;
pub const FIRST_UID: u32 = 1000;
pub const SHELL_PATH: &str = "/bin/plum";

#[derive(Clone)]
pub struct Account {
    pub name: String,
    /// `sha256$salt$hash`, or empty for "no password".
    pub hash: String,
    pub uid: u32,
    pub home: String,
    pub shell: String,
}

static mut CURRENT: Option<String> = None;

/// The user the shell runs as.
pub fn current_user() -> &'static str {
    unsafe {
        let cur = &*core::ptr::addr_of!(CURRENT);
        match cur { Some(s) => s.as_str(), None => LIVE_USER }
    }
}

/// 1..=32 characters: a lowercase letter first, then lowercase letters, digits, `_` and `-`.
/// `root` is refused: there is no all-powerful user in ospab.os.
pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    if b.is_empty() || b.len() > 32 || n == "root" { return false; }
    if !b[0].is_ascii_lowercase() { return false; }
    b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

// ─── Randomness for salts ────────────────────────────────────────────────────

static mut POOL: [u64; 4] = [0x243F_6A88_85A3_08D3, 0x1319_8A2E_0370_7344, 0xA409_3822_299F_31D0, 0x082E_FA98_EC4E_6C89];

fn rdtsc() -> u64 { unsafe { core::arch::x86_64::_rdtsc() } }

/// Mix a value (a timestamp, a key press time) into the entropy pool.
pub fn entropy_note(v: u64) {
    unsafe {
        let p = &mut *core::ptr::addr_of_mut!(POOL);
        let i = (v ^ rdtsc()) as usize & 3;
        p[i] = (p[i] ^ v ^ rdtsc()).rotate_left(23).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

#[target_feature(enable = "rdrand")]
unsafe fn rdrand64() -> Option<u64> {
    for _ in 0..10 {
        let mut v = 0u64;
        if core::arch::x86_64::_rdrand64_step(&mut v) == 1 { return Some(v); }
    }
    None
}

fn has_rdrand() -> bool {
    unsafe { core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0 }
}

/// Fill `out` with random bytes: RDRAND where the CPU has it, otherwise SHA-256 over the
/// entropy pool, TSC readings spread over a busy loop, and the PIT tick counter.
pub fn random_bytes(out: &mut [u8]) {
    let mut n = 0usize;
    if has_rdrand() {
        while n < out.len() {
            match unsafe { rdrand64() } {
                Some(v) => {
                    for b in v.to_le_bytes() { if n < out.len() { out[n] = b; n += 1; } }
                }
                None => break,
            }
        }
        if n == out.len() { return; }
    }
    let mut seed: Vec<u8> = Vec::new();
    for round in 0..64u64 {
        // Interrupt and memory timing jitter between readings
        for _ in 0..(200 + (rdtsc() & 0x3FF)) { unsafe { core::arch::asm!("pause"); } }
        entropy_note(round);
        seed.extend_from_slice(&rdtsc().to_le_bytes());
    }
    seed.extend_from_slice(&crate::arch::x86_64::idt::timer_ticks().to_le_bytes());
    unsafe {
        let p = &*core::ptr::addr_of!(POOL);
        for w in p { seed.extend_from_slice(&w.to_le_bytes()); }
    }
    let mut block = crate::userspace::tomato::sha256_hash(&seed);
    while n < out.len() {
        for &b in block.iter() { if n < out.len() { out[n] = b; n += 1; } }
        let mut next = block.to_vec();
        next.extend_from_slice(&seed);
        block = crate::userspace::tomato::sha256_hash(&next);
    }
}

// ─── Password hashing ────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b { s.push(H[(x >> 4) as usize] as char); s.push(H[(x & 15) as usize] as char); }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    let v = |c: u8| -> Option<u8> {
        match c { b'0'..=b'9' => Some(c - b'0'), b'a'..=b'f' => Some(c - b'a' + 10), _ => None }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) { out.push(v(b[i])? << 4 | v(b[i + 1])?); }
    Some(out)
}

pub fn hash_password(salt: &[u8], password: &[u8]) -> [u8; 32] {
    let sha = crate::userspace::tomato::sha256_hash;
    let mut buf: Vec<u8> = Vec::with_capacity(salt.len() + password.len());
    buf.extend_from_slice(salt);
    buf.extend_from_slice(password);
    let mut h = sha(&buf);
    for _ in 0..ROUNDS {
        let mut b: Vec<u8> = Vec::with_capacity(32 + buf.len());
        b.extend_from_slice(&h);
        b.extend_from_slice(&buf);
        h = sha(&b);
    }
    h
}

/// The `hash` field for a new password: `sha256$<salt>$<hash>`. An empty password gives an
/// empty field ("no password").
pub fn make_hash_field(password: &str, salt: &[u8; 16]) -> String {
    if password.is_empty() { return String::new(); }
    format!("{}${}${}", SCHEME, hex(salt), hex(&hash_password(salt, password.as_bytes())))
}

/// Check a password against a `hash` field. An empty field accepts only the empty password.
pub fn verify(field: &str, password: &str) -> bool {
    if field.is_empty() { return password.is_empty(); }
    let mut it = field.split('$');
    if it.next() != Some(SCHEME) { return false; }
    let (salt, want) = match (it.next().and_then(unhex), it.next().and_then(unhex), it.next()) {
        (Some(s), Some(h), None) if h.len() == 32 && !s.is_empty() => (s, h),
        _ => return false,
    };
    let got = hash_password(&salt, password.as_bytes());
    let mut diff = 0u8;
    for i in 0..32 { diff |= got[i] ^ want[i]; }
    diff == 0
}

// ─── /etc/passwd and /etc/login.conf ─────────────────────────────────────────

pub fn passwd_line(a: &Account) -> String {
    format!("{}:{}:{}:{}:{}\n", a.name, a.hash, a.uid, a.home, a.shell)
}

pub fn parse_passwd(text: &str) -> Vec<Account> {
    let mut v = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 5 || !valid_name(f[0]) { continue; }
        v.push(Account {
            name: String::from(f[0]),
            hash: String::from(f[1]),
            uid: f[2].parse().unwrap_or(FIRST_UID),
            home: String::from(f[3]),
            shell: String::from(f[4]),
        });
    }
    v
}

pub fn users() -> Vec<Account> {
    match crate::fs::read_file(PASSWD_FILE) {
        Some(d) => parse_passwd(core::str::from_utf8(&d).unwrap_or("")),
        None => Vec::new(),
    }
}

/// (autologin on, account name for it)
fn login_conf() -> (bool, Option<String>) {
    let mut auto = false;
    let mut user = None;
    if let Some(d) = crate::fs::read_file(LOGIN_CONF) {
        for line in core::str::from_utf8(&d).unwrap_or("").lines() {
            let line = line.trim();
            if line.starts_with('#') { continue; }
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "autologin" => auto = matches!(v.trim(), "yes" | "on" | "true" | "1"),
                    "user" => user = Some(String::from(v.trim())),
                    _ => {}
                }
            }
        }
    }
    (auto, user)
}

// ─── Becoming a user ─────────────────────────────────────────────────────────

/// Make `name` the current user: USER, LOGNAME and HOME in the shell environment, and the home
/// directory if it is missing.
pub fn set_user(name: &str) {
    let home = format!("/home/{}", name);
    unsafe { *core::ptr::addr_of_mut!(CURRENT) = Some(String::from(name)); }
    super::setenv("USER", name);
    super::setenv("LOGNAME", name);
    super::setenv("HOME", &home);
    super::setenv("PS1", "\\u@\\h:\\w$ ");
    if !crate::fs::exists(&home) {
        crate::fs::mkdir(&home);
    }
    if crate::fs::exists(&home) {
        super::setenv("PWD", &home);
    }
}

// ─── Console login ───────────────────────────────────────────────────────────

fn out(s: &str) { framebuffer::draw_string(s, io::FG, io::BG); }

/// Read a line from the keyboard with echo (`mask == None`) or `*` per character.
fn read_line(mask: bool) -> String {
    let mut s = String::new();
    let cw = framebuffer::cell_w();
    loop {
        match keyboard::try_read_key() {
            None => unsafe { core::arch::asm!("hlt"); },
            Some(c) => {
                entropy_note(rdtsc());
                match c {
                    '\n' => { out("\n"); return s; }
                    '\x08' => {
                        if s.pop().is_some() {
                            let (x, y) = framebuffer::cursor_pos();
                            if x >= cw {
                                framebuffer::set_cursor_pos(x - cw, y);
                                framebuffer::draw_char(' ', io::FG, io::BG);
                                framebuffer::set_cursor_pos(x - cw, y);
                            }
                        }
                    }
                    c if (c as u32) >= 32 && (c as u32) < 127 && s.len() < 64 => {
                        s.push(c);
                        framebuffer::draw_char(if mask { '*' } else { c }, io::FG, io::BG);
                    }
                    _ => {}
                }
            }
        }
    }
}

fn pause_secs(secs: u64) {
    let t0 = crate::arch::x86_64::idt::timer_ticks();
    while crate::arch::x86_64::idt::timer_ticks().wrapping_sub(t0) < secs * 100 {
        unsafe { core::arch::asm!("hlt"); }
    }
}

/// Decide who uses the console. Live system or no accounts: `live`. Otherwise autologin, or ask
/// for a name and password until they match.
pub fn login_console() {
    let mode = crate::arch::x86_64::boot::cmdline_get("mode");
    let list = users();
    if mode == "live" || mode == "installer" || list.is_empty() {
        set_user(LIVE_USER);
        return;
    }
    let (auto, auto_user) = login_conf();
    if auto {
        let pick = auto_user.as_deref()
            .and_then(|n| list.iter().find(|a| a.name == n))
            .or_else(|| list.first());
        if let Some(a) = pick {
            set_user(&a.name);
            return;
        }
    }
    out("\n");
    loop {
        out("login: ");
        let name = read_line(false);
        let name = name.trim();
        if name.is_empty() { continue; }
        out("password: ");
        let pw = read_line(true);
        // The same work for an unknown name, so that a wrong name takes as long as a wrong password.
        let acct = list.iter().find(|a| a.name == name);
        let ok = match acct {
            Some(a) => verify(&a.hash, &pw),
            None => { let _ = hash_password(b"unknown-user", pw.as_bytes()); false }
        };
        if ok {
            set_user(name);
            out("\n");
            return;
        }
        framebuffer::draw_string("Login incorrect\n\n", io::FG_ERR, io::BG);
        pause_secs(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn names() {
        assert!(valid_name("anna"));
        assert!(valid_name("a1_b-c"));
        assert!(!valid_name("root"));
        assert!(!valid_name(""));
        assert!(!valid_name("Anna"));
        assert!(!valid_name("1abc"));
        assert!(!valid_name("a b"));
        assert!(!valid_name("abcdefghijklmnopqrstuvwxyzabcdefg"));
    }
    #[test] fn passwd_parse() {
        let v = parse_passwd("# c\nanna:sha256$00$11:1000:/home/anna:/bin/plum\nbob::1001:/home/bob:/bin/plum\nbad line\n");
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].name, "bob");
        assert_eq!(v[1].hash, "");
        assert_eq!(v[0].uid, 1000);
    }
    #[test] fn empty_password() {
        assert!(verify("", ""));
        assert!(!verify("", "x"));
        assert!(!verify("sha256$zz$00", "x"));
    }
}
