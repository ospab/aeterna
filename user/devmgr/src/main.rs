// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! devmgr: the device manager, and `devctl`, its command line (same program, chosen by
//! argv[0]).
//!
//! devmgr is started by the kernel at boot with one bootstrap handle: a Resource of kind
//! PCI (list PCI functions, claim one). It
//!   * reads the driver packages in /usr/lib/drivers/<name>/driver.conf,
//!   * matches them against the PCI functions,
//!   * claims the function (taking it from an in-kernel driver when asked to),
//!   * starts the driver executable with the device handle (1) and a ready channel (2),
//!   * restarts a driver that exits, with growing delays.
//!
//! State for devctl is in files: devmgr writes /run/devmgr.status, devctl appends commands
//! to /run/devmgr.cmd.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use liboos::ipc::{Channel, Error, Handle, Process, Rights};
use liboos::println;
use libdriver::{log, sys, PciInfo, MSG_FAILED, MSG_READY};

liboos::entry!(main);

const DRIVER_DIR: &str = "/usr/lib/drivers";
const STATUS: &str = "/run/devmgr.status";
const CMD: &str = "/run/devmgr.cmd";
/// Ticks (100 Hz) between rescans of the driver directory and the PCI bus.
const RESCAN: u64 = 100;
const BACKOFF_MIN: u64 = 100;
const BACKOFF_MAX: u64 = 3000;
/// A driver that ran this long counts as healthy: the delay starts over.
const HEALTHY: u64 = 1500;

fn main(args: liboos::Args) -> i32 {
    let me = args.get(0).unwrap_or("devmgr");
    let name = me.rsplit('/').next().unwrap_or(me);
    if name.starts_with("devctl") || args.get(1) == Some("ctl") {
        let skip = if args.get(1) == Some("ctl") { 2 } else { 1 };
        let rest: Vec<&str> = args.iter().skip(skip).collect();
        return devctl(&rest);
    }
    libdriver::log_init("devmgr");
    daemon()
}

// ─── Files ───────────────────────────────────────────────────────────────────────

fn read_file(path: &str) -> Option<Vec<u8>> {
    let fd = liboos::open(path, liboos::O_READ);
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = liboos::read(fd as u64, &mut buf);
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    liboos::close(fd as u64);
    Some(out)
}

fn write_file(path: &str, data: &[u8], append: bool) -> bool {
    let flags = if append { liboos::O_WRITE | liboos::O_APPEND } else { liboos::O_WRITE };
    let fd = liboos::open(path, flags);
    if fd < 0 {
        return false;
    }
    let ok = data.is_empty() || liboos::write(fd as u64, data) >= 0;
    liboos::close(fd as u64);
    ok
}

fn list_dir(path: &str) -> Vec<String> {
    let mut buf = alloc::vec![0u8; 4096];
    let n = unsafe { sys::syscall4(sys::FS_READDIR, path.as_ptr() as u64, path.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64) };
    if n <= 0 {
        return Vec::new();
    }
    String::from_utf8_lossy(&buf[..n as usize]).lines().map(|l| l.to_string()).collect()
}

// ─── Driver packages ─────────────────────────────────────────────────────────────

/// One installed driver (a parsed driver.conf).
#[derive(Clone)]
struct Conf {
    name: String,
    exec: String,
    matches: Vec<Match>,
}

#[derive(Clone, Copy)]
enum Match {
    /// pci:VVVV:DDDD
    Id(u16, u16),
    /// pci-class:CC:SS
    Class(u8, u8),
}

fn parse_hex(s: &str) -> Option<u32> {
    u32::from_str_radix(s.trim(), 16).ok()
}

fn parse_match(t: &str) -> Option<Match> {
    let mut it = t.trim().split(':');
    match it.next()? {
        "pci" => Some(Match::Id(parse_hex(it.next()?)? as u16, parse_hex(it.next()?)? as u16)),
        "pci-class" => Some(Match::Class(parse_hex(it.next()?)? as u8, parse_hex(it.next()?)? as u8)),
        _ => None,
    }
}

fn parse_conf(text: &str) -> Option<Conf> {
    let mut c = Conf { name: String::new(), exec: String::new(), matches: Vec::new() };
    for line in text.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "name" => c.name = v.trim().to_string(),
                "exec" => c.exec = v.trim().to_string(),
                "match" => c.matches.extend(v.split(',').filter_map(parse_match)),
                _ => {}
            }
        }
    }
    if c.name.is_empty() || c.exec.is_empty() || c.matches.is_empty() { None } else { Some(c) }
}

fn load_confs() -> Vec<Conf> {
    let mut v = Vec::new();
    for d in list_dir(DRIVER_DIR) {
        let d = d.trim_end_matches('/');
        if d.is_empty() {
            continue;
        }
        if let Some(t) = read_file(&format!("{}/{}/driver.conf", DRIVER_DIR, d)) {
            if let Some(c) = parse_conf(&String::from_utf8_lossy(&t)) {
                v.push(c);
            }
        }
    }
    v
}

fn matches(c: &Conf, p: &PciInfo) -> bool {
    c.matches.iter().any(|m| match *m {
        Match::Id(v, d) => p.vendor == v && p.device == d,
        Match::Class(cl, sc) => p.class == cl && p.subclass == sc,
    })
}

// ─── PCI ─────────────────────────────────────────────────────────────────────────

fn enumerate(res: u32) -> Vec<PciInfo> {
    let mut v = Vec::new();
    for i in 0..256u64 {
        let mut info = PciInfo::zeroed();
        let r = unsafe { sys::syscall3(sys::PCI_ENUM, res as u64, i, &mut info as *mut _ as u64) };
        if r < 0 {
            break;
        }
        v.push(info);
    }
    v
}

fn bdf_str(b: u16) -> String {
    format!("{:02x}:{:02x}.{}", b >> 8, (b >> 3) & 0x1F, b & 7)
}

// ─── Running drivers ─────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum State {
    Starting,
    Running,
    /// Exited; restart at the given tick.
    Backoff(u64),
    /// Stopped by `devctl stop`.
    Stopped,
    /// Could not be started (claim or spawn failed).
    Failed,
}

struct Inst {
    conf: Conf,
    info: PciInfo,
    dev: Option<Handle>,
    proc: Option<Process>,
    ready: Option<Channel>,
    pid: u64,
    state: State,
    restarts: u32,
    started: u64,
    delay: u64,
    status: String,
}

impl Inst {
    fn state_name(&self) -> &'static str {
        match self.state {
            State::Starting => "starting",
            State::Running => "running",
            State::Backoff(_) => "restart-wait",
            State::Stopped => "stopped",
            State::Failed => "failed",
        }
    }
}

#[repr(C)]
struct SpawnReq {
    path_ptr: u64,
    path_len: u64,
    args_ptr: u64,
    args_len: u64,
    nhandles: u64,
    handles: [u64; 4],
    pid: u64,
}

fn spawn(path: &str, args: &[&str], handles: &[u32]) -> Result<(Process, u64), Error> {
    let mut blob: Vec<u8> = Vec::new();
    for a in args {
        blob.extend_from_slice(a.as_bytes());
        blob.push(0);
    }
    let mut req = SpawnReq {
        path_ptr: path.as_ptr() as u64,
        path_len: path.len() as u64,
        args_ptr: blob.as_ptr() as u64,
        args_len: blob.len() as u64,
        nhandles: handles.len() as u64,
        handles: [0; 4],
        pid: 0,
    };
    for (i, h) in handles.iter().enumerate() {
        req.handles[i] = *h as u64;
    }
    let r = unsafe { sys::syscall1(sys::PROC_SPAWN, &mut req as *mut _ as u64) };
    if r < 0 {
        return Err(libdriver::err(r));
    }
    Ok((Process(Handle::from_raw(r as u32)), req.pid))
}

fn now() -> u64 {
    liboos::uptime_ticks()
}

/// Claim the device (once) and start the driver process.
fn start(res: u32, i: &mut Inst) {
    if i.dev.is_none() {
        let flags = if i.info.owner == 1 { 1 } else { 0 };
        let r = unsafe { sys::syscall3(sys::PCI_CLAIM, res as u64, i.info.bdf as u64, flags) };
        if r < 0 {
            log!("{}: cannot claim {}: error {}", i.conf.name, bdf_str(i.info.bdf), r);
            i.state = State::Failed;
            return;
        }
        i.dev = Some(Handle::from_raw(r as u32));
    }
    let dev = i.dev.as_ref().unwrap();
    let ch = match Channel::create() {
        Ok(c) => c,
        Err(_) => {
            i.state = State::Failed;
            return;
        }
    };
    let dev_dup = dev.duplicate(Rights::READ | Rights::WRITE | Rights::TRANSFER);
    let ready_dup = ch.duplicate(Rights::WRITE | Rights::TRANSFER);
    let (dev_dup, ready_dup) = match (dev_dup, ready_dup) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            i.state = State::Failed;
            return;
        }
    };
    let args = [i.conf.name.as_str()];
    match spawn(&i.conf.exec, &args, &[dev_dup.raw(), ready_dup.0.raw()]) {
        Ok((p, pid)) => {
            log!("{}: started {} (pid {}) for {} {:04x}:{:04x}", i.conf.name, i.conf.exec, pid, bdf_str(i.info.bdf), i.info.vendor, i.info.device);
            i.proc = Some(p);
            i.pid = pid;
            i.ready = Some(ch);
            i.started = now();
            i.state = State::Starting;
        }
        Err(e) => {
            log!("{}: cannot start {}: {:?}", i.conf.name, i.conf.exec, e);
            i.state = State::Failed;
        }
    }
    // dev_dup and ready_dup are closed here: the child has its own references.
}

fn kill(i: &mut Inst) {
    if let Some(p) = i.proc.take() {
        let _ = p.kill();
        let _ = p.wait(20);
    }
    i.ready = None;
}

/// Check one instance: ready message, exit.
fn poll_inst(i: &mut Inst) {
    if let Some(ch) = &i.ready {
        while let Ok((m, _)) = ch.recv(1) {
            let text = String::from_utf8_lossy(m.data()).to_string();
            if m.tag == MSG_READY {
                log!("{}: ready ({})", i.conf.name, text);
                i.state = State::Running;
                i.status = text;
            } else if m.tag == MSG_FAILED {
                log!("{}: reports failure: {}", i.conf.name, text);
                i.status = text;
            }
        }
    }
    let exited = match &i.proc {
        Some(p) => match p.wait(1) {
            Ok(code) => Some(code),
            Err(Error::Timeout) => None,
            Err(_) => Some(-1),
        },
        None => None,
    };
    if let Some(code) = exited {
        let ran = now().saturating_sub(i.started);
        i.proc = None;
        i.ready = None;
        if ran >= HEALTHY {
            i.delay = BACKOFF_MIN;
        } else {
            i.delay = (i.delay * 2).clamp(BACKOFF_MIN, BACKOFF_MAX);
        }
        i.restarts += 1;
        log!("{}: exited with code {} after {} ticks; restart in {} ticks", i.conf.name, code, ran, i.delay);
        i.state = State::Backoff(now() + i.delay);
    }
}

// ─── The daemon ──────────────────────────────────────────────────────────────────

fn daemon() -> i32 {
    let res = 1u32;
    let probe = Handle::from_raw(res);
    let ok = probe.info().is_ok();
    let _ = probe.into_raw(); // never close the bootstrap handle
    if !ok {
        println!("devmgr: started without the PCI resource (bootstrap handle 1); the kernel starts it");
        return 1;
    }
    log!("device manager started");
    let mut insts: Vec<Inst> = Vec::new();
    let mut pci: Vec<PciInfo> = Vec::new();
    let mut last_scan = 0u64;
    let mut scanned = false;
    let mut dirty = true;
    let mut conf_names: Vec<String> = Vec::new();

    loop {
        let t = now();
        // Commands from devctl.
        if let Some(cmd) = read_file(CMD) {
            if !cmd.is_empty() {
                write_file(CMD, b"", false);
                for line in String::from_utf8_lossy(&cmd).lines() {
                    dirty = true;
                    let mut w = line.split_whitespace();
                    let (verb, target) = (w.next().unwrap_or(""), w.next().unwrap_or(""));
                    for i in insts.iter_mut().filter(|i| i.conf.name == target) {
                        match verb {
                            "stop" => {
                                kill(i);
                                i.state = State::Stopped;
                                log!("{}: stopped by devctl", i.conf.name);
                            }
                            "start" => {
                                if i.proc.is_none() {
                                    i.delay = BACKOFF_MIN;
                                    start(res, i);
                                }
                            }
                            "restart" => {
                                kill(i);
                                i.delay = BACKOFF_MIN;
                                start(res, i);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Rescan packages and PCI bus.
        if !scanned || t.saturating_sub(last_scan) >= RESCAN {
            scanned = true;
            last_scan = t;
            let confs = load_confs();
            let names: Vec<String> = confs.iter().map(|c| c.name.clone()).collect();
            if names != conf_names {
                conf_names = names;
                dirty = true;
            }
            pci = enumerate(res);
            for c in &confs {
                for p in &pci {
                    if p.owner == 2 && !insts.iter().any(|i| i.info.bdf == p.bdf) {
                        continue; // claimed by someone else (another devmgr run)
                    }
                    if matches(c, p) && !insts.iter().any(|i| i.info.bdf == p.bdf) {
                        log!("{}: matches {} {:04x}:{:04x}", c.name, bdf_str(p.bdf), p.vendor, p.device);
                        let mut inst = Inst {
                            conf: c.clone(),
                            info: *p,
                            dev: None,
                            proc: None,
                            ready: None,
                            pid: 0,
                            state: State::Starting,
                            restarts: 0,
                            started: 0,
                            delay: BACKOFF_MIN,
                            status: String::new(),
                        };
                        start(res, &mut inst);
                        insts.push(inst);
                        dirty = true;
                    }
                }
            }
        }

        // Watch the drivers.
        for i in insts.iter_mut() {
            let before = (i.state, i.pid);
            match i.state {
                State::Starting | State::Running => poll_inst(i),
                State::Backoff(at) if now() >= at => start(res, i),
                _ => {}
            }
            if before != (i.state, i.pid) {
                dirty = true;
            }
        }
        if insts.iter().all(|i| matches!(i.state, State::Stopped | State::Failed | State::Backoff(_))) {
            unsafe { sys::syscall1(21, 50) }; // sleep_ms: nothing to watch
        }

        if dirty || t % 100 == 0 {
            dirty = false;
            write_status(&pci, &insts);
        }
    }
}

fn write_status(pci: &[PciInfo], insts: &[Inst]) {
    let mut s = String::new();
    s.push_str("DEVICE   ID         CLASS  OWNER   DRIVER        STATE         PID  RESTARTS\n");
    for p in pci {
        // Bridges and host controllers are noise.
        if p.class == 0x06 {
            continue;
        }
        let inst = insts.iter().find(|i| i.info.bdf == p.bdf);
        let owner = match p.owner {
            1 => "kernel",
            2 => "ring3",
            _ => "free",
        };
        let (drv, st, pid, rs) = match inst {
            Some(i) => (i.conf.name.as_str(), i.state_name(), i.pid, i.restarts),
            None => ("-", "-", 0, 0),
        };
        s.push_str(&format!(
            "{}  {:04x}:{:04x}  {:02x}:{:02x}  {:<6}  {:<12}  {:<12}  {:<3}  {}\n",
            bdf_str(p.bdf), p.vendor, p.device, p.class, p.subclass, owner, drv, st, pid, rs
        ));
    }
    write_file(STATUS, s.as_bytes(), false);
}

// ─── devctl ──────────────────────────────────────────────────────────────────────

fn devctl(args: &[&str]) -> i32 {
    match args.first().copied() {
        None | Some("list") => match read_file(STATUS) {
            Some(t) => {
                liboos::print!("{}", String::from_utf8_lossy(&t));
                0
            }
            None => {
                println!("devctl: devmgr is not running (no {})", STATUS);
                1
            }
        },
        Some(v @ ("start" | "stop" | "restart")) => {
            let name = match args.get(1) {
                Some(n) => *n,
                None => {
                    println!("usage: devctl {} <driver>", v);
                    return 2;
                }
            };
            if write_file(CMD, format!("{} {}\n", v, name).as_bytes(), true) {
                println!("devctl: {} {} requested", v, name);
                0
            } else {
                println!("devctl: cannot write {}", CMD);
                1
            }
        }
        _ => {
            println!("usage: devctl list | start <driver> | stop <driver> | restart <driver>");
            2
        }
    }
}
