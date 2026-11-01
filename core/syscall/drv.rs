/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

System calls for ring-3 drivers and the device manager (290..=299):
PCI enumeration and claiming, per-device BAR / interrupt / config access, process spawn
with handles, directory listing, driver log, external NIC control.
ABI of each call: docs/en/syscall-abi.md ("Drivers in ring 3").
*/

use alloc::vec::Vec;

use crate::core::object::{self, resource, rights};
use crate::core::pcidev;
use crate::mm::usercopy;

use super::SyscallError as E;

fn ret_h(r: object::Res<u32>) -> i64 {
    match r {
        Ok(v) => v as i64,
        Err(e) => e,
    }
}

fn uerr(e: usercopy::UserCopyError) -> i64 {
    E::from(e) as i64
}

fn put_info(out: u64, info: &pcidev::PciInfo) -> i64 {
    // SAFETY: PciInfo is repr(C) plain data.
    let b = unsafe { core::slice::from_raw_parts(info as *const _ as *const u8, pcidev::INFO_SIZE) };
    match usercopy::copy_to_user(out, b) {
        Ok(()) => 0,
        Err(e) => uerr(e),
    }
}

// 290: pci_enum(resource, index, out*) -> 0, NotFound past the end
pub fn pci_enum(res: u64, index: u64, out: u64) -> i64 {
    if let Err(e) = object::pci_resource_check(res as u32, rights::READ) {
        return e;
    }
    if !usercopy::range_ok(out, pcidev::INFO_SIZE) {
        return E::BadAddress as i64;
    }
    match pcidev::info(index as usize) {
        Some(i) => put_info(out, &i),
        None => E::NotFound as i64,
    }
}

// 291: pci_claim(resource, bdf, flags) -> PciDevice handle; flags bit 0: take it from a kernel driver
pub fn pci_claim(res: u64, bdf: u64, flags: u64) -> i64 {
    if let Err(e) = object::pci_resource_check(res as u32, rights::WRITE) {
        return e;
    }
    let bdf = bdf as u16;
    if let Err(e) = pcidev::claim_user(bdf, flags & 1 != 0) {
        return e;
    }
    match object::pci_dev_install(bdf) {
        Ok(h) => h as i64,
        Err(e) => {
            pcidev::user_released(bdf);
            e
        }
    }
}

// 292: pci_open(dev, kind, index) -> handle. kind 0: memory BAR (MmioRegion),
// 1: I/O BAR (IoPortRange), 2: the legacy interrupt line (Interrupt)
pub fn pci_open(dev: u64, kind: u64, index: u64) -> i64 {
    let bdf = match object::pci_dev_bdf(dev as u32, rights::WRITE) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let info = match pcidev::info_bdf(bdf) {
        Some(i) => i,
        None => return E::NotFound as i64,
    };
    match kind {
        0 | 1 => {
            if index >= 6 {
                return E::InvalidArgument as i64;
            }
            let b = info.bars[index as usize];
            let is_io = b.flags & 2 != 0;
            if b.flags & 1 == 0 || b.size == 0 || is_io != (kind == 1) {
                return E::NotFound as i64;
            }
            if is_io {
                ret_h(object::pci_make_ioports(dev as u32, b.base as u16, b.size as u32))
            } else {
                ret_h(object::pci_make_mmio(dev as u32, b.base, b.size))
            }
        }
        2 => {
            if info.irq_pin == 0 || info.irq_line >= 16 {
                return E::NotSupported as i64;
            }
            if pcidev::irq_shared_with_kernel(bdf, info.irq_line) {
                return E::Busy as i64;
            }
            ret_h(object::pci_make_interrupt(dev as u32, info.irq_line))
        }
        _ => E::InvalidArgument as i64,
    }
}

// 293: pci_cfg_read(dev, offset, size) -> value
pub fn pci_cfg_read(dev: u64, off: u64, size: u64) -> i64 {
    match object::pci_dev_bdf(dev as u32, rights::READ).and_then(|b| pcidev::cfg_read(b, off, size)) {
        Ok(v) => v as i64,
        Err(e) => e,
    }
}

// 294: pci_cfg_write(dev, offset, size, value)
pub fn pci_cfg_write(dev: u64, off: u64, size: u64, val: u64) -> i64 {
    match object::pci_dev_bdf(dev as u32, rights::WRITE).and_then(|b| pcidev::cfg_write(b, off, size, val as u32)) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// 295: pci_info(dev, out*)
pub fn pci_info(dev: u64, out: u64) -> i64 {
    let bdf = match object::pci_dev_bdf(dev as u32, rights::READ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    match pcidev::info_bdf(bdf) {
        Some(i) => put_info(out, &i),
        None => E::NotFound as i64,
    }
}

/// proc_spawn request (10 u64 words).
#[repr(C)]
#[derive(Clone, Copy)]
struct SpawnReq {
    path_ptr: u64,
    path_len: u64,
    /// NUL-separated argument strings (argv[0] first)
    args_ptr: u64,
    args_len: u64,
    nhandles: u64,
    handles: [u64; 4],
    /// out: pid of the child
    pid: u64,
}

// 296: proc_spawn(req*) -> Process handle (READ|WRITE) of the child
pub fn proc_spawn(req_ptr: u64) -> i64 {
    use crate::core::scheduler::{self, Capability};
    if !scheduler::has_capability(Capability::Spawn) && !scheduler::has_capability(Capability::System) {
        return E::PermissionDenied as i64;
    }
    if !super::can_fs_read() {
        return E::PermissionDenied as i64;
    }
    let mut req = SpawnReq { path_ptr: 0, path_len: 0, args_ptr: 0, args_len: 0, nhandles: 0, handles: [0; 4], pid: 0 };
    // SAFETY: plain data.
    let rb = unsafe { core::slice::from_raw_parts_mut(&mut req as *mut _ as *mut u8, core::mem::size_of::<SpawnReq>()) };
    if let Err(e) = usercopy::copy_from_user(rb, req_ptr) {
        return uerr(e);
    }
    if req.nhandles > 4 {
        return E::InvalidArgument as i64;
    }
    let path = match usercopy::read_user_str(req.path_ptr, req.path_len as usize, 256) {
        Ok(p) => p,
        Err(e) => return uerr(e),
    };
    let args_raw = match usercopy::read_user_bytes(req.args_ptr, req.args_len as usize, 1024) {
        Ok(a) => a,
        Err(e) => return uerr(e),
    };
    let args: Vec<&str> = args_raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| core::str::from_utf8(s).ok())
        .collect();
    let hs: Vec<u32> = req.handles[..req.nhandles as usize].iter().map(|&h| h as u32).collect();
    let objs = match object::handles_to_objects(&hs) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let image = match crate::fs::read_file(&path) {
        Some(i) => i,
        None => return E::NotFound as i64,
    };
    if !image.starts_with(b"\x7FELF") {
        return E::InvalidArgument as i64;
    }
    let name = path.rsplit('/').next().unwrap_or("driver");
    let caps = alloc::vec![Capability::Serial];
    let pid = match crate::core::elf::spawn_with_handles(name, &image, &args, caps, &objs) {
        Ok(p) => p,
        Err(_) => return E::OutOfMemory as i64,
    };
    req.pid = pid as u64;
    let _ = usercopy::copy_to_user(req_ptr + 72, &req.pid.to_le_bytes());
    let me = scheduler::current_pid();
    match object::kernel_new_process(pid) {
        Some(o) => {
            let h = object::kernel_install(me, o, rights::READ | rights::WRITE);
            object::kernel_release(o);
            match h {
                Some(h) => h as i64,
                None => E::TableFull as i64,
            }
        }
        None => E::OutOfMemory as i64,
    }
}

// 297: fs_readdir(path*, path_len, buf*, buf_len) -> bytes; names separated by '\n', '/' after directories
pub fn fs_readdir(path: u64, plen: u64, buf: u64, blen: u64) -> i64 {
    if !super::can_fs_read() {
        return E::PermissionDenied as i64;
    }
    let p = match usercopy::read_user_str(path, plen as usize, 256) {
        Ok(p) => p,
        Err(e) => return uerr(e),
    };
    let entries = match crate::fs::readdir(&p) {
        Some(e) => e,
        None => return E::NotFound as i64,
    };
    let mut out: Vec<u8> = Vec::new();
    for e in entries {
        out.extend_from_slice(e.name.as_bytes());
        if matches!(e.node_type, crate::fs::NodeType::Directory) {
            out.push(b'/');
        }
        out.push(b'\n');
    }
    out.truncate((blen as usize).min(16 * 1024));
    match usercopy::copy_to_user(buf, &out) {
        Ok(()) => out.len() as i64,
        Err(e) => uerr(e),
    }
}

// 298: klog_write(level, msg*, len): the line goes to the serial log and the kernel event log (dmesg)
pub fn klog_write(_level: u64, ptr: u64, len: u64) -> i64 {
    if !super::can_serial_write() {
        return E::PermissionDenied as i64;
    }
    let s = match usercopy::read_user_str(ptr, len as usize, 160) {
        Ok(s) => s,
        Err(e) => return uerr(e),
    };
    crate::arch::x86_64::serial::write_str("[drv] ");
    crate::arch::x86_64::serial::write_str(&s);
    crate::arch::x86_64::serial::write_str("\r\n");
    crate::klog::record(crate::klog::EventSource::Driver, &s);
    0
}

// 299: netdrv_ctl(op, a, b, c). op 0 attach(dev, notification, ring region); 1 poll; 2 detach; 3 status
pub fn netdrv_ctl(op: u64, a: u64, b: u64, c: u64) -> i64 {
    match op {
        0 => match crate::net::ext::attach(a as u32, b as u32, c as u32) {
            Ok(()) => 0,
            Err(e) => e,
        },
        1 => crate::net::ext::poll(),
        2 => {
            crate::net::ext::detach();
            0
        }
        3 => crate::net::ext::status(),
        _ => E::InvalidArgument as i64,
    }
}

#[allow(dead_code)]
const _: u32 = resource::PCI;
