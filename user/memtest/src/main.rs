// SPDX-License-Identifier: AGPL-3.0-only
//! memtest — boot self-test of shared memory through handles (ROADMAP item 12).
//! Exit 0 = all good, otherwise the number of the check that failed.
//!
//! Modes (argument 1) and bootstrap handles:
//!   server        1 = channel (READ). Maps what the client sends, checks and writes back.
//!   client        1 = channel (WRITE). Creates a region, shares it RW and RO, checks rights.
//!   rowrite       1 = region (READ|MAP) whose first byte the kernel set to 0x5A. Maps it
//!                 read-only, reads, then writes: the #PF must kill it (never exits itself).
//!   contig        1 = DMA resource (READ|WRITE|DUP). Contiguous region with PHYS.
//!   mmio <hex>    1 = MmioRegion (READ|MAP) over the local APIC page; the APIC version
//!                 register (offset 0x30) must read as <hex>.
#![no_std]
#![no_main]

extern crate alloc;

use liboos::hw::Resource;
use liboos::ipc::{Channel, Error, Handle, Message, ObjectType, Rights};
use liboos::mem::{self, MemoryRegion, Prot};
use liboos::println;

liboos::entry!(main);

const SHARE_RW: u64 = 1;
const SHARE_RO: u64 = 2;
const LIVE: u64 = 3;
const QUIT: u64 = 4;

macro_rules! check {
    ($who:expr, $n:expr, $cond:expr) => {
        if !$cond {
            println!("[memtest {}] check {} FAILED: {}", $who, $n, stringify!($cond));
            return $n;
        }
    };
}

fn main(args: liboos::Args) -> i32 {
    match args.get(1) {
        Some("server") => server(),
        Some("client") => client(),
        Some("rowrite") => rowrite(),
        Some("contig") => contig(),
        Some("mmio") => mmio(args.get(2).unwrap_or("")),
        _ => 100,
    }
}

const BASIC: Rights = Rights(1 | 2 | 16 | 4 | 8); // READ WRITE MAP DUP TRANSFER

fn eq(m: &mem::Mapping, off: usize, s: &[u8]) -> bool {
    let mut buf = [0u8; 32];
    let b = &mut buf[..s.len()];
    m.read_bytes(off, b);
    b == s
}

// ─── client ──────────────────────────────────────────────────────────────────────────

fn client() -> i32 {
    let w = "client";
    let chan = Channel(Handle::bootstrap(1));

    // 1: a fresh region has the expected type, rights and size
    let region = match MemoryRegion::create(5000) {
        Ok(r) => r,
        Err(_) => return 1,
    };
    check!(w, 1, region.0.info() == Ok((ObjectType::MemoryRegion, BASIC)));
    check!(w, 1, region.size() == Ok(8192));

    // 2: map it read-write and fill both pages
    let m = match region.map(Prot::RW) {
        Ok(m) => m,
        Err(_) => return 2,
    };
    check!(w, 2, m.read::<u64>(0) == 0 && m.read::<u64>(4096) == 0); // zeroed
    m.write_bytes(0, b"client:hello");
    m.write::<u8>(4096, 0xC1);

    // 3: a read-write duplicate goes to the server, which checks and writes back
    let rw = match region.duplicate(Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER) {
        Ok(r) => r,
        Err(_) => return 3,
    };
    let mut msg = Message::new(SHARE_RW);
    let _ = msg.push_handle(rw.0);
    let r = chan.call(&mut msg);
    check!(w, 3, r.as_ref().map(|m| m.tag) == Ok(0));
    check!(w, 3, eq(&m, 4096 + 16, b"server:hi"));

    // 4: a read-only duplicate: the server checks it cannot map it writable
    let ro = match region.duplicate(Rights::READ | Rights::MAP | Rights::TRANSFER) {
        Ok(r) => r,
        Err(_) => return 4,
    };
    let mut msg = Message::new(SHARE_RO);
    let _ = msg.push_handle(ro.0);
    let r = chan.call(&mut msg);
    check!(w, 4, r.as_ref().map(|m| m.tag) == Ok(0));

    // 5: live sharing: the server still has the region mapped (its handle is closed)
    m.write_bytes(100, b"round2");
    let mut msg = Message::new(LIVE);
    let r = chan.call(&mut msg);
    check!(w, 5, r.as_ref().map(|m| m.tag) == Ok(0));
    check!(w, 5, eq(&m, 200, b"ack2"));

    // 6: rights are enforced locally too
    let nomap = match region.duplicate(Rights::READ | Rights::TRANSFER) {
        Ok(r) => r,
        Err(_) => return 6,
    };
    check!(w, 6, mem::map_raw(&nomap.0, 1) == Err(Error::PermissionDenied));
    check!(w, 6, region.phys() == Err(Error::PermissionDenied)); // no PHYS on anonymous memory
    check!(w, 6, nomap.duplicate(Rights::READ).is_err()); // no DUP right
    check!(w, 6, region.duplicate(Rights::READ | Rights::PHYS).err() == Some(Error::PermissionDenied));
    check!(w, 6, mem::map_raw(&region.0, 0) == Err(Error::InvalidArgument)); // no READ in prot
    check!(w, 6, mem::map_raw(&region.0, 2) == Err(Error::InvalidArgument)); // write-only
    check!(w, 6, mem::map_raw(&region.0, 7) == Err(Error::InvalidArgument)); // W+X
    check!(w, 6, mem::map_raw(&region.0, 5) == Err(Error::PermissionDenied)); // no EXEC right
    check!(w, 6, mem::map_raw(&chan.0, 1) == Err(Error::WrongType));

    // 7: a mapping outlives its handle; unmap only takes what mem_map returned
    check!(w, 7, mem::unmap_raw(m.addr() + 4096) == Err(Error::InvalidArgument));
    let r2 = match MemoryRegion::create(4096) {
        Ok(r) => r,
        Err(_) => return 7,
    };
    let m2 = match r2.map(Prot::RW) {
        Ok(m) => m,
        Err(_) => return 7,
    };
    check!(w, 7, r2.0.close().is_ok());
    m2.write::<u32>(8, 0xDEAD_BEEF);
    check!(w, 7, m2.read::<u32>(8) == 0xDEAD_BEEF);
    let a2 = m2.addr();
    check!(w, 7, m2.unmap().is_ok());
    check!(w, 7, mem::unmap_raw(a2) == Err(Error::InvalidArgument));

    // 8: size limits
    check!(w, 8, MemoryRegion::create(0).err() == Some(Error::InvalidArgument));
    check!(w, 8, MemoryRegion::create(1 << 40).err() == Some(Error::InvalidArgument));

    // 9: done; the server exits 42
    let mut msg = Message::new(QUIT);
    let _ = chan.call(&mut msg);
    println!("[memtest client] all checks passed");
    0
}

// ─── server ──────────────────────────────────────────────────────────────────────────

fn server() -> i32 {
    let chan = Channel(Handle::bootstrap(1));
    let mut kept: Option<mem::Mapping> = None;
    loop {
        let (mut msg, reply) = match chan.recv(0) {
            Ok(x) => x,
            Err(_) => return 1,
        };
        let code = match msg.tag {
            SHARE_RW => match msg.take_handle(0) {
                Some(h) => share_rw(MemoryRegion(h), &mut kept),
                None => 20,
            },
            SHARE_RO => match msg.take_handle(0) {
                Some(h) => share_ro(MemoryRegion(h)),
                None => 30,
            },
            LIVE => match &kept {
                Some(m) if eq(m, 100, b"round2") => {
                    m.write_bytes(200, b"ack2");
                    0
                }
                _ => 40,
            },
            QUIT => {
                drop(kept.take());
                if let Some(r) = reply {
                    let _ = r.reply(Message::new(0));
                }
                return 42;
            }
            _ => 99,
        };
        if code != 0 {
            println!("[memtest server] request {} failed with {}", msg.tag, code);
        }
        if let Some(r) = reply {
            let _ = r.reply(Message::new(code as u64));
        }
    }
}

fn share_rw(r: MemoryRegion, kept: &mut Option<mem::Mapping>) -> i32 {
    // Rights travel with the handle unchanged.
    if r.0.info() != Ok((ObjectType::MemoryRegion, Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER)) {
        return 21;
    }
    let m = match r.map(Prot::RW) {
        Ok(m) => m,
        Err(_) => return 22,
    };
    if !eq(&m, 0, b"client:hello") || m.read::<u8>(4096) != 0xC1 {
        return 23;
    }
    m.write_bytes(4096 + 16, b"server:hi");
    // Close the handle, keep the mapping: the region must stay alive for LIVE.
    if r.0.close().is_err() {
        return 24;
    }
    *kept = Some(m);
    0
}

fn share_ro(r: MemoryRegion) -> i32 {
    if mem::map_raw(&r.0, 3) != Err(Error::PermissionDenied) {
        return 31; // writable map from a read-only handle
    }
    if r.phys() != Err(Error::PermissionDenied) {
        return 32;
    }
    if r.duplicate(Rights::READ).is_ok() {
        return 33; // no DUP right
    }
    let m = match r.map(Prot::READ) {
        Ok(m) => m,
        Err(_) => return 34,
    };
    if !eq(&m, 0, b"client:hello") || m.writable() {
        return 35;
    }
    0
}

// ─── rowrite ─────────────────────────────────────────────────────────────────────────

fn rowrite() -> i32 {
    let r = MemoryRegion(Handle::bootstrap(1));
    let m = match r.map(Prot::READ) {
        Ok(m) => m,
        Err(_) => return 1,
    };
    if m.read::<u8>(0) != 0x5A {
        return 2;
    }
    println!("[memtest rowrite] read 0x5A through a read-only mapping; now writing to it");
    // SAFETY: deliberately invalid: the page is mapped read-only, the CPU must fault.
    unsafe { core::ptr::write_volatile(m.as_ptr(), 0xEE) };
    println!("[memtest rowrite] write went through: rights NOT enforced");
    3
}

// ─── contig (DMA) ────────────────────────────────────────────────────────────────────

fn contig() -> i32 {
    let w = "contig";
    let dma = Resource(Handle::bootstrap(1));
    check!(w, 1, dma.0.info().map(|(t, _)| t) == Ok(ObjectType::Resource));

    let r = match MemoryRegion::create_contig(&dma, 3 * 4096) {
        Ok(r) => r,
        Err(_) => return 2,
    };
    check!(w, 2, r.0.info() == Ok((ObjectType::MemoryRegion, Rights(BASIC.0 | Rights::PHYS.0))));
    let phys = match r.phys() {
        Ok(p) => p,
        Err(_) => return 3,
    };
    check!(w, 3, phys != 0 && phys % 4096 == 0);
    let m = match r.map(Prot::RW) {
        Ok(m) => m,
        Err(_) => return 4,
    };
    m.write::<u64>(2 * 4096, 0x1234_5678_9ABC_DEF0);
    check!(w, 4, m.read::<u64>(2 * 4096) == 0x1234_5678_9ABC_DEF0);

    // 5: a duplicate without PHYS hides the address (e.g. when shared with a client)
    let hidden = match r.duplicate(Rights::READ | Rights::MAP) {
        Ok(h) => h,
        Err(_) => return 5,
    };
    check!(w, 5, hidden.phys() == Err(Error::PermissionDenied));

    // 6: the resource is needed with WRITE; size is limited
    let weak = match dma.0.duplicate(Rights::READ) {
        Ok(h) => Resource(h),
        Err(_) => return 6,
    };
    check!(w, 6, MemoryRegion::create_contig(&weak, 4096).err() == Some(Error::PermissionDenied));
    check!(w, 6, MemoryRegion::create_contig(&dma, 64 << 20).err() == Some(Error::InvalidArgument));
    let not_res = Resource(Handle::from_raw(r.0.raw()));
    check!(w, 6, MemoryRegion::create_contig(&not_res, 4096).err() == Some(Error::WrongType));
    core::mem::forget(not_res);

    println!("[memtest contig] 3 contiguous pages at phys {:#x}, all checks passed", phys);
    0
}

// ─── mmio ────────────────────────────────────────────────────────────────────────────

fn mmio(expect: &str) -> i32 {
    let w = "mmio";
    let r = MemoryRegion(Handle::bootstrap(1));
    check!(w, 1, r.0.info() == Ok((ObjectType::MmioRegion, Rights::READ | Rights::MAP)));
    check!(w, 2, mem::map_raw(&r.0, 3) == Err(Error::PermissionDenied));
    let m = match r.map(Prot::READ) {
        Ok(m) => m,
        Err(_) => return 3,
    };
    let v = m.read::<u32>(0x30);
    let want = u32::from_str_radix(expect, 16).unwrap_or(!0);
    println!("[memtest mmio] local APIC version register via ring-3 mapping: {:#x} (kernel read {:#x})", v, want);
    check!(w, 4, v == want);
    0
}
