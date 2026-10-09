/*
 * AETERNA virtio-blk driver — polled, legacy (I/O port BAR0) and modern
 * (virtio 1.x PCI capabilities) transports.
 *
 * BSL 1.1 — Copyright (c) 2026 ospab
 *
 * QEMU/KVM/cloud disk: `-device virtio-blk-pci`.  One request in flight at a
 * time, three-descriptor chain (header, data, status), no interrupts.  All
 * waits are bounded with the TSC clock; a timed-out device is marked broken so
 * later I/O fails fast instead of stalling.  Sectors are always 512 bytes
 * (virtio-blk addresses the device in 512-byte units whatever its blk_size).
 *
 * DMA memory lives in the kernel image (statics), which is physically
 * contiguous; phys = virt - kernel_virt_offset, same trick as ahci.rs.
 */

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use crate::arch::x86_64::io::{inb, inl, inw, outb, outl, outw};
use crate::mm::r#virtual::{self as vmm, FLAG_NX, FLAG_PCD, FLAG_PWT, FLAG_WRITABLE};

const VIRTIO_VENDOR: u16 = 0x1AF4;
const DEV_ID_BLK_TRANSITIONAL: u16 = 0x1001;
const DEV_ID_BLK_MODERN: u16 = 0x1042;

const MAX_DEVS: usize = 4;
const QSZ_MAX: usize = 256;
const CHUNK_SECTORS: u32 = 128;
const CHUNK_BYTES: usize = CHUNK_SECTORS as usize * 512;

const UC_VIRT_BASE: u64 = 0xFFFF_FF30_0000_0000;
const UC_MAX_PAGES: u64 = 0x4000; // 64 MiB of address window, plenty

// Device status bits
const ST_ACK: u8 = 1;
const ST_DRIVER: u8 = 2;
const ST_DRIVER_OK: u8 = 4;
const ST_FEATURES_OK: u8 = 8;
const ST_FAILED: u8 = 0x80;

// Feature bits
const F_RO: u32 = 1 << 5;
const F_FLUSH: u32 = 1 << 9;

// Request types
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;

// Descriptor flags
const D_NEXT: u16 = 1;
const D_WRITE: u16 = 2;

// Legacy register offsets (I/O BAR0)
const L_HOST_FEAT: u16 = 0;
const L_GUEST_FEAT: u16 = 4;
const L_QUEUE_PFN: u16 = 8;
const L_QUEUE_SIZE: u16 = 12;
const L_QUEUE_SEL: u16 = 14;
const L_QUEUE_NOTIFY: u16 = 16;
const L_STATUS: u16 = 18;
const L_DEVCFG: u16 = 20;

// ─── DMA memory ───────────────────────────────────────────────────────────

#[repr(C, align(4096))]
struct QueueMem([u8; 16384]);

#[repr(C, align(4096))]
struct DataBuf([u8; CHUNK_BYTES]);

#[repr(C, align(16))]
struct ReqHdr([u8; 16]);

#[repr(C, align(16))]
struct StatusByte([u8; 16]);

static mut QMEM: [QueueMem; MAX_DEVS] = [const { QueueMem([0u8; 16384]) }; MAX_DEVS];
static mut DATA: DataBuf = DataBuf([0u8; CHUNK_BYTES]);
static mut HDR: ReqHdr = ReqHdr([0u8; 16]);
static mut STATUS: StatusByte = StatusByte([0u8; 16]);

// ─── Device table ─────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct Dev {
    modern: bool,
    io_base: u16,
    notify_addr: usize, // modern: MMIO address of this queue's notify register
    qsize: u16,
    avail_idx: u16,
    last_used: u16,
    capacity: u64, // 512-byte sectors
    flush: bool,
    read_only: bool,
    broken: bool,
}

const DEV_ZERO: Dev = Dev {
    modern: false, io_base: 0, notify_addr: 0, qsize: 0, avail_idx: 0, last_used: 0,
    capacity: 0, flush: false, read_only: false, broken: false,
};

static mut DEVS: [Dev; MAX_DEVS] = [DEV_ZERO; MAX_DEVS];
static mut DEV_COUNT: usize = 0;
static mut MAP_CURSOR: u64 = 0; // pages already used in the UC window

pub struct VirtioInfo {
    pub sectors: u64,
    pub size_mb: u64,
    pub model: [u8; 41],
    pub read_only: bool,
}

// ─── Helpers ──────────────────────────────────────────────────────────────

#[inline]
fn now_us() -> u64 { crate::arch::x86_64::tsc::tsc_stamp_us() }

fn log(s: &str) { crate::arch::x86_64::serial::write_str(s); }

fn log_dec(mut v: u64) {
    if v == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while v > 0 { buf[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}

fn log_hex(v: u64) {
    let h = b"0123456789abcdef";
    let mut started = false;
    for i in (0..16).rev() {
        let nib = ((v >> (i * 4)) & 0xF) as usize;
        if nib != 0 || started || i == 0 { started = true; crate::arch::x86_64::serial::write_byte(h[nib]); }
    }
}

fn virt_to_phys(vaddr: usize) -> u64 {
    let offset = crate::arch::x86_64::boot::kernel_virt_offset();
    (vaddr as u64).wrapping_sub(offset)
}

#[inline] unsafe fn r8(a: usize) -> u8 { read_volatile(a as *const u8) }
#[inline] unsafe fn r16(a: usize) -> u16 { read_volatile(a as *const u16) }
#[inline] unsafe fn r32(a: usize) -> u32 { read_volatile(a as *const u32) }
#[inline] unsafe fn w8(a: usize, v: u8) { write_volatile(a as *mut u8, v) }
#[inline] unsafe fn w16(a: usize, v: u16) { write_volatile(a as *mut u16, v) }
#[inline] unsafe fn w32(a: usize, v: u32) { write_volatile(a as *mut u32, v) }
#[inline] unsafe fn w64(a: usize, v: u64) { w32(a, v as u32); w32(a + 4, (v >> 32) as u32); }

/// Map `len` bytes of device memory at `phys` uncached; returns the virtual address.
fn map_mmio(phys: u64, len: u64) -> Option<usize> {
    let len = len.max(1).min(0x10000);
    let first = phys & !0xFFF;
    let off = phys & 0xFFF;
    let pages = (off + len + 0xFFF) / 0x1000;
    unsafe {
        if MAP_CURSOR + pages > UC_MAX_PAGES { return None; }
        let base = UC_VIRT_BASE + MAP_CURSOR * 0x1000;
        for p in 0..pages {
            if !vmm::map_page_current(base + p * 0x1000, first + p * 0x1000,
                                      FLAG_WRITABLE | FLAG_PCD | FLAG_PWT | FLAG_NX) {
                return None;
            }
        }
        MAP_CURSOR += pages;
        Some((base + off) as usize)
    }
}

fn bar_mmio_base(bus: u8, dev: u8, fun: u8, bar: u8) -> Option<u64> {
    if bar > 5 { return None; }
    let off = 0x10 + bar * 4;
    let lo = crate::pci::config_read32(bus, dev, fun, off);
    if lo & 1 != 0 || lo == 0 { return None; }
    let mut base = (lo & !0xF) as u64;
    if (lo >> 1) & 3 == 2 && bar < 5 {
        base |= (crate::pci::config_read32(bus, dev, fun, off + 4) as u64) << 32;
    }
    if base == 0 { None } else { Some(base) }
}

fn pow2(n: u16) -> bool { n != 0 && (n & (n - 1)) == 0 }

fn queue_layout(qs: usize) -> (usize, usize) {
    let avail = 16 * qs;
    let used = (avail + 6 + 2 * qs + 4095) & !4095;
    (avail, used)
}

// ─── Probe / init ─────────────────────────────────────────────────────────

/// Probe every virtio-blk PCI device. Returns the number of usable disks.
pub fn init() -> usize {
    unsafe { DEV_COUNT = 0; }
    let mut i = 0usize;
    while let Some(p) = crate::pci::get_device(i) {
        i += 1;
        if p.vendor_id != VIRTIO_VENDOR { continue; }
        if p.device_id != DEV_ID_BLK_TRANSITIONAL && p.device_id != DEV_ID_BLK_MODERN { continue; }
        let n = unsafe { DEV_COUNT };
        if n >= MAX_DEVS { log("[VIRTIO-BLK] too many devices, ignoring the rest\r\n"); break; }
        log("[VIRTIO-BLK] device at PCI ");
        log_hex(p.bus as u64); log(":"); log_hex(p.device as u64); log("."); log_hex(p.function as u64);
        log(" id=");
        log_hex(p.device_id as u64);
        log("\r\n");
        if let Some(d) = init_one(p.bus, p.device, p.function, n) {
            unsafe { DEVS[n] = d; DEV_COUNT = n + 1; }
            log("[VIRTIO-BLK] disk "); log_dec(n as u64); log(": ");
            log(if d.modern { "modern" } else { "legacy" });
            log(" transport, "); log_dec(d.capacity); log(" sectors (");
            log_dec(d.capacity >> 11); log(" MiB), queue "); log_dec(d.qsize as u64);
            if d.read_only { log(", read-only"); }
            if d.flush { log(", flush"); }
            log("\r\n");
        }
    }
    if unsafe { DEV_COUNT } == 0 && i > 0 {
        // Nothing found is normal (no virtio disk); stay quiet.
    }
    unsafe { DEV_COUNT }
}

fn init_one(bus: u8, dev: u8, fun: u8, slot: usize) -> Option<Dev> {
    // Memory + I/O decode + bus master, mask INTx (polled)
    let cmd = crate::pci::command(bus, dev, fun);
    crate::pci::set_command(bus, dev, fun, cmd | 0x0007 | 0x0400);

    // Look for the virtio 1.x PCI capabilities (vendor-specific cap id 0x09)
    let mut common: Option<(u8, u32, u32)> = None;
    let mut notify: Option<(u8, u32, u32, u32)> = None;
    let mut devcfg: Option<(u8, u32, u32)> = None;
    let status = crate::pci::config_read16(bus, dev, fun, 0x06);
    if status & 0x10 != 0 {
        let mut p = crate::pci::config_read8(bus, dev, fun, 0x34) & 0xFC;
        for _ in 0..48 {
            if p == 0 { break; }
            let id = crate::pci::config_read8(bus, dev, fun, p);
            let next = crate::pci::config_read8(bus, dev, fun, p + 1) & 0xFC;
            if id == 0x09 {
                let ty = crate::pci::config_read8(bus, dev, fun, p + 3);
                let bar = crate::pci::config_read8(bus, dev, fun, p + 4);
                let off = crate::pci::config_read32(bus, dev, fun, p + 8);
                let len = crate::pci::config_read32(bus, dev, fun, p + 12);
                match ty {
                    1 if common.is_none() => common = Some((bar, off, len)),
                    2 if notify.is_none() => {
                        let mult = crate::pci::config_read32(bus, dev, fun, p + 16);
                        notify = Some((bar, off, len, mult));
                    }
                    4 if devcfg.is_none() => devcfg = Some((bar, off, len)),
                    _ => {}
                }
            }
            p = next;
        }
    }

    if let (Some(c), Some(n), Some(d)) = (common, notify, devcfg) {
        match init_modern(bus, dev, fun, slot, c, n, d) {
            Some(x) => return Some(x),
            None => log("[VIRTIO-BLK] modern transport failed\r\n"),
        }
        return None;
    }

    // Legacy: I/O BAR0
    let bar0 = crate::pci::config_read32(bus, dev, fun, 0x10);
    if bar0 & 1 == 0 || (bar0 & 0xFFFC) == 0 {
        log("[VIRTIO-BLK] no modern capabilities and no I/O BAR0, skipping\r\n");
        return None;
    }
    let r = init_legacy((bar0 & 0xFFFC) as u16, slot);
    if r.is_none() { log("[VIRTIO-BLK] legacy transport failed\r\n"); }
    r
}

fn setup_queue_mem(slot: usize, qs: u16) -> (u64, u64, u64) {
    unsafe {
        let base = core::ptr::addr_of_mut!(QMEM[slot]) as *mut u8;
        core::ptr::write_bytes(base, 0, 16384);
        let (avail_off, used_off) = queue_layout(qs as usize);
        // avail.flags = 1: no interrupts wanted
        write_volatile(base.add(avail_off) as *mut u16, 1);
        let phys = virt_to_phys(base as usize);
        (phys, phys + avail_off as u64, phys + used_off as u64)
    }
}

fn init_modern(bus: u8, dev: u8, fun: u8, slot: usize,
               c: (u8, u32, u32), n: (u8, u32, u32, u32), d: (u8, u32, u32)) -> Option<Dev> {
    let map_cap = |bar: u8, off: u32, len: u32| -> Option<usize> {
        let base = bar_mmio_base(bus, dev, fun, bar)?;
        map_mmio(base + off as u64, len as u64)
    };
    let common = map_cap(c.0, c.1, c.2.max(0x40))?;
    let notify_base = map_cap(n.0, n.1, n.2)?;
    let devcfg = map_cap(d.0, d.1, d.2.max(8))?;

    unsafe {
        // Reset and wait for 0
        w8(common + 20, 0);
        let t0 = now_us();
        while r8(common + 20) != 0 {
            if now_us().wrapping_sub(t0) > 1_000_000 { log("[VIRTIO-BLK] reset timeout\r\n"); return None; }
            core::arch::asm!("pause");
        }
        let mut st = ST_ACK; w8(common + 20, st);
        st |= ST_DRIVER; w8(common + 20, st);

        w32(common + 0, 0); let f0 = r32(common + 4);
        w32(common + 0, 1); let f1 = r32(common + 4);
        if f1 & 1 == 0 {
            log("[VIRTIO-BLK] device lacks VERSION_1\r\n");
            w8(common + 20, ST_FAILED);
            return None;
        }
        let want0 = f0 & F_FLUSH;
        w32(common + 8, 0); w32(common + 12, want0);
        w32(common + 8, 1); w32(common + 12, 1);
        st |= ST_FEATURES_OK; w8(common + 20, st);
        if r8(common + 20) & ST_FEATURES_OK == 0 {
            log("[VIRTIO-BLK] FEATURES_OK rejected\r\n");
            w8(common + 20, ST_FAILED);
            return None;
        }

        // Queue 0
        w16(common + 22, 0);
        let mut qs = r16(common + 24);
        if qs == 0 { log("[VIRTIO-BLK] queue 0 unavailable\r\n"); w8(common + 20, ST_FAILED); return None; }
        if qs as usize > QSZ_MAX { qs = QSZ_MAX as u16; w16(common + 24, qs); }
        if !pow2(qs) { log("[VIRTIO-BLK] queue size not a power of two\r\n"); w8(common + 20, ST_FAILED); return None; }
        let (desc_p, avail_p, used_p) = setup_queue_mem(slot, qs);
        w64(common + 32, desc_p);
        w64(common + 40, avail_p);
        w64(common + 48, used_p);
        w16(common + 26, 0xFFFF); // no MSI-X vector
        let noff = r16(common + 30) as u64;
        let naddr = notify_base as u64 + noff * n.3 as u64;
        if noff * n.3 as u64 + 2 > (n.2 as u64).min(0x10000) {
            log("[VIRTIO-BLK] notify register outside its capability
");
            w8(common + 20, ST_FAILED);
            return None;
        }
        w16(common + 28, 1); // enable

        st |= ST_DRIVER_OK; w8(common + 20, st);

        let cap = r32(devcfg) as u64 | ((r32(devcfg + 4) as u64) << 32);
        if cap == 0 { log("[VIRTIO-BLK] zero capacity\r\n"); return None; }
        Some(Dev {
            modern: true, io_base: 0, notify_addr: naddr as usize, qsize: qs,
            avail_idx: 0, last_used: 0, capacity: cap,
            flush: want0 & F_FLUSH != 0, read_only: f0 & F_RO != 0, broken: false,
        })
    }
}

fn init_legacy(io: u16, slot: usize) -> Option<Dev> {
    unsafe {
        outb(io + L_STATUS, 0);
        let mut st = ST_ACK; outb(io + L_STATUS, st);
        st |= ST_DRIVER; outb(io + L_STATUS, st);

        let host = inl(io + L_HOST_FEAT);
        let guest = host & F_FLUSH;
        outl(io + L_GUEST_FEAT, guest);

        outw(io + L_QUEUE_SEL, 0);
        let qs = inw(io + L_QUEUE_SIZE);
        if qs == 0 { log("[VIRTIO-BLK] queue 0 unavailable\r\n"); outb(io + L_STATUS, ST_FAILED); return None; }
        if qs as usize > QSZ_MAX || !pow2(qs) {
            log("[VIRTIO-BLK] legacy queue size "); log_dec(qs as u64); log(" unsupported\r\n");
            outb(io + L_STATUS, ST_FAILED);
            return None;
        }
        let (desc_p, _, _) = setup_queue_mem(slot, qs);
        if desc_p >> 44 != 0 { log("[VIRTIO-BLK] queue above legacy PFN limit\r\n"); outb(io + L_STATUS, ST_FAILED); return None; }
        outl(io + L_QUEUE_PFN, (desc_p >> 12) as u32);

        st |= ST_DRIVER_OK; outb(io + L_STATUS, st);

        let cap = inl(io + L_DEVCFG) as u64 | ((inl(io + L_DEVCFG + 4) as u64) << 32);
        if cap == 0 { log("[VIRTIO-BLK] zero capacity\r\n"); return None; }
        Some(Dev {
            modern: false, io_base: io, notify_addr: 0, qsize: qs,
            avail_idx: 0, last_used: 0, capacity: cap,
            flush: guest & F_FLUSH != 0, read_only: host & F_RO != 0, broken: false,
        })
    }
}

// ─── Request path ─────────────────────────────────────────────────────────

/// Run one request: header, optional data buffer, status.  `dev_writes`:
/// the device writes into the data buffer (a read request).
unsafe fn request(idx: usize, ty: u32, sector: u64, data_len: u32, dev_writes: bool) -> bool {
    let d = &mut DEVS[idx];
    if d.broken { return false; }

    let qbase = core::ptr::addr_of_mut!(QMEM[idx]) as *mut u8;
    let qs = d.qsize as usize;
    let (avail_off, used_off) = queue_layout(qs);

    // Header + status
    let hdr = core::ptr::addr_of_mut!(HDR) as *mut u8;
    write_volatile(hdr as *mut u32, ty);
    write_volatile(hdr.add(4) as *mut u32, 0);
    write_volatile(hdr.add(8) as *mut u64, sector);
    let st = core::ptr::addr_of_mut!(STATUS) as *mut u8;
    write_volatile(st, 0xFF);

    let hdr_p = virt_to_phys(hdr as usize);
    let st_p = virt_to_phys(st as usize);
    let data_p = virt_to_phys(core::ptr::addr_of!(DATA) as usize);

    // Descriptors: 0 = header, 1 = data (optional), 2 = status
    let desc = qbase as *mut u64; // each descriptor = 16 bytes: addr u64, len u32, flags u16, next u16
    let put = |i: usize, addr: u64, len: u32, flags: u16, next: u16| {
        let p = (desc as usize + i * 16) as *mut u8;
        write_volatile(p as *mut u64, addr);
        write_volatile(p.add(8) as *mut u32, len);
        write_volatile(p.add(12) as *mut u16, flags);
        write_volatile(p.add(14) as *mut u16, next);
    };
    if data_len > 0 {
        put(0, hdr_p, 16, D_NEXT, 1);
        put(1, data_p, data_len, D_NEXT | if dev_writes { D_WRITE } else { 0 }, 2);
    } else {
        put(0, hdr_p, 16, D_NEXT, 2);
    }
    put(2, st_p, 1, D_WRITE, 0);

    // Publish in the avail ring and kick
    let avail = qbase.add(avail_off);
    let slot = (d.avail_idx as usize) % qs;
    write_volatile(avail.add(4 + 2 * slot) as *mut u16, 0);
    fence(Ordering::SeqCst);
    d.avail_idx = d.avail_idx.wrapping_add(1);
    write_volatile(avail.add(2) as *mut u16, d.avail_idx);
    fence(Ordering::SeqCst);
    if d.modern { w16(d.notify_addr, 0); } else { outw(d.io_base + L_QUEUE_NOTIFY, 0); }

    // Poll the used ring (bounded)
    let used_idx_p = qbase.add(used_off + 2) as *const u16;
    let t0 = now_us();
    loop {
        if read_volatile(used_idx_p) != d.last_used { break; }
        if now_us().wrapping_sub(t0) >= 5_000_000 {
            log("[VIRTIO-BLK] request timed out, disabling disk\r\n");
            d.broken = true;
            return false;
        }
        core::arch::asm!("pause");
    }
    fence(Ordering::SeqCst);
    d.last_used = d.last_used.wrapping_add(1);

    let status = read_volatile(st);
    if status != 0 {
        log("[VIRTIO-BLK] request failed, status=");
        log_dec(status as u64);
        log("\r\n");
        return false;
    }
    true
}

// ─── Public API ───────────────────────────────────────────────────────────

pub fn drive_count() -> usize { unsafe { DEV_COUNT } }

pub fn drive_info(i: usize) -> Option<VirtioInfo> {
    unsafe {
        if i >= DEV_COUNT { return None; }
        let d = &DEVS[i];
        let mut model = [0u8; 41];
        let name: &[u8] = if d.modern { b"virtio-blk (modern)" } else { b"virtio-blk (legacy)" };
        model[..name.len()].copy_from_slice(name);
        Some(VirtioInfo { sectors: d.capacity, size_mb: d.capacity >> 11, model, read_only: d.read_only })
    }
}

pub fn read_sectors(i: usize, lba: u64, count: u32, buf: &mut [u8]) -> bool {
    unsafe {
        if i >= DEV_COUNT { return false; }
        if buf.len() < count as usize * 512 { return false; }
        if lba.checked_add(count as u64).map_or(true, |e| e > DEVS[i].capacity) { return false; }
        let mut done = 0u32;
        while done < count {
            let n = (count - done).min(CHUNK_SECTORS);
            if !request(i, T_IN, lba + done as u64, n * 512, true) { return false; }
            let src = core::ptr::addr_of!(DATA) as *const u8;
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr().add(done as usize * 512), n as usize * 512);
            done += n;
        }
        true
    }
}

pub fn write_sectors(i: usize, lba: u64, count: u32, data: &[u8]) -> bool {
    unsafe {
        if i >= DEV_COUNT { return false; }
        if data.len() < count as usize * 512 { return false; }
        if DEVS[i].read_only { return false; }
        if lba.checked_add(count as u64).map_or(true, |e| e > DEVS[i].capacity) { return false; }
        let mut done = 0u32;
        while done < count {
            let n = (count - done).min(CHUNK_SECTORS);
            let dst = core::ptr::addr_of_mut!(DATA) as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr().add(done as usize * 512), dst, n as usize * 512);
            if !request(i, T_OUT, lba + done as u64, n * 512, false) { return false; }
            done += n;
        }
        true
    }
}

/// Flush the device write cache (no-op success when the device has none).
pub fn flush(i: usize) -> bool {
    unsafe {
        if i >= DEV_COUNT { return false; }
        if !DEVS[i].flush { return true; }
        request(i, T_FLUSH, 0, 0, false)
    }
}
