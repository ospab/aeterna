/*
 * AHCI (Advanced Host Controller Interface) SATA driver for AETERNA
 *
 * Supports:
 *   Any PCI function class=0x01 (Mass Storage), subclass=0x06 (SATA),
 *   prog-if=0x01 (AHCI 1.0), on any bus/device/function (q35's ICH9 AHCI
 *   lives at 00:1f.2, VMware's SATA controller sits behind a bridge).
 *
 * Works with:
 *   QEMU:      -machine q35 (built-in ICH9 AHCI) or -device ahci / ich9-ahci
 *   VMware:    SATA controller (AHCI mode)
 *   Bare metal: Intel / AMD AHCI controllers
 *
 * Implements:
 *   - BIOS/OS handoff, HBA reset, staggered spin-up, COMRESET fallback
 *   - Port detection (DET=3), ATA signature check (ATAPI/PM/SEMB skipped)
 *   - IDENTIFY, READ/WRITE DMA (EXT), FLUSH CACHE (EXT)
 *   - 48-bit LBA with 28-bit fallback, transfers chunked to the PRD limits
 *   - Task-file error detection, timeouts and port recovery
 *   - One command slot per port (polling, no interrupts, no NCQ)
 */
#![allow(dead_code)]
use core::ptr;
use core::sync::atomic::{fence, Ordering};

use crate::mm::r#virtual::{self as vmm, FLAG_NX, FLAG_PCD, FLAG_PWT, FLAG_WRITABLE};

// ─── PCI class codes ──────────────────────────────────────────────────────
const PCI_CLASS_STORAGE: u8  = 0x01;
const PCI_SUBCLASS_SATA: u8  = 0x06;
const PCI_PROGIF_AHCI:   u8  = 0x01;

// ─── AHCI HBA registers (offset from ABAR) ────────────────────────────────
const HBA_CAP:  u32 = 0x00; // Host Capabilities
const HBA_GHC:  u32 = 0x04; // Global Host Control
const HBA_IS:   u32 = 0x08; // Interrupt Status
const HBA_PI:   u32 = 0x0C; // Ports Implemented bitmask
const HBA_VS:   u32 = 0x10; // Version
const HBA_CAP2: u32 = 0x24; // Host Capabilities Extended
const HBA_BOHC: u32 = 0x28; // BIOS/OS Handoff Control and Status

const CAP_S64A: u32 = 1 << 31; // 64-bit addressing
const CAP_SSS:  u32 = 1 << 27; // Staggered spin-up
const CAP2_BOH: u32 = 1 << 0;  // BIOS/OS handoff supported

const BOHC_BOS: u32 = 1 << 0;  // BIOS owned semaphore
const BOHC_OOS: u32 = 1 << 1;  // OS owned semaphore
const BOHC_BB:  u32 = 1 << 4;  // BIOS busy

// Global Host Control bits
const GHC_AE: u32 = 1 << 31; // AHCI Enable
const GHC_IE: u32 = 1 << 1;  // Interrupt Enable
const GHC_HR: u32 = 1 << 0;  // HBA Reset

// Per-port registers (offset = PORT_BASE_OFFSET + port * PORT_SIZE)
const PORT_BASE_OFFSET: u32 = 0x100;
const PORT_SIZE:        u32 = 0x80;

const PORT_CLB:  u32 = 0x00; // Command List Base Address (low)
const PORT_CLBU: u32 = 0x04; // Command List Base Address (high)
const PORT_FB:   u32 = 0x08; // FIS Base Address (low)
const PORT_FBU:  u32 = 0x0C; // FIS Base Address (high)
const PORT_IS:   u32 = 0x10; // Interrupt Status
const PORT_IE:   u32 = 0x14; // Interrupt Enable
const PORT_CMD:  u32 = 0x18; // Command and Status
const PORT_TFD:  u32 = 0x20; // Task File Data
const PORT_SIG:  u32 = 0x24; // Signature
const PORT_SSTS: u32 = 0x28; // SATA Status (SCR0)
const PORT_SCTL: u32 = 0x2C; // SATA Control (SCR2)
const PORT_SERR: u32 = 0x30; // SATA Error (SCR1)
const PORT_CI:   u32 = 0x38; // Command Issue

// PORT_CMD bits
const PORT_CMD_ST:  u32 = 1 << 0;  // Start
const PORT_CMD_SUD: u32 = 1 << 1;  // Spin-Up Device
const PORT_CMD_POD: u32 = 1 << 2;  // Power On Device
const PORT_CMD_FRE: u32 = 1 << 4;  // FIS Receive Enable
const PORT_CMD_FR:  u32 = 1 << 14; // FIS Receive Running
const PORT_CMD_CR:  u32 = 1 << 15; // Command List Running
const PORT_CMD_ICC_MASK:   u32 = 0xF << 28;
const PORT_CMD_ICC_ACTIVE: u32 = 1 << 28;

// PORT_IS error bits (TFES | HBFS | HBDS | IFS)
const PORT_IS_TFES: u32 = 1 << 30;
const PORT_IS_ERR_MASK: u32 = (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27);

// PORT_TFD status bits
const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;

// PORT_SSTS
const SSTS_DET_PRESENT: u32 = 0x3;

// Device signatures
const SIG_ATA:   u32 = 0x0000_0101;
const SIG_ATAPI: u32 = 0xEB14_0101;
const SIG_SEMB:  u32 = 0xC33C_0101;
const SIG_PM:    u32 = 0x9669_0101;

// ATA command codes
const ATA_CMD_READ_DMA:       u8 = 0xC8; // 28-bit LBA
const ATA_CMD_WRITE_DMA:      u8 = 0xCA;
const ATA_CMD_READ_DMA_EX:    u8 = 0x25; // 48-bit LBA
const ATA_CMD_WRITE_DMA_EX:   u8 = 0x35;
const ATA_CMD_FLUSH_CACHE:    u8 = 0xE7;
const ATA_CMD_FLUSH_CACHE_EX: u8 = 0xEA;
const ATA_CMD_IDENTIFY:       u8 = 0xEC;

// FIS types
const FIS_TYPE_REG_H2D: u8 = 0x27;

const SECTOR_SIZE: usize = 512;

// Uncached MMIO window for ABARs (one 64 KiB slot per controller)
const AHCI_UC_VIRT_BASE: u64 = 0xFFFF_FF10_0000_0000;
const AHCI_UC_SLOT:      u64 = 0x1_0000;
const AHCI_ABAR_SPAN:    u64 = 0x1100; // generic regs + 32 ports

const MAX_CTRLS: usize = 4;
const MAX_ACTIVE_PORTS: usize = 8;

// Timeouts (microseconds)
const T_STOP_US:     u64 = 500_000;
const T_LINK_US:     u64 = 20_000;
const T_COMRESET_US: u64 = 1_000_000;
const T_BUSY_US:     u64 = 2_000_000;
const T_CMD_US:      u64 = 10_000_000;

// Bounce buffer: 256 sectors per command
const DATA_BUF_SIZE: usize = 128 * 1024;
const BOUNCE_SECTORS: u32 = (DATA_BUF_SIZE / SECTOR_SIZE) as u32;
// One PRD entry covers at most 4 MiB → 8192 sectors per zero-copy command
const DMA_MAX_SECTORS: u32 = 8192;

// ─── DMA structures ───────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct CmdHeader {
    flags: u16, // [4:0]=CFL (dwords), bit 6=W
    prdtl: u16, // PRD table length (entries)
    prdbc: u32, // PRD byte count (written by HBA)
    ctba_lo: u32,
    ctba_hi: u32,
    _rsv: [u32; 4],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct PrdEntry {
    dba_lo: u32,
    dba_hi: u32,
    _rsv: u32,
    dbc: u32, // byte count - 1 (bit 0 must be 1), bit 31 = IOC
}

/// Command table: must be 128-byte aligned (CTBA bits 6:0 are reserved).
#[repr(C, align(128))]
#[derive(Copy, Clone)]
struct CmdTable {
    cfis: [u8; 64],
    acmd: [u8; 16],
    _rsv: [u8; 48],
    prdt: [PrdEntry; 1],
}

/// Received-FIS area: 256 bytes, 256-byte aligned.
#[repr(C, align(256))]
#[derive(Copy, Clone)]
struct FisArea([u8; 256]);

/// Command list: 32 headers, 1 KiB aligned.
#[repr(C, align(1024))]
#[derive(Copy, Clone)]
struct PortCmdList([CmdHeader; 32]);

#[repr(C, align(4096))]
struct DataBuf([u8; DATA_BUF_SIZE]);

const EMPTY_HDR: CmdHeader = CmdHeader { flags: 0, prdtl: 0, prdbc: 0, ctba_lo: 0, ctba_hi: 0, _rsv: [0; 4] };
const EMPTY_PRD: PrdEntry = PrdEntry { dba_lo: 0, dba_hi: 0, _rsv: 0, dbc: 0 };

// These live in the kernel image (physically contiguous); x86 DMA is cache
// coherent, so write-back memory is fine for descriptors and buffers.
static mut CMD_LISTS: [PortCmdList; MAX_ACTIVE_PORTS] = [PortCmdList([EMPTY_HDR; 32]); MAX_ACTIVE_PORTS];
static mut FIS_AREAS: [FisArea; MAX_ACTIVE_PORTS] = [FisArea([0u8; 256]); MAX_ACTIVE_PORTS];
static mut CMD_TABLES: [CmdTable; MAX_ACTIVE_PORTS] = [CmdTable {
    cfis: [0u8; 64], acmd: [0u8; 16], _rsv: [0u8; 48], prdt: [EMPTY_PRD],
}; MAX_ACTIVE_PORTS];
static mut DATA_BUF: DataBuf = DataBuf([0u8; DATA_BUF_SIZE]);

// ─── Global state ─────────────────────────────────────────────────────────
#[derive(Copy, Clone)]
pub struct AhciDrive {
    pub present:   bool,
    pub ctrl:      u8,   // controller index into HBAS
    pub port_idx:  u8,   // HBA port index (0-31)
    pub alloc_idx: u8,   // slot in the static DMA arrays
    pub lba48:     bool,
    pub sectors:   u64,
    pub size_mb:   u64,
    pub model:     [u8; 41],
}

static mut DRIVES: [AhciDrive; MAX_ACTIVE_PORTS] = [AhciDrive {
    present: false, ctrl: 0, port_idx: 0, alloc_idx: 0, lba48: false,
    sectors: 0, size_mb: 0, model: [0u8; 41],
}; MAX_ACTIVE_PORTS];

static mut DRIVE_COUNT: usize = 0;
static mut HBAS: [usize; MAX_CTRLS] = [0; MAX_CTRLS];
static mut HBA_CAPS: [u32; MAX_CTRLS] = [0; MAX_CTRLS];
static mut HBA_COUNT: usize = 0;
static mut INITIALIZED: bool = false;

// ─── MMIO helpers ─────────────────────────────────────────────────────────
#[inline]
fn hba_read(c: usize, off: u32) -> u32 {
    unsafe { ptr::read_volatile((HBAS[c] + off as usize) as *const u32) }
}
#[inline]
fn hba_write(c: usize, off: u32, val: u32) {
    unsafe { ptr::write_volatile((HBAS[c] + off as usize) as *mut u32, val) }
}
#[inline]
fn port_read(c: usize, port: u32, reg: u32) -> u32 {
    hba_read(c, PORT_BASE_OFFSET + port * PORT_SIZE + reg)
}
#[inline]
fn port_write(c: usize, port: u32, reg: u32, val: u32) {
    hba_write(c, PORT_BASE_OFFSET + port * PORT_SIZE + reg, val)
}

// ─── Utility ──────────────────────────────────────────────────────────────
fn virt_to_phys(vaddr: usize) -> u64 {
    // Kernel-image statics: phys = virt - (kernel virt base - kernel phys base)
    let offset = crate::arch::x86_64::boot::kernel_virt_offset();
    (vaddr as u64).wrapping_sub(offset)
}

#[inline]
fn now_us() -> u64 { crate::arch::x86_64::tsc::tsc_stamp_us() }

fn sleep_us(us: u64) {
    let start = now_us();
    while now_us().wrapping_sub(start) < us {
        unsafe { core::arch::asm!("pause"); }
    }
}

/// Poll `cond` until it returns true or `timeout_us` elapses.
fn wait_until<F: FnMut() -> bool>(timeout_us: u64, mut cond: F) -> bool {
    let start = now_us();
    loop {
        if cond() { return true; }
        if now_us().wrapping_sub(start) >= timeout_us { return cond(); }
        for _ in 0..64 { unsafe { core::arch::asm!("pause"); } }
    }
}

fn log(s: &str) { crate::arch::x86_64::serial::write_str(s); }

// ─── PCI scan ─────────────────────────────────────────────────────────────
pub fn init() -> usize {
    unsafe {
        if INITIALIZED { return DRIVE_COUNT; }
        DRIVE_COUNT = 0;
        HBA_COUNT = 0;
    }

    for bus in 0u16..256 {
        let bus = bus as u8;
        for dev in 0u8..32 {
            if crate::pci::vendor_id(bus, dev, 0) == 0xFFFF { continue; }
            let nfunc = if crate::pci::header_type(bus, dev, 0) & 0x80 != 0 { 8 } else { 1 };
            for func in 0u8..nfunc {
                if crate::pci::vendor_id(bus, dev, func) == 0xFFFF { continue; }
                let (class, subclass, prog_if) = crate::pci::class_code(bus, dev, func);
                if class == PCI_CLASS_STORAGE && subclass == PCI_SUBCLASS_SATA
                    && prog_if == PCI_PROGIF_AHCI
                {
                    if unsafe { HBA_COUNT } >= MAX_CTRLS { continue; }
                    init_controller(bus, dev, func);
                }
            }
        }
    }

    unsafe {
        INITIALIZED = HBA_COUNT > 0;
        log("[AHCI] ");
        serial_dec(HBA_COUNT as u64);
        log(" controller(s), ");
        serial_dec(DRIVE_COUNT as u64);
        log(" SATA disk(s)\r\n");
        DRIVE_COUNT
    }
}

fn init_controller(bus: u8, dev: u8, func: u8) {
    log("[AHCI] Controller ");
    serial_hex8(bus); log(":"); serial_hex8(dev); log("."); serial_dec(func as u64);
    log(" id=");
    serial_hex16(crate::pci::vendor_id(bus, dev, func));
    log(":");
    serial_hex16(crate::pci::device_id(bus, dev, func));

    // Memory space + bus master; mask INTx (we poll)
    let cmd = crate::pci::command(bus, dev, func);
    crate::pci::set_command(bus, dev, func, cmd | 0x0006 | 0x0400);

    // ABAR = BAR5 (always 32-bit memory BAR)
    let bar5 = crate::pci::config_read32(bus, dev, func, 0x24);
    let abar_phys = (bar5 & 0xFFFF_FFF0) as u64;
    log(" ABAR=0x"); serial_hex32(abar_phys as u32); log("\r\n");
    if bar5 & 1 != 0 || abar_phys == 0 {
        log("[AHCI]   ABAR not assigned, skipping\r\n");
        return;
    }

    // Map the ABAR uncached (PCD|PWT) into this controller's slot
    let ci = unsafe { HBA_COUNT };
    let slot_va = AHCI_UC_VIRT_BASE + ci as u64 * AHCI_UC_SLOT;
    let page_off = abar_phys & 0xFFF;
    let pages = (page_off + AHCI_ABAR_SPAN + 0xFFF) / 0x1000;
    for p in 0..pages {
        if !vmm::map_page_current(slot_va + p * 0x1000, (abar_phys & !0xFFF) + p * 0x1000,
                                  FLAG_WRITABLE | FLAG_PCD | FLAG_PWT | FLAG_NX) {
            log("[AHCI]   failed to map ABAR\r\n");
            return;
        }
    }
    unsafe {
        HBAS[ci] = (slot_va + page_off) as usize;
        HBA_COUNT += 1;
    }

    if !init_hba(ci) {
        log("[AHCI]   HBA init failed\r\n");
    }
}

fn bios_handoff(c: usize) {
    if hba_read(c, HBA_CAP2) & CAP2_BOH == 0 { return; }
    let bohc = hba_read(c, HBA_BOHC);
    if bohc & BOHC_BOS == 0 { return; }
    log("[AHCI]   BIOS/OS handoff\r\n");
    hba_write(c, HBA_BOHC, bohc | BOHC_OOS);
    // BIOS must clear BOS within 25 ms; if it sets BB, give it up to 2 s
    wait_until(25_000, || hba_read(c, HBA_BOHC) & BOHC_BOS == 0);
    if hba_read(c, HBA_BOHC) & BOHC_BB != 0 {
        wait_until(2_000_000, || hba_read(c, HBA_BOHC) & BOHC_BB == 0);
    }
}

fn init_hba(c: usize) -> bool {
    bios_handoff(c);

    // AHCI mode on, then full HBA reset (clears all port state)
    hba_write(c, HBA_GHC, hba_read(c, HBA_GHC) | GHC_AE);
    let pi_before = hba_read(c, HBA_PI);
    hba_write(c, HBA_GHC, hba_read(c, HBA_GHC) | GHC_HR);
    if !wait_until(1_000_000, || hba_read(c, HBA_GHC) & GHC_HR == 0) {
        log("[AHCI]   HBA reset timeout\r\n");
        return false;
    }
    hba_write(c, HBA_GHC, (hba_read(c, HBA_GHC) | GHC_AE) & !GHC_IE);
    // Some firmware-initialised HBAs need PI rewritten after reset
    if hba_read(c, HBA_PI) == 0 && pi_before != 0 {
        hba_write(c, HBA_PI, pi_before);
    }
    hba_write(c, HBA_IS, 0xFFFF_FFFF);

    let cap = hba_read(c, HBA_CAP);
    unsafe { HBA_CAPS[c] = cap; }
    let pi = hba_read(c, HBA_PI);
    let vs = hba_read(c, HBA_VS);
    log("[AHCI]   VS=0x"); serial_hex32(vs);
    log(" CAP=0x"); serial_hex32(cap);
    log(" PI=0x"); serial_hex32(pi);
    log("\r\n");

    // Spin up every implemented port (staggered spin-up HBAs leave them
    // off after reset), then let links settle once for all ports in
    // parallel: wait while any port still reports DET=1 (device seen,
    // PHY not up yet), bounded to 1 s. Empty ports (DET=0) cost nothing.
    if cap & CAP_SSS != 0 {
        for port in 0u32..32 {
            if pi & (1 << port) == 0 { continue; }
            let cmd = port_read(c, port, PORT_CMD);
            port_write(c, port, PORT_CMD, cmd | PORT_CMD_SUD | PORT_CMD_POD);
        }
    }
    sleep_us(10_000);
    let settled = wait_until(1_000_000, || {
        (0u32..32).all(|p| pi & (1 << p) == 0 || det(c, p) != 1)
    });
    if !settled {
        log("[AHCI]   link settle timeout (some port stuck at DET=1)\r\n");
    }

    for port in 0u32..32 {
        if pi & (1 << port) == 0 { continue; }
        if unsafe { DRIVE_COUNT } >= MAX_ACTIVE_PORTS { break; }
        probe_port(c, port);
    }
    true
}

fn stop_port(c: usize, port: u32) -> bool {
    let cmd = port_read(c, port, PORT_CMD);
    if cmd & PORT_CMD_ST != 0 {
        port_write(c, port, PORT_CMD, cmd & !PORT_CMD_ST);
    }
    let ok_cr = wait_until(T_STOP_US, || port_read(c, port, PORT_CMD) & PORT_CMD_CR == 0);
    let cmd = port_read(c, port, PORT_CMD);
    if cmd & PORT_CMD_FRE != 0 {
        port_write(c, port, PORT_CMD, cmd & !PORT_CMD_FRE);
    }
    let ok_fr = wait_until(T_STOP_US, || port_read(c, port, PORT_CMD) & PORT_CMD_FR == 0);
    ok_cr && ok_fr
}

fn start_port(c: usize, port: u32) {
    wait_until(T_STOP_US, || port_read(c, port, PORT_CMD) & PORT_CMD_CR == 0);
    let cmd = port_read(c, port, PORT_CMD);
    port_write(c, port, PORT_CMD, cmd | PORT_CMD_FRE | PORT_CMD_ST);
}

fn det(c: usize, port: u32) -> u32 { port_read(c, port, PORT_SSTS) & 0xF }

/// COMRESET via PxSCTL.DET. Port must be stopped (ST=0).
fn comreset(c: usize, port: u32) -> bool {
    let sctl = port_read(c, port, PORT_SCTL);
    port_write(c, port, PORT_SCTL, (sctl & !0xF) | 0x1);
    sleep_us(2_000); // spec: hold at least 1 ms
    port_write(c, port, PORT_SCTL, sctl & !0xF);
    let ok = wait_until(T_COMRESET_US, || det(c, port) == SSTS_DET_PRESENT);
    port_write(c, port, PORT_SERR, 0xFFFF_FFFF);
    ok
}

fn probe_port(c: usize, port: u32) {
    let ai = unsafe { DRIVE_COUNT };
    let cap = unsafe { HBA_CAPS[c] };

    if !stop_port(c, port) {
        log("[AHCI]   port "); serial_dec(port as u64); log(": engine won't stop\r\n");
        return;
    }

    // Command list / FIS receive area
    let cl_phys = virt_to_phys(unsafe { ptr::addr_of!(CMD_LISTS[ai]) as usize });
    let fb_phys = virt_to_phys(unsafe { ptr::addr_of!(FIS_AREAS[ai]) as usize });
    let ct_phys = virt_to_phys(unsafe { ptr::addr_of!(CMD_TABLES[ai]) as usize });
    let buf_phys = virt_to_phys(unsafe { ptr::addr_of!(DATA_BUF) as usize });
    if cap & CAP_S64A == 0 && (cl_phys | fb_phys | ct_phys | buf_phys) >> 32 != 0 {
        log("[AHCI]   DMA memory above 4 GiB but HBA is 32-bit only\r\n");
        return;
    }
    unsafe {
        let cl = &mut *ptr::addr_of_mut!(CMD_LISTS[ai]);
        for h in cl.0.iter_mut() { *h = EMPTY_HDR; }
        cl.0[0].ctba_lo = ct_phys as u32;
        cl.0[0].ctba_hi = (ct_phys >> 32) as u32;
        (*ptr::addr_of_mut!(FIS_AREAS[ai])).0 = [0u8; 256];
    }
    fence(Ordering::SeqCst);
    port_write(c, port, PORT_CLB,  cl_phys as u32);
    port_write(c, port, PORT_CLBU, (cl_phys >> 32) as u32);
    port_write(c, port, PORT_FB,   fb_phys as u32);
    port_write(c, port, PORT_FBU,  (fb_phys >> 32) as u32);
    port_write(c, port, PORT_IE, 0);

    // Power on / spin up (staggered spin-up HBAs leave devices off), FIS receive on
    let mut cmd = port_read(c, port, PORT_CMD) | PORT_CMD_FRE;
    if cap & CAP_SSS != 0 { cmd |= PORT_CMD_SUD | PORT_CMD_POD; }
    port_write(c, port, PORT_CMD, cmd);
    wait_until(T_STOP_US, || port_read(c, port, PORT_CMD) & PORT_CMD_FR != 0);

    // Link up?
    wait_until(T_LINK_US, || det(c, port) == SSTS_DET_PRESENT);
    let d = det(c, port);
    if d == 0 || d == 4 {
        return; // nothing attached / PHY offline
    }
    if d != SSTS_DET_PRESENT {
        // Device detected but no PHY communication: COMRESET once
        let cmd = port_read(c, port, PORT_CMD);
        port_write(c, port, PORT_CMD, cmd & !PORT_CMD_FRE);
        wait_until(T_STOP_US, || port_read(c, port, PORT_CMD) & PORT_CMD_FR == 0);
        let ok = comreset(c, port);
        port_write(c, port, PORT_CMD, port_read(c, port, PORT_CMD) | PORT_CMD_FRE);
        if !ok {
            log("[AHCI]   port "); serial_dec(port as u64); log(": no link after COMRESET\r\n");
            return;
        }
    }

    // Wake the link if it is in a low-power state
    let ipm = (port_read(c, port, PORT_SSTS) >> 8) & 0xF;
    if ipm != 1 {
        let cmd = port_read(c, port, PORT_CMD);
        port_write(c, port, PORT_CMD, (cmd & !PORT_CMD_ICC_MASK) | PORT_CMD_ICC_ACTIVE);
        wait_until(T_LINK_US, || (port_read(c, port, PORT_SSTS) >> 8) & 0xF == 1);
    }

    port_write(c, port, PORT_SERR, 0xFFFF_FFFF);
    port_write(c, port, PORT_IS, 0xFFFF_FFFF);

    // Wait for the device's initial D2H FIS (clears BSY, latches signature)
    if !wait_until(T_BUSY_US, || port_read(c, port, PORT_TFD) & (TFD_BSY | TFD_DRQ) == 0) {
        log("[AHCI]   port "); serial_dec(port as u64); log(": BSY stuck, COMRESET\r\n");
        let cmd = port_read(c, port, PORT_CMD);
        port_write(c, port, PORT_CMD, cmd & !PORT_CMD_FRE);
        wait_until(T_STOP_US, || port_read(c, port, PORT_CMD) & PORT_CMD_FR == 0);
        comreset(c, port);
        port_write(c, port, PORT_CMD, port_read(c, port, PORT_CMD) | PORT_CMD_FRE);
        if !wait_until(T_BUSY_US, || port_read(c, port, PORT_TFD) & (TFD_BSY | TFD_DRQ) == 0) {
            log("[AHCI]   port "); serial_dec(port as u64); log(": device not ready\r\n");
            stop_port(c, port);
            return;
        }
    }

    let sig = port_read(c, port, PORT_SIG);
    log("[AHCI]   port "); serial_dec(port as u64);
    log(": SSTS=0x"); serial_hex32(port_read(c, port, PORT_SSTS));
    log(" sig=0x"); serial_hex32(sig);

    match sig {
        SIG_ATAPI => { log(" (ATAPI, skipped)\r\n"); stop_port(c, port); return; }
        SIG_SEMB  => { log(" (SEMB, skipped)\r\n");  stop_port(c, port); return; }
        SIG_PM    => { log(" (port multiplier, unsupported)\r\n"); stop_port(c, port); return; }
        SIG_ATA   => log(" (ATA)\r\n"),
        _         => log(" (unknown, trying IDENTIFY)\r\n"),
    }

    port_write(c, port, PORT_SERR, 0xFFFF_FFFF);
    port_write(c, port, PORT_IS, 0xFFFF_FFFF);
    start_port(c, port);

    let drv = AhciDrive {
        present: false, ctrl: c as u8, port_idx: port as u8, alloc_idx: ai as u8,
        lba48: false, sectors: 0, size_mb: 0, model: [0u8; 41],
    };
    if identify(drv) {
        unsafe { DRIVE_COUNT += 1; }
    } else {
        log("[AHCI]   port "); serial_dec(port as u64); log(": IDENTIFY failed\r\n");
        stop_port(c, port);
    }
}

fn identify(mut drv: AhciDrive) -> bool {
    let buf_phys = virt_to_phys(unsafe { ptr::addr_of!(DATA_BUF) as usize });
    if !exec(&drv, ATA_CMD_IDENTIFY, 0, 0, buf_phys, 512, false) {
        return false;
    }

    let mut id = [0u16; 256];
    unsafe {
        let src = &(*ptr::addr_of!(DATA_BUF)).0;
        for i in 0..256 { id[i] = u16::from_le_bytes([src[i * 2], src[i * 2 + 1]]); }
    }

    let lba48 = id[83] & (1 << 10) != 0;
    let sects48 = (id[100] as u64) | ((id[101] as u64) << 16)
        | ((id[102] as u64) << 32) | ((id[103] as u64) << 48);
    let sects28 = (id[60] as u64) | ((id[61] as u64) << 16);
    drv.lba48 = lba48 && sects48 != 0;
    drv.sectors = if drv.lba48 { sects48 } else { sects28 };
    if drv.sectors == 0 { return false; }
    drv.size_mb = drv.sectors / 2048;

    // Model: words 27..46, byte-swapped ASCII
    let mut mi = 0usize;
    for w in &id[27..47] {
        for b in [(*w >> 8) as u8, (*w & 0xFF) as u8] {
            if b != 0 && mi < 40 { drv.model[mi] = b; mi += 1; }
        }
    }
    while mi > 0 && drv.model[mi - 1] == b' ' { mi -= 1; drv.model[mi] = 0; }
    drv.present = true;

    log("[AHCI]   Model: ");
    log(unsafe { core::str::from_utf8_unchecked(&drv.model[..mi]) });
    log(", "); serial_dec(drv.size_mb); log(" MiB");
    log(if drv.lba48 { ", LBA48\r\n" } else { ", LBA28\r\n" });

    unsafe { DRIVES[DRIVE_COUNT] = drv; }
    true
}

/// Recover a port after a task-file / interface error or a timeout.
fn recover_port(c: usize, port: u32) {
    let cmd = port_read(c, port, PORT_CMD);
    port_write(c, port, PORT_CMD, cmd & !PORT_CMD_ST);
    wait_until(T_STOP_US, || port_read(c, port, PORT_CMD) & PORT_CMD_CR == 0);
    port_write(c, port, PORT_SERR, 0xFFFF_FFFF);
    port_write(c, port, PORT_IS, 0xFFFF_FFFF);
    if port_read(c, port, PORT_TFD) & (TFD_BSY | TFD_DRQ) != 0 {
        let cmd = port_read(c, port, PORT_CMD);
        port_write(c, port, PORT_CMD, cmd & !PORT_CMD_FRE);
        wait_until(T_STOP_US, || port_read(c, port, PORT_CMD) & PORT_CMD_FR == 0);
        comreset(c, port);
        port_write(c, port, PORT_CMD, port_read(c, port, PORT_CMD) | PORT_CMD_FRE);
        wait_until(T_BUSY_US, || port_read(c, port, PORT_TFD) & (TFD_BSY | TFD_DRQ) == 0);
    }
    port_write(c, port, PORT_SERR, 0xFFFF_FFFF);
    port_write(c, port, PORT_IS, 0xFFFF_FFFF);
    start_port(c, port);
}

/// Build and issue one command in slot 0, poll for completion.
/// `bytes == 0` → non-data command. `count` is the ATA sector count field.
fn exec(drv: &AhciDrive, cmd: u8, lba: u64, count: u32, buf_phys: u64, bytes: u32, write: bool) -> bool {
    let c = drv.ctrl as usize;
    let port = drv.port_idx as u32;
    let ai = drv.alloc_idx as usize;

    if bytes > 0 && (buf_phys & 1 != 0 || bytes > 4 * 1024 * 1024 || bytes & 1 != 0) { return false; }
    if unsafe { HBA_CAPS[c] } & CAP_S64A == 0 && (buf_phys + bytes as u64) > 0x1_0000_0000 {
        return false;
    }

    // Device must be idle before issuing
    if port_read(c, port, PORT_TFD) & (TFD_BSY | TFD_DRQ) != 0 {
        recover_port(c, port);
        if port_read(c, port, PORT_TFD) & (TFD_BSY | TFD_DRQ) != 0 { return false; }
    }

    unsafe {
        let ct = &mut *ptr::addr_of_mut!(CMD_TABLES[ai]);
        ct.cfis = [0u8; 64];
        ct.cfis[0] = FIS_TYPE_REG_H2D;
        ct.cfis[1] = 1 << 7; // C = command
        ct.cfis[2] = cmd;
        let lba28 = matches!(cmd, ATA_CMD_READ_DMA | ATA_CMD_WRITE_DMA);
        ct.cfis[4] = lba as u8;
        ct.cfis[5] = (lba >> 8) as u8;
        ct.cfis[6] = (lba >> 16) as u8;
        ct.cfis[7] = match cmd {
            ATA_CMD_IDENTIFY => 0,
            _ if lba28 => 0x40 | ((lba >> 24) as u8 & 0x0F),
            _ => 0x40,
        };
        if !lba28 {
            ct.cfis[8]  = (lba >> 24) as u8;
            ct.cfis[9]  = (lba >> 32) as u8;
            ct.cfis[10] = (lba >> 40) as u8;
        }
        ct.cfis[12] = count as u8;
        ct.cfis[13] = (count >> 8) as u8;

        ct.prdt[0] = if bytes > 0 {
            PrdEntry {
                dba_lo: buf_phys as u32,
                dba_hi: (buf_phys >> 32) as u32,
                _rsv: 0,
                dbc: bytes - 1,
            }
        } else { EMPTY_PRD };

        let hdr = &mut (*ptr::addr_of_mut!(CMD_LISTS[ai])).0[0];
        hdr.flags = 5 | if write { 1 << 6 } else { 0 }; // CFL = 5 dwords
        hdr.prdtl = if bytes > 0 { 1 } else { 0 };
        hdr.prdbc = 0;
    }
    // Descriptors must be globally visible before the doorbell
    fence(Ordering::SeqCst);

    port_write(c, port, PORT_IS, 0xFFFF_FFFF);
    port_write(c, port, PORT_CI, 1);

    let start = now_us();
    loop {
        let is = port_read(c, port, PORT_IS);
        if is & PORT_IS_ERR_MASK != 0 {
            log("[AHCI] cmd 0x"); serial_hex8(cmd);
            log(" error IS=0x"); serial_hex32(is);
            log(" TFD=0x"); serial_hex32(port_read(c, port, PORT_TFD));
            log(" SERR=0x"); serial_hex32(port_read(c, port, PORT_SERR));
            log("\r\n");
            recover_port(c, port);
            return false;
        }
        if port_read(c, port, PORT_CI) & 1 == 0 { break; }
        if now_us().wrapping_sub(start) >= T_CMD_US {
            log("[AHCI] cmd 0x"); serial_hex8(cmd);
            log(" timeout IS=0x"); serial_hex32(is);
            log(" TFD=0x"); serial_hex32(port_read(c, port, PORT_TFD));
            log(" SERR=0x"); serial_hex32(port_read(c, port, PORT_SERR));
            log("\r\n");
            recover_port(c, port);
            return false;
        }
        for _ in 0..64 { unsafe { core::arch::asm!("pause"); } }
    }
    fence(Ordering::SeqCst);

    if port_read(c, port, PORT_TFD) & TFD_ERR != 0 {
        log("[AHCI] cmd 0x"); serial_hex8(cmd);
        log(" device error TFD=0x"); serial_hex32(port_read(c, port, PORT_TFD)); log("\r\n");
        recover_port(c, port);
        return false;
    }
    true
}

/// One DMA transfer of `n` sectors (n ≤ limit for the drive's LBA mode).
fn rw_dma(drv: &AhciDrive, lba: u64, n: u32, buf_phys: u64, write: bool) -> bool {
    if n == 0 { return true; }
    if lba + n as u64 > drv.sectors { return false; }
    let (cmd, count) = if drv.lba48 {
        (if write { ATA_CMD_WRITE_DMA_EX } else { ATA_CMD_READ_DMA_EX }, n & 0xFFFF)
    } else {
        if n > 256 || lba + n as u64 > (1 << 28) { return false; }
        (if write { ATA_CMD_WRITE_DMA } else { ATA_CMD_READ_DMA }, n & 0xFF)
    };
    exec(drv, cmd, lba, count, buf_phys, n * SECTOR_SIZE as u32, write)
}

// ─── Public API ───────────────────────────────────────────────────────────

pub fn is_initialized() -> bool { unsafe { INITIALIZED } }
pub fn drive_count() -> usize   { unsafe { DRIVE_COUNT } }

pub fn drive_info(idx: usize) -> Option<&'static AhciDrive> {
    unsafe {
        if idx < DRIVE_COUNT && DRIVES[idx].present { Some(&*ptr::addr_of!(DRIVES[idx])) } else { None }
    }
}

/// Read `count` sectors from AHCI drive `drive_idx` at LBA `lba` into `buf`.
pub fn read_sectors(drive_idx: usize, lba: u64, count: u32, buf: &mut [u8]) -> bool {
    if buf.len() < count as usize * SECTOR_SIZE { return false; }
    let d = match drive_info(drive_idx) { Some(d) => *d, None => return false };
    let bounce_phys = virt_to_phys(unsafe { ptr::addr_of!(DATA_BUF) as usize });

    let mut done = 0u32;
    while done < count {
        let n = (count - done).min(BOUNCE_SECTORS);
        if !rw_dma(&d, lba + done as u64, n, bounce_phys, false) { return false; }
        let off = done as usize * SECTOR_SIZE;
        let len = n as usize * SECTOR_SIZE;
        unsafe { buf[off..off + len].copy_from_slice(&(&(*ptr::addr_of!(DATA_BUF)).0)[..len]); }
        done += n;
    }
    true
}

/// Write `count` sectors from `data` to AHCI drive `drive_idx` at LBA `lba`.
pub fn write_sectors(drive_idx: usize, lba: u64, count: u32, data: &[u8]) -> bool {
    if data.len() < count as usize * SECTOR_SIZE { return false; }
    let d = match drive_info(drive_idx) { Some(d) => *d, None => return false };
    let bounce_phys = virt_to_phys(unsafe { ptr::addr_of!(DATA_BUF) as usize });

    let mut done = 0u32;
    while done < count {
        let n = (count - done).min(BOUNCE_SECTORS);
        let off = done as usize * SECTOR_SIZE;
        let len = n as usize * SECTOR_SIZE;
        unsafe { (&mut (*ptr::addr_of_mut!(DATA_BUF)).0)[..len].copy_from_slice(&data[off..off + len]); }
        if !rw_dma(&d, lba + done as u64, n, bounce_phys, true) { return false; }
        done += n;
    }
    true
}

/// Send FLUSH CACHE (EXT) to drain the drive's volatile write cache.
pub fn flush_cache(drive_idx: usize) -> bool {
    let d = match drive_info(drive_idx) { Some(d) => *d, None => return true };
    let cmd = if d.lba48 { ATA_CMD_FLUSH_CACHE_EX } else { ATA_CMD_FLUSH_CACHE };
    if exec(&d, cmd, 0, 0, 0, 0, false) {
        log("[AHCI] Flush cache OK\r\n");
        true
    } else {
        log("[AHCI] Flush cache failed\r\n");
        false
    }
}

/// Zero-copy DMA write from a physically contiguous buffer of at least
/// `count * 512` bytes (e.g. PMM-allocated). Returns true on success.
pub fn dma_write(drive_idx: usize, lba: u64, count: u32, buffer_phys: u64) -> bool {
    if count == 0 { return true; }
    let d = match drive_info(drive_idx) { Some(d) => *d, None => return false };
    let max = if d.lba48 { DMA_MAX_SECTORS } else { 256 };

    let mut done = 0u32;
    while done < count {
        let n = (count - done).min(max);
        let phys = buffer_phys + done as u64 * SECTOR_SIZE as u64;
        if !rw_dma(&d, lba + done as u64, n, phys, true) { return false; }
        done += n;
    }
    true
}

fn serial_hex8(v: u8) {
    let h = b"0123456789abcdef";
    crate::arch::x86_64::serial::write_byte(h[(v >> 4) as usize]);
    crate::arch::x86_64::serial::write_byte(h[(v & 0xF) as usize]);
}
fn serial_hex16(v: u16) { serial_hex8((v >> 8) as u8); serial_hex8(v as u8); }
fn serial_hex32(v: u32) { serial_hex16((v >> 16) as u16); serial_hex16(v as u16); }
fn serial_dec(mut v: u64) {
    if v == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while v > 0 { buf[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}
