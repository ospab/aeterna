/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

PCI functions for ring-3 drivers (docs/en/dev/drivers.md).

A privileged device manager (a process holding a Resource of kind PCI) lists the PCI
functions and claims one. A claim gives it a PciDevice object; from that single handle a
driver derives its BARs (MmioRegion / IoPortRange), its legacy interrupt, config space
access limited to the function, and DMA memory. The claim table keeps a device that an
in-kernel driver uses away from ring 3, and the other way round.
*/

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::core::syscall::SyscallError as E;

pub const OWNER_FREE: u8 = 0;
pub const OWNER_KERNEL: u8 = 1;
pub const OWNER_USER: u8 = 2;

const MAX: usize = 64;

static OWNER: [AtomicU8; MAX] = [const { AtomicU8::new(0) }; MAX];
/// Release callbacks of kernel drivers (fn() -> bool as usize, 0 = cannot release).
static RELEASE: [AtomicUsize; MAX] = [const { AtomicUsize::new(0) }; MAX];

/// One BAR as ring 3 sees it (24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BarInfo {
    pub base: u64,
    pub size: u64,
    /// 1 present, 2 I/O space, 4 64-bit, 8 prefetchable
    pub flags: u32,
    pub _pad: u32,
}

/// What `pci_enum` and `pci_info` return (168 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PciInfo {
    pub bdf: u16,
    pub vendor: u16,
    pub device: u16,
    pub subsys_vendor: u16,
    pub subsys_device: u16,
    pub class: u8,
    pub subclass: u8,
    pub progif: u8,
    pub revision: u8,
    pub header_type: u8,
    pub irq_line: u8,
    pub irq_pin: u8,
    /// 0 free, 1 kernel driver, 2 ring-3 driver
    pub owner: u8,
    pub msi_cap: u8,
    pub msix_cap: u8,
    pub _res: [u8; 4],
    pub bars: [BarInfo; 6],
}

pub const INFO_SIZE: usize = core::mem::size_of::<PciInfo>();

struct BarCache {
    valid: [bool; MAX],
    bars: [[BarInfo; 6]; MAX],
}

static mut BAR_CACHE: BarCache = BarCache { valid: [false; MAX], bars: [[BarInfo { base: 0, size: 0, flags: 0, _pad: 0 }; 6]; MAX] };
static mut DEFAULTS_DONE: bool = false;

pub fn bdf_of(bus: u8, dev: u8, func: u8) -> u16 {
    ((bus as u16) << 8) | ((dev as u16) << 3) | func as u16
}

fn split(bdf: u16) -> (u8, u8, u8) {
    ((bdf >> 8) as u8, ((bdf >> 3) & 0x1F) as u8, (bdf & 7) as u8)
}

pub fn index_of(bdf: u16) -> Option<usize> {
    let (b, d, f) = split(bdf);
    (0..crate::pci::device_count().min(MAX)).find(|&i| {
        crate::pci::get_device(i).map_or(false, |x| x.bus == b && x.device == d && x.function == f)
    })
}

/// Devices the kernel drives itself and cannot give away: storage, display, audio,
/// bridges, USB. NICs are claimed by the network code once it has chosen one.
fn init_defaults() {
    // SAFETY: only called with interrupts off from syscall context.
    unsafe {
        if DEFAULTS_DONE {
            return;
        }
        DEFAULTS_DONE = true;
    }
    for i in 0..crate::pci::device_count().min(MAX) {
        if let Some(d) = crate::pci::get_device(i) {
            if matches!(d.class, 0x01 | 0x03 | 0x04 | 0x06 | 0x0C) && OWNER[i].load(Ordering::Relaxed) == 0 {
                OWNER[i].store(OWNER_KERNEL, Ordering::Relaxed);
            }
        }
    }
}

/// An in-kernel driver uses the function `bdf`. `release` stops the driver and
/// leaves the device idle (None: it cannot be released).
pub fn kernel_claim(bdf: u16, release: Option<fn() -> bool>) {
    if let Some(i) = index_of(bdf) {
        OWNER[i].store(OWNER_KERNEL, Ordering::Relaxed);
        RELEASE[i].store(release.map_or(0, |f| f as usize), Ordering::Relaxed);
    }
}

pub fn count() -> usize {
    crate::pci::device_count().min(MAX)
}

fn bar_info(i: usize, d: &crate::pci::PciDevice) -> [BarInfo; 6] {
    // SAFETY: interrupts are off in syscall context; single CPU.
    let c = unsafe { &mut *core::ptr::addr_of_mut!(BAR_CACHE) };
    if !c.valid[i] {
        let mut out = [BarInfo::default(); 6];
        if d.class != 0x06 || true {
            // Header type 0 only; sizing a bridge is not needed.
            let ht = crate::pci::header_type(d.bus, d.device, d.function) & 0x7F;
            if ht == 0 {
                let mut k = 0u8;
                while k < 6 {
                    // Skip the BAR while the owner is a running kernel driver? Reading the BAR
                    // briefly writes all-ones; do it with interrupts off (we are in a syscall).
                    match crate::pci::read_bar(d.bus, d.device, d.function, k) {
                        crate::pci::BarType::Mmio { base, size, is_64bit, prefetchable } => {
                            out[k as usize] = BarInfo {
                                base,
                                size,
                                flags: 1 | if is_64bit { 4 } else { 0 } | if prefetchable { 8 } else { 0 },
                                _pad: 0,
                            };
                            if is_64bit {
                                k += 1;
                            }
                        }
                        crate::pci::BarType::Io { base, size } => {
                            out[k as usize] = BarInfo { base: base as u64, size: size as u64, flags: 1 | 2, _pad: 0 };
                        }
                        crate::pci::BarType::None => {}
                    }
                    k += 1;
                }
            }
        }
        c.bars[i] = out;
        c.valid[i] = true;
    }
    c.bars[i]
}

pub fn info(index: usize) -> Option<PciInfo> {
    crate::core::scheduler::without_interrupts(|| {
        init_defaults();
        if index >= count() {
            return None;
        }
        let d = crate::pci::get_device(index)?;
        let (b, dv, f) = (d.bus, d.device, d.function);
        let bars = bar_info(index, d);
        Some(PciInfo {
            bdf: bdf_of(b, dv, f),
            vendor: d.vendor_id,
            device: d.device_id,
            subsys_vendor: crate::pci::config_read16(b, dv, f, 0x2C),
            subsys_device: crate::pci::config_read16(b, dv, f, 0x2E),
            class: d.class,
            subclass: d.subclass,
            progif: d.progif,
            revision: crate::pci::config_read8(b, dv, f, 0x08),
            header_type: crate::pci::header_type(b, dv, f),
            irq_line: crate::pci::interrupt_line(b, dv, f),
            irq_pin: crate::pci::interrupt_pin(b, dv, f),
            owner: OWNER[index].load(Ordering::Relaxed),
            msi_cap: crate::pci::find_capability(b, dv, f, crate::pci::CAP_MSI).unwrap_or(0),
            msix_cap: crate::pci::find_capability(b, dv, f, crate::pci::CAP_MSIX).unwrap_or(0),
            _res: [0; 4],
            bars,
        })
    })
}

pub fn info_bdf(bdf: u16) -> Option<PciInfo> {
    info(index_of(bdf)?)
}

/// Claim `bdf` for ring 3. `force`: ask an in-kernel driver to let go first.
pub fn claim_user(bdf: u16, force: bool) -> Result<(), i64> {
    let i = index_of(bdf).ok_or(E::NotFound as i64)?;
    crate::core::scheduler::without_interrupts(init_defaults);
    match OWNER[i].load(Ordering::Relaxed) {
        OWNER_USER => return Err(E::Busy as i64),
        OWNER_KERNEL => {
            if !force {
                return Err(E::Busy as i64);
            }
            let f = RELEASE[i].load(Ordering::Relaxed);
            if f == 0 {
                return Err(E::NotSupported as i64);
            }
            // SAFETY: stored from a `fn() -> bool` in kernel_claim.
            let release: fn() -> bool = unsafe { core::mem::transmute(f) };
            if !release() {
                return Err(E::NotSupported as i64);
            }
            RELEASE[i].store(0, Ordering::Relaxed);
        }
        _ => {}
    }
    OWNER[i].store(OWNER_USER, Ordering::Relaxed);
    Ok(())
}

/// The last handle to the PciDevice object is gone: the function is idle again.
/// Called with the object lock held; touches only atomics and config space.
pub fn user_released(bdf: u16) {
    if let Some(i) = index_of(bdf) {
        let (b, d, f) = split(bdf);
        // Stop DMA: clear bus master and the interrupt-line enable.
        let cmd = crate::pci::command(b, d, f);
        crate::pci::set_command(b, d, f, (cmd & !0x0004) | 0x0400);
        OWNER[i].store(OWNER_FREE, Ordering::Relaxed);
    }
}

/// Config-space access for a claimed function. `size` 1, 2 or 4.
pub fn cfg_read(bdf: u16, off: u64, size: u64) -> Result<u32, i64> {
    check_cfg(off, size)?;
    let (b, d, f) = split(bdf);
    Ok(crate::core::scheduler::without_interrupts(|| match size {
        1 => crate::pci::config_read8(b, d, f, off as u8) as u32,
        2 => crate::pci::config_read16(b, d, f, off as u8) as u32,
        _ => crate::pci::config_read32(b, d, f, off as u8),
    }))
}

pub fn cfg_write(bdf: u16, off: u64, size: u64, val: u32) -> Result<(), i64> {
    check_cfg(off, size)?;
    // Not the identity, the BARs, the ROM base, the capability pointer.
    let end = off + size;
    let overlaps = |lo: u64, hi: u64| off < hi && end > lo;
    if overlaps(0x00, 0x04) || overlaps(0x10, 0x28) || overlaps(0x30, 0x35) {
        return Err(E::PermissionDenied as i64);
    }
    let (b, d, f) = split(bdf);
    crate::core::scheduler::without_interrupts(|| match size {
        1 => crate::pci::config_write8(b, d, f, off as u8, val as u8),
        2 => crate::pci::config_write16(b, d, f, off as u8, val as u16),
        _ => crate::pci::config_write32(b, d, f, off as u8, val),
    });
    Ok(())
}

fn check_cfg(off: u64, size: u64) -> Result<(), i64> {
    if !matches!(size, 1 | 2 | 4) || off % size != 0 || off + size > 256 {
        return Err(E::InvalidArgument as i64);
    }
    Ok(())
}

/// Other functions sharing an interrupt line with `bdf` that an in-kernel driver owns.
pub fn irq_shared_with_kernel(bdf: u16, line: u8) -> bool {
    let me = index_of(bdf);
    let mut v: Vec<usize> = Vec::new();
    for i in 0..count() {
        if Some(i) != me && OWNER[i].load(Ordering::Relaxed) == OWNER_KERNEL {
            if let Some(d) = crate::pci::get_device(i) {
                if crate::pci::interrupt_line(d.bus, d.device, d.function) == line
                    && crate::pci::interrupt_pin(d.bus, d.device, d.function) != 0
                    && !matches!(d.class, 0x06)
                {
                    v.push(i);
                }
            }
        }
    }
    !v.is_empty()
}
