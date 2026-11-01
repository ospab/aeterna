// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! libdriver: what a ring-3 driver needs, on top of liboos.
//!
//! The device manager (`devmgr`) starts a driver with two bootstrap handles:
//! handle 1 is the [`Pci`] device (exactly one PCI function), handle 2 is a channel to
//! the device manager for the ready message. From the device handle the driver gets
//! its BARs ([`Pci::bar_map`], [`Pci::bar_io`]), its interrupt ([`Pci::irq`]), config
//! space and DMA memory ([`Pci::dma_alloc`]).
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//! libdriver::driver_entry!("mydrv", main);
//! fn main(d: libdriver::Driver) -> i32 {
//!     let pci = d.pci();
//!     pci.enable_bus_master().unwrap();
//!     let regs = pci.bar_map(0).unwrap();
//!     libdriver::log!("id {:#x}", regs.read::<u32>(0));
//!     d.ready("up");
//!     0
//! }
//! ```
#![no_std]

extern crate alloc;

use alloc::string::String;
use core::fmt::Write;

use liboos::hw::{Interrupt, IoPorts};
use liboos::ipc::{Channel, Error, Handle, Message, Notification, Result, Rights};
use liboos::mem::{Mapping, MemoryRegion, Prot};

pub use liboos;

/// Raw system calls (numbers 290..=299, docs/en/syscall-abi.md).
pub mod sys {
    pub const PCI_ENUM: u64 = 290;
    pub const PCI_CLAIM: u64 = 291;
    pub const PCI_OPEN: u64 = 292;
    pub const PCI_CFG_READ: u64 = 293;
    pub const PCI_CFG_WRITE: u64 = 294;
    pub const PCI_INFO: u64 = 295;
    pub const PROC_SPAWN: u64 = 296;
    pub const FS_READDIR: u64 = 297;
    pub const KLOG_WRITE: u64 = 298;
    pub const NETDRV_CTL: u64 = 299;
    pub const MEM_CREATE_CONTIG: u64 = 243;

    pub use liboos::sys::{syscall1, syscall2, syscall3};

    #[inline(always)]
    pub unsafe fn syscall4(n: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
        let r: i64;
        core::arch::asm!("syscall", inlateout("rax") n as i64 => r, in("rdi") a1, in("rsi") a2,
            in("rdx") a3, in("r10") a4, out("rcx") _, out("r11") _, options(nostack));
        r
    }
}

/// Kernel error code to [`Error`].
pub fn err(c: i64) -> Error {
    match c {
        -2 => Error::PermissionDenied,
        -3 => Error::InvalidArgument,
        -5 => Error::Busy,
        -6 => Error::OutOfMemory,
        -7 => Error::NotSupported,
        -10 => Error::BadAddress,
        -11 => Error::BadHandle,
        -12 => Error::WrongType,
        -13 => Error::PeerClosed,
        -14 => Error::TableFull,
        -15 => Error::Timeout,
        o => Error::Other(o),
    }
}

pub(crate) fn check(r: i64) -> Result<i64> {
    if r < 0 { Err(err(r)) } else { Ok(r) }
}

// ─── Logging ─────────────────────────────────────────────────────────────────────

static mut TAG: [u8; 16] = [0; 16];
static mut TAG_LEN: usize = 0;

/// Set the tag put in front of every log line (`[e1000] ...`). Done by `driver_entry!`.
pub fn log_init(tag: &str) {
    let n = tag.len().min(16);
    // SAFETY: single-threaded process.
    unsafe {
        TAG[..n].copy_from_slice(&tag.as_bytes()[..n]);
        TAG_LEN = n;
    }
}

#[doc(hidden)]
pub fn _log(args: core::fmt::Arguments) {
    let mut s = String::new();
    // SAFETY: single-threaded process.
    let tag = unsafe { core::str::from_utf8_unchecked(&TAG[..TAG_LEN]) };
    let _ = write!(s, "[{}] ", tag);
    let _ = s.write_fmt(args);
    let b = s.as_bytes();
    let n = b.len().min(120);
    unsafe { sys::syscall3(sys::KLOG_WRITE, 0, b.as_ptr() as u64, n as u64) };
}

/// Log a line with the driver tag: to the serial log and to the kernel event log, which
/// `dmesg` shows.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::_log(format_args!($($arg)*)) };
}

// ─── PCI ─────────────────────────────────────────────────────────────────────────

/// One BAR as the kernel reports it.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct BarInfo {
    pub base: u64,
    pub size: u64,
    /// 1 present, 2 I/O space, 4 64-bit, 8 prefetchable
    pub flags: u32,
    pub _pad: u32,
}

impl BarInfo {
    pub fn present(&self) -> bool {
        self.flags & 1 != 0
    }
    pub fn is_io(&self) -> bool {
        self.flags & 2 != 0
    }
}

/// Description of a PCI function (same layout as the kernel's `PciInfo`, 168 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
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

impl PciInfo {
    pub const fn zeroed() -> PciInfo {
        PciInfo {
            bdf: 0, vendor: 0, device: 0, subsys_vendor: 0, subsys_device: 0, class: 0, subclass: 0,
            progif: 0, revision: 0, header_type: 0, irq_line: 0, irq_pin: 0, owner: 0, msi_cap: 0,
            msix_cap: 0, _res: [0; 4], bars: [BarInfo { base: 0, size: 0, flags: 0, _pad: 0 }; 6],
        }
    }
}

/// The PCI function a driver owns. Dropping the last handle idles the device.
pub struct Pci(pub Handle);

impl Pci {
    /// Wrap bootstrap handle `n`.
    pub fn from_bootstrap(n: u32) -> Pci {
        Pci(Handle::from_raw(n))
    }

    pub fn info(&self) -> Result<PciInfo> {
        let mut i = PciInfo::zeroed();
        check(unsafe { sys::syscall2(sys::PCI_INFO, self.0.raw() as u64, &mut i as *mut _ as u64) })?;
        Ok(i)
    }

    pub fn config_read(&self, off: u16, size: u8) -> Result<u32> {
        check(unsafe { sys::syscall3(sys::PCI_CFG_READ, self.0.raw() as u64, off as u64, size as u64) })
            .map(|v| v as u32)
    }

    pub fn config_write(&self, off: u16, size: u8, val: u32) -> Result<()> {
        check(unsafe { sys::syscall4(sys::PCI_CFG_WRITE, self.0.raw() as u64, off as u64, size as u64, val as u64) })
            .map(|_| ())
    }

    /// Set memory space, I/O space and bus master in the command register, and clear
    /// "interrupt disable".
    pub fn enable_bus_master(&self) -> Result<()> {
        let c = self.config_read(0x04, 2)?;
        self.config_write(0x04, 2, (c | 0x07) & !0x0400)
    }

    /// Map memory BAR `index` (uncached). The returned [`Mapping`] gives volatile
    /// register access.
    pub fn bar_map(&self, index: u8) -> Result<Mapping> {
        let h = check(unsafe { sys::syscall3(sys::PCI_OPEN, self.0.raw() as u64, 0, index as u64) })?;
        MemoryRegion(Handle::from_raw(h as u32)).map(Prot::RW)
    }

    /// I/O BAR `index`; call `enable()` on the result before IN/OUT.
    pub fn bar_io(&self, index: u8) -> Result<IoPorts> {
        let info = self.info()?;
        let b = info.bars.get(index as usize).ok_or(Error::InvalidArgument)?;
        let h = check(unsafe { sys::syscall3(sys::PCI_OPEN, self.0.raw() as u64, 1, index as u64) })?;
        Ok(IoPorts::new(Handle::from_raw(h as u32), b.base as u16, b.size as u16))
    }

    /// The device's interrupt line, with a notification already bound to it.
    pub fn irq(&self) -> Result<Irq> {
        // MSI / MSI-X first (irq_alloc_msi, call 254), then the legacy INTx line.
        let mut out = [0u32; 1];
        let r = unsafe { sys::syscall3(254, self.0.raw() as u64, 1, out.as_mut_ptr() as u64) };
        if r >= 1 && out[0] != 0 {
            return Irq::new(Interrupt(Handle::from_raw(out[0])));
        }
        let h = check(unsafe { sys::syscall3(sys::PCI_OPEN, self.0.raw() as u64, 2, 0) })?;
        Irq::new(Interrupt(Handle::from_raw(h as u32)))
    }

    /// Allocate `size` bytes (at most 4 MiB) of physically contiguous memory for DMA,
    /// zeroed and mapped read/write. `uncached` maps it with caching disabled.
    pub fn dma_alloc(&self, size: usize, uncached: bool) -> Result<Dma> {
        let h = check(unsafe {
            sys::syscall3(sys::MEM_CREATE_CONTIG, self.0.raw() as u64, size as u64, uncached as u64)
        })?;
        let region = MemoryRegion(Handle::from_raw(h as u32));
        let phys = region.phys()?;
        let map = region.map(Prot::RW)?;
        Ok(Dma { region, map, phys })
    }
}

/// Physically contiguous DMA memory, mapped in this process.
pub struct Dma {
    pub region: MemoryRegion,
    pub map: Mapping,
    phys: u64,
}

impl Dma {
    /// Physical (bus) address to program into the device.
    pub fn phys(&self) -> u64 {
        self.phys
    }
    pub fn virt(&self) -> usize {
        self.map.addr()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn as_ptr(&self) -> *mut u8 {
        self.map.as_ptr()
    }
}

/// A device interrupt delivered as a notification. Bit 1 is the interrupt; other bits can
/// be signalled by other parties (the kernel's network stack uses bit 2).
pub struct Irq {
    int: Interrupt,
    notif: Notification,
}

/// Notification bit of the device interrupt.
pub const IRQ_BIT: u32 = 1;

impl Irq {
    fn new(int: Interrupt) -> Result<Irq> {
        let notif = Notification::create()?;
        int.bind(&notif, IRQ_BIT)?;
        Ok(Irq { int, notif })
    }

    /// Unmask the line. Call once after setting up the device, and again after
    /// servicing each interrupt.
    pub fn unmask(&self) -> Result<()> {
        self.int.ack()
    }

    /// Same as [`Irq::unmask`], named after the kernel call.
    pub fn ack(&self) -> Result<()> {
        self.int.ack()
    }

    /// Sleep until a bit is set or `timeout_ticks` (100 Hz) pass. Returns the bits, 0 on
    /// a timeout.
    pub fn wait(&self, timeout_ticks: u64) -> Result<u32> {
        match self.notif.wait(timeout_ticks) {
            Ok(b) => Ok(b),
            Err(Error::Timeout) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// The notification, for APIs that signal it (`netdrv` attach).
    pub fn notification(&self) -> &Notification {
        &self.notif
    }
}

// ─── Device manager protocol ─────────────────────────────────────────────────────

/// Message tag: the driver is running (data: free text status).
pub const MSG_READY: u64 = 0x5244_5944; // "RDYD"
/// Message tag: the driver gives up (data: reason).
pub const MSG_FAILED: u64 = 0x4641_494C; // "FAIL"

/// What a driver gets at start-up.
pub struct Driver {
    name: &'static str,
    pci: Option<Pci>,
    mgr: Option<Channel>,
}

impl Driver {
    pub fn new(name: &'static str) -> Driver {
        log_init(name);
        let pci = Pci::from_bootstrap(1);
        let ok = pci.0.info().is_ok();
        let pci = if ok { Some(pci) } else { core::mem::forget(pci); None };
        let mgr = Handle::from_raw(2);
        let mgr = if mgr.info().is_ok() { Some(Channel(mgr)) } else { core::mem::forget(mgr); None };
        Driver { name, pci, mgr }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The device (bootstrap handle 1). Panics when started without one.
    pub fn pci(&self) -> &Pci {
        self.pci.as_ref().expect("started without a PCI device")
    }

    pub fn has_device(&self) -> bool {
        self.pci.is_some()
    }

    /// Tell the device manager the driver is up.
    pub fn ready(&self, status: &str) {
        self.send(MSG_READY, status);
    }

    pub fn failed(&self, why: &str) {
        self.send(MSG_FAILED, why);
    }

    fn send(&self, tag: u64, text: &str) {
        if let Some(c) = &self.mgr {
            let mut m = Message::with_data(tag, text.as_bytes());
            let _ = c.send(&mut m);
        }
    }

    /// Main loop: wait for events on `irq` (timeout in ticks) and call `f(bits)`
    /// (0 = timeout) until it returns `Some(exit_code)`.
    pub fn run(&self, irq: &Irq, timeout_ticks: u64, mut f: impl FnMut(u32) -> Option<i32>) -> i32 {
        loop {
            let bits = match irq.wait(timeout_ticks) {
                Ok(b) => b,
                Err(e) => {
                    log!("wait failed: {:?}", e);
                    return 1;
                }
            };
            if bits & IRQ_BIT != 0 {
                let _ = irq.ack();
            }
            if let Some(code) = f(bits) {
                return code;
            }
        }
    }
}

/// Declare the entry point of a driver: `fn main(d: libdriver::Driver) -> i32`.
#[macro_export]
macro_rules! driver_entry {
    ($name:expr, $main:path) => {
        $crate::liboos::entry!(__drv_main);
        fn __drv_main(_args: $crate::liboos::Args) -> i32 {
            $main($crate::Driver::new($name))
        }
    };
}

// ─── Network driver link (net/ext.rs in the kernel) ──────────────────────────────

pub mod netring {
    //! Shared packet rings between a NIC driver and the kernel network stack. Layout of
    //! the header: `net/ext.rs`. The driver allocates one DMA region, fills in the header
    //! and attaches it.
    use super::*;

    pub const MAGIC: u32 = 0x474E_524E;
    pub const VERSION: u32 = 1;
    pub const KICK_TX: u32 = 2;

    // Header field offsets (bytes).
    pub const O_MAGIC: usize = 0;
    pub const O_VERSION: usize = 4;
    pub const O_MAC: usize = 8;
    pub const O_FLAGS: usize = 14;
    pub const O_NSLOTS: usize = 16;
    pub const O_SLOT_SIZE: usize = 20;
    pub const O_RX_OFF: usize = 24;
    pub const O_TX_OFF: usize = 28;
    pub const O_RX_PROD: usize = 32;
    pub const O_RX_CONS: usize = 36;
    pub const O_TX_PROD: usize = 40;
    pub const O_TX_CONS: usize = 44;
    pub const O_RX_DROPPED: usize = 48;
    pub const O_TX_DROPPED: usize = 52;
    pub const O_RX_LEN: usize = 64;
    pub const O_TX_LEN: usize = 64 + 256;
    pub const HEADER_SIZE: usize = 64 + 512;

    /// Attach the ring region to the kernel network stack. `notif` is signalled with
    /// [`KICK_TX`] when frames wait to be sent.
    pub fn attach(dev: &Pci, notif: &Notification, region: &MemoryRegion) -> Result<()> {
        check(unsafe {
            sys::syscall4(sys::NETDRV_CTL, 0, dev.0.raw() as u64, notif.0.raw() as u64, region.0.raw() as u64)
        })
        .map(|_| ())
    }

    /// The driver has published received frames: let the stack process them now.
    pub fn poll() -> Result<()> {
        check(unsafe { sys::syscall4(sys::NETDRV_CTL, 1, 0, 0, 0) }).map(|_| ())
    }

    pub fn detach() {
        unsafe { sys::syscall4(sys::NETDRV_CTL, 2, 0, 0, 0) };
    }
}

// Handles used by the helpers above come from liboos.
pub use liboos::ipc::Rights as HandleRights;
#[allow(dead_code)]
fn _unused(_: Rights) {}
