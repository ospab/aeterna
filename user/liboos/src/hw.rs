// SPDX-License-Identifier: AGPL-3.0-only
//! Hardware as handles, for drivers in ring 3: interrupts, I/O ports, device memory and
//! the DMA resource. Programs cannot create these objects; the process that starts a
//! driver (the kernel at boot, later `seed`) hands them over as bootstrap handles.
//!
//! * [`Interrupt`]: bind it to a [`Notification`]; each interrupt masks the line and sets
//!   the bits; [`Interrupt::ack`] unmasks it once the device has been serviced.
//! * [`IoPorts`]: after [`IoPorts::enable`] the process may use IN/OUT on the range
//!   directly (the kernel opens those ports in the CPU's I/O permission bitmap while
//!   this process runs). Any other port still faults (#GP kills the process).
//! * MMIO: a [`crate::mem::MemoryRegion`] handle of type `MmioRegion`, mapped uncached.
//! * [`Resource`] with DMA: lets [`crate::mem::MemoryRegion::create_contig`] allocate
//!   physically contiguous buffers whose physical address the driver may read.

use crate::ipc::{check, Handle, Notification, Result};
use crate::sys::{self, nr};

/// An IRQ line owned by this driver.
#[derive(Debug, PartialEq, Eq)]
pub struct Interrupt(pub Handle);

impl Interrupt {
    /// Deliver interrupts as `bits` on `notif` (needs READ here and WRITE on `notif`).
    /// The line stays masked until [`Interrupt::ack`].
    pub fn bind(&self, notif: &Notification, bits: u32) -> Result<()> {
        check(unsafe { sys::syscall3(nr::IRQ_BIND, self.0.raw() as u64, notif.0.raw() as u64, bits as u64) })
            .map(|_| ())
    }

    /// Unmask the line: the device has been serviced, the next interrupt may come.
    pub fn ack(&self) -> Result<()> {
        check(unsafe { sys::syscall1(nr::IRQ_ACK, self.0.raw() as u64) }).map(|_| ())
    }
}

/// A range of x86 I/O ports `[base, base + count)`.
#[derive(Debug)]
pub struct IoPorts {
    pub handle: Handle,
    base: u16,
    count: u16,
}

impl IoPorts {
    /// Wrap a handle the parent gave us for ports `base..base+count` (the kernel checks
    /// the real range; these numbers only bound the accessors below).
    pub fn new(handle: Handle, base: u16, count: u16) -> IoPorts {
        IoPorts { handle, base, count }
    }

    /// Open the ports for this process (needs READ and WRITE). Stays in effect until
    /// [`IoPorts::disable`] or exit, even if the handle is closed.
    pub fn enable(&self) -> Result<()> {
        check(unsafe { sys::syscall1(nr::IOPORT_ENABLE, self.handle.raw() as u64) }).map(|_| ())
    }

    pub fn disable(&self) -> Result<()> {
        check(unsafe { sys::syscall1(nr::IOPORT_DISABLE, self.handle.raw() as u64) }).map(|_| ())
    }

    fn port(&self, off: u16) -> u16 {
        assert!(off < self.count, "port offset out of range");
        self.base + off
    }

    /// Read a byte from port `base + off` (after `enable`).
    pub fn inb(&self, off: u16) -> u8 {
        unsafe { inb(self.port(off)) }
    }

    /// Write a byte to port `base + off` (after `enable`).
    pub fn outb(&self, off: u16, v: u8) {
        unsafe { outb(self.port(off), v) }
    }
}

/// Raw port input. Faults (and the kernel kills the process) unless the port is enabled.
///
/// # Safety
/// Talking to a device behind the back of its driver can confuse it.
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags));
    v
}

/// Raw port output. See [`inb`].
///
/// # Safety
/// As for [`inb`].
pub unsafe fn outb(port: u16, v: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags));
}

/// Authority to create special objects (for now: DMA regions).
#[derive(Debug, PartialEq, Eq)]
pub struct Resource(pub Handle);
