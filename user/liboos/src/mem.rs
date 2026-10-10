// SPDX-License-Identifier: AGPL-3.0-only
//! Shared memory through handles: [`MemoryRegion`] objects and their [`Mapping`]s.
//!
//! A region is a set of physical pages owned by the kernel object. Any process holding a
//! handle with [`Rights::MAP`] can map it; two processes mapping the same region see each
//! other's writes. Pass a region to another process by moving its handle in a message
//! (usually a duplicate with fewer rights, e.g. read-only).
//!
//! A mapping keeps the region alive on its own: closing the handle does not unmap, and
//! the pages are freed when the last handle is closed and the last mapping is gone.
//! Process exit drops both.
//!
//! Memory shared with another process can change under you at any time, so access goes
//! through volatile reads and writes ([`Mapping::read`], [`Mapping::write`], ...) instead
//! of Rust references.

use crate::ipc::{check, Error, Handle, Result, Rights};
use crate::sys::{self, nr};

/// Page size.
pub const PAGE: usize = 4096;

/// Protection for [`MemoryRegion::map`]. Combine with `|`. Must include `READ`;
/// `WRITE | EXEC` together is refused (W^X).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Prot(pub u32);

impl Prot {
    pub const READ: Prot = Prot(1);
    pub const WRITE: Prot = Prot(2);
    pub const EXEC: Prot = Prot(4);
    pub const RW: Prot = Prot(3);
}

impl core::ops::BitOr for Prot {
    type Output = Prot;
    fn bitor(self, o: Prot) -> Prot {
        Prot(self.0 | o.0)
    }
}

/// A memory object: anonymous ([`MemoryRegion::create`]), physically contiguous for DMA
/// ([`MemoryRegion::create_contig`]), or a device range (an MMIO handle received from
/// the parent; same API, mapped uncached).
#[derive(Debug, PartialEq, Eq)]
pub struct MemoryRegion(pub Handle);

impl MemoryRegion {
    /// New zeroed region of `size` bytes (rounded up to whole pages, at most 64 MiB).
    /// The handle has READ, WRITE, MAP, DUP and TRANSFER.
    pub fn create(size: usize) -> Result<MemoryRegion> {
        let r = unsafe { sys::syscall1(nr::MEM_CREATE, size as u64) };
        check(r).map(|h| MemoryRegion(Handle::from_raw(h as u32)))
    }

    /// New physically contiguous region (at most 4 MiB) for device DMA. Needs a DMA
    /// [`crate::hw::Resource`] handle with WRITE; the region handle also has PHYS.
    pub fn create_contig(dma: &crate::hw::Resource, size: usize) -> Result<MemoryRegion> {
        let r = unsafe { sys::syscall2(nr::MEM_CREATE_CONTIG, dma.0.raw() as u64, size as u64) };
        check(r).map(|h| MemoryRegion(Handle::from_raw(h as u32)))
    }

    /// Duplicate with fewer (or equal) rights. Needs DUP.
    pub fn duplicate(&self, rights: Rights) -> Result<MemoryRegion> {
        self.0.duplicate(rights).map(MemoryRegion)
    }

    /// Size in bytes (whole pages).
    pub fn size(&self) -> Result<usize> {
        check(unsafe { sys::syscall1(nr::MEM_SIZE, self.0.raw() as u64) }).map(|s| s as usize)
    }

    /// Physical address (contiguous and device regions; needs PHYS).
    pub fn phys(&self) -> Result<u64> {
        check(unsafe { sys::syscall1(nr::MEM_PHYS, self.0.raw() as u64) }).map(|p| p as u64)
    }

    /// Map the whole region. Needs MAP + READ, WRITE for `Prot::WRITE`, EXEC for `Prot::EXEC`.
    pub fn map(&self, prot: Prot) -> Result<Mapping> {
        let size = self.size()?;
        let r = unsafe { sys::syscall3(nr::MEM_MAP, self.0.raw() as u64, 0, prot.0 as u64) };
        check(r).map(|a| Mapping { addr: a as usize, size, prot })
    }
}

/// A region mapped into this process. Unmapped on drop.
#[derive(Debug)]
pub struct Mapping {
    addr: usize,
    size: usize,
    prot: Prot,
}

impl Mapping {
    pub fn addr(&self) -> usize {
        self.addr
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn writable(&self) -> bool {
        self.prot.0 & Prot::WRITE.0 != 0
    }

    fn at<T>(&self, off: usize) -> *mut T {
        let n = core::mem::size_of::<T>();
        assert!(off % core::mem::align_of::<T>() == 0, "unaligned access");
        assert!(off.checked_add(n).map_or(false, |e| e <= self.size), "offset out of range");
        (self.addr + off) as *mut T
    }

    /// Volatile read of a `u8`/`u16`/`u32`/`u64` at byte offset `off` (must be aligned).
    pub fn read<T: Copy>(&self, off: usize) -> T {
        unsafe { core::ptr::read_volatile(self.at::<T>(off)) }
    }

    /// Volatile write at byte offset `off`. Panics on a read-only mapping (the hardware
    /// would kill the process with a page fault).
    pub fn write<T: Copy>(&self, off: usize, v: T) {
        assert!(self.writable(), "write to a read-only mapping");
        unsafe { core::ptr::write_volatile(self.at::<T>(off), v) }
    }

    /// Copy bytes out of the mapping.
    pub fn read_bytes(&self, off: usize, dst: &mut [u8]) {
        for (i, b) in dst.iter_mut().enumerate() {
            *b = self.read::<u8>(off + i);
        }
    }

    /// Copy bytes into the mapping.
    pub fn write_bytes(&self, off: usize, src: &[u8]) {
        for (i, &b) in src.iter().enumerate() {
            self.write::<u8>(off + i, b);
        }
    }

    /// Raw pointer to the start, for code that manages access itself.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr as *mut u8
    }

    /// Unmap now and see the result (drop ignores it).
    pub fn unmap(self) -> Result<()> {
        let a = self.addr;
        core::mem::forget(self);
        unmap_raw(a)
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let _ = unmap_raw(self.addr);
    }
}

/// `mem_unmap` on an address returned by `mem_map`.
pub fn unmap_raw(addr: usize) -> Result<()> {
    check(unsafe { sys::syscall1(nr::MEM_UNMAP, addr as u64) }).map(|_| ())
}

/// Map a raw handle value without wrapping it (for tests of the rights checks).
pub fn map_raw(h: &Handle, prot: u32) -> core::result::Result<usize, Error> {
    check(unsafe { sys::syscall3(nr::MEM_MAP, h.raw() as u64, 0, prot as u64) }).map(|a| a as usize)
}
