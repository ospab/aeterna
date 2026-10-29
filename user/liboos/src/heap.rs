// SPDX-License-Identifier: AGPL-3.0-only
//! The program heap: regions obtained with `mmap`, each managed by a linked-list allocator.
//! It starts with one small region and maps another one when an allocation does not fit, so
//! small programs stay small and games can still allocate tens of MiB.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};
use linked_list_allocator::Heap;

/// A minimal spinlock: programs are single-threaded today, this only guards re-entry.
struct Mutex<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

unsafe impl<T> Sync for Mutex<T> {}

struct Guard<'a, T>(&'a Mutex<T>);

impl<T> Mutex<T> {
    const fn new(value: T) -> Self {
        Mutex { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }
    fn lock(&self) -> Guard<'_, T> {
        while self.locked.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        Guard(self)
    }
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.0.value.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0.value.get() }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        self.0.locked.store(false, Ordering::Release);
    }
}

/// Size of the first region, mapped before `main`.
const FIRST_REGION: usize = 4 * 1024 * 1024;
/// Smallest region mapped when the heap grows.
const GROW_REGION: usize = 8 * 1024 * 1024;
const MAX_REGIONS: usize = 16;

struct Region {
    heap: Heap,
    start: usize,
    end: usize,
}

struct Regions {
    list: [Option<Region>; MAX_REGIONS],
}

struct GrowingHeap(Mutex<Regions>);

#[global_allocator]
static HEAP: GrowingHeap = GrowingHeap(Mutex::new(Regions { list: [const { None }; MAX_REGIONS] }));

impl Regions {
    fn add(&mut self, size: usize) -> bool {
        let Some(slot) = self.list.iter_mut().find(|r| r.is_none()) else { return false };
        let Ok(p) = crate::mmap(size) else { return false };
        // SAFETY: the region was just mapped for us and is used for nothing else.
        let heap = unsafe { Heap::new(p, size) };
        *slot = Some(Region { heap, start: p as usize, end: p as usize + size });
        true
    }

    fn try_alloc(&mut self, layout: Layout) -> *mut u8 {
        for r in self.list.iter_mut().flatten() {
            if let Ok(p) = r.heap.allocate_first_fit(layout) {
                return p.as_ptr();
            }
        }
        null_mut()
    }
}

unsafe impl GlobalAlloc for GrowingHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut regions = self.0.lock();
        let p = regions.try_alloc(layout);
        if !p.is_null() {
            return p;
        }
        // Room for the block plus the allocator's own bookkeeping, rounded to whole pages.
        let need = (layout.size() + layout.align() + 4096 + 0xFFF) & !0xFFF;
        if !regions.add(need.max(GROW_REGION)) {
            return null_mut();
        }
        regions.try_alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut regions = self.0.lock();
        let a = ptr as usize;
        for r in regions.list.iter_mut().flatten() {
            if a >= r.start && a < r.end {
                // SAFETY: ptr was returned by this region's allocator with this layout.
                unsafe { r.heap.deallocate(core::ptr::NonNull::new_unchecked(ptr), layout) };
                return;
            }
        }
    }
}

/// Map the first heap region. Called once from the runtime before `main`.
pub(crate) fn init() {
    if !HEAP.0.lock().add(FIRST_REGION) {
        crate::write(2, b"liboos: cannot map heap, allocations will fail\n");
    }
}
