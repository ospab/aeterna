// SPDX-License-Identifier: AGPL-3.0-only
//! The program heap: one region obtained with `mmap` on first use, managed by a
//! linked-list allocator.

use linked_list_allocator::LockedHeap;

/// Heap size reserved on first allocation.
const HEAP_SIZE: usize = 4 * 1024 * 1024;

#[global_allocator]
static HEAP: LockedHeap = LockedHeap::empty();

/// Map the heap region. Called once from the runtime before `main`.
pub(crate) fn init() {
    match crate::mmap(HEAP_SIZE) {
        // SAFETY: the region was just mapped for us and is used for nothing else.
        Ok(p) => unsafe { HEAP.lock().init(p, HEAP_SIZE) },
        Err(_) => {
            crate::write(2, b"liboos: cannot map heap, allocations will fail\n");
        }
    }
}
