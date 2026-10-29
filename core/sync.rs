/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

Kernel synchronization primitives. Rules and lock order: docs/en/kernel.md.

  IrqSpinLock<T>  disables interrupts, then takes a real atomic lock (SMP-ready).
                  A holder is never interrupted on its own CPU, so an interrupt handler
                  may take any IrqSpinLock that task code takes. Use try_lock in handlers
                  that can also run from a fault path.
  OnceCell<T>     write-once global, lock-free reads.
  Mutex<T>        task-context lock that yields while contended (long sections, may be
                  preempted; never from an interrupt handler).
  irq_save / irq_restore / without_interrupts   raw IRQ-off sections.

Every IrqSpinLock has a rank. Locks must be taken in increasing rank order; the kernel
checks this at run time (bitmask of held ranks, one CPU today) and panics on a violation,
on recursion, and on `sys_yield`/`park` with a lock held.

None of the asm below is `nomem`: each statement is a compiler barrier, so loads and
stores of protected data cannot move across the lock or across `sti`/`hlt`.
*/

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// Spins before a lock is declared stuck. On one CPU a held lock can never be released
/// while we spin with interrupts off, so this turns a silent hang into a panic.
const SPIN_LIMIT: u64 = 200_000_000;

/// Lock ranks (order of acquisition: lower first; must be below 64, one bit each). Keep in sync with docs/en/kernel.md.
pub mod rank {
    pub const OBJ: u8 = 5; // kernel objects, handle tables
    pub const SCHED: u8 = 10; // task table
    pub const VFS: u8 = 15; // mount table, disk-sync state
    pub const DEV: u8 = 20; // device state shared with interrupt handlers (keyboard, audio, net)
    pub const TIME: u8 = 22;
    pub const NUMA: u8 = 25;
    pub const VMM: u8 = 30; // page-table edits
    pub const PMM: u8 = 35; // frame bitmap
    pub const HEAP: u8 = 40; // innermost
}

/// Ranks of the locks held on this CPU (bit n = rank n). Per-CPU once there are more CPUs.
static HELD: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
fn note_acquire(name: &'static str, rank: u8) {
    let bit = 1u64 << rank;
    let held = HELD.load(Ordering::Relaxed);
    if held & !(bit - 1) != 0 {
        order_violation(name, rank, held);
    }
    HELD.store(held | bit, Ordering::Relaxed);
}

#[inline(always)]
fn note_release(rank: u8) {
    HELD.store(HELD.load(Ordering::Relaxed) & !(1u64 << rank), Ordering::Relaxed);
}

#[cold]
#[inline(never)]
fn order_violation(name: &'static str, rank: u8, held: u64) -> ! {
    crate::arch::x86_64::serial::write_str("[SYNC] lock order violation taking ");
    crate::arch::x86_64::serial::write_str(name);
    crate::arch::x86_64::serial::write_str("\r\n");
    panic!("lock order violation: {} (rank {}), held mask {:#x}", name, rank, held);
}

/// Panic if this CPU holds any spinlock. Called by code that sleeps.
#[inline]
pub fn assert_no_locks(what: &'static str) {
    let held = HELD.load(Ordering::Relaxed);
    if held != 0 {
        crate::arch::x86_64::serial::write_str("[SYNC] sleeping with a lock held: ");
        crate::arch::x86_64::serial::write_str(what);
        crate::arch::x86_64::serial::write_str("\r\n");
        panic!("{} with spinlocks held (mask {:#x})", what, held);
    }
}

/// Disable interrupts and return the previous RFLAGS (pass it to `irq_restore`).
#[inline(always)]
pub fn irq_save() -> u64 {
    let flags: u64;
    // SAFETY: reads RFLAGS and clears IF; no memory side effects besides the stack push/pop.
    unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags) };
    flags
}

/// Re-enable interrupts if they were enabled when `flags` was saved.
#[inline(always)]
pub fn irq_restore(flags: u64) {
    if flags & 0x200 != 0 {
        // SAFETY: only restores the state the caller had.
        unsafe { core::arch::asm!("sti") };
    }
}

/// Are interrupts enabled right now?
#[inline(always)]
pub fn irq_enabled() -> bool {
    let flags: u64;
    // SAFETY: reads RFLAGS.
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) flags) };
    flags & 0x200 != 0
}

/// Run `f` with interrupts disabled, restoring the previous state afterwards.
#[inline]
pub fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    let flags = irq_save();
    let r = f();
    irq_restore(flags);
    r
}

// ─── IrqSpinLock ──────────────────────────────────────────────────────────────

pub struct IrqSpinLock<T> {
    locked: AtomicBool,
    name: &'static str,
    rank: u8,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialized by `locked`.
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}
unsafe impl<T: Send> Send for IrqSpinLock<T> {}

pub struct IrqSpinLockGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    flags: u64,
}

impl<T> IrqSpinLock<T> {
    pub const fn new(name: &'static str, rank: u8, value: T) -> Self {
        assert!(rank < 64);
        IrqSpinLock { locked: AtomicBool::new(false), name, rank, data: UnsafeCell::new(value) }
    }

    /// Disable interrupts and take the lock. Panics if it stays held for far too long,
    /// or if the lock order / recursion rules are broken.
    #[inline]
    pub fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let flags = irq_save();
        note_acquire(self.name, self.rank);
        self.spin();
        IrqSpinLockGuard { lock: self, flags }
    }

    #[inline]
    fn spin(&self) {
        let mut spins: u64 = 0;
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
            spins += 1;
            if spins > SPIN_LIMIT {
                stuck(self.name);
            }
        }
    }

    /// Take the lock if it is free; otherwise restore interrupts and return None.
    #[inline]
    pub fn try_lock(&self) -> Option<IrqSpinLockGuard<'_, T>> {
        let flags = irq_save();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            note_acquire(self.name, self.rank);
            Some(IrqSpinLockGuard { lock: self, flags })
        } else {
            irq_restore(flags);
            None
        }
    }

    /// Is the lock held right now? For assertions and diagnostics only.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// Raw pointer to the protected data, without taking the lock.
    ///
    /// # Safety
    /// The caller must already hold the lock (through a guard that is alive further up the
    /// call chain) or otherwise be the only context that can touch the data.
    #[inline]
    pub unsafe fn data_ptr(&self) -> *mut T {
        self.data.get()
    }

    /// Mutable access without locking, valid because `&mut self` is unique (boot-time init).
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Take the lock again with interrupts already off; `flags` is what `irq_save`
    /// returned originally (so the final drop restores the outermost state).
    pub fn relock_with(&self, flags: u64) -> IrqSpinLockGuard<'_, T> {
        note_acquire(self.name, self.rank);
        self.spin();
        IrqSpinLockGuard { lock: self, flags }
    }
}

#[cold]
#[inline(never)]
fn stuck(name: &'static str) -> ! {
    crate::arch::x86_64::serial::write_str("[SYNC] lock stuck: ");
    crate::arch::x86_64::serial::write_str(name);
    crate::arch::x86_64::serial::write_str("\r\n");
    panic!("lock stuck: {}", name);
}

impl<'a, T> IrqSpinLockGuard<'a, T> {
    /// Release the lock but keep interrupts disabled, and return the saved flags.
    /// Pair with `IrqSpinLock::relock_with` to continue the same critical section later
    /// (used around `park`, which needs interrupts off but the lock free).
    pub fn unlock_keep_irq_off(self) -> (&'a IrqSpinLock<T>, u64) {
        let lock = self.lock;
        let flags = self.flags;
        core::mem::forget(self);
        note_release(lock.rank);
        lock.locked.store(false, Ordering::Release);
        (lock, flags)
    }
}

impl<T> Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: the guard proves the lock is held.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqSpinLockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves the lock is held.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for IrqSpinLockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        note_release(self.lock.rank);
        self.lock.locked.store(false, Ordering::Release);
        irq_restore(self.flags);
    }
}

// ─── OnceCell ─────────────────────────────────────────────────────────────────

const EMPTY: u8 = 0;
const BUSY: u8 = 1;
const READY: u8 = 2;

/// A global that is written once and read many times without locking.
pub struct OnceCell<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: written once behind the BUSY state, then only shared references are handed out.
unsafe impl<T: Send + Sync> Sync for OnceCell<T> {}
unsafe impl<T: Send> Send for OnceCell<T> {}

impl<T> OnceCell<T> {
    pub const fn new() -> Self {
        OnceCell { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    #[inline]
    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == READY {
            // SAFETY: READY means the value was fully written.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }

    /// Store the value. Returns it back if the cell was already set (or is being set).
    pub fn set(&self, v: T) -> Result<(), T> {
        if self
            .state
            .compare_exchange(EMPTY, BUSY, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(v);
        }
        // SAFETY: we own the BUSY state; nobody reads until READY.
        unsafe { (*self.value.get()).write(v) };
        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    /// Initialize with `f` on first use. If another context is initializing at the same
    /// moment this spins until it is done (`f` must not use this cell).
    pub fn get_or_init(&self, f: impl FnOnce() -> T) -> &T {
        if let Some(v) = self.get() {
            return v;
        }
        if self
            .state
            .compare_exchange(EMPTY, BUSY, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // SAFETY: we own the BUSY state.
            unsafe { (*self.value.get()).write(f()) };
            self.state.store(READY, Ordering::Release);
        } else {
            while self.state.load(Ordering::Acquire) != READY {
                core::hint::spin_loop();
            }
        }
        self.get().unwrap()
    }
}

// ─── Tiny helpers ─────────────────────────────────────────────────────────────

/// A usize shared with interrupt handlers (counters, indices): plain atomic, relaxed.
pub struct IrqCounter(AtomicUsize);

impl IrqCounter {
    pub const fn new(v: usize) -> Self { IrqCounter(AtomicUsize::new(v)) }
    #[inline] pub fn get(&self) -> usize { self.0.load(Ordering::Relaxed) }
    #[inline] pub fn set(&self, v: usize) { self.0.store(v, Ordering::Relaxed) }
    #[inline] pub fn inc(&self) -> usize { self.0.fetch_add(1, Ordering::Relaxed) }
}

// ─── Mutex (task context) ─────────────────────────────────────────────────────

/// Take `flag` (false = free). While another task holds it, yield the CPU instead of
/// spinning with interrupts off. Task context only: an interrupt handler must never call it.
/// The holder may be preempted, so sections can be long (VFS, disk), but must not wait for
/// the contender. Before the scheduler runs (early boot) it just spins.
pub fn yield_lock(flag: &AtomicBool) {
    let mut spins: u64 = 0;
    while flag.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        spins += 1;
        if crate::core::scheduler::is_initialized() && HELD.load(Ordering::Relaxed) == 0 {
            crate::core::scheduler::sys_yield();
        } else {
            core::hint::spin_loop();
            if spins > SPIN_LIMIT {
                stuck("yield_lock");
            }
        }
    }
}

pub fn yield_unlock(flag: &AtomicBool) {
    flag.store(false, Ordering::Release);
}

/// Mutual exclusion for task context, see `yield_lock`.
pub struct Mutex<T> {
    flag: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialized by `flag`.
unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Send> Send for Mutex<T> {}

pub struct MutexGuard<'a, T> {
    m: &'a Mutex<T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Mutex { flag: AtomicBool::new(false), data: UnsafeCell::new(value) }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        yield_lock(&self.flag);
        MutexGuard { m: self }
    }

    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self.flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            Some(MutexGuard { m: self })
        } else {
            None
        }
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves the flag is held.
        unsafe { &*self.m.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves the flag is held.
        unsafe { &mut *self.m.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.m.flag.store(false, Ordering::Release);
    }
}
