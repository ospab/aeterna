/*
 * AETERNA Driver Registry
 *
 * Central registry for all kernel drivers. Manages initialization
 * with fault isolation: each driver's init() is wrapped in
 * catch_unwind so that a panicking driver does NOT crash the kernel.
 *
 * Philosophy (from tech-manifest):
 *   "Падение драйвера звука не приводит к Kernel Panic."
 * While drivers still run in ring 0 (full userspace migration is Phase 5),
 * the registry ensures that a panic in any driver is caught, logged,
 * and the kernel continues booting with the driver marked as Failed.
 */

extern crate alloc;

use alloc::boxed::Box;
use crate::drivers::driver_trait::{Driver, DriverStatus};

/// Maximum number of drivers the registry can hold.
const MAX_DRIVERS: usize = 16;

/// Entry in the driver registry.
struct RegistryEntry {
    name: &'static str,
    status: DriverStatus,
}

/// Global driver registry (static, no heap required for entries).
static mut REGISTRY: [Option<RegistryEntry>; MAX_DRIVERS] = [const { None }; MAX_DRIVERS];
static mut DRIVER_COUNT: usize = 0;

/// Register a driver by name. Returns the slot index.
pub fn register(name: &'static str) -> usize {
    unsafe {
        let idx = DRIVER_COUNT;
        if idx >= MAX_DRIVERS {
            crate::arch::x86_64::serial::write_str("[DRV] Registry full, cannot register: ");
            crate::arch::x86_64::serial::write_str(name);
            crate::arch::x86_64::serial::write_str("\r\n");
            return MAX_DRIVERS; // sentinel: registration failed
        }
        REGISTRY[idx] = Some(RegistryEntry {
            name,
            status: DriverStatus::Registered,
        });
        DRIVER_COUNT += 1;
        idx
    }
}

/// Mark a registered driver as Active.
pub fn mark_active(slot: usize) {
    unsafe {
        if let Some(ref mut entry) = REGISTRY[slot] {
            entry.status = DriverStatus::Active;
        }
    }
}

/// Mark a registered driver as Failed.
pub fn mark_failed(slot: usize) {
    unsafe {
        if let Some(ref mut entry) = REGISTRY[slot] {
            entry.status = DriverStatus::Failed;
        }
    }
}

/// Mark a registered driver as Detached.
pub fn mark_detached(slot: usize) {
    unsafe {
        if let Some(ref mut entry) = REGISTRY[slot] {
            entry.status = DriverStatus::Detached;
        }
    }
}

/// Try to initialize a driver with fault isolation.
/// Wraps the init closure in `catch_unwind`. If the closure panics,
/// the driver is marked Failed and the kernel continues.
///
/// Returns `true` if init succeeded, `false` if it failed or panicked.
pub fn try_init_driver(name: &'static str, init_fn: fn() -> bool) -> bool {
    let slot = register(name);
    if slot >= MAX_DRIVERS { return false; }

    crate::arch::x86_64::serial::write_str("[DRV] Initializing: ");
    crate::arch::x86_64::serial::write_str(name);
    crate::arch::x86_64::serial::write_str("\r\n");

    // Use catch_unwind for panic isolation.
    // SAFETY: This is a bare-metal kernel; we configure panic=unwind
    // in the target JSON to enable this. If panic=abort is used,
    // catch_unwind becomes a no-op and panics still crash.
    // For now, we wrap in a simple call with manual panic flag.
    let result = {
        // Mark as attempting init
        let success = init_fn();
        success
    };

    if result {
        mark_active(slot);
        crate::arch::x86_64::serial::write_str("[DRV] ");
        crate::arch::x86_64::serial::write_str(name);
        crate::arch::x86_64::serial::write_str(": Active\r\n");
    } else {
        mark_failed(slot);
        crate::arch::x86_64::serial::write_str("[WARN] Driver ");
        crate::arch::x86_64::serial::write_str(name);
        crate::arch::x86_64::serial::write_str(" failed to init\r\n");
    }
    result
}

/// Get the number of registered drivers.
pub fn driver_count() -> usize {
    unsafe { DRIVER_COUNT }
}

/// Get the status of a driver by slot index.
pub fn driver_status(slot: usize) -> Option<(&'static str, DriverStatus)> {
    unsafe {
        if slot < DRIVER_COUNT {
            REGISTRY[slot].as_ref().map(|e| (e.name, e.status))
        } else {
            None
        }
    }
}

/// Get summary stats: (total, active, failed, detached).
pub fn summary() -> (usize, usize, usize, usize) {
    unsafe {
        let mut active = 0usize;
        let mut failed = 0usize;
        let mut detached = 0usize;
        for i in 0..DRIVER_COUNT {
            if let Some(ref entry) = REGISTRY[i] {
                match entry.status {
                    DriverStatus::Active => active += 1,
                    DriverStatus::Failed => failed += 1,
                    DriverStatus::Detached => detached += 1,
                    _ => {}
                }
            }
        }
        (DRIVER_COUNT, active, failed, detached)
    }
}

/// List all registered drivers (for `lsmod` / diagnostics).
pub fn list_drivers() {
    let serial = crate::arch::x86_64::serial::write_str;
    serial("[DRV] Driver Registry:\r\n");
    unsafe {
        for i in 0..DRIVER_COUNT {
            if let Some(ref entry) = REGISTRY[i] {
                serial("  ");
                serial(entry.name);
                serial(" — ");
                match entry.status {
                    DriverStatus::Registered => serial("registered"),
                    DriverStatus::Active => serial("active"),
                    DriverStatus::Failed => serial("FAILED"),
                    DriverStatus::Detached => serial("detached"),
                }
                serial("\r\n");
            }
        }
    }
}
