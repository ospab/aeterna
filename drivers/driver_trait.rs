/*
 * AETERNA Driver Trait
 *
 * Common interface for the hardware drivers that run in the kernel (ring 0). Drivers that run
 * as ring-3 processes use user/libdriver instead.
 */

/// Status of a driver within the driver registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverStatus {
    /// Registered but not yet initialized.
    Registered,
    /// Successfully initialized and operational.
    Active,
    /// Initialization failed (panic caught or probe returned false).
    Failed,
    /// Explicitly detached by the kernel or userspace request.
    Detached,
}

/// Common interface for AETERNA drivers.
///
/// Every hardware driver should implement this trait. The registry
/// calls `probe()` first; if it returns `true`, `init()` is invoked.
/// A panic stops the kernel (panic = "abort"); return `false` on failure instead.
pub trait Driver {
    /// Human-readable driver name for logging and `lsmod`.
    fn name(&self) -> &'static str;

    /// Probe whether the hardware this driver supports is present.
    /// Should not allocate or perform I/O beyond PCI config reads.
    fn probe(&self) -> bool;

    /// Initialize the driver. Called only if `probe()` returned true.
    /// Returns false on failure; must not panic.
    fn init(&self) -> bool;

    /// Current status of the driver (queried via registry).
    fn status(&self) -> DriverStatus;
}
