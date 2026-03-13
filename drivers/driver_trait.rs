/*
 * AETERNA Driver Trait
 *
 * Common interface for all hardware drivers in the AETERNA microkernel.
 * In Phase 5, drivers implementing this trait will run as isolated
 * userspace processes communicating via IPC. Currently they run in
 * ring 0 but are wrapped in catch_unwind for fault isolation.
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
/// calls `probe()` first; if it returns `true`, `init()` is invoked
/// inside a `catch_unwind` boundary to prevent driver panics from
/// killing the kernel.
pub trait Driver {
    /// Human-readable driver name for logging and `lsmod`.
    fn name(&self) -> &'static str;

    /// Probe whether the hardware this driver supports is present.
    /// Should not allocate or perform I/O beyond PCI config reads.
    fn probe(&self) -> bool;

    /// Initialize the driver. Called only if `probe()` returned true.
    /// May panic — the registry wraps this in `catch_unwind`.
    fn init(&self) -> bool;

    /// Current status of the driver (queried via registry).
    fn status(&self) -> DriverStatus;
}
