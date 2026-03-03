/*
 * AETERNA GPU / Display Driver Subsystem
 *
 * Supported hardware:
 *   vmware_svga — VMware SVGA II virtual GPU (PCI 15AD:0405)
 *                 Provides resolution switching and FIFO command queue
 *   vmmouse     — VMware Backdoor Absolute Mouse (port 0x5658)
 *                 Delivers absolute cursor coordinates without PS/2 relative math
 */

pub mod vmware_svga;
pub mod vmmouse;

/// Initialize all GPU/display accelerators — call after PCI enumeration.
/// Returns true if any accelerated display was found and initialized.
pub fn init() -> bool {
    let svga = vmware_svga::init();
    if svga {
        // VMMouse is only useful alongside the SVGA adapter
        vmmouse::init();
    }
    svga
}

/// Re-export high-level accessors
pub use vmware_svga::{is_ready as svga_ready, set_mode};
pub use vmmouse::{poll as mouse_poll, is_absolute};
