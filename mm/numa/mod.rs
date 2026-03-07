/*
 * AETERNA Deterministic Memory Fabric — NUMA & Execution Domains
 * 
 * Provides static partitioning of physical memory into predictable
 * domains (MEDs) to minimize cross-node latency and jitter.
 */

use spin::Mutex;
use alloc::vec::Vec;
use crate::mm::physical::{PhysRegion, FRAME_SIZE};

/// Maximum Number of Execution Domains supported in v1.0.0
pub const MAX_MEDS: usize = 16;

/// Memory Execution Domain (MED)
/// Represents a contiguous or NUMA-local region of physical memory
/// dedicated to specific execution tasks or I/O domains.
#[derive(Debug, Clone, Copy)]
pub struct MemoryExecutionDomain {
    pub id: u32,
    pub numa_node: u32,
    pub phys_start: u64,
    pub phys_end: u64,
    pub free_pointer: u64,
}

struct NumaState {
    domains: Vec<MemoryExecutionDomain>,
    initialized: bool,
}

static NUMA_STATE: Mutex<NumaState> = Mutex::new(NumaState {
    domains: Vec::new(),
    initialized: false,
});

/// Initialize NUMA domains and MEDs.
/// For now, if no ACPI SRAT is found, it creates a single MED covering all usable RAM.
pub fn init() {
    let mut state = NUMA_STATE.lock();
    if state.initialized { return; }

    // Fallback: Create Domain 0 from the largest usable physical region
    // In the future: Parse ACPI SRAT here.
    let regions = crate::mm::physical::get_usable_regions();
    for (i, reg) in regions.iter().enumerate() {
        if i >= MAX_MEDS { break; }
        if reg.length == 0 { continue; }

        state.domains.push(MemoryExecutionDomain {
            id: i as u32,
            numa_node: 0, // Assume single node for now
            phys_start: reg.base,
            phys_end: reg.base + reg.length,
            free_pointer: reg.base,
        });
    }

    state.initialized = true;
    crate::arch::x86_64::serial::write_str("[MM] Deterministic Memory Fabric initialized (");
    crate::arch::x86_64::serial::write_str("MED count: ");
    serial_dec(state.domains.len() as u64);
    crate::arch::x86_64::serial::write_str(")\r\n");
}

/// Allocate a frame from a specific Execution Domain.
/// Returns physical address or 0 if exhausted.
pub fn alloc_from_med(domain_id: u32, size_bytes: usize) -> u64 {
    let mut state = NUMA_STATE.lock();
    for dom in state.domains.iter_mut() {
        if dom.id == domain_id {
            let addr = dom.free_pointer;
            let next = addr + size_bytes as u64;
            if next <= dom.phys_end {
                dom.free_pointer = next;
                return addr;
            }
        }
    }
    0
}

/// Get a list of available MEDs for system information.
pub fn get_med_info() -> Vec<MemoryExecutionDomain> {
    NUMA_STATE.lock().domains.clone()
}

// ─── Internal Helper ──────────────────────────────────────────────────────

fn serial_dec(mut val: u64) {
    if val == 0 {
        crate::arch::x86_64::serial::write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    for j in (0..i).rev() {
        crate::arch::x86_64::serial::write_byte(buf[j]);
    }
}
