/*
 * AETERNA Shared Memory Ring (SMR) — Zero-Copy IPC Fabric
 * 
 * Hardware-aligned, lock-free descriptor rings for high-throughput
 * and low-latency communication between execution domains.
 */

use core::sync::atomic::{AtomicU32, Ordering};
use crate::core::capability::CapabilityToken;

/// Maximum number of descriptors in a single SMR.
/// Must be a power of two for efficient bitwise wrapping.
pub const SMR_CAPACITY: usize = 128;

/// Metadata associated with a descriptor, used for alignment and protocol tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct DescriptorMetadata {
    pub tag: u64,
    pub flags: u64,
}

/// A single descriptor in the SMR.
/// Points to a physical memory region (MED) and carries an authorization token.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))] // Align to cache line to prevent false sharing
pub struct SmrDescriptor {
    /// Physical address of the payload
    pub phys_addr: u64,
    /// Length of the payload in bytes
    pub length: u64,
    /// Permission flags (Read/Write/Execute)
    pub permissions: u32,
    /// Generation / State counter
    pub generation: u32,
    /// User metadata (e.g., protocol-specific tags)
    pub metadata: DescriptorMetadata,
}

/// SMR Header — located at the start of the shared page.
#[repr(C, align(64))]
pub struct SmrHeader {
    /// Index where the producer will write the next descriptor
    pub head: AtomicU32,
    /// Index where the consumer will read the next descriptor
    pub tail: AtomicU32,
    /// Capacity of the ring
    pub capacity: u32,
    /// Unique identifier for this channel
    pub channel_id: u32,
}

/// Shared Memory Ring instance.
pub struct SmrRing {
    header: *mut SmrHeader,
    descriptors: *mut [SmrDescriptor; SMR_CAPACITY],
}

impl SmrRing {
    /// Initialize a new SMR in a pre-allocated memory region.
    /// SAFETY: The memory at `base_addr` must be at least 
    /// sizeof(SmrHeader) + sizeof(SmrDescriptor) * SMR_CAPACITY.
    pub unsafe fn from_raw(base_addr: u64) -> Self {
        let header = base_addr as *mut SmrHeader;
        let descriptors = (base_addr + 64) as *mut [SmrDescriptor; SMR_CAPACITY];
        
        Self { header, descriptors }
    }

    /// Try to push a descriptor onto the ring.
    /// Returns true if successful, false if the ring is full.
    pub fn try_push(&self, desc: SmrDescriptor) -> bool {
        unsafe {
            let h = (*self.header).head.load(Ordering::Relaxed);
            let t = (*self.header).tail.load(Ordering::Acquire);

            if h.wrapping_sub(t) >= SMR_CAPACITY as u32 {
                return false; // Full
            }

            let slot = (h as usize) % SMR_CAPACITY;
            (*self.descriptors)[slot] = desc;
            
            // Increment head with Release semantics to ensure descriptor write is visible
            (*self.header).head.store(h.wrapping_add(1), Ordering::Release);
            true
        }
    }

    /// Try to pop a descriptor from the ring.
    /// Returns Some(descriptor) if successful, None if the ring is empty.
    pub fn try_pop(&self) -> Option<SmrDescriptor> {
        unsafe {
            let t = (*self.header).tail.load(Ordering::Relaxed);
            let h = (*self.header).head.load(Ordering::Acquire);

            if t == h {
                return None; // Empty
            }

            let slot = (t as usize) % SMR_CAPACITY;
            let desc = (*self.descriptors)[slot];

            // Increment tail with Release semantics to signal slot is free
            (*self.header).tail.store(t.wrapping_add(1), Ordering::Release);
            Some(desc)
        }
    }

    /// Peer-to-peer peering: Check if there's data without popping it.
    pub fn is_empty(&self) -> bool {
        unsafe {
            let t = (*self.header).tail.load(Ordering::Relaxed);
            let h = (*self.header).head.load(Ordering::Relaxed);
            t == h
        }
    }
}
