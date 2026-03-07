/*
 * AETERNA Userspace IPC Channel Manager
 *
 * Manages SMR (Shared Memory Ring) channels that connect userspace
 * servers (VFS, drivers) with their clients via the kernel.
 *
 * Each channel is a pair of SmrRings backed by physically contiguous
 * memory allocated from the PMM.
 */

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use crate::core::ipc::smr::{SmrRing, SmrDescriptor, SmrHeader, SMR_CAPACITY, DescriptorMetadata};

/// Maximum number of IPC channels
const MAX_CHANNELS: usize = 16;

/// Channel state
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChannelState {
    Free,
    Active,
}

/// A managed IPC channel backed by an SMR ring
struct SmrChannel {
    state: ChannelState,
    owner_pid: u32,
    ring_phys: u64,    // Physical address of the SMR region
    ring_virt: u64,    // HHDM virtual address
}

/// Global channel table
static mut CHANNELS: [Option<SmrChannel>; MAX_CHANNELS] = [const { None }; MAX_CHANNELS];
static mut NEXT_CHANNEL_ID: u32 = 1;

/// Size of one SMR region: header (64 bytes) + descriptors
const SMR_REGION_SIZE: u64 = 64 + (core::mem::size_of::<SmrDescriptor>() as u64) * (SMR_CAPACITY as u64);

/// Create a new IPC channel.
/// Returns channel_id (>0) on success, or 0 on failure.
pub fn create_channel(owner_pid: u32) -> u32 {
    // Allocate physical memory for the ring
    let frames_needed = (SMR_REGION_SIZE + 4095) / 4096;
    let phys = match crate::mm::physical::alloc_frames(frames_needed) {
        Some(p) => p,
        None => return 0,
    };

    let hhdm = crate::arch::x86_64::boot::hhdm_offset().unwrap_or(0);
    let virt = phys + hhdm;

    // Zero-initialize the region
    unsafe {
        core::ptr::write_bytes(virt as *mut u8, 0, SMR_REGION_SIZE as usize);
    }

    // Initialize the SMR header
    unsafe {
        let header = virt as *mut SmrHeader;
        (*header).head = AtomicU32::new(0);
        (*header).tail = AtomicU32::new(0);
        (*header).capacity = SMR_CAPACITY as u32;
    }

    // Find a free slot
    unsafe {
        for i in 0..MAX_CHANNELS {
            if CHANNELS[i].is_none() {
                let id = NEXT_CHANNEL_ID;
                NEXT_CHANNEL_ID += 1;

                CHANNELS[i] = Some(SmrChannel {
                    state: ChannelState::Active,
                    owner_pid,
                    ring_phys: phys,
                    ring_virt: virt,
                });

                crate::arch::x86_64::serial::write_str("[IPC] Channel created: ");
                serial_dec(id as u64);
                crate::arch::x86_64::serial::write_str(" for PID ");
                serial_dec(owner_pid as u64);
                crate::arch::x86_64::serial::write_str("\r\n");

                // Store channel_id in the header for identification
                let header = virt as *mut SmrHeader;
                (*header).channel_id = id;

                return id;
            }
        }
    }

    0 // No free slot
}

/// Send a descriptor to a channel.
/// Returns 0 on success, -1 on failure.
pub fn send_to_channel(channel_id: u32, phys_addr: u64, length: u64) -> i64 {
    unsafe {
        for i in 0..MAX_CHANNELS {
            if let Some(ref ch) = CHANNELS[i] {
                let header = ch.ring_virt as *mut SmrHeader;
                if (*header).channel_id == channel_id && ch.state == ChannelState::Active {
                    let ring = SmrRing::from_raw(ch.ring_virt);
                    let desc = SmrDescriptor {
                        phys_addr,
                        length,
                        permissions: 0x03, // Read+Write
                        generation: 0,
                        metadata: DescriptorMetadata { tag: 0, flags: 0 },
                    };
                    return if ring.try_push(desc) { 0 } else { -1 };
                }
            }
        }
    }
    -1
}

/// Receive a descriptor from a channel.
/// Returns the descriptor's phys_addr on success, or 0 if empty.
pub fn recv_from_channel(channel_id: u32) -> (u64, u64) {
    unsafe {
        for i in 0..MAX_CHANNELS {
            if let Some(ref ch) = CHANNELS[i] {
                let header = ch.ring_virt as *mut SmrHeader;
                if (*header).channel_id == channel_id && ch.state == ChannelState::Active {
                    let ring = SmrRing::from_raw(ch.ring_virt);
                    return match ring.try_pop() {
                        Some(desc) => (desc.phys_addr, desc.length),
                        None => (0, 0),
                    };
                }
            }
        }
    }
    (0, 0)
}

fn serial_dec(mut val: u64) {
    if val == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while val > 0 { buf[i] = b'0' + (val % 10) as u8; val /= 10; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}
