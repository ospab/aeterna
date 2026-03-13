/*
 * AETERNA Userspace IPC Channel Manager
 *
 * Manages SMR (Shared Memory Ring) channels that connect userspace
 * servers (VFS, drivers) with their clients via the kernel.
 *
 * Each channel is a pair of SmrRings backed by physically contiguous
 * memory allocated from the PMM.
 *
 * Security: channels enforce PID-based access control. Only the owner
 * and PIDs explicitly granted access may send/receive on a channel.
 * This prevents unauthorized cross-process IPC communication.
 */

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use crate::core::ipc::smr::{SmrRing, SmrDescriptor, SmrHeader, SMR_CAPACITY, DescriptorMetadata};

/// Maximum number of IPC channels
const MAX_CHANNELS: usize = 16;

/// Maximum number of PIDs that can be granted access to a single channel.
const MAX_CHANNEL_PEERS: usize = 4;

/// Channel state
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChannelState {
    Free,
    Active,
}

/// A managed IPC channel backed by an SMR ring.
/// Access is restricted to the `owner_pid` and up to `MAX_CHANNEL_PEERS`
/// additional PIDs that have been explicitly granted access.
struct SmrChannel {
    state: ChannelState,
    owner_pid: u32,
    ring_phys: u64,    // Physical address of the SMR region
    ring_virt: u64,    // HHDM virtual address
    /// List of PIDs granted access to this channel (besides owner).
    allowed_pids: [u32; MAX_CHANNEL_PEERS],
    /// Number of valid entries in `allowed_pids`.
    allowed_count: usize,
}

impl SmrChannel {
    /// Check whether a given PID has access to this channel.
    fn has_access(&self, pid: u32) -> bool {
        if pid == self.owner_pid {
            return true;
        }
        for i in 0..self.allowed_count {
            if self.allowed_pids[i] == pid {
                return true;
            }
        }
        false
    }

    /// Grant access to an additional PID. Returns true on success.
    fn grant_access(&mut self, pid: u32) -> bool {
        if self.has_access(pid) {
            return true; // already authorized
        }
        if self.allowed_count >= MAX_CHANNEL_PEERS {
            return false; // table full
        }
        self.allowed_pids[self.allowed_count] = pid;
        self.allowed_count += 1;
        true
    }
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
                    allowed_pids: [0; MAX_CHANNEL_PEERS],
                    allowed_count: 0,
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

/// Grant another PID access to a channel.
/// Requires that the caller is the channel owner or has `Capability::System`.
pub fn grant_channel_access(channel_id: u32, target_pid: u32) -> bool {
    let caller_pid = crate::core::scheduler::current_pid();
    let has_system = crate::core::scheduler::has_capability(
        crate::core::scheduler::Capability::System,
    );

    unsafe {
        for i in 0..MAX_CHANNELS {
            if let Some(ref mut ch) = CHANNELS[i] {
                let header = ch.ring_virt as *mut SmrHeader;
                if (*header).channel_id == channel_id && ch.state == ChannelState::Active {
                    // Only owner or System-capability holder can grant access
                    if caller_pid != ch.owner_pid && !has_system {
                        crate::arch::x86_64::serial::write_str("[IPC] Access denied: PID ");
                        serial_dec(caller_pid as u64);
                        crate::arch::x86_64::serial::write_str(" tried to grant access to channel ");
                        serial_dec(channel_id as u64);
                        crate::arch::x86_64::serial::write_str("\r\n");
                        return false;
                    }
                    let ok = ch.grant_access(target_pid);
                    if ok {
                        crate::arch::x86_64::serial::write_str("[IPC] Granted PID ");
                        serial_dec(target_pid as u64);
                        crate::arch::x86_64::serial::write_str(" access to channel ");
                        serial_dec(channel_id as u64);
                        crate::arch::x86_64::serial::write_str("\r\n");
                    }
                    return ok;
                }
            }
        }
    }
    false
}

/// Send a descriptor to a channel.
/// Returns 0 on success, -1 on failure, -2 on access denied.
pub fn send_to_channel(channel_id: u32, phys_addr: u64, length: u64) -> i64 {
    let caller_pid = crate::core::scheduler::current_pid();

    unsafe {
        for i in 0..MAX_CHANNELS {
            if let Some(ref ch) = CHANNELS[i] {
                let header = ch.ring_virt as *mut SmrHeader;
                if (*header).channel_id == channel_id && ch.state == ChannelState::Active {
                    // Access control check
                    if !ch.has_access(caller_pid) {
                        crate::arch::x86_64::serial::write_str("[IPC] Send denied: PID ");
                        serial_dec(caller_pid as u64);
                        crate::arch::x86_64::serial::write_str(" on channel ");
                        serial_dec(channel_id as u64);
                        crate::arch::x86_64::serial::write_str("\r\n");
                        return -2; // Access denied
                    }

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
/// Returns the descriptor's phys_addr on success, or 0 if empty / access denied.
pub fn recv_from_channel(channel_id: u32) -> (u64, u64) {
    let caller_pid = crate::core::scheduler::current_pid();

    unsafe {
        for i in 0..MAX_CHANNELS {
            if let Some(ref ch) = CHANNELS[i] {
                let header = ch.ring_virt as *mut SmrHeader;
                if (*header).channel_id == channel_id && ch.state == ChannelState::Active {
                    // Access control check
                    if !ch.has_access(caller_pid) {
                        crate::arch::x86_64::serial::write_str("[IPC] Recv denied: PID ");
                        serial_dec(caller_pid as u64);
                        crate::arch::x86_64::serial::write_str(" on channel ");
                        serial_dec(channel_id as u64);
                        crate::arch::x86_64::serial::write_str("\r\n");
                        return (0, 0);
                    }

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
