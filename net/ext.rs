/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab

External NIC: the link between the in-kernel network stack and a NIC driver that runs in
ring 3 (docs/en/dev/drivers.md, "Network drivers").

The driver allocates one physically contiguous DMA region and lays it out like this:

  page 0      header (RingHeader below), with the packet lengths
  rx_off      nslots receive slots of slot_size bytes: the NIC DMAs frames straight into them
  tx_off      nslots transmit slots: the kernel copies a frame in, the NIC sends it from there

and registers it with `netdrv_ctl(ATTACH, device, notification, region)`. The stack reads
received frames in place (zero copy on the receive path) and releases a slot when it asks
for the next frame. Indices are free-running u32 counters; slot = index % nslots.
rx_prod and tx_cons belong to the driver, rx_cons and tx_prod to the kernel.

Wake-ups: the kernel signals `notification` (bit 2) after queuing a frame to send. The
driver calls `netdrv_ctl(POLL)` after it has published received frames; the kernel then runs
the stack's receive path in the driver's syscall. If the driver dies, the next stack call
notices it and the NIC goes back to "no link" until a driver attaches again. The IP
configuration is kept, so a restarted driver continues with the same lease.
*/

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::core::object::{self, ExtGrab};
use crate::core::sync::{IrqSpinLock, rank};
use crate::core::syscall::SyscallError as E;

pub const MAGIC: u32 = 0x474E_524E; // "NRNG"
pub const VERSION: u32 = 1;
pub const MAX_SLOTS: u32 = 128;
/// Notification bit the kernel sets when frames wait in the transmit ring.
pub const KICK_TX: u32 = 2;

/// Header at offset 0 of the region (all fields little endian; the driver writes it
/// before attaching, then only the indices, lengths and `flags`).
#[repr(C)]
pub struct RingHeader {
    pub magic: u32,
    pub version: u32,
    pub mac: [u8; 6],
    /// bit 0: link up, bit 1: driver running
    pub flags: u16,
    pub nslots: u32,
    pub slot_size: u32,
    pub rx_off: u32,
    pub tx_off: u32,
    pub rx_prod: AtomicU32,
    pub rx_cons: AtomicU32,
    pub tx_prod: AtomicU32,
    pub tx_cons: AtomicU32,
    pub rx_dropped: u32,
    pub tx_dropped: u32,
    pub _pad: [u32; 2],
    pub rx_len: [u16; 128],
    pub tx_len: [u16; 128],
}

struct Ext {
    grab: ExtGrab,
    pid: u32,
    base: usize, // HHDM address of the region
    nslots: u32,
    slot: u32,
    rx_off: usize,
    tx_off: usize,
    /// A frame handed out by receive_packet is released on the next call.
    rx_held: bool,
}

static EXT: IrqSpinLock<Option<Ext>> = IrqSpinLock::new("EXT", rank::DEV, None);
static ATTACHED: AtomicBool = AtomicBool::new(false);
static TX_COUNT: AtomicU32 = AtomicU32::new(0);
static RX_COUNT: AtomicU32 = AtomicU32::new(0);

fn hdr(base: usize) -> &'static mut RingHeader {
    // SAFETY: the region is kept alive by the reference in `Ext`, and `base` is its
    // HHDM mapping. Racing with the driver is by design: the fields shared with it are atomics
    // or plain words written by one side only.
    unsafe { &mut *(base as *mut RingHeader) }
}

/// True while a driver is attached.
pub fn is_attached() -> bool {
    ATTACHED.load(Ordering::Relaxed)
}

pub fn attach(dev: u32, notif: u32, region: u32) -> Result<(), i64> {
    if super::active_nic() == super::NIC_NONE {
        return Err(E::NotSupported as i64);
    }
    let grab = object::ext_grab(dev, notif, region)?;
    let bad = |g: &ExtGrab| {
        object::ext_drop(g);
        Err(E::InvalidArgument as i64)
    };
    if (grab.size as usize) < core::mem::size_of::<RingHeader>() {
        return bad(&grab);
    }
    let base = crate::mm::r#virtual::phys_to_virt(grab.phys) as usize;
    let h = hdr(base);
    let (n, ss) = (h.nslots, h.slot_size);
    let (ro, to) = (h.rx_off as u64, h.tx_off as u64);
    let end = |off: u64| off + n as u64 * ss as u64;
    if h.magic != MAGIC
        || h.version != VERSION
        || n == 0
        || n > MAX_SLOTS
        || !n.is_power_of_two()
        || ss < 1600
        || ss > 4096
        || ro % 64 != 0
        || to % 64 != 0
        || ro < core::mem::size_of::<RingHeader>() as u64
        || to < core::mem::size_of::<RingHeader>() as u64
        || end(ro) > grab.size
        || end(to) > grab.size
    {
        return bad(&grab);
    }
    // A stale previous driver (crashed) is replaced.
    detach();
    h.rx_cons.store(h.rx_prod.load(Ordering::Acquire), Ordering::Release);
    h.tx_prod.store(h.tx_cons.load(Ordering::Acquire), Ordering::Release);
    let pid = crate::core::scheduler::current_pid();
    let mac = h.mac;
    *EXT.lock() = Some(Ext {
        grab,
        pid,
        base,
        nslots: n,
        slot: ss,
        rx_off: ro as usize,
        tx_off: to as usize,
        rx_held: false,
    });
    ATTACHED.store(true, Ordering::Release);
    // SAFETY: single words written during setup; readers tolerate either value.
    unsafe { super::OUR_MAC = mac; }
    super::switch_to_ext();
    crate::arch::x86_64::serial::write_str("[NET] external NIC driver attached (ring 3)\r\n");
    Ok(())
}

pub fn detach() {
    let old = EXT.lock().take();
    if let Some(e) = old {
        ATTACHED.store(false, Ordering::Release);
        object::ext_drop(&e.grab);
        crate::arch::x86_64::serial::write_str("[NET] external NIC driver detached\r\n");
    }
}

/// Detach if the driver process is gone. Called before taking the EXT lock.
fn check_alive() -> bool {
    if !is_attached() {
        return false;
    }
    let pid = match EXT.lock().as_ref() {
        Some(e) => e.pid,
        None => return false,
    };
    if crate::core::scheduler::task_alive(pid) {
        true
    } else {
        detach();
        false
    }
}

pub fn link_up() -> bool {
    if !check_alive() {
        return false;
    }
    EXT.lock().as_ref().map_or(false, |e| hdr(e.base).flags & 1 != 0)
}

/// Next received frame, in place in the driver's DMA region.
pub fn receive_packet() -> Option<(&'static [u8], usize)> {
    if !check_alive() {
        return None;
    }
    let mut g = EXT.lock();
    let e = g.as_mut()?;
    let h = hdr(e.base);
    let mut cons = h.rx_cons.load(Ordering::Relaxed);
    if e.rx_held {
        cons = cons.wrapping_add(1);
        h.rx_cons.store(cons, Ordering::Release);
        e.rx_held = false;
    }
    if cons == h.rx_prod.load(Ordering::Acquire) {
        return None;
    }
    let slot = (cons % e.nslots) as usize;
    let len = (h.rx_len[slot] as usize).min(e.slot as usize);
    let p = (e.base + e.rx_off + slot * e.slot as usize) as *const u8;
    e.rx_held = true;
    RX_COUNT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: inside the region; the slot is not reused until rx_cons moves past it.
    Some((unsafe { core::slice::from_raw_parts(p, len) }, len))
}

pub fn send_packet(buf: &[u8], len: usize) {
    if len == 0 || len > buf.len() || !check_alive() {
        return;
    }
    {
        let mut g = EXT.lock();
        let e = match g.as_mut() {
            Some(e) => e,
            None => return,
        };
        let h = hdr(e.base);
        let prod = h.tx_prod.load(Ordering::Relaxed);
        if prod.wrapping_sub(h.tx_cons.load(Ordering::Acquire)) >= e.nslots || len > e.slot as usize {
            h.tx_dropped = h.tx_dropped.wrapping_add(1);
            return;
        }
        let slot = (prod % e.nslots) as usize;
        let dst = (e.base + e.tx_off + slot * e.slot as usize) as *mut u8;
        // SAFETY: slot inside the region, owned by the kernel until tx_prod moves past it.
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, len) };
        h.tx_len[slot] = len as u16;
        h.tx_prod.store(prod.wrapping_add(1), Ordering::Release);
        TX_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    kick();
}

/// Wake the driver. Skipped when a lock above OBJ is held (the driver also wakes on a
/// short timeout, so the frame still goes out).
fn kick() {
    if crate::core::sync::locks_held() {
        return;
    }
    let n = EXT.lock().as_ref().map(|e| e.grab.notif);
    if let Some(n) = n {
        object::kernel_signal(n, KICK_TX);
    }
}

/// netdrv_ctl(POLL): the driver published frames; run the receive path now.
pub fn poll() -> i64 {
    if !check_alive() {
        return E::PeerClosed as i64;
    }
    crate::core::scheduler::without_interrupts(super::poll_if_idle);
    0
}

/// netdrv_ctl(STATUS): bit 0 attached, bits 8.. frames received by the stack (low 16 bits),
/// bits 24.. frames sent.
pub fn status() -> i64 {
    (is_attached() as i64)
        | ((RX_COUNT.load(Ordering::Relaxed) as i64 & 0xFFFF) << 8)
        | ((TX_COUNT.load(Ordering::Relaxed) as i64 & 0xFFFF) << 24)
}
