/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
xHCI (USB 3) host controller driver: HID boot keyboards and mice.

  1. PCI scan (class 0C/03/30), BAR0 through the HHDM, BIOS->OS handoff (USBLEGSUP)
  2. Halt + reset, DCBAA (+ scratchpad), command ring, event ring, run
  3. Root port reset, Enable Slot, Address Device, descriptors, Configure Endpoint
  4. Hubs (one or more levels): power, reset and enumerate downstream ports
  5. HID boot protocol (SET_PROTOCOL 0, SET_IDLE 0), interrupt IN endpoint,
     a few Normal TRBs kept queued per endpoint

There is no IRQ plumbing: `poll()` drains the event ring from the keyboard and
mouse read paths (arch/x86_64/keyboard.rs and mouse.rs). It is cheap (one
memory read when idle) and guarded against re-entry.

All waits are bounded with tsc_stamp_us(); init never blocks boot when there is
no controller or no device.
*/

mod hid;

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, AtomicBool, Ordering};

use crate::arch::x86_64::{boot, serial, tsc};

// ─── logging ────────────────────────────────────────────────────────────────

struct Ser;
impl core::fmt::Write for Ser {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial::write_str(s);
        Ok(())
    }
}

macro_rules! xlog {
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(&mut Ser, format_args!($($arg)*));
        serial::write_str("\r\n");
    }};
}

// ─── constants ──────────────────────────────────────────────────────────────

// Operational registers
const OP_USBCMD: u64 = 0x00;
const OP_USBSTS: u64 = 0x04;
const OP_PAGESIZE: u64 = 0x08;
const OP_CRCR: u64 = 0x18;
const OP_DCBAAP: u64 = 0x30;
const OP_CONFIG: u64 = 0x38;
const OP_PORTSC: u64 = 0x400;

const CMD_RUN: u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;
const STS_HCH: u32 = 1 << 0;
const STS_CNR: u32 = 1 << 11;

// PORTSC
const PS_CCS: u32 = 1 << 0;
const PS_PED: u32 = 1 << 1;
const PS_PR: u32 = 1 << 4;
const PS_PP: u32 = 1 << 9;
const PS_CSC: u32 = 1 << 17;
const PS_PRC: u32 = 1 << 21;
/// RW1C change bits: PEC, WRC, OCC, PRC, PLC, CEC (+ CSC).
const PS_CHANGES: u32 = (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);
/// Bits that must be written back unchanged (PP, PIC, wake enables).
const PS_PRESERVE: u32 = (1 << 9) | (3 << 14) | (7 << 25);

// TRB types (control field)
const T_NORMAL: u32 = 1 << 10;
const T_SETUP: u32 = 2 << 10;
const T_DATA: u32 = 3 << 10;
const T_STATUS: u32 = 4 << 10;
const T_LINK: u32 = 6 << 10;
const T_ENABLE_SLOT: u32 = 9 << 10;
const T_DISABLE_SLOT: u32 = 10 << 10;
const T_ADDRESS: u32 = 11 << 10;
const T_CONFIG_EP: u32 = 12 << 10;
const T_EVAL: u32 = 13 << 10;
const T_RESET_EP: u32 = 14 << 10;
const T_SET_TR_DEQ: u32 = 16 << 10;
const T_NOOP: u32 = 23 << 10;
const EV_TRANSFER: u32 = 32;
const EV_CMD_DONE: u32 = 33;
const EV_PORT_CHANGE: u32 = 34;

const TRB_TC: u32 = 1 << 1; // link: toggle cycle
const TRB_ISP: u32 = 1 << 2;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;
const TRB_DIR_IN: u32 = 1 << 16;

// Completion codes
const CC_SUCCESS: u32 = 1;
const CC_SHORT: u32 = 13;

const CMD_RING_N: usize = 64;
const EP0_RING_N: usize = 32;
const HID_RING_N: usize = 16;
const EV_RING_N: usize = 256;
const MAX_SLOTS: usize = 16;
const MAX_HID: usize = 8;
const HID_QUEUED: usize = 6; // Normal TRBs kept in flight per endpoint
const HID_BUF_OFF: u64 = 256; // report buffers inside the ring page
const HID_BUF_STRIDE: u64 = 64;

const KIND_KBD: u8 = 1;
const KIND_MOUSE: u8 = 2;

// ─── data structures ────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C)]
struct Trb {
    p: u64,
    s: u32,
    c: u32,
}

impl Trb {
    const fn new(p: u64, s: u32, c: u32) -> Self {
        Trb { p, s, c }
    }
}

/// A producer ring (command, EP0 or interrupt endpoint) living in one DMA page.
#[derive(Clone, Copy)]
struct Ring {
    virt: u64,
    phys: u64,
    n: usize,
    enq: usize,
    cycle: u32,
}

impl Ring {
    const EMPTY: Ring = Ring { virt: 0, phys: 0, n: 0, enq: 0, cycle: 1 };

    fn init(&mut self, virt: u64, phys: u64, n: usize) {
        self.virt = virt;
        self.phys = phys;
        self.n = n;
        self.enq = 0;
        self.cycle = 1;
        // Link back to the start; its cycle bit is set when the producer reaches it.
        let link = Trb::new(phys, 0, T_LINK | TRB_TC);
        // SAFETY: the page is ours and zeroed.
        unsafe { write_volatile((virt + (n as u64 - 1) * 16) as *mut Trb, link) };
    }

    fn trb_phys(&self, idx: usize) -> u64 {
        self.phys + idx as u64 * 16
    }

    /// Physical address + DCS the controller should dequeue from next.
    fn deq_ptr(&self) -> u64 {
        self.trb_phys(self.enq) | self.cycle as u64
    }

    /// Queue one TRB. Returns its physical address.
    fn push(&mut self, mut t: Trb) -> u64 {
        t.c = (t.c & !1) | self.cycle;
        let phys = self.trb_phys(self.enq);
        // SAFETY: enq < n-1 always points inside the ring page.
        unsafe { write_volatile((self.virt + self.enq as u64 * 16) as *mut Trb, t) };
        self.enq += 1;
        if self.enq == self.n - 1 {
            let link = Trb::new(self.phys, 0, T_LINK | TRB_TC | self.cycle);
            // SAFETY: link TRB slot of this ring.
            unsafe { write_volatile((self.virt + (self.n as u64 - 1) * 16) as *mut Trb, link) };
            self.cycle ^= 1;
            self.enq = 0;
        }
        fence(Ordering::SeqCst);
        phys
    }
}

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    ctx_virt: u64,
    ctx_phys: u64,
    ep0: Ring,
    speed: u8,
    root_port: u8, // 1-based
    route: u32,
    depth: u8,
    tt_slot: u8,
    tt_port: u8,
    mps0: u16,
}

impl Slot {
    const EMPTY: Slot = Slot {
        used: false, ctx_virt: 0, ctx_phys: 0, ep0: Ring::EMPTY, speed: 0, root_port: 0,
        route: 0, depth: 0, tt_slot: 0, tt_port: 0, mps0: 8,
    };
}

#[derive(Clone, Copy)]
struct HidEp {
    used: bool,
    slot: u8,
    dci: u8,
    kind: u8,
    mps: u16,
    ring: Ring,
    buf_virt: u64,
    errors: u8,
    need_recover: bool,
    kbd: hid::KbdState,
}

impl HidEp {
    const EMPTY: HidEp = HidEp {
        used: false, slot: 0, dci: 0, kind: 0, mps: 0, ring: Ring::EMPTY, buf_virt: 0,
        errors: 0, need_recover: false, kbd: hid::KbdState::new(),
    };
}

struct Hc {
    mmio: u64,
    op: u64,
    rt: u64,
    db: u64,
    csz: u64,
    max_slots: u8,
    max_ports: u8,
    cmd: Ring,
    ev_virt: u64,
    ev_phys: u64,
    ev_deq: usize,
    ev_cycle: u32,
    dcbaa: u64,
    inp_virt: u64,
    inp_phys: u64,
    data_virt: u64,
    data_phys: u64,
    slots: [Slot; MAX_SLOTS + 1],
    hid: [HidEp; MAX_HID],
    cmd_res: Option<(u32, u8)>,
    ctl_wait: u64,
    ctl_done: Option<u32>,
    port_change: bool,
    broken: bool,
    kbd_count: u8,
    mouse_count: u8,
    hid_logged_err: u8,
    hid_logged_reports: [u8; 3],
}

static mut HC: Hc = Hc {
    mmio: 0, op: 0, rt: 0, db: 0, csz: 32, max_slots: 0, max_ports: 0,
    cmd: Ring::EMPTY, ev_virt: 0, ev_phys: 0, ev_deq: 0, ev_cycle: 1, dcbaa: 0,
    inp_virt: 0, inp_phys: 0, data_virt: 0, data_phys: 0,
    slots: [Slot::EMPTY; MAX_SLOTS + 1], hid: [HidEp::EMPTY; MAX_HID],
    cmd_res: None, ctl_wait: 0, ctl_done: None, port_change: false, broken: false,
    kbd_count: 0, mouse_count: 0, hid_logged_err: 0, hid_logged_reports: [0; 3],
};

static AVAILABLE: AtomicBool = AtomicBool::new(false);
static POLLING: AtomicBool = AtomicBool::new(false);

fn hc() -> &'static mut Hc {
    // SAFETY: single global controller; `poll` is re-entry guarded and init runs
    // before AVAILABLE is set, so accesses never overlap.
    unsafe { &mut *core::ptr::addr_of_mut!(HC) }
}

// ─── low level helpers ──────────────────────────────────────────────────────

fn rd32(addr: u64) -> u32 {
    // SAFETY: MMIO / DMA address inside the HHDM.
    unsafe { read_volatile(addr as *const u32) }
}

fn wr32(addr: u64, v: u32) {
    // SAFETY: as above.
    unsafe { write_volatile(addr as *mut u32, v) }
}

fn wr64(addr: u64, v: u64) {
    wr32(addr, v as u32);
    wr32(addr + 4, (v >> 32) as u32);
}

fn hhdm() -> u64 {
    boot::hhdm_offset().unwrap_or(0)
}

fn now() -> u64 {
    tsc::tsc_stamp_us()
}

fn spin_pause() {
    // SAFETY: pause is always valid.
    unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
}

/// Poll `cond` until true or `limit_us` elapses. Also capped by an iteration
/// count so a stalled time source cannot hang boot.
fn wait_until(limit_us: u64, mut cond: impl FnMut() -> bool) -> bool {
    let start = now();
    let mut iters: u64 = 0;
    loop {
        if cond() {
            return true;
        }
        iters += 1;
        if now().wrapping_sub(start) >= limit_us || iters > limit_us.saturating_mul(60) + 50_000 {
            return false;
        }
        spin_pause();
    }
}

/// Sleep (busy, bounded) for `ms` milliseconds.
fn delay_ms(ms: u64) {
    tsc::busy_wait_us(ms * 1000);
}

/// Zeroed physically contiguous DMA pages. Returns (virt, phys).
fn dma_alloc(pages: u64) -> Option<(u64, u64)> {
    let phys = crate::mm::physical::alloc_frames(pages)?;
    Some((phys + hhdm(), phys))
}

fn irq_save_cli() -> u64 {
    let flags: u64;
    // SAFETY: save RFLAGS and disable interrupts.
    unsafe { core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options(nomem)) };
    flags
}

fn irq_restore(flags: u64) {
    if flags & (1 << 9) != 0 {
        // SAFETY: interrupts were on before.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    }
}

// ─── context accessors ──────────────────────────────────────────────────────
//
// Input context:  index 0 = control, 1 = slot, 1+dci = endpoint dci.
// Device context: index 0 = slot, dci = endpoint dci.

impl Hc {
    fn in_ctx(&self, index: u64) -> u64 {
        self.inp_virt + index * self.csz
    }

    fn dev_ctx(&self, slot: u8, index: u64) -> u64 {
        self.slots[slot as usize].ctx_virt + index * self.csz
    }

    fn clear_input(&self) {
        for i in 0..(self.csz * 34 / 4) {
            wr32(self.inp_virt + i * 4, 0);
        }
    }

    fn ring_doorbell(&self, target_slot: u8, target: u8) {
        wr32(self.db + target_slot as u64 * 4, target as u32);
    }

    // ─── event ring ─────────────────────────────────────────────────────────

    fn next_event(&mut self) -> Option<Trb> {
        let addr = self.ev_virt + self.ev_deq as u64 * 16;
        // SAFETY: inside the event ring page.
        let t = unsafe { read_volatile(addr as *const Trb) };
        if (t.c & 1) != self.ev_cycle {
            return None;
        }
        fence(Ordering::Acquire);
        self.ev_deq += 1;
        if self.ev_deq == EV_RING_N {
            self.ev_deq = 0;
            self.ev_cycle ^= 1;
        }
        Some(t)
    }

    fn ack_events(&self) {
        let deq = self.ev_phys + self.ev_deq as u64 * 16;
        wr64(self.rt + 0x20 + 0x18, deq | (1 << 3)); // ERDP, clear EHB
    }

    /// Drain all pending events. Returns true if any were handled.
    fn pump(&mut self) -> bool {
        let mut any = false;
        while let Some(t) = self.next_event() {
            any = true;
            self.dispatch(t);
        }
        if any {
            self.ack_events();
        }
        any
    }

    fn dispatch(&mut self, t: Trb) {
        let ty = (t.c >> 10) & 0x3F;
        let cc = (t.s >> 24) & 0xFF;
        match ty {
            EV_CMD_DONE => {
                self.cmd_res = Some((cc, ((t.c >> 24) & 0xFF) as u8));
            }
            EV_TRANSFER => {
                let slot = ((t.c >> 24) & 0xFF) as u8;
                let dci = ((t.c >> 16) & 0x1F) as u8;
                if dci == 1 {
                    // Control endpoint: the status stage (or the first error) ends the wait.
                    if t.p == self.ctl_wait || (cc != CC_SUCCESS && cc != CC_SHORT) {
                        self.ctl_done = Some(cc);
                    }
                } else {
                    self.hid_event(slot, dci, t.p, cc, t.s & 0xFF_FFFF);
                }
            }
            EV_PORT_CHANGE => {
                self.port_change = true;
            }
            _ => {}
        }
    }

    // ─── commands ───────────────────────────────────────────────────────────

    /// Queue a command and wait for its completion. Returns (cc, slot id).
    fn command(&mut self, t: Trb, timeout_us: u64) -> Option<(u32, u8)> {
        if self.broken {
            return None;
        }
        self.cmd_res = None;
        self.cmd.push(t);
        self.ring_doorbell(0, 0);
        let start = now();
        let mut iters: u64 = 0;
        loop {
            self.pump();
            if let Some(r) = self.cmd_res.take() {
                return Some(r);
            }
            iters += 1;
            if now().wrapping_sub(start) >= timeout_us || iters > timeout_us.saturating_mul(60) + 50_000 {
                xlog!("[XHCI] command timeout (type {})", (t.c >> 10) & 0x3F);
                self.broken = true;
                return None;
            }
            spin_pause();
        }
    }

    fn cmd_ok(&mut self, t: Trb, what: &str) -> Option<u8> {
        match self.command(t, 1_000_000) {
            Some((CC_SUCCESS, slot)) => Some(slot),
            Some((cc, _)) => {
                xlog!("[XHCI] {} failed, cc={}", what, cc);
                None
            }
            None => None,
        }
    }

    // ─── control transfers ──────────────────────────────────────────────────

    /// One control transfer on EP0. For OUT data, fill `data_virt` first; for IN
    /// data the result is left in `data_virt`. Returns true on success.
    fn control(&mut self, slot: u8, bm: u8, req: u8, val: u16, idx: u16, len: u16) -> bool {
        if self.broken || !self.slots[slot as usize].used {
            return false;
        }
        let dir_in = bm & 0x80 != 0;
        let setup = bm as u64
            | (req as u64) << 8
            | (val as u64) << 16
            | (idx as u64) << 32
            | (len as u64) << 48;
        let trt: u32 = if len == 0 { 0 } else if dir_in { 3 } else { 2 };
        let data_phys = self.data_phys;
        {
            let ring = &mut self.slots[slot as usize].ep0;
            ring.push(Trb::new(setup, 8, T_SETUP | TRB_IDT | (trt << 16)));
            if len > 0 {
                ring.push(Trb::new(data_phys, len as u32, T_DATA | if dir_in { TRB_DIR_IN } else { 0 }));
            }
        }
        let status_dir = if len > 0 && dir_in { 0 } else { TRB_DIR_IN };
        let status_phys = self.slots[slot as usize].ep0.push(Trb::new(0, 0, T_STATUS | TRB_IOC | status_dir));
        self.ctl_wait = status_phys;
        self.ctl_done = None;
        self.ring_doorbell(slot, 1);

        let start = now();
        let mut iters: u64 = 0;
        let cc = loop {
            self.pump();
            if let Some(cc) = self.ctl_done.take() {
                break Some(cc);
            }
            iters += 1;
            if now().wrapping_sub(start) >= 1_000_000 || iters > 60_000_000 {
                break None;
            }
            spin_pause();
        };
        self.ctl_wait = 0;
        match cc {
            Some(CC_SUCCESS) | Some(CC_SHORT) => true,
            Some(cc) => {
                xlog!("[XHCI] slot {} control req {:#x} failed, cc={}", slot, req, cc);
                // Stall / transaction error halt the endpoint: reset it and skip the TD.
                let deq = self.slots[slot as usize].ep0.deq_ptr();
                self.recover_ep(slot, 1, deq);
                false
            }
            None => {
                xlog!("[XHCI] slot {} control req {:#x} timed out", slot, req);
                false
            }
        }
    }

    /// Reset a halted endpoint and move its dequeue pointer past the failed TD.
    fn recover_ep(&mut self, slot: u8, dci: u8, deq: u64) {
        let ep = (dci as u32) << 16;
        let _ = self.command(Trb::new(0, 0, T_RESET_EP | ep | (slot as u32) << 24), 500_000);
        let _ = self.command(Trb::new(deq, 0, T_SET_TR_DEQ | ep | (slot as u32) << 24), 500_000);
    }

    fn data(&self, off: usize) -> u8 {
        // SAFETY: data page is 4 KiB; callers stay inside it.
        unsafe { read_volatile((self.data_virt + off as u64) as *const u8) }
    }

    fn data_copy(&self, out: &mut [u8]) {
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.data(i);
        }
    }

    // ─── HID endpoint events ────────────────────────────────────────────────

    fn hid_index(&self, slot: u8, dci: u8) -> Option<usize> {
        (0..MAX_HID).find(|&i| self.hid[i].used && self.hid[i].slot == slot && self.hid[i].dci == dci)
    }

    fn hid_queue_one(&mut self, i: usize) {
        let ep = &mut self.hid[i];
        let idx = ep.ring.enq;
        let buf_phys = ep.ring.phys + HID_BUF_OFF + idx as u64 * HID_BUF_STRIDE;
        let len = (ep.mps as u32).min(HID_BUF_STRIDE as u32).max(8);
        ep.ring.push(Trb::new(buf_phys, len, T_NORMAL | TRB_IOC | TRB_ISP));
    }

    fn hid_event(&mut self, slot: u8, dci: u8, ptr: u64, cc: u32, _residual: u32) {
        let i = match self.hid_index(slot, dci) {
            Some(i) => i,
            None => return,
        };
        if cc == CC_SUCCESS || cc == CC_SHORT {
            self.hid[i].errors = 0;
            // The event points at the completed TRB; its buffer sits at the same index.
            let ring = self.hid[i].ring;
            let idx = ((ptr.wrapping_sub(ring.phys)) / 16) as usize;
            if idx < HID_RING_N - 1 {
                let buf = self.hid[i].buf_virt + idx as u64 * HID_BUF_STRIDE;
                let mut rep = [0u8; 16];
                for (k, b) in rep.iter_mut().enumerate() {
                    // SAFETY: inside the ring page.
                    *b = unsafe { read_volatile((buf + k as u64) as *const u8) };
                }
                let len = (self.hid[i].mps as usize).min(16);
                if self.hid_logged_reports[self.hid[i].kind as usize] < 10 {
                    self.hid_logged_reports[self.hid[i].kind as usize] += 1;
                    xlog!("[USB-HID] slot {} ep {} report {:02x?}", slot, dci, &rep[..len.min(8)]);
                }
                match self.hid[i].kind {
                    KIND_KBD => hid::kbd_report(&mut self.hid[i].kbd, &rep[..len.max(8).min(16)], now()),
                    KIND_MOUSE => hid::mouse_report(&rep[..len.max(3)]),
                    _ => {}
                }
            }
            self.hid_queue_one(i);
            self.ring_doorbell(slot, dci);
        } else {
            let ep = &mut self.hid[i];
            ep.errors = ep.errors.saturating_add(1);
            ep.need_recover = true;
            if self.hid_logged_err < 8 {
                self.hid_logged_err += 1;
                xlog!("[USB-HID] slot {} ep {} transfer error cc={}", slot, dci, cc);
            }
        }
    }

    fn hid_recover(&mut self) {
        for i in 0..MAX_HID {
            if !self.hid[i].used || !self.hid[i].need_recover {
                continue;
            }
            self.hid[i].need_recover = false;
            if self.hid[i].errors > 20 {
                // Device is gone or hopeless: stop servicing it.
                self.hid[i].used = false;
                xlog!("[USB-HID] slot {} ep {} disabled after repeated errors", self.hid[i].slot, self.hid[i].dci);
                continue;
            }
            let (slot, dci) = (self.hid[i].slot, self.hid[i].dci);
            // Restart on a clean ring position with a fresh set of queued TRBs.
            let deq = self.hid[i].ring.deq_ptr();
            self.recover_ep(slot, dci, deq);
            for _ in 0..HID_QUEUED {
                self.hid_queue_one(i);
            }
            self.ring_doorbell(slot, dci);
        }
    }
}

// ─── initialization ─────────────────────────────────────────────────────────

/// Initialize the first xHCI controller and enumerate HID boot devices.
/// Returns true when a controller was found and started (devices may be zero).
pub fn init() -> bool {
    xlog!("[XHCI] scanning for controller");
    let dev = match crate::pci::find_by_class(0x0C, 0x03, 0x30) {
        Some(d) => *d,
        None => {
            xlog!("[XHCI] no xHCI controller");
            return false;
        }
    };
    xlog!("[XHCI] controller at PCI {:02x}:{:02x}.{} id {:04x}:{:04x}",
        dev.bus, dev.device, dev.function, dev.vendor_id, dev.device_id);

    let (bar_phys, bar_size) = match crate::pci::read_bar(dev.bus, dev.device, dev.function, 0) {
        crate::pci::BarType::Mmio { base, size, .. } => {
            xlog!("[XHCI] BAR0 {:#x} size {:#x}", base, size);
            (base, size)
        }
        _ => {
            xlog!("[XHCI] BAR0 is not MMIO");
            return false;
        }
    };

    // Memory space + bus master; leave legacy INTx masked (we poll).
    let cmd = crate::pci::command(dev.bus, dev.device, dev.function);
    crate::pci::set_command(dev.bus, dev.device, dev.function, cmd | 0x06 | 0x400);

    // Pre-Skylake Intel PCHs boot with ports routed to EHCI; hand them to xHCI.
    if dev.vendor_id == 0x8086 && matches!(dev.device_id, 0x1E31 | 0x8C31 | 0x9C31) {
        intel_route_ports(&dev);
    }

    let h = hc();
    h.mmio = match map_bar(bar_phys, bar_size) {
        Some(v) => v,
        None => {
            xlog!("[XHCI] cannot map BAR0");
            return false;
        }
    };

    let caplen = (rd32(h.mmio) & 0xFF) as u64;
    let hci_ver = (rd32(h.mmio) >> 16) as u16;
    let hcs1 = rd32(h.mmio + 0x04);
    let hcs2 = rd32(h.mmio + 0x08);
    let hcc1 = rd32(h.mmio + 0x10);
    if hci_ver == 0xFFFF || caplen < 0x10 {
        xlog!("[XHCI] controller does not respond (version {:#x})", hci_ver);
        return false;
    }
    h.op = h.mmio + caplen;
    h.rt = h.mmio + (rd32(h.mmio + 0x18) & !0x1F) as u64;
    h.db = h.mmio + (rd32(h.mmio + 0x14) & !0x3) as u64;
    h.csz = if hcc1 & (1 << 2) != 0 { 64 } else { 32 };
    h.max_ports = ((hcs1 >> 24) & 0xFF) as u8;
    let hw_slots = (hcs1 & 0xFF) as u8;
    h.max_slots = hw_slots.min(MAX_SLOTS as u8);
    xlog!("[XHCI] version {:x}.{:02x}, {} ports, {} slots, context size {}",
        hci_ver >> 8, hci_ver & 0xFF, h.max_ports, hw_slots, h.csz);

    bios_handoff(h, hcc1);

    // Halt, then reset.
    let op = h.op;
    if rd32(op + OP_USBCMD) & CMD_RUN != 0 {
        wr32(op + OP_USBCMD, rd32(op + OP_USBCMD) & !CMD_RUN);
    }
    if !wait_until(200_000, || rd32(op + OP_USBSTS) & STS_HCH != 0) {
        xlog!("[XHCI] controller did not halt");
        return false;
    }
    wr32(op + OP_USBCMD, CMD_HCRST);
    if !wait_until(500_000, || rd32(op + OP_USBCMD) & CMD_HCRST == 0)
        || !wait_until(500_000, || rd32(op + OP_USBSTS) & STS_CNR == 0)
    {
        xlog!("[XHCI] controller reset timed out");
        return false;
    }
    xlog!("[XHCI] reset complete");

    // The 4 KiB page size must be supported.
    if rd32(op + OP_PAGESIZE) & 1 == 0 {
        xlog!("[XHCI] 4 KiB pages not supported");
        return false;
    }

    // DMA structures.
    if !setup_memory(h, hcs2) {
        xlog!("[XHCI] out of DMA memory");
        return false;
    }

    wr32(op + OP_CONFIG, h.max_slots as u32);
    wr64(op + OP_DCBAAP, h.dcbaa - hhdm());
    wr64(op + OP_CRCR, h.cmd.phys | 1);

    // Event ring (interrupter 0), interrupts stay disabled.
    let ir0 = h.rt + 0x20;
    wr32(ir0 + 0x00, 0);
    wr32(ir0 + 0x08, 1);
    wr64(ir0 + 0x18, h.ev_phys);
    wr64(ir0 + 0x10, h.ev_phys + 0x1000); // ERST in the second page

    // Run.
    wr32(op + OP_USBCMD, CMD_RUN);
    if !wait_until(200_000, || rd32(op + OP_USBSTS) & STS_HCH == 0) {
        xlog!("[XHCI] controller did not start");
        return false;
    }

    // Prove the command ring works.
    if h.cmd_ok(Trb::new(0, 0, T_NOOP), "No-Op").is_none() {
        xlog!("[XHCI] command ring not responding");
        return false;
    }
    xlog!("[XHCI] controller running");

    enumerate_ports(h);
    h.port_change = false;
    AVAILABLE.store(true, Ordering::Release);

    xlog!("[USB-HID] {} keyboard(s), {} mouse/mice ready", h.kbd_count, h.mouse_count);
    true
}

fn intel_route_ports(dev: &crate::pci::PciDevice) {
    let (b, d, f) = (dev.bus, dev.device, dev.function);
    crate::pci::config_write32(b, d, f, 0xD8, 0xFFFF_FFFF);
    let avail3 = crate::pci::config_read32(b, d, f, 0xDC);
    crate::pci::config_write32(b, d, f, 0xD8, avail3);
    crate::pci::config_write32(b, d, f, 0xD0, 0xFFFF_FFFF);
    let avail2 = crate::pci::config_read32(b, d, f, 0xD4);
    crate::pci::config_write32(b, d, f, 0xD0, avail2);
    xlog!("[XHCI] Intel port routing: USB3 {:#x} USB2 {:#x}", avail3, avail2);
}

/// Take ownership from the firmware (USBLEGSUP extended capability).
fn bios_handoff(h: &Hc, hcc1: u32) {
    let mut off = ((hcc1 >> 16) & 0xFFFF) as u64 * 4;
    let mut guard = 0;
    while off != 0 && guard < 64 {
        guard += 1;
        let cap = rd32(h.mmio + off);
        if cap & 0xFF == 1 {
            let legsup = h.mmio + off;
            if cap & (1 << 16) != 0 {
                xlog!("[XHCI] BIOS owns the controller, requesting handoff");
                wr32(legsup, cap | (1 << 24));
                if !wait_until(1_000_000, || rd32(legsup) & (1 << 16) == 0) {
                    xlog!("[XHCI] BIOS did not release the controller, forcing");
                    wr32(legsup, (rd32(legsup) & !(1 << 16)) | (1 << 24));
                }
            }
            // Disable SMIs and clear pending SMI status.
            let ctl = legsup + 4;
            let v = rd32(ctl);
            let v = (v & !((1 << 0) | (1 << 4) | (1 << 13) | (1 << 14) | (1 << 15))) | (7 << 29);
            wr32(ctl, v);
        }
        let next = ((cap >> 8) & 0xFF) as u64;
        if next == 0 {
            break;
        }
        off += next * 4;
    }
}

fn setup_memory(h: &mut Hc, hcs2: u32) -> bool {
    // DCBAA
    let (v, _) = match dma_alloc(1) { Some(x) => x, None => return false };
    h.dcbaa = v;

    // Scratchpad buffers
    let nscratch = (((hcs2 >> 21) & 0x1F) << 5) | ((hcs2 >> 27) & 0x1F);
    if nscratch > 0 {
        let arr_pages = ((nscratch as u64 * 8) + 4095) / 4096;
        let (av, ap) = match dma_alloc(arr_pages) { Some(x) => x, None => return false };
        for i in 0..nscratch as u64 {
            let (_, pp) = match dma_alloc(1) { Some(x) => x, None => return false };
            // SAFETY: inside the scratchpad array we just allocated.
            unsafe { write_volatile((av + i * 8) as *mut u64, pp) };
        }
        // SAFETY: DCBAA entry 0.
        unsafe { write_volatile(h.dcbaa as *mut u64, ap) };
        xlog!("[XHCI] {} scratchpad buffers", nscratch);
    }

    // Command ring
    let (cv, cp) = match dma_alloc(1) { Some(x) => x, None => return false };
    h.cmd.init(cv, cp, CMD_RING_N);

    // Event ring: 256 TRBs = 4 KiB; the segment table gets its own page.
    let (ev, ep) = match dma_alloc(2) { Some(x) => x, None => return false };
    h.ev_virt = ev;
    h.ev_phys = ep;
    h.ev_deq = 0;
    h.ev_cycle = 1;
    // ERST entry (16 bytes) at the start of the second page.
    let erst_v = ev + 0x1000;
    // SAFETY: second page of the allocation.
    unsafe {
        write_volatile(erst_v as *mut u64, ep);
        write_volatile((erst_v + 8) as *mut u32, EV_RING_N as u32);
        write_volatile((erst_v + 12) as *mut u32, 0);
    }

    // Input context and control data pages
    let (iv, ip) = match dma_alloc(2) { Some(x) => x, None => return false };
    h.inp_virt = iv;
    h.inp_phys = ip;
    let (dv, dp) = match dma_alloc(1) { Some(x) => x, None => return false };
    h.data_virt = dv;
    h.data_phys = dp;
    true
}

// ─── port enumeration ───────────────────────────────────────────────────────

fn port_reg(h: &Hc, port0: u8) -> u64 {
    h.op + OP_PORTSC + port0 as u64 * 16
}

fn enumerate_ports(h: &mut Hc) {
    let nports = h.max_ports;

    // Power every port that is off (PPC controllers), then let attach settle.
    let mut powered = false;
    for p in 0..nports {
        let reg = port_reg(h, p);
        let sc = rd32(reg);
        if sc & PS_PP == 0 {
            wr32(reg, (sc & PS_PRESERVE) | PS_PP);
            powered = true;
        }
    }
    delay_ms(if powered { 120 } else { 40 });

    let mut found = scan_root_ports(h);
    if !found {
        // Slow attach (USB 3 link training, hubs powering up): one more try.
        delay_ms(300);
        found = scan_root_ports(h);
    }
    if !found {
        xlog!("[XHCI] no devices attached to any root port");
    }
}

/// Enumerate every connected root port that has no device yet. True if any port had a device.
fn scan_root_ports(h: &mut Hc) -> bool {
    let mut any = false;
    for p in 0..h.max_ports {
        let sc = rd32(port_reg(h, p));
        if sc & PS_CCS == 0 {
            continue;
        }
        any = true;
        if h.slots.iter().any(|s| s.used && s.depth == 0 && s.root_port == p + 1) {
            continue;
        }
        xlog!("[XHCI] port {} connected, PORTSC={:#010x}", p + 1, sc);
        enumerate_root_port(h, p);
    }
    any
}

fn enumerate_root_port(h: &mut Hc, p: u8) {
    let reg = port_reg(h, p);
    let sc = rd32(reg);
    let pls = (sc >> 5) & 0xF;

    if !(sc & PS_PED != 0 && pls == 0) {
        // Reset (also clears stale change bits).
        wr32(reg, (sc & PS_PRESERVE) | PS_CHANGES | PS_PR);
        if !wait_until(500_000, || rd32(reg) & PS_PRC != 0) {
            xlog!("[XHCI] port {} reset timed out", p + 1);
            return;
        }
        let sc = rd32(reg);
        wr32(reg, (sc & PS_PRESERVE) | PS_CHANGES);
        if !wait_until(100_000, || rd32(reg) & PS_PED != 0) {
            xlog!("[XHCI] port {} not enabled after reset, PORTSC={:#010x}", p + 1, rd32(reg));
            return;
        }
    } else {
        wr32(reg, (sc & PS_PRESERVE) | PS_CHANGES);
    }
    delay_ms(20); // reset recovery
    let speed = ((rd32(reg) >> 10) & 0xF) as u8;
    enumerate_device(h, p + 1, 0, 0, speed, 0, 0);
}

fn speed_name(s: u8) -> &'static str {
    match s {
        1 => "full",
        2 => "low",
        3 => "high",
        4 => "super",
        5 => "super+",
        _ => "?",
    }
}

struct HidCand {
    iface: u8,
    kind: u8,
    ep_addr: u8,
    mps: u16,
    interval: u8,
}

/// Address a freshly reset device and set it up. `depth` is the number of hubs above it.
fn enumerate_device(h: &mut Hc, root_port: u8, route: u32, depth: u8, speed: u8, tt_slot: u8, tt_port: u8) {
    let slot = match h.cmd_ok(Trb::new(0, 0, T_ENABLE_SLOT), "Enable Slot") {
        Some(s) if s != 0 && (s as usize) <= MAX_SLOTS && s <= h.max_slots => s,
        Some(_) => {
            xlog!("[XHCI] no free device slot");
            return;
        }
        None => return,
    };
    let si = slot as usize;

    // Device context + EP0 ring.
    let (cv, cp) = match dma_alloc(1) { Some(x) => x, None => return };
    let (rv, rp) = match dma_alloc(1) { Some(x) => x, None => return };
    h.slots[si] = Slot::EMPTY;
    h.slots[si].used = true;
    h.slots[si].ctx_virt = cv;
    h.slots[si].ctx_phys = cp;
    h.slots[si].ep0.init(rv, rp, EP0_RING_N);
    h.slots[si].speed = speed;
    h.slots[si].root_port = root_port;
    h.slots[si].route = route;
    h.slots[si].depth = depth;
    h.slots[si].tt_slot = tt_slot;
    h.slots[si].tt_port = tt_port;
    // SAFETY: DCBAA entry for this slot.
    unsafe { write_volatile((h.dcbaa + slot as u64 * 8) as *mut u64, cp) };

    let mps0: u16 = match speed {
        4 | 5 => 512,
        3 => 64,
        _ => 8,
    };
    h.slots[si].mps0 = mps0;

    // Input context for Address Device.
    h.clear_input();
    wr32(h.in_ctx(0) + 4, 0b11); // add slot + EP0
    let hubbed_tt = (speed == 1 || speed == 2) && tt_slot != 0;
    wr32(h.in_ctx(1), route | (speed as u32) << 20 | 1 << 27);
    wr32(h.in_ctx(1) + 4, (root_port as u32) << 16);
    if hubbed_tt {
        wr32(h.in_ctx(1) + 8, tt_slot as u32 | (tt_port as u32) << 8);
    }
    let ep0 = h.in_ctx(2);
    wr32(ep0 + 4, (3 << 1) | (4 << 3) | (mps0 as u32) << 16);
    wr64(ep0 + 8, rp | 1);
    wr32(ep0 + 16, 8);

    let inp = h.inp_phys;
    if h.cmd_ok(Trb::new(inp, 0, T_ADDRESS | (slot as u32) << 24), "Address Device").is_none() {
        disable_slot(h, slot);
        return;
    }
    delay_ms(5);

    // First 8 bytes of the device descriptor give the real EP0 packet size.
    if !h.control(slot, 0x80, 6, 0x0100, 0, 8) {
        xlog!("[XHCI] slot {}: cannot read device descriptor", slot);
        disable_slot(h, slot);
        return;
    }
    let mps_code = h.data(7);
    let real_mps: u16 = if speed >= 4 { 1u16 << mps_code.min(15) } else { mps_code as u16 };
    if real_mps != 0 && real_mps != mps0 && speed < 3 {
        h.clear_input();
        wr32(h.in_ctx(0) + 4, 0b10); // evaluate EP0 only
        let src = h.dev_ctx(slot, 1);
        for i in 0..8u64 {
            wr32(h.in_ctx(2) + i * 4, rd32(src + i * 4));
        }
        let w1 = rd32(h.in_ctx(2) + 4);
        wr32(h.in_ctx(2) + 4, (w1 & 0xFFFF) | (real_mps as u32) << 16);
        let inp = h.inp_phys;
        let _ = h.cmd_ok(Trb::new(inp, 0, T_EVAL | (slot as u32) << 24), "Evaluate Context");
        h.slots[si].mps0 = real_mps;
    }

    if !h.control(slot, 0x80, 6, 0x0100, 0, 18) {
        xlog!("[XHCI] slot {}: cannot read full device descriptor", slot);
        disable_slot(h, slot);
        return;
    }
    let mut dd = [0u8; 18];
    h.data_copy(&mut dd);
    let dev_class = dd[4];
    let vid = u16::from_le_bytes([dd[8], dd[9]]);
    let pid = u16::from_le_bytes([dd[10], dd[11]]);

    // Configuration descriptor (header, then everything).
    if !h.control(slot, 0x80, 6, 0x0200, 0, 9) {
        xlog!("[XHCI] slot {}: cannot read configuration descriptor", slot);
        disable_slot(h, slot);
        return;
    }
    let total = (u16::from_le_bytes([h.data(2), h.data(3)]) as usize).min(512);
    let cfg_value = h.data(5);
    if total < 9 || !h.control(slot, 0x80, 6, 0x0200, 0, total as u16) {
        xlog!("[XHCI] slot {}: cannot read full configuration descriptor", slot);
        disable_slot(h, slot);
        return;
    }
    let mut cfg = [0u8; 512];
    h.data_copy(&mut cfg[..total]);

    // Walk the descriptors: boot HID interfaces with an interrupt IN endpoint, hubs.
    let mut cands: [Option<HidCand>; 4] = [None, None, None, None];
    let mut ncand = 0;
    let mut is_hub = dev_class == 9;
    let mut cur_iface: Option<(u8, u8, u8, u8)> = None; // (num, class, subclass, proto)
    let mut off = 0usize;
    while off + 2 <= total {
        let len = cfg[off] as usize;
        let ty = cfg[off + 1];
        if len < 2 || off + len > total {
            break;
        }
        match ty {
            4 if len >= 9 => {
                let alt = cfg[off + 3];
                cur_iface = if alt == 0 {
                    Some((cfg[off + 2], cfg[off + 5], cfg[off + 6], cfg[off + 7]))
                } else {
                    None
                };
                if cfg[off + 5] == 9 {
                    is_hub = true;
                }
            }
            5 if len >= 7 => {
                if let Some((num, 3, 1, proto @ (1 | 2))) = cur_iface {
                    let addr = cfg[off + 2];
                    let attr = cfg[off + 3];
                    if addr & 0x80 != 0 && attr & 3 == 3 && ncand < cands.len()
                        && !cands.iter().flatten().any(|c| c.iface == num)
                    {
                        cands[ncand] = Some(HidCand {
                            iface: num,
                            kind: if proto == 1 { KIND_KBD } else { KIND_MOUSE },
                            ep_addr: addr,
                            mps: u16::from_le_bytes([cfg[off + 4], cfg[off + 5]]) & 0x7FF,
                            interval: cfg[off + 6],
                        });
                        ncand += 1;
                    }
                }
            }
            _ => {}
        }
        off += len;
    }

    xlog!("[XHCI] slot {}: {:04x}:{:04x} class {} {} speed, port {} route {:#x}{}{}",
        slot, vid, pid, dev_class, speed_name(speed), root_port, route,
        if is_hub { ", hub" } else { "" },
        if ncand > 0 { ", HID boot" } else { "" });

    if ncand == 0 && !is_hub {
        // Nothing we drive (storage, tablet without boot protocol, ...). Release the slot.
        disable_slot(h, slot);
        return;
    }

    if !h.control(slot, 0x00, 9, cfg_value as u16, 0, 0) {
        xlog!("[XHCI] slot {}: Set Configuration failed", slot);
        disable_slot(h, slot);
        return;
    }

    if ncand > 0 {
        setup_hid(h, slot, &cands, ncand);
    }
    if is_hub {
        setup_hub(h, slot, depth, speed);
    }
}

fn disable_slot(h: &mut Hc, slot: u8) {
    let _ = h.command(Trb::new(0, 0, T_DISABLE_SLOT | (slot as u32) << 24), 500_000);
    // SAFETY: DCBAA entry for this slot.
    unsafe { write_volatile((h.dcbaa + slot as u64 * 8) as *mut u64, 0) };
    h.slots[slot as usize].used = false;
}

fn interval_exp(speed: u8, b_interval: u8) -> u32 {
    let bi = (b_interval as u32).max(1);
    let exp = if speed >= 3 {
        // High/SuperSpeed: bInterval = 2^(n-1) microframes.
        bi - 1
    } else {
        // Full/low speed: bInterval is in frames (ms); 1 ms = 8 microframes.
        31 - (bi * 8).leading_zeros()
    };
    exp.min(15)
}

fn setup_hid(h: &mut Hc, slot: u8, cands: &[Option<HidCand>; 4], ncand: usize) {
    let si = slot as usize;
    let speed = h.slots[si].speed;

    // Boot protocol + report only on change (best effort: some devices stall SET_IDLE).
    for c in cands.iter().flatten() {
        let _ = h.control(slot, 0x21, 0x0B, 0, c.iface as u16, 0);
        let _ = h.control(slot, 0x21, 0x0A, 0, c.iface as u16, 0);
    }

    // Allocate endpoint slots + rings.
    let mut maxdci = 1u8;
    let mut add_flags = 1u32; // slot context
    let mut chosen = [usize::MAX; 4];
    for (ci, c) in cands.iter().enumerate().take(ncand) {
        let c = match c { Some(c) => c, None => continue };
        let hi = match (0..MAX_HID).find(|&i| !h.hid[i].used && !h.hid[i].need_recover && h.hid[i].slot == 0) {
            Some(i) => i,
            None => {
                xlog!("[USB-HID] too many HID endpoints");
                break;
            }
        };
        let (rv, rp) = match dma_alloc(1) { Some(x) => x, None => break };
        let dci = (c.ep_addr & 0x0F) * 2 + 1;
        let ep = &mut h.hid[hi];
        *ep = HidEp::EMPTY;
        ep.slot = slot; // reserves the entry until `used` is set
        ep.dci = dci;
        ep.kind = c.kind;
        ep.mps = c.mps.max(3);
        ep.ring.init(rv, rp, HID_RING_N);
        ep.buf_virt = rv + HID_BUF_OFF;
        maxdci = maxdci.max(dci);
        add_flags |= 1 << dci;
        chosen[ci] = hi;
    }
    if add_flags == 1 {
        return;
    }

    // Configure Endpoint: copy the slot context, add the interrupt endpoints.
    h.clear_input();
    wr32(h.in_ctx(0) + 4, add_flags);
    for i in 0..8u64 {
        wr32(h.in_ctx(1) + i * 4, rd32(h.dev_ctx(slot, 0) + i * 4));
    }
    let d0 = rd32(h.in_ctx(1));
    wr32(h.in_ctx(1), (d0 & 0x07FF_FFFF) | (maxdci as u32) << 27);
    for (ci, c) in cands.iter().enumerate().take(ncand) {
        let (c, hi) = match (c, chosen[ci]) {
            (Some(c), hi) if hi != usize::MAX => (c, hi),
            _ => continue,
        };
        let ep = &h.hid[hi];
        let ctx = h.in_ctx(1 + ep.dci as u64);
        wr32(ctx, interval_exp(speed, c.interval) << 16);
        wr32(ctx + 4, (3 << 1) | (7 << 3) | (ep.mps as u32) << 16); // CErr 3, Interrupt IN
        wr64(ctx + 8, ep.ring.phys | 1);
        wr32(ctx + 16, (ep.mps as u32) | (ep.mps as u32) << 16);
    }
    let inp = h.inp_phys;
    if h.cmd_ok(Trb::new(inp, 0, T_CONFIG_EP | (slot as u32) << 24), "Configure Endpoint").is_none() {
        for hi in chosen.iter().filter(|&&x| x != usize::MAX) {
            h.hid[*hi] = HidEp::EMPTY;
        }
        return;
    }

    for (ci, c) in cands.iter().enumerate().take(ncand) {
        let (c, hi) = match (c, chosen[ci]) {
            (Some(c), hi) if hi != usize::MAX => (c, hi),
            _ => continue,
        };
        h.hid[hi].used = true;
        for _ in 0..HID_QUEUED {
            h.hid_queue_one(hi);
        }
        let dci = h.hid[hi].dci;
        h.ring_doorbell(slot, dci);
        match c.kind {
            KIND_KBD => h.kbd_count += 1,
            _ => h.mouse_count += 1,
        }
        xlog!("[USB-HID] slot {} {} on iface {}, endpoint DCI {}, mps {}, interval {}",
            slot, if c.kind == KIND_KBD { "keyboard" } else { "mouse" }, c.iface, dci, c.mps, c.interval);
    }
}

// ─── hubs ───────────────────────────────────────────────────────────────────

fn setup_hub(h: &mut Hc, slot: u8, depth: u8, speed: u8) {
    let ss = speed >= 4;
    if depth >= 4 {
        xlog!("[XHCI] hub nesting too deep, ignoring");
        return;
    }
    // Hub descriptor.
    let dtype: u16 = if ss { 0x2A00 } else { 0x2900 };
    if !h.control(slot, 0xA0, 6, dtype, 0, 12) {
        xlog!("[XHCI] slot {}: hub descriptor read failed", slot);
        return;
    }
    let nports = h.data(2);
    let chars = u16::from_le_bytes([h.data(3), h.data(4)]);
    let pwr_good_ms = (h.data(5) as u64 * 2).min(500);
    if nports == 0 || nports > 15 {
        xlog!("[XHCI] slot {}: hub reports {} ports", slot, nports);
        return;
    }
    if ss && !h.control(slot, 0x20, 12, depth as u16, 0, 0) {
        xlog!("[XHCI] slot {}: Set Hub Depth failed", slot);
    }

    // Tell the controller this slot is a hub.
    h.clear_input();
    wr32(h.in_ctx(0) + 4, 1);
    for i in 0..8u64 {
        wr32(h.in_ctx(1) + i * 4, rd32(h.dev_ctx(slot, 0) + i * 4));
    }
    let d0 = rd32(h.in_ctx(1));
    wr32(h.in_ctx(1), d0 | 1 << 26);
    let d1 = rd32(h.in_ctx(1) + 4);
    wr32(h.in_ctx(1) + 4, (d1 & 0x00FF_FFFF) | (nports as u32) << 24);
    if !ss {
        let d2 = rd32(h.in_ctx(1) + 8);
        wr32(h.in_ctx(1) + 8, (d2 & !(3 << 16)) | (((chars >> 5) & 3) as u32) << 16);
    }
    let inp = h.inp_phys;
    if h.cmd_ok(Trb::new(inp, 0, T_CONFIG_EP | (slot as u32) << 24), "Configure hub slot").is_none() {
        return;
    }
    xlog!("[XHCI] slot {}: hub with {} ports", slot, nports);

    // Power all ports, wait for power-good, then look at each one.
    for p in 1..=nports {
        let _ = h.control(slot, 0x23, 3, 8, p as u16, 0);
    }
    delay_ms(pwr_good_ms + 100);

    for p in 1..=nports {
        if !h.control(slot, 0xA3, 0, 0, p as u16, 4) {
            continue;
        }
        let st = u32::from_le_bytes([h.data(0), h.data(1), h.data(2), h.data(3)]);
        if st & 1 == 0 {
            continue; // nothing connected
        }
        xlog!("[XHCI] hub slot {} port {} connected, status {:#010x}", slot, p, st);
        // Clear C_PORT_CONNECTION, then reset the port.
        let _ = h.control(slot, 0x23, 1, 16, p as u16, 0);
        if !h.control(slot, 0x23, 3, 4, p as u16, 0) {
            continue;
        }
        let mut st = 0u32;
        let mut ok = false;
        let start = now();
        while now().wrapping_sub(start) < 600_000 {
            delay_ms(20);
            if h.control(slot, 0xA3, 0, 0, p as u16, 4) {
                st = u32::from_le_bytes([h.data(0), h.data(1), h.data(2), h.data(3)]);
                if st & (1 << 4) == 0 && st & (1 << 20) != 0 {
                    ok = true;
                    break;
                }
            } else {
                break;
            }
        }
        let _ = h.control(slot, 0x23, 1, 20, p as u16, 0); // C_PORT_RESET
        if !ok || st & 2 == 0 {
            xlog!("[XHCI] hub slot {} port {} did not enable, status {:#010x}", slot, p, st);
            continue;
        }
        delay_ms(20);
        let dspeed = if ss {
            4
        } else if st & (1 << 9) != 0 {
            2
        } else if st & (1 << 10) != 0 {
            3
        } else {
            1
        };
        let hub = h.slots[slot as usize];
        let route = hub.route | ((p.min(15) as u32) << (4 * depth as u32));
        let (tt_s, tt_p) = if hub.speed == 3 && dspeed < 3 {
            (slot, p)
        } else {
            (hub.tt_slot, hub.tt_port)
        };
        enumerate_device(h, hub.root_port, route, depth + 1, dspeed, tt_s, tt_p);
    }
}

// ─── runtime: polling ───────────────────────────────────────────────────────

/// True once a controller is running.
pub fn is_available() -> bool {
    AVAILABLE.load(Ordering::Acquire)
}

/// (keyboards, mice) found at init.
pub fn hid_counts() -> (u8, u8) {
    let h = hc();
    (h.kbd_count, h.mouse_count)
}

/// Process pending xHCI events and run keyboard auto-repeat. Safe to call from
/// any non-interrupt context, as often as you like; does nothing without a
/// controller. `allow_repeat` should only be set by callers that consume keys
/// (it queues more scancodes).
pub fn poll(allow_repeat: bool) {
    if !AVAILABLE.load(Ordering::Acquire) {
        return;
    }
    if POLLING.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        return;
    }
    let h = hc();
    h.pump();
    if !h.broken && h.hid.iter().any(|e| e.used && e.need_recover) {
        h.hid_recover();
    }
    if allow_repeat {
        let t = now();
        for i in 0..MAX_HID {
            if h.hid[i].used && h.hid[i].kind == KIND_KBD && hid::kbd_repeating(&h.hid[i].kbd) {
                hid::kbd_repeat(&mut h.hid[i].kbd, t);
            }
        }
    }
    POLLING.store(false, Ordering::Release);
}

/// Virtual window for the controller registers, mapped uncached (the HHDM maps
/// device memory write-back and does not reach BARs above 4 GiB).
const XHCI_UC_VIRT_BASE: u64 = 0xFFFF_FF40_0000_0000;

fn map_bar(phys: u64, size: u64) -> Option<u64> {
    use crate::mm::r#virtual as vmm;
    let page_off = phys & 0xFFF;
    let base_page = phys & !0xFFF;
    let span = size.clamp(0x1000, 0x40000); // registers + doorbells + runtime fit in 256 KiB
    let pages = (page_off + span + 0xFFF) / 0x1000;
    for p in 0..pages {
        if !vmm::map_page_current(
            XHCI_UC_VIRT_BASE + p * 0x1000,
            base_page + p * 0x1000,
            vmm::FLAG_WRITABLE | vmm::FLAG_PCD | vmm::FLAG_PWT | vmm::FLAG_NX,
        ) {
            return None;
        }
    }
    Some(XHCI_UC_VIRT_BASE + page_off)
}
