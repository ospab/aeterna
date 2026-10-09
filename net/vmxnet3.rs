/*
 * VMware vmxnet3 paravirtual NIC driver (PCI 15ad:07b0)
 *
 * Emulated by VMware Workstation/ESXi and by QEMU (`-device vmxnet3`).
 * Minimal, polling-only implementation of device revision 1 / UPT 1:
 *   - one TX queue (TX ring + TX completion ring + data ring),
 *   - one RX queue (ring 0 with 1536-byte HEAD buffers, ring 1 unused,
 *     RX completion ring),
 *   - interrupts disabled (intrCtrl = DISABLE_ALL); the stack polls.
 * Layouts follow vmxnet3_defs.h (Linux) / the VMware vmxnet3 spec.
 * BAR0 = "PT" registers (producer doorbells), BAR1 = "VD" registers.
 */

use core::sync::atomic::{fence, Ordering};

const VMXNET3_VENDOR: u16 = 0x15AD;
const VMXNET3_DEVICE: u16 = 0x07B0;

// BAR1 (VD) registers
const VD_VRRS: usize = 0x00;
const VD_UVRS: usize = 0x08;
const VD_DSAL: usize = 0x10;
const VD_DSAH: usize = 0x18;
const VD_CMD:  usize = 0x20;
const VD_MACL: usize = 0x28;
const VD_MACH: usize = 0x30;
// BAR0 (PT) registers
const PT_IMR0:   usize = 0x000;
const PT_TXPROD: usize = 0x600;
const PT_RXPROD: usize = 0x800;
const PT_RXPROD2: usize = 0xA00;

const CMD_ACTIVATE_DEV:   u32 = 0xCAFE_0000;
const CMD_RESET_DEV:      u32 = 0xCAFE_0002;
const CMD_UPDATE_RX_MODE: u32 = 0xCAFE_0003;
const CMD_GET_LINK:       u32 = 0xF00D_0002;

const RXM_UCAST: u32 = 0x01;
const RXM_MCAST: u32 = 0x02;
const RXM_BCAST: u32 = 0x04;

const TX_RING: usize = 32;
const RX_RING: usize = 32;
const RX_COMP: usize = RX_RING * 2; // completion ring covers both RX rings
const BUF_SIZE: usize = 1536;
const DATA_DESC_SIZE: usize = 128;

// Driver-shared area offsets (Vmxnet3_DriverShared)
const DS_MAGIC: usize = 0;
const DS_VERSION: usize = 8;
const DS_GOS: usize = 12;
const DS_REV_SPT: usize = 16;
const DS_UPT_SPT: usize = 20;
const DS_UPT_FEATURES: usize = 24;
const DS_QUEUE_DESC_PA: usize = 40;
const DS_QUEUE_DESC_LEN: usize = 52;
const DS_MTU: usize = 56;
const DS_MAX_RX_SG: usize = 60;
const DS_NUM_TXQ: usize = 62;
const DS_NUM_RXQ: usize = 63;
const DS_AUTOMASK: usize = 80;
const DS_NUM_INTRS: usize = 81;
const DS_EVENT_INTR: usize = 82;
const DS_INTR_CTRL: usize = 108;
const DS_RX_MODE: usize = 120;
const DS_SIZE: usize = 720;

// Queue descriptor table: TxQueueDesc (256 bytes) followed by RxQueueDesc
const TXQ_OFF: usize = 0;
const RXQ_OFF: usize = 256;
const QDESC_LEN: usize = 256 + 256;

#[repr(C, align(4096))]
struct Page<const N: usize>([u8; N]);

static mut SHARED: Page<4096> = Page([0; 4096]);
static mut QDESC: Page<4096> = Page([0; 4096]);
static mut TX_DESC: Page<4096> = Page([0; 4096]);   // TX_RING * 16
static mut TX_COMP_R: Page<4096> = Page([0; 4096]); // TX_RING * 16
static mut TX_DATA: Page<4096> = Page([0; 4096]);   // TX_RING * 128
static mut RX_DESC0: Page<4096> = Page([0; 4096]);  // RX_RING * 16
static mut RX_DESC1: Page<4096> = Page([0; 4096]);  // RX_RING * 16 (unused ring)
static mut RX_COMP_R: Page<4096> = Page([0; 4096]); // RX_COMP * 16
static mut TX_BUFS: [[u8; BUF_SIZE]; TX_RING] = [[0; BUF_SIZE]; TX_RING];
static mut RX_BUFS: [[u8; BUF_SIZE]; RX_RING] = [[0; BUF_SIZE]; RX_RING];
static mut PACKET_OUT: [u8; BUF_SIZE] = [0; BUF_SIZE];

static mut BAR0: usize = 0;
static mut BAR1: usize = 0;
static mut MAC: [u8; 6] = [0; 6];
static mut INITIALIZED: bool = false;

// Ring state
static mut TX_NEXT: usize = 0;
static mut TX_GEN: u32 = 1;
static mut TX_INFLIGHT: usize = 0;
static mut TXC_NEXT: usize = 0;
static mut TXC_GEN: u32 = 1;
static mut RX_FILL: usize = 0;
static mut RX_FILL_GEN: u32 = 1;
static mut RXC_NEXT: usize = 0;
static mut RXC_GEN: u32 = 1;

fn virt_to_phys(vaddr: usize) -> u64 {
    let offset = crate::arch::x86_64::boot::kernel_virt_offset();
    (vaddr as u64).wrapping_sub(offset)
}

fn phys_to_virt(phys: u64) -> usize {
    let hhdm = crate::arch::x86_64::boot::hhdm_offset().unwrap_or(0xFFFF_8000_0000_0000);
    (phys + hhdm) as usize
}

unsafe fn rd(base: usize, off: usize) -> u32 { core::ptr::read_volatile((base + off) as *const u32) }
unsafe fn wr(base: usize, off: usize, v: u32) { core::ptr::write_volatile((base + off) as *mut u32, v) }

unsafe fn put32(buf: *mut u8, off: usize, v: u32) { core::ptr::write_volatile(buf.add(off) as *mut u32, v) }
unsafe fn put64(buf: *mut u8, off: usize, v: u64) { core::ptr::write_volatile(buf.add(off) as *mut u64, v) }
unsafe fn get32(buf: *const u8, off: usize) -> u32 { core::ptr::read_volatile(buf.add(off) as *const u32) }

unsafe fn cmd(c: u32) -> u32 {
    wr(BAR1, VD_CMD, c);
    rd(BAR1, VD_CMD)
}

/// Issue a "set" command whose result is not read back (as Linux does for
/// RESET_DEV / UPDATE_RX_MODE; reading status for them is undefined).
unsafe fn cmd_nostatus(c: u32) {
    wr(BAR1, VD_CMD, c);
}

fn mmio_bar(bus: u8, dev: u8, func: u8, idx: u8) -> Option<u64> {
    match crate::pci::read_bar(bus, dev, func, idx) {
        crate::pci::BarType::Mmio { base, .. } if base != 0 => Some(base),
        _ => None,
    }
}

/// Give RX ring-0 descriptor `i` (buffer i) to the device with generation `gen`.
unsafe fn rx_post(i: usize, gen: u32) {
    let d = RX_DESC0.0.as_mut_ptr().add(i * 16);
    put64(d, 0, virt_to_phys(RX_BUFS[i].as_ptr() as usize));
    put32(d, 12, 0);
    fence(Ordering::SeqCst);
    // len:14 | btype(0=HEAD):1 | dtype:1 | rsvd:15 | gen:1
    put32(d, 8, (BUF_SIZE as u32 & 0x3FFF) | (gen << 31));
}

pub fn probe_and_init() -> bool {
    let s = crate::arch::x86_64::serial::write_str;
    let (bus, dev, func) = match crate::pci::find_by_vendor_device(VMXNET3_VENDOR, VMXNET3_DEVICE) {
        Some(d) => (d.bus, d.device, d.function),
        None => match super::pci_scan(VMXNET3_VENDOR, VMXNET3_DEVICE) {
            Some(t) => t,
            None => return false,
        },
    };
    s("[vmxnet3] Found VMware vmxnet3 (15ad:07b0) at ");
    super::serial_bdf(bus, dev, func);
    s("\r\n");

    let (b0, b1) = match (mmio_bar(bus, dev, func, 0), mmio_bar(bus, dev, func, 1)) {
        (Some(a), Some(b)) => (a, b),
        _ => { s("[vmxnet3] BAR0/BAR1 are not MMIO\r\n"); return false; }
    };
    // Memory space + bus master
    let c = crate::pci::command(bus, dev, func);
    crate::pci::set_command(bus, dev, func, (c | 0x06) & !0x0400);

    unsafe {
        BAR0 = phys_to_virt(b0);
        BAR1 = phys_to_virt(b1);

        // Version negotiation: revision 1, UPT version 1
        let vrrs = rd(BAR1, VD_VRRS);
        if vrrs & 1 == 0 { s("[vmxnet3] device does not support revision 1\r\n"); return false; }
        wr(BAR1, VD_VRRS, 1);
        let uvrs = rd(BAR1, VD_UVRS);
        if uvrs & 1 == 0 { s("[vmxnet3] device does not support UPT 1\r\n"); return false; }
        wr(BAR1, VD_UVRS, 1);

        cmd_nostatus(CMD_RESET_DEV);

        let macl = rd(BAR1, VD_MACL);
        let mach = rd(BAR1, VD_MACH);
        MAC = [macl as u8, (macl >> 8) as u8, (macl >> 16) as u8, (macl >> 24) as u8,
               mach as u8, (mach >> 8) as u8];

        // ── Rings ──
        for p in [&mut TX_DESC.0, &mut TX_COMP_R.0, &mut TX_DATA.0, &mut RX_DESC0.0,
                  &mut RX_DESC1.0, &mut RX_COMP_R.0, &mut QDESC.0, &mut SHARED.0] {
            for b in p.iter_mut() { *b = 0; }
        }
        TX_NEXT = 0; TX_GEN = 1; TX_INFLIGHT = 0; TXC_NEXT = 0; TXC_GEN = 1;
        RXC_NEXT = 0; RXC_GEN = 1;
        // Fill RX ring 0 except one slot (next2fill stays one behind the device).
        for i in 0..RX_RING - 1 { rx_post(i, 1); }
        RX_FILL = RX_RING - 1;
        RX_FILL_GEN = 1;

        // ── Queue descriptors ──
        let q = QDESC.0.as_mut_ptr();
        // TX queue: ctrl.txNumDeferred=0, txThreshold=1
        put32(q, TXQ_OFF + 4, 1);
        put64(q, TXQ_OFF + 16, virt_to_phys(TX_DESC.0.as_ptr() as usize));
        put64(q, TXQ_OFF + 24, virt_to_phys(TX_DATA.0.as_ptr() as usize));
        put64(q, TXQ_OFF + 32, virt_to_phys(TX_COMP_R.0.as_ptr() as usize));
        put32(q, TXQ_OFF + 56, TX_RING as u32);           // txRingSize
        put32(q, TXQ_OFF + 60, TX_RING as u32);           // dataRingSize
        put32(q, TXQ_OFF + 64, TX_RING as u32);           // compRingSize
        core::ptr::write_volatile(q.add(TXQ_OFF + 74) as *mut u16, DATA_DESC_SIZE as u16);
        // RX queue
        put64(q, RXQ_OFF + 16, virt_to_phys(RX_DESC0.0.as_ptr() as usize));
        put64(q, RXQ_OFF + 24, virt_to_phys(RX_DESC1.0.as_ptr() as usize));
        put64(q, RXQ_OFF + 32, virt_to_phys(RX_COMP_R.0.as_ptr() as usize));
        put32(q, RXQ_OFF + 56, RX_RING as u32);            // rxRingSize[0]
        put32(q, RXQ_OFF + 60, RX_RING as u32);            // rxRingSize[1]
        put32(q, RXQ_OFF + 64, RX_COMP as u32);            // compRingSize

        // ── Driver shared area ──
        let d = SHARED.0.as_mut_ptr();
        put32(d, DS_MAGIC, 0xBABE_FEE1);
        put32(d, DS_VERSION, 1);
        put32(d, DS_GOS, 2 | (1 << 2));     // 64-bit, "Linux"-type guest
        put32(d, DS_REV_SPT, 1);
        put32(d, DS_UPT_SPT, 1);
        put64(d, DS_UPT_FEATURES, 0);
        put64(d, DS_QUEUE_DESC_PA, virt_to_phys(QDESC.0.as_ptr() as usize));
        put32(d, DS_QUEUE_DESC_LEN, QDESC_LEN as u32);
        put32(d, DS_MTU, 1500);
        core::ptr::write_volatile(d.add(DS_MAX_RX_SG) as *mut u16, 1);
        *d.add(DS_NUM_TXQ) = 1;
        *d.add(DS_NUM_RXQ) = 1;
        *d.add(DS_AUTOMASK) = 1;
        *d.add(DS_NUM_INTRS) = 1;
        *d.add(DS_EVENT_INTR) = 0;
        put32(d, DS_INTR_CTRL, 1);          // VMXNET3_IC_DISABLE_ALL: we poll
        put32(d, DS_RX_MODE, RXM_UCAST | RXM_BCAST | RXM_MCAST);
        let _ = DS_SIZE;
        fence(Ordering::SeqCst);

        let pa = virt_to_phys(SHARED.0.as_ptr() as usize);
        wr(BAR1, VD_DSAL, pa as u32);
        wr(BAR1, VD_DSAH, (pa >> 32) as u32);

        let r = cmd(CMD_ACTIVATE_DEV);
        if r != 0 {
            s("[vmxnet3] ACTIVATE_DEV failed, status 0x");
            super::serial_hex16(r as u16);
            s("\r\n");
            return false;
        }
        wr(BAR0, PT_RXPROD, RX_FILL as u32);
        wr(BAR0, PT_RXPROD2, 0);
        cmd_nostatus(CMD_UPDATE_RX_MODE);
        wr(BAR0, PT_IMR0, 1); // keep the (only) interrupt masked

        let link = cmd(CMD_GET_LINK);
        s("[vmxnet3] activated, link ");
        s(if link & 1 != 0 { "up" } else { "down" });
        s(", ");
        super::serial_dec((link >> 16) as u64);
        s(" Mbit/s\r\n");

        INITIALIZED = true;
    }
    true
}

pub fn mac_address() -> [u8; 6] { unsafe { MAC } }
pub fn is_initialized() -> bool { unsafe { INITIALIZED } }

/// Reclaim completed TX descriptors.
unsafe fn tx_reap() {
    loop {
        let c = TX_COMP_R.0.as_ptr().add(TXC_NEXT * 16);
        if (get32(c, 12) >> 31) != TXC_GEN { break; }
        TXC_NEXT += 1;
        if TXC_NEXT == TX_RING { TXC_NEXT = 0; TXC_GEN ^= 1; }
        if TX_INFLIGHT > 0 { TX_INFLIGHT -= 1; }
    }
}

pub fn send_packet(data: &[u8], len: usize) {
    if !is_initialized() || len == 0 || len > 1514 || len > data.len() { return; }
    unsafe {
        tx_reap();
        let t0 = crate::arch::x86_64::idt::timer_ticks();
        while TX_INFLIGHT >= TX_RING - 1 {
            if crate::arch::x86_64::idt::timer_ticks().wrapping_sub(t0) > 50 { return; }
            tx_reap();
            core::hint::spin_loop();
        }
        let i = TX_NEXT;
        TX_BUFS[i][..len].copy_from_slice(&data[..len]);
        let d = TX_DESC.0.as_mut_ptr().add(i * 16);
        put64(d, 0, virt_to_phys(TX_BUFS[i].as_ptr() as usize));
        // hlen:10 om:2 eop:1 cq:1 ext2:1 ti:1 tci:16
        put32(d, 12, (1 << 12) | (1 << 13));
        fence(Ordering::SeqCst);
        // len:14 gen:1 rsvd:1 dtype:1 ext1:1 msscof:14  (gen written last)
        put32(d, 8, (len as u32 & 0x3FFF) | (TX_GEN << 14));
        fence(Ordering::SeqCst);

        TX_NEXT += 1;
        if TX_NEXT == TX_RING { TX_NEXT = 0; TX_GEN ^= 1; }
        TX_INFLIGHT += 1;
        // txNumDeferred bookkeeping in the shared queue control, then doorbell.
        let q = QDESC.0.as_mut_ptr();
        put32(q, TXQ_OFF, 0);
        wr(BAR0, PT_TXPROD, TX_NEXT as u32);

        // QEMU / VMware process the ring synchronously or quickly; reap now.
        tx_reap();
    }
}

pub fn receive_packet() -> Option<(&'static [u8], usize)> {
    if !is_initialized() { return None; }
    unsafe {
        loop {
            let c = RX_COMP_R.0.as_ptr().add(RXC_NEXT * 16);
            let w3 = get32(c, 12);
            if (w3 >> 31) != RXC_GEN { return None; }
            fence(Ordering::SeqCst);
            let w0 = get32(c, 0);
            let w2 = get32(c, 8);
            RXC_NEXT += 1;
            if RXC_NEXT == RX_COMP { RXC_NEXT = 0; RXC_GEN ^= 1; }

            let idx = (w0 & 0xFFF) as usize;
            let rq = (w0 >> 16) & 0x3FF;
            let eop = w0 & (1 << 14) != 0;
            let sop = w0 & (1 << 15) != 0;
            let len = (w2 & 0x3FFF) as usize;
            let err = w2 & (1 << 14) != 0;

            if rq != 0 || idx >= RX_RING { continue; } // ring 1 is never posted

            let ok = sop && eop && !err && len >= 14 && len <= BUF_SIZE;
            if ok {
                PACKET_OUT[..len].copy_from_slice(&RX_BUFS[idx][..len]);
            }
            // Refill one descriptor at next2fill.
            rx_post(RX_FILL, RX_FILL_GEN);
            RX_FILL += 1;
            if RX_FILL == RX_RING { RX_FILL = 0; RX_FILL_GEN ^= 1; }
            wr(BAR0, PT_RXPROD, RX_FILL as u32);

            if ok {
                if super::trace() {
                    crate::arch::x86_64::serial::write_str("[vmxnet3] RX len=");
                    super::serial_dec(len as u64);
                    crate::arch::x86_64::serial::write_str("\r\n");
                }
                return Some((&PACKET_OUT[..len], len));
            }
        }
    }
}

pub fn handle_irq() {
    // Interrupts are disabled in the shared area (polling driver); nothing to ack.
}

/// Link state as reported by the device (GET_LINK command).
pub fn link_up() -> bool {
    if !is_initialized() { return false; }
    unsafe { cmd(CMD_GET_LINK) & 1 != 0 }
}
