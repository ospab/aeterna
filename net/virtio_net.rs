/*
 * VirtIO-Net driver (legacy / transitional PCI interface, I/O BAR0)
 *
 * QEMU's `-device virtio-net-pci` exposes a transitional device (1AF4:1000)
 * with the legacy register block in BAR0.  This driver:
 *   - negotiates only VIRTIO_NET_F_MAC (so every buffer carries the plain
 *     10-byte virtio_net_hdr, no mergeable RX buffers, no offloads),
 *   - sets up queue 0 (RX) and queue 1 (TX) in statically allocated,
 *     page-aligned memory inside the kernel image (physically contiguous,
 *     translated with kernel_virt_offset like the other NIC drivers),
 *   - polls the used rings; the IRQ handler only acknowledges the ISR.
 */

use core::sync::atomic::{fence, Ordering};
use crate::arch::x86_64::io::{inb, outb, inw, outw, inl, outl};

// ─── Legacy register offsets (BAR0, I/O space) ────────────────────────────
const REG_HOST_FEATURES:  u16 = 0x00;
const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_PFN:      u16 = 0x08;
const REG_QUEUE_SIZE:     u16 = 0x0C;
const REG_QUEUE_SEL:      u16 = 0x0E;
const REG_QUEUE_NOTIFY:   u16 = 0x10;
const REG_STATUS:         u16 = 0x12;
const REG_ISR:            u16 = 0x13;
const REG_CONFIG:         u16 = 0x14; // device config (MAC) when MSI-X is off

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER:      u8 = 2;
const STATUS_DRIVER_OK:   u8 = 4;
const STATUS_FAILED:      u8 = 128;

const F_MAC: u32 = 1 << 5;

const VRING_DESC_F_WRITE: u16 = 2;

const NET_HDR_LEN: usize = 10;
const BUF_SIZE: usize = 2048;
const MAX_QSZ: usize = 1024;
const RX_BUFS_N: usize = 64;
const TX_BUFS_N: usize = 16;
const QMEM_SIZE: usize = 10 * 4096; // enough for a 1024-entry legacy vring

#[repr(C, align(4096))]
struct QMem([u8; QMEM_SIZE]);

#[repr(C, align(4096))]
struct Bufs<const N: usize>([[u8; BUF_SIZE]; N]);

static mut RX_Q: QMem = QMem([0; QMEM_SIZE]);
static mut TX_Q: QMem = QMem([0; QMEM_SIZE]);
static mut RX_BUFS: Bufs<RX_BUFS_N> = Bufs([[0; BUF_SIZE]; RX_BUFS_N]);
static mut TX_BUFS: Bufs<TX_BUFS_N> = Bufs([[0; BUF_SIZE]; TX_BUFS_N]);
static mut PACKET_OUT: [u8; BUF_SIZE] = [0; BUF_SIZE];

/// Runtime state of one virtqueue.
#[derive(Clone, Copy)]
struct Vq {
    size: u16,       // queue size reported by the device
    used_off: usize, // byte offset of the used ring inside QMem
    avail_idx: u16,  // our shadow of avail->idx
    last_used: u16,  // next used ring entry to consume
}

impl Vq {
    const fn empty() -> Self { Vq { size: 0, used_off: 0, avail_idx: 0, last_used: 0 } }
}

static mut IO_BASE: u16 = 0;
static mut MAC: [u8; 6] = [0; 6];
static mut INITIALIZED: bool = false;
static mut RXQ: Vq = Vq::empty();
static mut TXQ: Vq = Vq::empty();

fn virt_to_phys(vaddr: usize) -> u64 {
    let offset = crate::arch::x86_64::boot::kernel_virt_offset();
    (vaddr as u64).wrapping_sub(offset)
}

fn align_up(v: usize, a: usize) -> usize { (v + a - 1) & !(a - 1) }

// ─── Raw vring accessors (base = start of the queue memory) ───────────────
unsafe fn desc_set(base: *mut u8, i: u16, addr: u64, len: u32, flags: u16) {
    let d = base.add(i as usize * 16);
    core::ptr::write_volatile(d as *mut u64, addr);
    core::ptr::write_volatile(d.add(8) as *mut u32, len);
    core::ptr::write_volatile(d.add(12) as *mut u16, flags);
    core::ptr::write_volatile(d.add(14) as *mut u16, 0);
}

unsafe fn avail_push(base: *mut u8, q: &mut Vq, desc_id: u16) {
    let avail = base.add(q.size as usize * 16);
    let slot = (q.avail_idx % q.size) as usize;
    core::ptr::write_volatile(avail.add(4 + slot * 2) as *mut u16, desc_id);
    fence(Ordering::SeqCst);
    q.avail_idx = q.avail_idx.wrapping_add(1);
    core::ptr::write_volatile(avail.add(2) as *mut u16, q.avail_idx);
    fence(Ordering::SeqCst);
}

unsafe fn used_idx(base: *mut u8, q: &Vq) -> u16 {
    fence(Ordering::SeqCst);
    core::ptr::read_volatile(base.add(q.used_off + 2) as *const u16)
}

unsafe fn used_elem(base: *mut u8, q: &Vq, n: u16) -> (u32, u32) {
    let e = base.add(q.used_off + 4 + (n % q.size) as usize * 8);
    (core::ptr::read_volatile(e as *const u32), core::ptr::read_volatile(e.add(4) as *const u32))
}

/// Select queue `sel`, read its size, place it in `mem`.
unsafe fn setup_queue(io: u16, sel: u16, mem: *mut u8) -> Option<Vq> {
    outw(io + REG_QUEUE_SEL, sel);
    let size = inw(io + REG_QUEUE_SIZE) as usize;
    if size == 0 || size > MAX_QSZ || !size.is_power_of_two() { return None; }
    let used_off = align_up(16 * size + 6 + 2 * size, 4096);
    let total = used_off + align_up(6 + 8 * size, 4096);
    if total > QMEM_SIZE { return None; }
    core::ptr::write_bytes(mem, 0, QMEM_SIZE);
    let phys = virt_to_phys(mem as usize);
    outl(io + REG_QUEUE_PFN, (phys >> 12) as u32);
    Some(Vq { size: size as u16, used_off, avail_idx: 0, last_used: 0 })
}

pub fn probe_and_init() -> bool {
    let s = crate::arch::x86_64::serial::write_str;
    let dev = match crate::pci::find_by_vendor_device(0x1AF4, 0x1000) {
        Some(d) => *d,
        None => return false,
    };
    s("[VirtIO-Net] Found transitional virtio-net device\r\n");

    // I/O space + bus master, INTx enabled
    let cmd = crate::pci::command(dev.bus, dev.device, dev.function);
    crate::pci::set_command(dev.bus, dev.device, dev.function, (cmd | 0x07) & !0x0400);

    let io = match crate::pci::read_bar(dev.bus, dev.device, dev.function, 0) {
        crate::pci::BarType::Io { base, .. } => base as u16,
        _ => { s("[VirtIO-Net] BAR0 is not I/O space\r\n"); return false; }
    };

    unsafe {
        IO_BASE = io;
        outb(io + REG_STATUS, 0); // reset
        outb(io + REG_STATUS, STATUS_ACKNOWLEDGE);
        outb(io + REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        let host = inl(io + REG_HOST_FEATURES);
        outl(io + REG_GUEST_FEATURES, host & F_MAC);

        let rxq = setup_queue(io, 0, RX_Q.0.as_mut_ptr());
        let txq = setup_queue(io, 1, TX_Q.0.as_mut_ptr());
        let (mut rxq, txq) = match (rxq, txq) {
            (Some(r), Some(t)) => (r, t),
            _ => {
                s("[VirtIO-Net] unsupported queue layout\r\n");
                outb(io + REG_STATUS, STATUS_FAILED);
                return false;
            }
        };

        // Post RX buffers (device-writable)
        let rx_base = RX_Q.0.as_mut_ptr();
        let nrx = RX_BUFS_N.min(rxq.size as usize);
        for i in 0..nrx {
            let phys = virt_to_phys(RX_BUFS.0[i].as_ptr() as usize);
            desc_set(rx_base, i as u16, phys, BUF_SIZE as u32, VRING_DESC_F_WRITE);
            avail_push(rx_base, &mut rxq, i as u16);
        }
        RXQ = rxq;
        TXQ = txq;

        if host & F_MAC != 0 {
            for i in 0..6 { MAC[i] = inb(io + REG_CONFIG + i as u16); }
        } else {
            MAC = [0x52, 0x54, 0x00, 0xAE, 0x00, 0x01];
        }

        outb(io + REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK);
        outw(io + REG_QUEUE_NOTIFY, 0);

        let irq = crate::pci::interrupt_line(dev.bus, dev.device, dev.function);
        if irq < 16 { crate::arch::x86_64::pic::enable_irq(irq); }

        s("[VirtIO-Net] ready, rx/tx queue size ");
        serial_dec(rxq.size as u64);
        s("/");
        serial_dec(txq.size as u64);
        s(", IRQ ");
        serial_dec(irq as u64);
        s("\r\n");

        INITIALIZED = true;
    }
    true
}

pub fn mac_address() -> [u8; 6] { unsafe { MAC } }

pub fn is_initialized() -> bool { unsafe { INITIALIZED } }

pub fn send_packet(buf: &[u8], len: usize) {
    if !is_initialized() || len == 0 || len > 1514 || len > buf.len() { return; }
    unsafe {
        let io = IO_BASE;
        let base = TX_Q.0.as_mut_ptr();
        let mut q = TXQ;
        // Descriptor/buffer slot = position in the avail ring modulo TX_BUFS_N.
        let slot = (q.avail_idx as usize) % TX_BUFS_N.min(q.size as usize);
        let tb = &mut TX_BUFS.0[slot];
        for b in tb[..NET_HDR_LEN].iter_mut() { *b = 0; }
        tb[NET_HDR_LEN..NET_HDR_LEN + len].copy_from_slice(&buf[..len]);
        let phys = virt_to_phys(tb.as_ptr() as usize);
        desc_set(base, slot as u16, phys, (NET_HDR_LEN + len) as u32, 0);
        avail_push(base, &mut q, slot as u16);
        outw(io + REG_QUEUE_NOTIFY, 1);

        // Wait for the device to consume it (QEMU does so synchronously).
        let start = crate::arch::x86_64::idt::timer_ticks();
        while used_idx(base, &q) != q.avail_idx {
            if crate::arch::x86_64::idt::timer_ticks().wrapping_sub(start) > 50 { break; }
            core::hint::spin_loop();
        }
        q.last_used = used_idx(base, &q);
        TXQ = q;
    }
}

pub fn receive_packet() -> Option<(&'static [u8], usize)> {
    if !is_initialized() { return None; }
    unsafe {
        let io = IO_BASE;
        let base = RX_Q.0.as_mut_ptr();
        let mut q = RXQ;
        if used_idx(base, &q) == q.last_used { return None; }
        let (id, total) = used_elem(base, &q, q.last_used);
        q.last_used = q.last_used.wrapping_add(1);

        let id = id as usize;
        let mut out_len = 0usize;
        if id < RX_BUFS_N {
            let total = (total as usize).min(BUF_SIZE);
            if total > NET_HDR_LEN {
                out_len = total - NET_HDR_LEN;
                PACKET_OUT[..out_len].copy_from_slice(&RX_BUFS.0[id][NET_HDR_LEN..total]);
            }
            // Recycle the buffer
            avail_push(base, &mut q, id as u16);
            outw(io + REG_QUEUE_NOTIFY, 0);
        }
        RXQ = q;
        if out_len == 0 { return None; }
        if super::trace() {
            crate::arch::x86_64::serial::write_str("[VirtIO-Net] RX len=");
            serial_dec(out_len as u64);
            crate::arch::x86_64::serial::write_str("\r\n");
        }
        Some((&PACKET_OUT[..out_len], out_len))
    }
}

pub fn handle_irq() {
    if !is_initialized() { return; }
    // Reading the ISR register acknowledges (de-asserts) the interrupt.
    unsafe { let _ = inb(IO_BASE + REG_ISR); }
}

pub fn link_up() -> bool {
    // VIRTIO_NET_F_STATUS is not negotiated, so the link is always up per spec.
    is_initialized()
}

fn serial_dec(mut v: u64) {
    if v == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while v > 0 { buf[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}
