/*
 * AMD PCnet-PCI II (Am79C970A, PCI 1022:2000) driver
 *
 * This is VMware's default "vlance" NIC and is emulated by QEMU as
 * `-device pcnet`. The chip is programmed in 32-bit mode:
 *   - DWIO (32-bit I/O register access, entered by a 32-bit write to RDP),
 *   - SWSTYLE 2 (32-bit PCnet-PCI init block and 16-byte descriptors).
 * RX/TX descriptor rings and buffers live in static, physically contiguous
 * kernel memory (translated with kernel_virt_offset like the other drivers).
 * The stack polls the RX ring; the IRQ handler only acknowledges CSR0.
 */

use crate::arch::x86_64::io::{inb, inl, inw, outl};

const PCNET_VENDOR: u16 = 0x1022;
const PCNET_DEVICE: u16 = 0x2000;

// I/O register offsets in DWIO mode
const REG_RDP: u16 = 0x10;
const REG_RAP: u16 = 0x14;
const REG_RESET: u16 = 0x18;
const REG_BDP: u16 = 0x1C;
// Word-I/O (WIO) reset register, valid right after power-up/reset
const REG_RESET_WIO: u16 = 0x14;

// CSR0 bits
const CSR0_INIT: u32 = 0x0001;
const CSR0_STRT: u32 = 0x0002;
const CSR0_STOP: u32 = 0x0004;
const CSR0_TDMD: u32 = 0x0008;
const CSR0_TXON: u32 = 0x0010;
const CSR0_RXON: u32 = 0x0020;
const CSR0_IENA: u32 = 0x0040;
const CSR0_IDON: u32 = 0x0100;
const CSR0_INT_BITS: u32 = 0x7F00; // BABL CERR MISS MERR RINT TINT IDON (write-1-to-clear)

// Descriptor status bits (upper 16 bits of the second dword)
const DESC_OWN: u16 = 0x8000;
const DESC_ERR: u16 = 0x4000;
const DESC_STP: u16 = 0x0200;
const DESC_ENP: u16 = 0x0100;

const RX_COUNT: usize = 32; // must be a power of two (log2 goes into the init block)
const TX_COUNT: usize = 8;
const RX_LOG2: u8 = 5;
const TX_LOG2: u8 = 3;
const BUF_SIZE: usize = 1536;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Desc {
    addr: u32,
    bcnt_status: u32, // low 16 = BCNT (two's complement, top nibble 1111), high 16 = status
    misc: u32,        // RX: message byte count (MCNT) in bits 11:0
    user: u32,
}

#[repr(C, align(16))]
struct InitBlock {
    mode: u16,
    rlen: u8, // log2(RX ring size) << 4
    tlen: u8, // log2(TX ring size) << 4
    padr: [u8; 6],
    _res: u16,
    ladrf: [u8; 8],
    rdra: u32,
    tdra: u32,
}

#[repr(C, align(16))]
struct Bufs<const N: usize>([[u8; BUF_SIZE]; N]);

const EMPTY_DESC: Desc = Desc { addr: 0, bcnt_status: 0, misc: 0, user: 0 };
static mut RX_DESCS: [Desc; RX_COUNT] = [EMPTY_DESC; RX_COUNT];
static mut TX_DESCS: [Desc; TX_COUNT] = [EMPTY_DESC; TX_COUNT];
static mut RX_BUFS: Bufs<RX_COUNT> = Bufs([[0; BUF_SIZE]; RX_COUNT]);
static mut TX_BUFS: Bufs<TX_COUNT> = Bufs([[0; BUF_SIZE]; TX_COUNT]);
static mut INIT_BLOCK: InitBlock = InitBlock {
    mode: 0, rlen: 0, tlen: 0, padr: [0; 6], _res: 0, ladrf: [0; 8], rdra: 0, tdra: 0,
};
static mut PACKET_OUT: [u8; BUF_SIZE] = [0; BUF_SIZE];

static mut IO_BASE: u16 = 0;
static mut MAC: [u8; 6] = [0; 6];
static mut INITIALIZED: bool = false;
static mut RX_CUR: usize = 0;
static mut TX_CUR: usize = 0;

fn virt_to_phys(vaddr: usize) -> u64 {
    let offset = crate::arch::x86_64::boot::kernel_virt_offset();
    (vaddr as u64).wrapping_sub(offset)
}

unsafe fn csr_read(io: u16, n: u32) -> u32 {
    outl(io + REG_RAP, n);
    inl(io + REG_RDP) & 0xFFFF
}

unsafe fn csr_write(io: u16, n: u32, v: u32) {
    outl(io + REG_RAP, n);
    outl(io + REG_RDP, v & 0xFFFF);
}

unsafe fn bcr_write(io: u16, n: u32, v: u32) {
    outl(io + REG_RAP, n);
    outl(io + REG_BDP, v & 0xFFFF);
}

unsafe fn bcr_read(io: u16, n: u32) -> u32 {
    outl(io + REG_RAP, n);
    inl(io + REG_BDP) & 0xFFFF
}

fn bcnt(len: usize) -> u32 {
    // Two's complement of the buffer length, bits 15:12 must be ones.
    ((0u16.wrapping_sub(len as u16)) as u32 & 0x0FFF) | 0xF000
}

unsafe fn rx_give(i: usize) {
    let d = &mut RX_DESCS[i];
    core::ptr::write_volatile(&mut d.misc, 0);
    core::ptr::write_volatile(&mut d.bcnt_status, bcnt(BUF_SIZE) | ((DESC_OWN as u32) << 16));
}

/// Find the controller on any bus (via the kernel PCI table, then a brute-force scan).
fn find_device() -> Option<(u8, u8, u8)> {
    if let Some(d) = crate::pci::find_by_vendor_device(PCNET_VENDOR, PCNET_DEVICE) {
        return Some((d.bus, d.device, d.function));
    }
    super::pci_scan(PCNET_VENDOR, PCNET_DEVICE)
}

pub fn probe_and_init() -> bool {
    let s = crate::arch::x86_64::serial::write_str;
    let (bus, dev, func) = match find_device() {
        Some(t) => t,
        None => return false,
    };
    s("[PCnet] Found AMD PCnet-PCI II (1022:2000) at ");
    super::serial_bdf(bus, dev, func);
    s("\r\n");

    // I/O BAR: BAR0 on the Am79C970A (BAR1 is the MMIO alias).
    let io = match crate::pci::read_bar(bus, dev, func, 0) {
        crate::pci::BarType::Io { base, .. } if base != 0 && base <= 0xFFFF => base as u16,
        _ => { s("[PCnet] BAR0 is not an I/O BAR\r\n"); return false; }
    };
    // I/O space + bus master, INTx enabled
    let cmd = crate::pci::command(bus, dev, func);
    crate::pci::set_command(bus, dev, func, (cmd | 0x05) & !0x0400);

    unsafe {
        IO_BASE = io;

        // Reset: 32-bit read (DWIO) and 16-bit read (WIO) of the reset register,
        // then switch to DWIO with a 32-bit write of 0 to RDP.
        let _ = inl(io + REG_RESET);
        let _ = inw(io + REG_RESET_WIO);
        let t0 = crate::arch::x86_64::idt::timer_ticks();
        while crate::arch::x86_64::idt::timer_ticks().wrapping_sub(t0) < 2 { core::hint::spin_loop(); }
        // Station address from the address PROM (first 6 bytes of I/O space),
        // read with byte accesses while still in WIO mode.
        for i in 0..6 { MAC[i] = inb(io + i as u16); }
        outl(io + REG_RDP, 0); // enter DWIO

        // SWSTYLE = 2: 32-bit PCnet-PCI structures (SSIZE32 follows automatically).
        let bcr20 = bcr_read(io, 20);
        bcr_write(io, 20, (bcr20 & !0xFF) | 2);

        // Rings
        for i in 0..RX_COUNT {
            let p = virt_to_phys(RX_BUFS.0[i].as_ptr() as usize);
            if p >> 32 != 0 { s("[PCnet] buffers above 4 GiB, unsupported\r\n"); return false; }
            RX_DESCS[i].addr = p as u32;
            RX_DESCS[i].user = 0;
            rx_give(i);
        }
        for i in 0..TX_COUNT {
            let p = virt_to_phys(TX_BUFS.0[i].as_ptr() as usize);
            TX_DESCS[i] = Desc { addr: p as u32, bcnt_status: 0, misc: 0, user: 0 };
        }
        RX_CUR = 0;
        TX_CUR = 0;

        // Init block
        INIT_BLOCK.mode = 0; // normal operation (no promiscuous mode)
        INIT_BLOCK.rlen = RX_LOG2 << 4;
        INIT_BLOCK.tlen = TX_LOG2 << 4;
        INIT_BLOCK.padr = MAC;
        INIT_BLOCK.ladrf = [0; 8]; // no multicast
        INIT_BLOCK.rdra = virt_to_phys(RX_DESCS.as_ptr() as usize) as u32;
        INIT_BLOCK.tdra = virt_to_phys(TX_DESCS.as_ptr() as usize) as u32;
        let ib = virt_to_phys(core::ptr::addr_of!(INIT_BLOCK) as usize);
        if ib >> 32 != 0 { s("[PCnet] init block above 4 GiB, unsupported\r\n"); return false; }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        csr_write(io, 1, ib as u32 & 0xFFFF);
        csr_write(io, 2, (ib >> 16) as u32 & 0xFFFF);
        // CSR4: auto-pad short TX frames (APAD_XMT, bit 11); keep other defaults.
        let csr4 = csr_read(io, 4);
        csr_write(io, 4, csr4 | 0x0800);

        // INIT and wait for IDON
        csr_write(io, 0, CSR0_INIT);
        let t0 = crate::arch::x86_64::idt::timer_ticks();
        loop {
            if csr_read(io, 0) & CSR0_IDON != 0 { break; }
            if crate::arch::x86_64::idt::timer_ticks().wrapping_sub(t0) > 100 {
                s("[PCnet] init timeout (no IDON)\r\n");
                return false;
            }
            core::hint::spin_loop();
        }
        // Clear IDON, start, enable interrupts
        csr_write(io, 0, CSR0_IDON | CSR0_STRT | CSR0_IENA);

        let irq = crate::pci::interrupt_line(bus, dev, func);
        if irq != 0 && irq < 16 { crate::arch::x86_64::pic::enable_irq(irq); }

        let csr0 = csr_read(io, 0);
        s("[PCnet] I/O 0x");
        super::serial_hex16(io);
        s(", IRQ ");
        super::serial_dec(irq as u64);
        s(", CSR0=0x");
        super::serial_hex16(csr0 as u16);
        s(if csr0 & (CSR0_RXON | CSR0_TXON) == (CSR0_RXON | CSR0_TXON) { " (RX/TX on)\r\n" } else { " (RX/TX NOT running)\r\n" });

        INITIALIZED = true;
    }
    true
}

pub fn mac_address() -> [u8; 6] { unsafe { MAC } }
pub fn is_initialized() -> bool { unsafe { INITIALIZED } }

pub fn send_packet(data: &[u8], len: usize) {
    if !is_initialized() || len == 0 || len > 1514 || len > data.len() { return; }
    unsafe {
        let io = IO_BASE;
        let i = TX_CUR;
        let d = &mut TX_DESCS[i];

        // Wait for the descriptor to come back from a previous transmit.
        let t0 = crate::arch::x86_64::idt::timer_ticks();
        while (core::ptr::read_volatile(&d.bcnt_status) >> 16) as u16 & DESC_OWN != 0 {
            if crate::arch::x86_64::idt::timer_ticks().wrapping_sub(t0) > 50 { return; }
            core::hint::spin_loop();
        }

        TX_BUFS.0[i][..len].copy_from_slice(&data[..len]);
        core::ptr::write_volatile(&mut d.misc, 0);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let status = DESC_OWN | DESC_STP | DESC_ENP;
        core::ptr::write_volatile(&mut d.bcnt_status, bcnt(len) | ((status as u32) << 16));
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // Transmit demand (keep IENA set; don't touch the W1C interrupt bits)
        csr_write(io, 0, CSR0_TDMD | CSR0_IENA);
        TX_CUR = (TX_CUR + 1) % TX_COUNT;
    }
}

pub fn receive_packet() -> Option<(&'static [u8], usize)> {
    if !is_initialized() { return None; }
    unsafe {
        loop {
            let i = RX_CUR;
            let d = &mut RX_DESCS[i];
            let st = (core::ptr::read_volatile(&d.bcnt_status) >> 16) as u16;
            if st & DESC_OWN != 0 { return None; }

            RX_CUR = (RX_CUR + 1) % RX_COUNT;
            let good = st & DESC_ERR == 0 && st & DESC_STP != 0 && st & DESC_ENP != 0;
            let mcnt = (core::ptr::read_volatile(&d.misc) & 0x0FFF) as usize;
            if !good || mcnt < 14 + 4 || mcnt > BUF_SIZE {
                rx_give(i); // drop and keep looking
                continue;
            }
            let len = mcnt - 4; // strip FCS
            PACKET_OUT[..len].copy_from_slice(&RX_BUFS.0[i][..len]);
            rx_give(i);
            if super::trace() {
                crate::arch::x86_64::serial::write_str("[PCnet] RX len=");
                super::serial_dec(len as u64);
                crate::arch::x86_64::serial::write_str("\r\n");
            }
            return Some((&PACKET_OUT[..len], len));
        }
    }
}

pub fn handle_irq() {
    if !is_initialized() { return; }
    unsafe {
        let io = IO_BASE;
        // The interrupted code may be between a RAP write and an RDP access:
        // preserve RAP.
        let saved_rap = inl(io + REG_RAP) & 0xFF;
        let csr0 = csr_read(io, 0);
        if csr0 & CSR0_INT_BITS != 0 {
            // Acknowledge (write-1-to-clear) and keep interrupts enabled.
            csr_write(io, 0, (csr0 & CSR0_INT_BITS) | CSR0_IENA);
        }
        outl(io + REG_RAP, saved_rap);
    }
}

/// True while the controller's receiver and transmitter are running.
/// (The Am79C970A has no portable PHY link-status register; BCR4 LED
/// semantics are board-specific, so we report controller state instead.)
pub fn link_up() -> bool {
    if !is_initialized() { return false; }
    unsafe {
        let csr0 = csr_read(IO_BASE, 0);
        csr0 & CSR0_STOP == 0 && csr0 & (CSR0_RXON | CSR0_TXON) == (CSR0_RXON | CSR0_TXON)
    }
}
