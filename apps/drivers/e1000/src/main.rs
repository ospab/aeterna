// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ospab
//! drv-e1000: Intel 8254x / e1000 network driver in ring 3.
//!
//! The device manager starts it with the PCI function (handle 1) and a ready channel
//! (handle 2). It maps BAR 0, resets the card, builds the descriptor rings in one DMA
//! region and attaches that region to the kernel network stack (`netring`). The same
//! region holds the packet buffers: the card writes received frames into the slots the
//! stack reads, and sends the frames the stack copied into the transmit slots.
//!
//! Ring layout in the DMA region (offsets in bytes):
//!   0x0000 ring header (netring.rs)   0x1000 RX descriptors   0x1400 TX descriptors
//!   0x2000 RX slots (64 x 2048)       0x22000 TX slots (64 x 2048)
#![no_std]
#![no_main]

use libdriver::liboos::ipc::Notification;
use libdriver::liboos::mem::Mapping;
use libdriver::netring as nr;
use libdriver::{log, Driver, Dma, IRQ_BIT};

libdriver::driver_entry!("e1000", main);

// Registers
const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const EERD: usize = 0x0014;
const ICR: usize = 0x00C0;
const IMS: usize = 0x00D0;
const IMC: usize = 0x00D8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const MTA: usize = 0x5200;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_ASDE: u32 = 1 << 5;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const RCTL_EN: u32 = 1 << 1;
const RCTL_UPE: u32 = 1 << 3;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

const N: usize = 64;
const SLOT: usize = 2048;
const RXD: usize = 0x1000;
const TXD: usize = 0x1400;
const RXB: usize = 0x2000;
const TXB: usize = RXB + N * SLOT;
const REGION: usize = TXB + N * SLOT;

struct Nic {
    regs: Mapping,
    dma: Dma,
    rx_next: u32,     // next RX descriptor to look at (free-running)
    rx_released: u32, // slots handed back to the card (free-running)
    tx_posted: u32,   // frames given to the card
    tx_done: u32,     // frames the card has sent
}

impl Nic {
    fn r(&self, reg: usize) -> u32 {
        self.regs.read::<u32>(reg)
    }
    fn w(&self, reg: usize, v: u32) {
        self.regs.write::<u32>(reg, v)
    }
    fn hdr<T: Copy>(&self, off: usize) -> T {
        self.dma.map.read::<T>(off)
    }
    fn hdr_w<T: Copy>(&self, off: usize, v: T) {
        self.dma.map.write::<T>(off, v)
    }
}

fn sleep_ms(ms: u64) {
    unsafe { libdriver::sys::syscall1(21, ms) };
}

fn eeprom_read(n: &Nic, addr: u32) -> Option<u16> {
    n.w(EERD, 1 | (addr << 8));
    for _ in 0..100_000 {
        let v = n.r(EERD);
        if v & (1 << 4) != 0 {
            return Some((v >> 16) as u16);
        }
    }
    None
}

fn read_mac(n: &Nic) -> [u8; 6] {
    if let (Some(a), Some(b), Some(c)) = (eeprom_read(n, 0), eeprom_read(n, 1), eeprom_read(n, 2)) {
        return [a as u8, (a >> 8) as u8, b as u8, (b >> 8) as u8, c as u8, (c >> 8) as u8];
    }
    let (l, h) = (n.r(RAL0), n.r(RAH0));
    [l as u8, (l >> 8) as u8, (l >> 16) as u8, (l >> 24) as u8, h as u8, (h >> 8) as u8]
}

fn main(d: Driver) -> i32 {
    if !d.has_device() {
        log!("no PCI device handle: started by hand? the device manager starts this driver");
        return 1;
    }
    let pci = d.pci();
    let info = match pci.info() {
        Ok(i) => i,
        Err(e) => {
            log!("pci info: {:?}", e);
            d.failed("pci info");
            return 1;
        }
    };
    log!("{:04x}:{:04x} at {:02x}:{:02x}.{} irq {}", info.vendor, info.device, info.bdf >> 8, (info.bdf >> 3) & 31, info.bdf & 7, info.irq_line);
    if let Err(e) = pci.enable_bus_master() {
        log!("cannot enable bus master: {:?}", e);
        d.failed("bus master");
        return 1;
    }
    let regs = match pci.bar_map(0) {
        Ok(m) => m,
        Err(e) => {
            log!("cannot map BAR 0: {:?}", e);
            d.failed("bar0");
            return 1;
        }
    };
    let dma = match pci.dma_alloc(REGION, false) {
        Ok(m) => m,
        Err(e) => {
            log!("cannot allocate {} bytes of DMA memory: {:?}", REGION, e);
            d.failed("dma");
            return 1;
        }
    };
    let mut nic = Nic { regs, dma, rx_next: 0, rx_released: 0, tx_posted: 0, tx_done: 0 };

    // Reset and bring the link up.
    nic.w(IMC, 0xFFFF_FFFF);
    let c = nic.r(CTRL);
    nic.w(CTRL, c | CTRL_RST);
    sleep_ms(20);
    for _ in 0..1000 {
        if nic.r(CTRL) & CTRL_RST == 0 {
            break;
        }
        sleep_ms(1);
    }
    sleep_ms(20);
    nic.w(IMC, 0xFFFF_FFFF);
    let _ = nic.r(ICR);
    let c = nic.r(CTRL);
    nic.w(CTRL, (c | CTRL_SLU | CTRL_ASDE) & !CTRL_RST);

    let mac = read_mac(&nic);
    log!("MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    for i in 0..128 {
        nic.w(MTA + i * 4, 0);
    }

    // Ring header for the kernel network stack.
    let phys = nic.dma.phys();
    nic.hdr_w::<u32>(nr::O_MAGIC, nr::MAGIC);
    nic.hdr_w::<u32>(nr::O_VERSION, nr::VERSION);
    for (i, b) in mac.iter().enumerate() {
        nic.hdr_w::<u8>(nr::O_MAC + i, *b);
    }
    nic.hdr_w::<u32>(nr::O_NSLOTS, N as u32);
    nic.hdr_w::<u32>(nr::O_SLOT_SIZE, SLOT as u32);
    nic.hdr_w::<u32>(nr::O_RX_OFF, RXB as u32);
    nic.hdr_w::<u32>(nr::O_TX_OFF, TXB as u32);

    // Descriptors.
    nic.w(TCTL, 0);
    nic.w(RCTL, 0);
    for i in 0..N {
        let t = TXD + i * 16;
        nic.hdr_w::<u64>(t, phys + (TXB + i * SLOT) as u64);
        nic.hdr_w::<u64>(t + 8, 0);
        let r = RXD + i * 16;
        nic.hdr_w::<u64>(r, phys + (RXB + i * SLOT) as u64);
        nic.hdr_w::<u64>(r + 8, 0);
    }
    let (tx, rx) = (phys + TXD as u64, phys + RXD as u64);
    nic.w(TDBAL, tx as u32);
    nic.w(TDBAH, (tx >> 32) as u32);
    nic.w(TDLEN, (N * 16) as u32);
    nic.w(TDH, 0);
    nic.w(TDT, 0);
    nic.w(TCTL, TCTL_EN | TCTL_PSP | (0x0F << 4) | (0x040 << 12));
    nic.w(TIPG, 0x0060_200A);
    nic.w(RDBAL, rx as u32);
    nic.w(RDBAH, (rx >> 32) as u32);
    nic.w(RDLEN, (N * 16) as u32);
    nic.w(RDH, 0);
    nic.w(RDT, (N - 1) as u32);
    let ral = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
    let rah = u32::from_le_bytes([mac[4], mac[5], 0, 0]) | (1 << 31);
    nic.w(RAL0, ral);
    nic.w(RAH0, rah);
    nic.w(RCTL, RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_SECRC);

    // Interrupt, if the line is ours; otherwise poll every tick.
    let irq = match pci.irq() {
        Ok(i) => Some(i),
        Err(e) => {
            log!("no interrupt line ({:?}): polling every 10 ms", e);
            None
        }
    };
    let own_notif = if irq.is_none() { Notification::create().ok() } else { None };
    if irq.is_some() {
        nic.w(IMS, 0x01 | 0x04 | 0x10 | 0x40 | 0x80);
        let _ = nic.r(ICR);
    }

    let link = nic.r(STATUS) & STATUS_LU != 0;
    nic.hdr_w::<u16>(nr::O_FLAGS, 2 | link as u16);
    let notif = match (&irq, &own_notif) {
        (Some(i), _) => i.notification(),
        (None, Some(n)) => n,
        _ => {
            d.failed("notification");
            return 1;
        }
    };
    if let Err(e) = nr::attach(pci, notif, &nic.dma.region) {
        log!("cannot attach to the network stack: {:?}", e);
        d.failed("attach");
        return 1;
    }
    if let Some(i) = &irq {
        let _ = i.unmask();
    }
    log!("running: link {}, {}", if link { "up" } else { "down" }, if irq.is_some() { "interrupts" } else { "polling" });
    let mut status = alloc_status(&mac, link);
    d.ready(&status);

    let mut last_link = link;
    loop {
        let bits = match notif.wait(1) {
            Ok(b) => b,
            Err(_) => 0,
        };
        if bits & IRQ_BIT != 0 {
            let _ = nic.r(ICR);
            if let Some(i) = &irq {
                let _ = i.ack();
            }
        }
        // Receive: publish finished descriptors.
        let mut got = false;
        loop {
            let slot = (nic.rx_next as usize) % N;
            let desc = RXD + slot * 16;
            let st = nic.hdr::<u8>(desc + 12);
            if st & 1 == 0 {
                break;
            }
            let len = nic.hdr::<u16>(desc + 8);
            let ok = st & 2 != 0 && nic.hdr::<u8>(desc + 13) == 0;
            nic.hdr_w::<u16>(nr::O_RX_LEN + slot * 2, if ok { len } else { 0 });
            nic.rx_next = nic.rx_next.wrapping_add(1);
            nic.hdr_w::<u32>(nr::O_RX_PROD, nic.rx_next);
            got = true;
        }
        if got {
            let _ = nr::poll();
        }
        // Hand slots the stack has finished with back to the card.
        let cons = nic.hdr::<u32>(nr::O_RX_CONS);
        while nic.rx_released != cons && cons.wrapping_sub(nic.rx_released) <= N as u32 {
            // Slot index rx_released % N is free again.
            let slot = (nic.rx_released as usize) % N;
            nic.hdr_w::<u8>(RXD + slot * 16 + 12, 0);
            nic.w(RDT, slot as u32);
            nic.rx_released = nic.rx_released.wrapping_add(1);
        }
        // Transmit: reap finished frames, post new ones.
        while nic.tx_done != nic.tx_posted {
            let slot = (nic.tx_done as usize) % N;
            if nic.hdr::<u8>(TXD + slot * 16 + 12) & 1 == 0 {
                break;
            }
            nic.tx_done = nic.tx_done.wrapping_add(1);
            nic.hdr_w::<u32>(nr::O_TX_CONS, nic.tx_done);
        }
        let prod = nic.hdr::<u32>(nr::O_TX_PROD);
        let mut posted = false;
        while nic.tx_posted != prod && nic.tx_posted.wrapping_sub(nic.tx_done) < (N - 1) as u32 {
            let slot = (nic.tx_posted as usize) % N;
            let t = TXD + slot * 16;
            let len = nic.hdr::<u16>(nr::O_TX_LEN + slot * 2);
            nic.hdr_w::<u16>(t + 8, len);
            nic.hdr_w::<u8>(t + 11, 0x0B); // EOP | IFCS | RS
            nic.hdr_w::<u8>(t + 12, 0);
            nic.tx_posted = nic.tx_posted.wrapping_add(1);
            posted = true;
        }
        if posted {
            nic.w(TDT, nic.tx_posted % N as u32);
        }
        // Link changes.
        let link = nic.r(STATUS) & STATUS_LU != 0;
        if link != last_link {
            last_link = link;
            nic.hdr_w::<u16>(nr::O_FLAGS, 2 | link as u16);
            log!("link {}", if link { "up" } else { "down" });
            status = alloc_status(&mac, link);
        }
        let _ = &status;
    }
}

fn alloc_status(mac: &[u8; 6], link: bool) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::new();
    let _ = write!(s, "mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link {}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], if link { "up" } else { "down" });
    s
}

extern crate alloc;
