// SPDX-License-Identifier: AGPL-3.0-only
//! uartdrv — the first ring-3 driver (proof of concept, ROADMAP item 13): a 16550 UART on
//! COM2 (ports 0x2F8..0x2FF, IRQ 3), driven entirely through handles.
//!
//! Bootstrap handles: 1 = IoPortRange 0x2F8+8 (READ|WRITE), 2 = Interrupt IRQ 3 (READ|WRITE).
//!
//! Modes (argument 1):
//!   run      enable the ports, bind the IRQ to a notification; loopback round trip with
//!            receive interrupts, then send a line out of COM2 paced by transmit-empty
//!            interrupts. Exit 0 = ok, 77 = no UART at COM2, otherwise the failed step.
//!   badport  enable the range, then touch port 0x300 just past it: #GP must kill us.
//!   noperm   touch 0x2F8 without enabling the range: #GP must kill us.
#![no_std]
#![no_main]

use liboos::hw::{self, Interrupt, IoPorts};
use liboos::ipc::{Error, Handle, Notification, Rights};
use liboos::println;

liboos::entry!(main);

// 16550 registers (offsets from the base port)
const RBR_THR: u16 = 0; // receive buffer / transmit holding (DLAB=0); divisor low (DLAB=1)
const IER: u16 = 1; // interrupt enable; divisor high (DLAB=1)
const IIR_FCR: u16 = 2; // interrupt identification (read) / FIFO control (write)
const LCR: u16 = 3;
const MCR: u16 = 4;
const LSR: u16 = 5;
const SCR: u16 = 7;

const IER_RX: u8 = 0x01;
const IER_THRE: u8 = 0x02;
const MCR_OUT2: u8 = 0x08; // gates the IRQ line on PC hardware
const MCR_LOOP: u8 = 0x10;
const LSR_DR: u8 = 0x01;

/// Wait up to 1 s per interrupt.
const IRQ_TIMEOUT: u64 = 100;

fn main(args: liboos::Args) -> i32 {
    let ports = IoPorts::new(Handle::bootstrap(1), 0x2F8, 8);
    let irq = Interrupt(Handle::bootstrap(2));
    match args.get(1) {
        Some("badport") => {
            if ports.enable().is_err() {
                return 1;
            }
            println!("[uartdrv] ports 0x2F8-0x2FF enabled; touching 0x300 (outside the range)");
            let _ = unsafe { hw::inb(0x300) };
            println!("[uartdrv] port 0x300 was readable: I/O bitmap NOT enforced");
            3
        }
        Some("noperm") => {
            println!("[uartdrv] touching 0x2F8 without ioport_enable");
            let _ = unsafe { hw::inb(0x2F8) };
            println!("[uartdrv] port 0x2F8 was readable without permission");
            3
        }
        _ => run(&ports, &irq),
    }
}

/// Unmask the line and sleep until the next interrupt.
fn wait_irq(irq: &Interrupt, n: &Notification) -> Result<(), Error> {
    irq.ack()?;
    n.wait(IRQ_TIMEOUT).map(|_| ())
}

fn run(p: &IoPorts, irq: &Interrupt) -> i32 {
    // 1: rights and setup
    if irq.0.info().map(|(_, r)| r.contains(Rights::READ | Rights::WRITE)) != Ok(true) {
        return 1;
    }
    let n = match Notification::create() {
        Ok(n) => n,
        Err(_) => return 1,
    };
    if irq.bind(&n, 1).is_err() || p.enable().is_err() {
        return 1;
    }

    // 2: is there a UART at all? (QEMU creates COM2 only with a second -serial)
    p.outb(SCR, 0x5A);
    if p.inb(SCR) != 0x5A {
        println!("[uartdrv] no UART at 0x2F8 (start QEMU with a second -serial): skipped");
        return 77;
    }

    // 3: 115200 8N1, no FIFO, loopback, receive interrupts
    p.outb(IER, 0);
    p.outb(LCR, 0x80);
    p.outb(RBR_THR, 1);
    p.outb(IER, 0);
    p.outb(LCR, 0x03);
    p.outb(IIR_FCR, 0);
    p.outb(MCR, MCR_OUT2 | MCR_LOOP);
    for _ in 0..4 {
        let _ = p.inb(RBR_THR);
        let _ = p.inb(LSR);
        let _ = p.inb(IIR_FCR);
    }
    p.outb(IER, IER_RX);

    let mut irqs = 0u32;
    for &b in b"IRQ3" {
        p.outb(RBR_THR, b);
        // The byte comes back through the loopback and raises "data available".
        let mut got = None;
        for _ in 0..4 {
            if wait_irq(irq, &n).is_err() {
                println!("[uartdrv] no receive interrupt for {:?}", b as char);
                return 4;
            }
            irqs += 1;
            let _ = p.inb(IIR_FCR);
            if p.inb(LSR) & LSR_DR != 0 {
                got = Some(p.inb(RBR_THR));
                break;
            }
        }
        if got != Some(b) {
            println!("[uartdrv] loopback sent {:#x}, got {:?}", b, got);
            return 5;
        }
    }
    println!("[uartdrv] loopback: 4 bytes echoed, {} receive interrupts", irqs);

    // 6: real output on COM2, one byte per transmit-holding-empty interrupt
    p.outb(IER, 0);
    p.outb(MCR, MCR_OUT2);
    p.outb(IER, IER_THRE); // THR is empty now: the first interrupt comes right away
    let line = b"hello from the ring-3 COM2 driver (IoPortRange 0x2F8, IRQ 3 via Notification)\r\n";
    let mut tx_irqs = 0u32;
    for &b in line.iter() {
        if wait_irq(irq, &n).is_err() {
            println!("[uartdrv] no transmit interrupt after {} bytes", tx_irqs);
            return 6;
        }
        tx_irqs += 1;
        let _ = p.inb(IIR_FCR); // acknowledges THRE in the UART
        p.outb(RBR_THR, b);
    }
    // Let the last byte go, then quiet the device.
    let _ = wait_irq(irq, &n);
    p.outb(IER, 0);
    p.outb(MCR, 0);
    if p.disable().is_err() {
        return 7;
    }
    println!("[uartdrv] sent {} bytes on COM2 with {} transmit interrupts; driver done", line.len(), tx_irqs);
    0
}
