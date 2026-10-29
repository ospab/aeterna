/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Minimal PS/2 mouse driver for AETERNA.
Handles 3-byte standard PS/2 mouse packets.
*/

use crate::arch::x86_64::io::{inb, outb};

const PS2_STATUS: u16 = 0x64;
const PS2_COMMAND: u16 = 0x64;
const PS2_DATA: u16 = 0x60;

/// Packet assembly state and the deltas accumulated since the last poll. Written by the
/// IRQ 12 handler and by USB HID injection, read by the GUI: lock class DEV.
struct MouseState {
    cycle: u8,
    packet: [u8; 3],
    dx: i32,
    dy: i32,
    btns: u8,
}

static MOUSE: crate::core::sync::IrqSpinLock<MouseState> = crate::core::sync::IrqSpinLock::new(
    "MOUSE",
    crate::core::sync::rank::DEV,
    MouseState { cycle: 0, packet: [0; 3], dx: 0, dy: 0, btns: 0 },
);

/// Initialize PS/2 mouse
pub fn init() {
    unsafe {
        // Wait for 8042 to be ready
        wait_write();
        // Enable the auxiliary mouse port
        outb(PS2_COMMAND, 0xA8);
        
        // Enable interrupts and mouse clock
        wait_write();
        outb(PS2_COMMAND, 0x20); // Get command byte (CCB)
        wait_read();
        let mut status = inb(PS2_DATA);
        status |= 0x02;  // Enable IRQ 12
        status &= !0x20; // Clear "Disable mouse clock"
        wait_write();
        outb(PS2_COMMAND, 0x60); // Set command byte
        wait_write();
        outb(PS2_DATA, status);
        
        // Set defaults
        mouse_write(0xF6);
        let ack1 = mouse_read(); 
        
        // Enable data reporting
        mouse_write(0xF4);
        let ack2 = mouse_read();
        
        crate::arch::x86_64::serial::write_str("[MOUSE] Init: CCB=");
        serial_hex_u8(status);
        crate::arch::x86_64::serial::write_str(", ACK1=");
        serial_hex_u8(ack1);
        crate::arch::x86_64::serial::write_str(", ACK2=");
        serial_hex_u8(ack2);
        crate::arch::x86_64::serial::write_str("\r\n");

        // Unmask IRQ 12 in the PIC
        crate::arch::x86_64::pic::enable_irq(12);
    }
}

fn serial_hex_u8(b: u8) {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    crate::arch::x86_64::serial::write_byte(HEX[(b >> 4) as usize]);
    crate::arch::x86_64::serial::write_byte(HEX[(b & 0x0F) as usize]);
}

unsafe fn wait_write() {
    let mut timeout = 100000;
    while timeout > 0 && (inb(PS2_STATUS) & 0x02) != 0 {
        timeout -= 1;
    }
}

unsafe fn wait_read() {
    let mut timeout = 100000;
    while timeout > 0 && (inb(PS2_STATUS) & 0x01) == 0 {
        timeout -= 1;
    }
}

unsafe fn mouse_write(data: u8) {
    wait_write();
    outb(PS2_COMMAND, 0xD4); // Tell 8042 next data goes to mouse
    wait_write();
    outb(PS2_DATA, data);
}

unsafe fn mouse_read() -> u8 {
    wait_read();
    inb(PS2_DATA)
}

/// IRQ 12 handler called from IDT dispatcher
pub fn handle_irq() {
    unsafe {
        let status = inb(PS2_STATUS);
        if (status & 0x01) != 0 && (status & 0x20) != 0 {
            let data = inb(PS2_DATA);
            process_byte(data);
        }
    }
}

fn process_byte(b: u8) {
    let mut m = MOUSE.lock();
    match m.cycle {
        0 => {
            if (b & 0x08) != 0 {
                m.packet[0] = b;
                m.cycle = 1;
            }
        }
        1 => {
            m.packet[1] = b;
            m.cycle = 2;
        }
        2 => {
            m.packet[2] = b;
            m.cycle = 0;

            let flags = m.packet[0];
            let mut dx = m.packet[1] as i32;
            let mut dy = m.packet[2] as i32;

            if (flags & 0x10) != 0 { dx |= !0xFF; }
            if (flags & 0x20) != 0 { dy |= !0xFF; }

            m.dx += dx;
            m.dy += dy;
            m.btns = flags & 0x07;
        }
        _ => m.cycle = 0,
    }
}

/// Add a movement from another source (USB HID mouse). `dy` follows the PS/2
/// convention (positive = up). Buttons: bit0 left, bit1 right, bit2 middle.
pub fn inject(dx: i32, dy: i32, btns: u8) {
    let mut m = MOUSE.lock();
    m.dx += dx;
    m.dy += dy;
    m.btns = btns & 0x07;
}

/// Consume accumulated deltas
pub fn poll() -> (i32, i32, u8) {
    crate::xhci::poll(false); // USB mice have no IRQ: service them on every poll
    let mut m = MOUSE.lock();
    let r = (m.dx, m.dy, m.btns);
    m.dx = 0;
    m.dy = 0;
    r
}
