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

static mut MOUSE_CYCLE: u8 = 0;
static mut MOUSE_PACKET: [u8; 3] = [0; 3];

// Accumulated deltas since last poll
static mut MOUSE_DX: i32 = 0;
static mut MOUSE_DY: i32 = 0;
static mut MOUSE_BTNS: u8 = 0;

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

unsafe fn process_byte(b: u8) {
    match MOUSE_CYCLE {
        0 => {
            if (b & 0x08) != 0 {
                MOUSE_PACKET[0] = b;
                MOUSE_CYCLE = 1;
            }
        }
        1 => {
            MOUSE_PACKET[1] = b;
            MOUSE_CYCLE = 2;
        }
        2 => {
            MOUSE_PACKET[2] = b;
            MOUSE_CYCLE = 0;
            
            let flags = MOUSE_PACKET[0];
            let mut dx = MOUSE_PACKET[1] as i32;
            let mut dy = MOUSE_PACKET[2] as i32;
            
            if (flags & 0x10) != 0 { dx |= !0xFF; }
            if (flags & 0x20) != 0 { dy |= !0xFF; }
            
            MOUSE_DX += dx;
            MOUSE_DY += dy;
            MOUSE_BTNS = flags & 0x07;
        }
        _ => MOUSE_CYCLE = 0,
    }
}

/// Add a movement from another source (USB HID mouse). `dy` follows the PS/2
/// convention (positive = up). Buttons: bit0 left, bit1 right, bit2 middle.
pub fn inject(dx: i32, dy: i32, btns: u8) {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options(nomem));
        MOUSE_DX += dx;
        MOUSE_DY += dy;
        MOUSE_BTNS = btns & 0x07;
        if flags & (1 << 9) != 0 {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }
}

/// Consume accumulated deltas
pub fn poll() -> (i32, i32, u8) {
    crate::xhci::poll(false); // USB mice have no IRQ: service them on every poll
    unsafe {
        let dx = MOUSE_DX;
        let dy = MOUSE_DY;
        let btns = MOUSE_BTNS;
        MOUSE_DX = 0;
        MOUSE_DY = 0;
        (dx, dy, btns)
    }
}
