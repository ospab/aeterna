/*
 * Userspace RTL8139 Driver (AI-Native Architecture)
 * 
 * Sandboxed network driver using syscalls for I/O port access,
 * interrupt handling, and DMA buffer management.
 *
 * I/O Pattern:
 *   1. PCI probe → find RTL8139
 *   2. DevDetach → release kernel driver
 *   3. IopIn/IopOut → read MAC, configure RX buffer
 *   4. DmaAlloc → allocate RX/TX DMA ring
 *   5. IrqWait → wait for packets
 */

/// RTL8139 register offsets
const REG_MAC0:      u16 = 0x00;  // MAC address bytes 0-3
const REG_MAC4:      u16 = 0x04;  // MAC address bytes 4-5
const REG_RBSTART:   u16 = 0x30;  // RX buffer start (physical addr)
const REG_CMD:       u16 = 0x37;  // Command register
const REG_IMR:       u16 = 0x3C;  // Interrupt mask register
const REG_ISR:       u16 = 0x3E;  // Interrupt status register
const REG_RCR:       u16 = 0x44;  // RX config register

/// RX buffer size: 8K + 16 + 1500 (wrap padding)
const RX_BUF_SIZE: u64 = 8192 + 16 + 1500;

pub fn init() {
    crate::arch::x86_64::serial::write_str("[USER-DRV] Initializing userspace RTL8139...\r\n");

    // 1. Find device
    let d = match crate::pci::find_by_vendor_device(0x10EC, 0x8139) {
        Some(d) => d,
        None => {
            crate::arch::x86_64::serial::write_str("[USER-DRV] RTL8139 not found.\r\n");
            return;
        }
    };

    crate::arch::x86_64::serial::write_str("[USER-DRV] Found RTL8139 at ");
    serial_hex_byte(d.bus);
    crate::arch::x86_64::serial::write_str(":");
    serial_hex_byte(d.device);
    crate::arch::x86_64::serial::write_str("\r\n");

    // 2. Detach kernel driver
    crate::core::syscall::dispatch(&crate::core::syscall::SyscallArgs {
        number: 110, // DevDetach
        arg1: 0,     // RTL8139
        arg2: 0, arg3: 0, arg4: 0, arg5: 0,
    });

    // 3. Read I/O base from BAR0
    let bar0 = crate::pci::config_read32(d.bus, d.device, d.function, 0x10);
    let io_base = (bar0 & 0xFFFC) as u16;

    crate::arch::x86_64::serial::write_str("[USER-DRV] IO Base: 0x");
    serial_hex16(io_base);
    crate::arch::x86_64::serial::write_str("\r\n");

    // 4. Read MAC address via IopIn syscalls
    crate::arch::x86_64::serial::write_str("[USER-DRV] MAC: ");
    for i in 0..6u16 {
        let byte = ioport_in8(io_base + REG_MAC0 + i);
        serial_hex_byte(byte);
        if i < 5 { crate::arch::x86_64::serial::write_str(":"); }
    }
    crate::arch::x86_64::serial::write_str("\r\n");

    // 5. Allocate DMA buffer for RX ring
    let rx_phys = crate::core::syscall::dispatch(&crate::core::syscall::SyscallArgs {
        number: 130, // DmaAlloc
        arg1: RX_BUF_SIZE,
        arg2: 4096, // page-aligned
        arg3: 0, arg4: 0, arg5: 0,
    });

    if rx_phys > 0 {
        crate::arch::x86_64::serial::write_str("[USER-DRV] RX DMA buffer at phys 0x");
        serial_hex32(rx_phys as u32);
        crate::arch::x86_64::serial::write_str("\r\n");

        // 6. Configure card: reset → set RX buffer → enable RX/TX
        ioport_out8(io_base + REG_CMD, 0x10); // Reset
        // Brief spin-wait for reset to settle
        for _ in 0..1000 { core::hint::spin_loop(); }

        // Set RX buffer physical address
        ioport_out32(io_base + REG_RBSTART, rx_phys as u32);

        // Enable RX and TX
        ioport_out8(io_base + REG_CMD, 0x0C); // RE + TE

        // Accept all packets + wrap
        ioport_out32(io_base + REG_RCR, 0x0000_008F);

        // Enable interrupts: ROK + TOK
        ioport_out16(io_base + REG_IMR, 0x0005);

        crate::arch::x86_64::serial::write_str("[USER-DRV] RTL8139 configured. Userspace I/O active.\r\n");
    } else {
        crate::arch::x86_64::serial::write_str("[USER-DRV] DMA alloc failed for RTL8139 RX buffer\r\n");
    }
}

// ─── Userspace I/O wrappers via syscalls ─────────────────────────────────────

fn ioport_in8(port: u16) -> u8 {
    crate::core::syscall::dispatch(&crate::core::syscall::SyscallArgs {
        number: 60, // IopIn
        arg1: port as u64,
        arg2: 1, // 1 byte
        arg3: 0, arg4: 0, arg5: 0,
    }) as u8
}

fn ioport_out8(port: u16, val: u8) {
    crate::core::syscall::dispatch(&crate::core::syscall::SyscallArgs {
        number: 61, // IopOut
        arg1: port as u64,
        arg2: 1, // 1 byte
        arg3: val as u64, arg4: 0, arg5: 0,
    });
}

fn ioport_out16(port: u16, val: u16) {
    crate::core::syscall::dispatch(&crate::core::syscall::SyscallArgs {
        number: 61,
        arg1: port as u64,
        arg2: 2,
        arg3: val as u64, arg4: 0, arg5: 0,
    });
}

fn ioport_out32(port: u16, val: u32) {
    crate::core::syscall::dispatch(&crate::core::syscall::SyscallArgs {
        number: 61,
        arg1: port as u64,
        arg2: 4,
        arg3: val as u64, arg4: 0, arg5: 0,
    });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn serial_hex_byte(v: u8) {
    let hex = b"0123456789ABCDEF";
    crate::arch::x86_64::serial::write_byte(hex[(v >> 4) as usize]);
    crate::arch::x86_64::serial::write_byte(hex[(v & 0xF) as usize]);
}

fn serial_hex16(v: u16) {
    serial_hex_byte((v >> 8) as u8);
    serial_hex_byte(v as u8);
}

fn serial_hex32(v: u32) {
    serial_hex16((v >> 16) as u16);
    serial_hex16(v as u16);
}
