/*
 * Userspace NVMe Driver (AI-Native Architecture)
 * 
 * Demonstrates detaching the kernel NVMe driver and
 * taking control via MMIO BAR0 access and Admin Queues.
 *
 * I/O Pattern:
 *   1. PCI probe → find NVMe controller (class 01h/08h/02h)
 *   2. DevDetach → release kernel driver
 *   3. Read BAR0 → get MMIO base address
 *   4. DmaAlloc → allocate Admin Queue memory
 *   5. Read controller capabilities and version
 */

pub fn init() {
    crate::arch::x86_64::serial::write_str("[USER-DRV] Initializing userspace NVMe...\r\n");

    // 1. Find device (Class 01h, Sub 08h, ProgIF 02h)
    let d = match crate::pci::find_by_class(0x01, 0x08, 0x02) {
        Some(d) => d,
        None => {
            crate::arch::x86_64::serial::write_str("[USER-DRV] NVMe device not found.\r\n");
            return;
        }
    };

    crate::arch::x86_64::serial::write_str("[USER-DRV] Found NVMe at ");
    serial_hex_byte(d.bus);
    crate::arch::x86_64::serial::write_str(":");
    serial_hex_byte(d.device);
    crate::arch::x86_64::serial::write_str("\r\n");

    // 2. Detach kernel driver
    crate::core::syscall::dispatch(&crate::core::syscall::SyscallArgs {
        number: 110, // DevDetach
        arg1: 1,     // NVMe
        arg2: 0, arg3: 0, arg4: 0, arg5: 0,
    });

    // 3. Read BAR0 (MMIO base)
    let bar0_lo = crate::pci::config_read32(d.bus, d.device, d.function, 0x10);
    let bar0_hi = crate::pci::config_read32(d.bus, d.device, d.function, 0x14);
    let mmio_base = ((bar0_hi as u64) << 32) | ((bar0_lo & 0xFFFFF000) as u64);

    crate::arch::x86_64::serial::write_str("[USER-DRV] NVMe MMIO BAR0: 0x");
    serial_hex64(mmio_base);
    crate::arch::x86_64::serial::write_str("\r\n");

    // 4. Map MMIO region via HHDM (if available)
    // In full userspace this would use sys_mmap with MAP_DEVICE
    let hhdm = crate::arch::x86_64::boot::hhdm_offset().unwrap_or(0);
    if mmio_base > 0 && hhdm > 0 {
        let virt = mmio_base + hhdm;

        // Read CAP register (offset 0x00, 64-bit)
        let cap = unsafe { core::ptr::read_volatile(virt as *const u64) };
        let mqes = (cap & 0xFFFF) as u16 + 1; // Maximum Queue Entries Supported
        let dstrd = ((cap >> 32) & 0xF) as u8; // Doorbell Stride

        crate::arch::x86_64::serial::write_str("[USER-DRV] NVMe CAP: MQES=");
        serial_dec16(mqes);
        crate::arch::x86_64::serial::write_str(", DSTRD=");
        serial_dec8(dstrd);
        crate::arch::x86_64::serial::write_str("\r\n");

        // Read VS register (offset 0x08, 32-bit) — NVMe version
        let vs = unsafe { core::ptr::read_volatile((virt + 0x08) as *const u32) };
        let major = (vs >> 16) & 0xFF;
        let minor = (vs >> 8) & 0xFF;

        crate::arch::x86_64::serial::write_str("[USER-DRV] NVMe Version: ");
        serial_dec8(major as u8);
        crate::arch::x86_64::serial::write_str(".");
        serial_dec8(minor as u8);
        crate::arch::x86_64::serial::write_str("\r\n");

        // 5. Allocate Admin Queue pair (SQ + CQ)
        let aq_size: u64 = 4096 * 2; // 1 page for SQ, 1 page for CQ
        let aq_phys = crate::core::syscall::dispatch(&crate::core::syscall::SyscallArgs {
            number: 130, // DmaAlloc
            arg1: aq_size,
            arg2: 4096,
            arg3: 0, arg4: 0, arg5: 0,
        });

        if aq_phys > 0 {
            crate::arch::x86_64::serial::write_str("[USER-DRV] NVMe AQ DMA at phys 0x");
            serial_hex32(aq_phys as u32);
            crate::arch::x86_64::serial::write_str("\r\n");
        }
    }

    crate::arch::x86_64::serial::write_str("[USER-DRV] NVMe userspace driver initialized.\r\n");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn serial_hex_byte(v: u8) {
    let hex = b"0123456789ABCDEF";
    crate::arch::x86_64::serial::write_byte(hex[(v >> 4) as usize]);
    crate::arch::x86_64::serial::write_byte(hex[(v & 0xF) as usize]);
}

fn serial_hex32(v: u32) {
    serial_hex_byte((v >> 24) as u8);
    serial_hex_byte((v >> 16) as u8);
    serial_hex_byte((v >> 8) as u8);
    serial_hex_byte(v as u8);
}

fn serial_hex64(v: u64) {
    serial_hex32((v >> 32) as u32);
    serial_hex32(v as u32);
}

fn serial_dec8(mut v: u8) {
    if v >= 100 { crate::arch::x86_64::serial::write_byte(b'0' + v / 100); v %= 100; }
    if v >= 10 { crate::arch::x86_64::serial::write_byte(b'0' + v / 10); v %= 10; }
    crate::arch::x86_64::serial::write_byte(b'0' + v);
}

fn serial_dec16(mut v: u16) {
    let mut buf = [0u8; 5];
    let mut i = 0;
    if v == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    while v > 0 { buf[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}
