/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Early CPU/board init: SSE, Limine check, GDT, IDT, PIC, serial, framebuffer.
*/
use core::arch::asm;
use super::boot;
use super::gdt_simple;
use super::idt;
use super::pic;
use super::serial;
use super::framebuffer;

/// Disable CPU interrupts.
pub fn disable_interrupts() {
    unsafe { asm!("cli"); }
}

/// Enable CPU interrupts.
pub fn enable_interrupts() {
    unsafe { asm!("sti"); }
}

/// Enable SSE/SSE2 (CR4.OSFXSR, OSXMMEXCPT; CR0.EM clear, MP set).
pub fn enable_sse() {
    unsafe {
        asm!(
            "mov rax, cr4",
            "or rax, 0x660",
            "mov cr4, rax",
            "mov rax, cr0",
            "and rax, 0xFFFFFFFFFFFFFFFB",
            "or rax, 0x2",
            "mov cr0, rax",
            options(nostack, preserves_flags)
        );
    }
}

/// Enable AVX/AVX2: set CR4.OSXSAVE and configure XCR0 so that YMM registers
/// are saved/restored by the hardware.  Without this, any VEX-encoded AVX
/// instruction triggers #UD even when CPUID.7:EBX[5] reports AVX2 support.
///
/// Safe to call on pre-AVX CPUs — checks CPUID before touching any new bits.
pub fn enable_avx() {
    use core::arch::x86_64::__cpuid;
    unsafe {
        // CPUID leaf 1: ECX[26]=XSAVE, ECX[28]=AVX
        let leaf1 = __cpuid(1);
        if leaf1.ecx & (1 << 26) == 0 {
            serial::write_str("[ARCH] XSAVE not supported, skipping AVX enable\r\n");
            return;
        }

        // Set CR4.OSXSAVE (bit 18): tells CPU the OS will save XSTATE
        asm!(
            "mov rax, cr4",
            "or rax, 0x40000",
            "mov cr4, rax",
            out("rax") _,
            options(nostack, preserves_flags, nomem)
        );

        if leaf1.ecx & (1 << 28) == 0 {
            serial::write_str("[ARCH] CR4.OSXSAVE set; AVX not present, XCR0 left as-is\r\n");
            return;
        }

        // Write XCR0 = x87 (bit 0) + SSE/XMM (bit 1) + AVX/YMM (bit 2) exactly: the
        // per-task save area is sized for these components only.
        asm!(
            "xor ecx, ecx",   // XCR0 selector = 0
            "mov eax, 7",
            "xor edx, edx",
            "xsetbv",
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, nomem)
        );

        serial::write_str("[ARCH] AVX/YMM enabled (CR4.OSXSAVE + XCR0[2])
");
        setup_xsave(7);
    }
}

// ── Per-task FPU/SIMD state: XSAVE when the CPU has it, FXSAVE otherwise ─────────────
// Read by the ISR stubs in idt.rs (via `sym`), so they are plain statics.

/// 1 = context switches use XSAVE/XRSTOR, 0 = FXSAVE/FXRSTOR.
#[no_mangle]
pub static mut XSAVE_ENABLED: u8 = 0;
/// Bytes to reserve for one save area (>= 512; XSAVE: CPUID.0Dh.0:EBX for the enabled XCR0).
#[no_mangle]
pub static mut XSAVE_AREA_SIZE: u64 = 512;
/// Requested-feature bitmap passed in EDX:EAX to XSAVE/XRSTOR (= XCR0).
#[no_mangle]
pub static mut XSAVE_MASK_LO: u32 = 0;
#[no_mangle]
pub static mut XSAVE_MASK_HI: u32 = 0;

/// Largest save area a task can hold (x87 + SSE + AVX needs 832 bytes).
pub const XSAVE_AREA_MAX: usize = 1024;

/// Size of the XSAVE/FXSAVE image the context switch writes per task.
pub fn xsave_area_size() -> usize {
    unsafe { XSAVE_AREA_SIZE as usize }
}

/// Whether context switches use XSAVE (true) or FXSAVE (false).
pub fn xsave_enabled() -> bool {
    unsafe { XSAVE_ENABLED != 0 }
}

/// Load the FPU/SIMD state from `area` (the format the stubs saved it in).
///
/// # Safety
/// `area` must be 64-byte aligned and hold a valid image of `xsave_area_size()` bytes.
pub unsafe fn restore_fpu_state(area: *const u8) {
    if XSAVE_ENABLED != 0 {
        asm!("xrstor [{}]", in(reg) area, in("eax") XSAVE_MASK_LO, in("edx") XSAVE_MASK_HI,
            options(nostack));
    } else {
        asm!("fxrstor [{}]", in(reg) area, options(nostack));
    }
}

/// Decide on XSAVE for context switches once XCR0 is final.
fn setup_xsave(xcr0: u32) {
    use core::arch::x86_64::__cpuid_count;
    unsafe {
        // Trust the hypervisor only as far as it is self-consistent: read XCR0 back, and
        // take the area size CPUID reports for exactly those components.
        let (lo, hi): (u32, u32);
        asm!("xor ecx, ecx", "xgetbv", out("eax") lo, out("edx") hi, out("ecx") _,
            options(nostack, nomem));
        let xcr0 = lo;
        let leaf = __cpuid_count(0xD, 0);
        let size = leaf.ebx as usize; // size for the currently enabled XCR0 components
        // Minimum plausible size: legacy 512 + header 64, plus 256 for YMM when enabled.
        let min = 576 + if xcr0 & 4 != 0 { 256 } else { 0 };
        if hi != 0 || xcr0 & 3 != 3 || size < min || size > XSAVE_AREA_MAX || leaf.eax & xcr0 != xcr0 {
            // Cannot hold it: fall back to the legacy image and drop the YMM state from XCR0.
            asm!("xor ecx, ecx", "mov eax, 3", "xor edx, edx", "xsetbv",
                out("eax") _, out("ecx") _, out("edx") _, options(nostack, nomem));
            serial::write_str("[ARCH] XSAVE area too large, AVX disabled, using FXSAVE
");
            return;
        }
        XSAVE_AREA_SIZE = size as u64;
        XSAVE_MASK_LO = xcr0;
        XSAVE_MASK_HI = 0;
        XSAVE_ENABLED = 1;
        serial::write_str("[ARCH] Context switch uses XSAVE (area ");
        serial_dec(size as u64);
        serial::write_str(" bytes)
");
    }
}

/// Full arch init: SSE, Limine check, GDT, IDT, PIC, serial, framebuffer.
pub fn init() {
    disable_interrupts();
    enable_sse();
    enable_avx();

    serial::init();
    serial::write_str("[BOOT] Serial COM1 ready\r\n");

    if !boot::base_revision_supported() {
        serial::write_str("[BOOT] WARN: Limine base revision not supported\r\n");
    }
    if let Some(off) = boot::hhdm_offset() {
        serial::write_str("[MM] HHDM offset: 0x");
        serial_hex(off);
        serial::write_str("\r\n");
    }

    gdt_simple::init();
    serial::write_str("[CPU] GDT + TSS loaded\r\n");

    idt::init();

    // Initialize PIC (remap IRQs to IDT 32-47)
    pic::init();

    // Program PIT channel 0 to fire at 100 Hz (preemptive scheduling fallback)
    pic::init_pit_100hz();

    // Initialize PS/2 Mouse
    super::mouse::init();

    // Calibrate TSC — must come after PIT is live (uses 10 tick = 100 ms window).
    // Enable interrupts first so that `hlt` in calibrate() actually receives PIT ticks.
    enable_interrupts();
    super::tsc::calibrate();
    // Seed the wall clock from the CMOS RTC (needs the calibrated TSC).
    crate::time::init();

    // Init Local APIC one-shot timer (vector 48) — arms 1 ms precision preemption.
    // Requires TSC calibrated and interrupts enabled.
    super::apic::init_timer();

    // Initialize framebuffer if available
    if let Some(fb) = boot::framebuffer() {
        unsafe {
            framebuffer::init(
                fb.address as *mut u32,
                fb.width,
                fb.height,
                fb.pitch,
                fb.bpp,
                fb.red_mask_shift,
                fb.green_mask_shift,
                fb.blue_mask_shift,
            );
        }
        serial::write_str("[FB] ");
        serial_dec(fb.width);
        serial::write_str("x");
        serial_dec(fb.height);
        serial::write_str(", ");
        serial_dec(fb.bpp as u64);
        serial::write_str(" bpp\r\n");

        // Initialize fbconsole for text output
        super::fbconsole::init();

        // Blank screen; the boot log (src/main.rs) is the only thing drawn on it.
        framebuffer::clear(0x00000000);
    } else {
        serial::write_str("[FB] No framebuffer from the boot loader\r\n");
    }

    // Enable hardware interrupts
    enable_interrupts();
    serial::write_str("[CPU] Interrupts enabled\r\n");
}

pub fn serial_hex(mut val: u64) {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    let mut buf = [0u8; 16];
    for i in (0..16).rev() {
        buf[i] = HEX[(val & 0xF) as usize];
        val >>= 4;
    }
    for b in buf {
        serial::write_byte(b);
    }
}

/// Print an unsigned integer to the serial port in decimal.
pub fn serial_dec(mut val: u64) {
    if val == 0 {
        serial::write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        serial::write_byte(buf[i]);
    }
}
