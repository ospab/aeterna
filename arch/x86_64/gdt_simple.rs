/*
Business Source License 1.1
Copyright (c) 2026 ospab
Simple GDT implementation without external dependencies.
*/

use core::arch::asm;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TaskStateSegment {
    _reserved1: u32,
    pub rsp: [u64; 3],
    _reserved2: u64,
    pub ist: [u64; 7],
    _reserved3: u64,
    _reserved4: u16,
    pub iopb_offset: u16,
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            _reserved1: 0,
            rsp: [0; 3],
            _reserved2: 0,
            ist: [0; 7],
            _reserved3: 0,
            _reserved4: 0,
            iopb_offset: core::mem::size_of::<TaskStateSegment>() as u16,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    flags_limit_high: u8,
    base_high: u8,
}

impl GdtEntry {
    pub const fn new() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            flags_limit_high: 0,
            base_high: 0,
        }
    }

    pub fn set_code_segment(&mut self) {
        self.access = 0x9A; // Present, Ring 0, Code, Executable, Accessed
        self.flags_limit_high = 0xA0; // Granularity 4KB, 32-bit, Limit high 0xF
    }

    pub fn set_data_segment(&mut self) {
        self.access = 0x92; // Present, Ring 0, Data, Writable, Accessed
        self.flags_limit_high = 0xC0; // Granularity 4KB, 32-bit, Limit high 0xF
    }

    pub fn set_user_code_segment(&mut self) {
        self.access = 0xFA; // Present, Ring 3, Code, Executable, Accessed
        self.flags_limit_high = 0xA0; // Granularity 4KB, 64-bit, Limit high 0xF
    }

    pub fn set_user_data_segment(&mut self) {
        self.access = 0xF2; // Present, Ring 3, Data, Writable, Accessed
        self.flags_limit_high = 0xC0; // Granularity 4KB, 32-bit, Limit high 0xF
    }

    pub fn set_tss_segment(&mut self) {
        self.access = 0x89; // Present, Ring 0, TSS, Available
        self.flags_limit_high = 0x00; // TSS special case
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct GdtPointer {
    pub limit: u16,
    pub base: u64,
}

pub const GDT_ENTRIES: usize = 7;
static mut GDT: [GdtEntry; GDT_ENTRIES] = [
    GdtEntry::new(), // 0: Null
    GdtEntry::new(), // 1: Kernel Code
    GdtEntry::new(), // 2: Kernel Data
    GdtEntry::new(), // 3: User Data
    GdtEntry::new(), // 4: User Code
    GdtEntry::new(), // 5: TSS (low)
    GdtEntry::new(), // 6: TSS (high)
];

/// Kernel code segment selector (GDT index 1)
pub const KERNEL_CS: u16 = 0x08;
/// Kernel data segment selector (GDT index 2)
pub const KERNEL_DS: u16 = 0x10;
/// User data segment selector (GDT index 3, RPL 3)
pub const USER_DS: u16 = 0x18 | 3;
/// User code segment selector (GDT index 4, RPL 3)
pub const USER_CS: u16 = 0x20 | 3;
/// TSS segment selector (GDT index 5)
pub const TSS_SELECTOR: u16 = 0x28;

static mut TSS: TaskStateSegment = TaskStateSegment::new();
static mut RING0_STACK: [u8; 16384] = [0; 16384];

unsafe fn install_tss_descriptor() {
    let tss_base = core::ptr::addr_of!(TSS) as u64;
    let tss_limit = (core::mem::size_of::<TaskStateSegment>() - 1) as u64;

    let low: u64 =
        (tss_limit & 0xFFFF)
        | ((tss_base & 0x00FF_FFFF) << 16)
        | (0x89u64 << 40)
        | (((tss_limit >> 16) & 0xF) << 48)
        | (((tss_base >> 24) & 0xFF) << 56);
    let high: u64 = tss_base >> 32;

    let gdt64 = core::ptr::addr_of_mut!(GDT) as *mut u64;
    *gdt64.add(5) = low;
    *gdt64.add(6) = high;
}

pub fn set_tss_rsp0(rsp0: u64) {
    unsafe {
        TSS.rsp[0] = rsp0;
    }
}

pub fn init() {
    unsafe {
        // 1: Kernel Code
        GDT[1].set_code_segment();
        GDT[1].limit_low = 0xFFFF;
        
        // 2: Kernel Data
        GDT[2].set_data_segment();
        GDT[2].limit_low = 0xFFFF;

        // 3: User Data (Ring 3)
        GDT[3].set_user_data_segment();
        GDT[3].limit_low = 0xFFFF;

        // 4: User Code (Ring 3)
        GDT[4].set_user_code_segment();
        GDT[4].limit_low = 0xFFFF;

        // Install TSS descriptor entries (5 and 6)
        install_tss_descriptor();

        // Default ring0 stack for CPL3 -> CPL0 transitions
        let rsp0 = (core::ptr::addr_of!(RING0_STACK) as u64) + RING0_STACK.len() as u64;
        TSS.rsp[0] = rsp0;

        let gdt_ptr = GdtPointer {
            limit: (core::mem::size_of::<[GdtEntry; GDT_ENTRIES]>() - 1) as u16,
            base: core::ptr::addr_of!(GDT) as u64,
        };

        asm!("lgdt [{}]", in(reg) &gdt_ptr, options(readonly, nostack));

        // Reload CS via far return
        asm!(
            "push {cs}",        // push new CS selector
            "lea {tmp}, [rip + 2f]", 
            "push {tmp}",       
            "retfq",            
            "2:",               
            cs = in(reg) KERNEL_CS as u64,
            tmp = lateout(reg) _,
            options(preserves_flags),
        );

        // Reload all data segment registers
        asm!(
            "mov ds, {0:x}",
            "mov es, {0:x}",
            "mov fs, {0:x}",
            "mov gs, {0:x}",
            "mov ss, {0:x}",
            in(reg) KERNEL_DS as u64,
            options(nostack, preserves_flags),
        );

        // Load TSS so interrupts/exceptions from Ring 3 get a valid RSP0
        asm!(
            "ltr ax",
            in("ax") TSS_SELECTOR,
            options(nostack, preserves_flags),
        );
    }
}
