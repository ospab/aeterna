/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Interrupt routing: I/O APIC, MSI and MSI-X, vector allocator, handler registry.

Vector map
  0x00-0x1F   CPU exceptions
  0x20-0x2F   ISA IRQ 0-15 (legacy numbering; also used with the I/O APIC: IRQ n -> 0x20+n)
  0x30        local APIC timer
  0x40-0xEF   dynamic: PCI INTx on GSIs above 15, MSI, MSI-X (generic stubs, see below)
  0xFF        local APIC spurious

Without a MADT or an I/O APIC the kernel keeps the 8259 PIC (`pic.rs`) and only the
registry, the stubs and MSI work.

PCI INTx routing: the ACPI _PRT needs an AML interpreter, which the kernel does not have.
`pci_intx_gsi` first uses a static scan of the DSDT (`acpi::prt_lookup`: constant _PRT/PRTA
entries, PCI bus 0 only, link devices with one fixed interrupt as in QEMU). Otherwise it
reads the PCI interrupt line register as an ISA IRQ and maps it through the MADT overrides.
On real machines whose _PRT is a Method or uses PCI link devices (LNKA...) the second path
is taken, and the line register is only right when the firmware set it for APIC routing.
Drivers must keep polling as a fallback. MSI/MSI-X does not depend on any of this.
*/

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use alloc::string::String;
use alloc::format;
use crate::core::sync::{rank, IrqSpinLock};

pub const VEC_LEGACY_BASE: u8 = 32;
pub const VEC_DYN_FIRST: u8 = 0x40;
pub const VEC_DYN_LAST: u8 = 0xEF;
pub const VEC_SPURIOUS: u8 = 0xFF;

/// Handler: `(vector, context)`. Runs in interrupt context with interrupts disabled.
pub type Handler = fn(u8, usize);
const HANDLERS_PER_VECTOR: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Trigger { Edge, Level }
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Polarity { High, Low }

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind { Free, Legacy, Gsi, Msi, MsiX, Timer }

#[derive(Clone, Copy)]
struct Meta {
    kind: Kind,
    name: &'static str,
    /// GSI for Legacy/Gsi, packed bus/dev/func for MSI.
    src: u32,
    /// First vector of the MSI block this vector belongs to.
    group: u8,
}
impl Meta {
    const EMPTY: Meta = Meta { kind: Kind::Free, name: "", src: 0, group: 0 };
}

static META: IrqSpinLock<[Meta; 256]> = IrqSpinLock::new("IRQ", rank::DEV, [Meta::EMPTY; 256]);
static COUNTS: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
static HANDLERS: [[AtomicUsize; HANDLERS_PER_VECTOR]; 256] =
    [const { [const { AtomicUsize::new(0) }; HANDLERS_PER_VECTOR] }; 256];
static CONTEXTS: [[AtomicUsize; HANDLERS_PER_VECTOR]; 256] =
    [const { [const { AtomicUsize::new(0) }; HANDLERS_PER_VECTOR] }; 256];
/// GSI -> vector currently routed (0 = none), for GSIs below 256.
static GSI_VECTOR: [AtomicU8; 256] = [const { AtomicU8::new(0) }; 256];

static IOAPIC_ACTIVE: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn ioapic_active() -> bool { IOAPIC_ACTIVE.load(Ordering::Relaxed) }

fn log(s: &str) { crate::arch::x86_64::serial::write_str(s); }
fn log_dec(v: u64) { crate::arch::x86_64::init::serial_dec(v); }

// ─── uncached mapping window ──────────────────────────────────────────────────────────

const UC_BASE: u64 = 0xFFFF_FF48_0000_0000;
const UC_LIMIT: u64 = UC_BASE + (256 << 20);
static UC_NEXT: AtomicU64 = AtomicU64::new(UC_BASE);

/// Map `size` bytes of device memory at physical `phys` uncached; returns the virtual address.
/// The mapping is never released (a few pages per device).
pub fn map_uc(phys: u64, size: u64) -> Option<u64> {
    use crate::mm::r#virtual as vmm;
    let off = phys & 0xFFF;
    let pages = (off + size.max(1) + 0xFFF) / 0x1000;
    let start = UC_NEXT.fetch_add(pages * 0x1000, Ordering::Relaxed);
    if start + pages * 0x1000 > UC_LIMIT { return None; }
    for p in 0..pages {
        if !vmm::map_page_current(
            start + p * 0x1000,
            (phys & !0xFFF) + p * 0x1000,
            vmm::FLAG_WRITABLE | vmm::FLAG_PCD | vmm::FLAG_PWT | vmm::FLAG_NX,
        ) {
            return None;
        }
    }
    Some(start + off)
}

// ─── I/O APIC ────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct IoApic {
    base: u64, // virtual
    gsi_base: u32,
    entries: u32,
}
static mut IOAPICS: [IoApic; crate::acpi::MADT_MAX_IOAPICS] =
    [IoApic { base: 0, gsi_base: 0, entries: 0 }; crate::acpi::MADT_MAX_IOAPICS];
static mut IOAPIC_N: usize = 0;

fn ioapics() -> &'static [IoApic] {
    // SAFETY: written once in init, before IOAPIC_ACTIVE is set.
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(IOAPICS) as *const IoApic, IOAPIC_N) }
}

unsafe fn io_read(a: &IoApic, reg: u32) -> u32 {
    core::ptr::write_volatile(a.base as *mut u32, reg);
    core::ptr::read_volatile((a.base + 0x10) as *const u32)
}
unsafe fn io_write(a: &IoApic, reg: u32, v: u32) {
    core::ptr::write_volatile(a.base as *mut u32, reg);
    core::ptr::write_volatile((a.base + 0x10) as *mut u32, v);
}

fn find_ioapic(gsi: u32) -> Option<(&'static IoApic, u32)> {
    ioapics().iter().find(|a| gsi >= a.gsi_base && gsi < a.gsi_base + a.entries).map(|a| (a, gsi - a.gsi_base))
}

static IOAPIC_LOCK: IrqSpinLock<()> = IrqSpinLock::new("IOAPIC", rank::DEV, ());

const ENT_MASK: u32 = 1 << 16;
const ENT_LEVEL: u32 = 1 << 15;
const ENT_LOW: u32 = 1 << 13;

fn program_entry(gsi: u32, vector: u8, trig: Trigger, pol: Polarity, masked: bool) -> bool {
    let (a, pin) = match find_ioapic(gsi) { Some(x) => x, None => return false };
    let mut lo = vector as u32;
    if trig == Trigger::Level { lo |= ENT_LEVEL; }
    if pol == Polarity::Low { lo |= ENT_LOW; }
    if masked { lo |= ENT_MASK; }
    let hi = (crate::arch::x86_64::apic::id() as u32) << 24;
    let _g = IOAPIC_LOCK.lock();
    // SAFETY: MMIO of a mapped I/O APIC.
    unsafe {
        io_write(a, 0x10 + pin * 2, lo | ENT_MASK); // mask while changing the high word
        io_write(a, 0x11 + pin * 2, hi);
        io_write(a, 0x10 + pin * 2, lo);
    }
    true
}

fn set_masked(gsi: u32, masked: bool) {
    if let Some((a, pin)) = find_ioapic(gsi) {
        let _g = IOAPIC_LOCK.lock();
        // SAFETY: MMIO of a mapped I/O APIC.
        unsafe {
            let lo = io_read(a, 0x10 + pin * 2);
            io_write(a, 0x10 + pin * 2, if masked { lo | ENT_MASK } else { lo & !ENT_MASK });
        }
    }
}

/// ISA IRQ -> (GSI, trigger, polarity) using the MADT source overrides.
fn isa_route(irq: u8) -> (u32, Trigger, Polarity) {
    if let Some(m) = crate::acpi::madt() {
        for i in 0..m.override_count {
            let o = m.overrides[i];
            if o.bus == 0 && o.source == irq {
                let pol = if o.flags & 3 == 3 { Polarity::Low } else { Polarity::High };
                let trig = if (o.flags >> 2) & 3 == 3 { Trigger::Level } else { Trigger::Edge };
                return (o.gsi, trig, pol);
            }
        }
    }
    (irq as u32, Trigger::Edge, Polarity::High)
}

const LEGACY_NAMES: [&str; 16] = [
    "timer (PIT)", "keyboard (i8042)", "cascade", "COM2", "COM1", "irq5", "floppy", "irq7",
    "RTC", "ACPI SCI / PCI", "PCI", "PCI", "mouse (i8042)", "FPU", "ATA primary", "ATA secondary",
];

// ─── legacy line API (used through pic.rs) ───────────────────────────────────────────

/// Unmask ISA IRQ `irq` in the I/O APIC (vector 0x20 + irq). Only valid in I/O APIC mode.
pub fn legacy_unmask(irq: u8) {
    if irq >= 16 { return; }
    let (gsi, trig, pol) = isa_route(irq);
    let v = VEC_LEGACY_BASE + irq;
    {
        let mut m = META.lock();
        if m[v as usize].kind == Kind::Free {
            m[v as usize] = Meta { kind: Kind::Legacy, name: LEGACY_NAMES[irq as usize], src: gsi, group: v };
        }
    }
    program_entry(gsi, v, trig, pol, false);
}

pub fn legacy_mask(irq: u8) {
    if irq >= 16 { return; }
    set_masked(isa_route(irq).0, true);
}

/// End of interrupt for the I/O APIC / MSI path.
#[inline(always)]
pub fn eoi() { crate::arch::x86_64::apic::send_eoi(); }

// ─── handler registry ───────────────────────────────────────────────────────────────

/// Add a handler to `vector` (up to four may share one). Returns false when full.
pub fn register(vector: u8, name: &'static str, handler: Handler, ctx: usize) -> bool {
    {
        let mut m = META.lock();
        let e = &mut m[vector as usize];
        if e.kind == Kind::Free {
            *e = Meta { kind: Kind::Gsi, name, src: 0, group: vector };
        } else if e.name.is_empty() {
            e.name = name;
        }
    }
    for i in 0..HANDLERS_PER_VECTOR {
        if HANDLERS[vector as usize][i]
            .compare_exchange(0, handler as usize, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            CONTEXTS[vector as usize][i].store(ctx, Ordering::Release);
            return true;
        }
    }
    false
}

/// Remove every handler of `vector` that was registered with `ctx`.
pub fn unregister(vector: u8, ctx: usize) {
    for i in 0..HANDLERS_PER_VECTOR {
        if CONTEXTS[vector as usize][i].load(Ordering::Acquire) == ctx {
            HANDLERS[vector as usize][i].store(0, Ordering::Release);
        }
    }
}

fn has_handlers(vector: u8) -> bool {
    HANDLERS[vector as usize].iter().any(|h| h.load(Ordering::Acquire) != 0)
}

/// Run the handlers of `vector` and count the interrupt. Returns false if none is registered.
pub fn dispatch(vector: u8) -> bool {
    COUNTS[vector as usize].fetch_add(1, Ordering::Relaxed);
    let mut any = false;
    for i in 0..HANDLERS_PER_VECTOR {
        let h = HANDLERS[vector as usize][i].load(Ordering::Acquire);
        if h != 0 {
            any = true;
            let ctx = CONTEXTS[vector as usize][i].load(Ordering::Acquire);
            // SAFETY: only `register` stores here, always a valid `Handler`.
            let f: Handler = unsafe { core::mem::transmute(h) };
            f(vector, ctx);
        }
    }
    any
}

/// Called for generic vectors from the assembly stub.
pub fn dispatch_generic(vector: u8) {
    if !dispatch(vector) {
        // Nobody wants it: a level-triggered pin would storm, so silence the GSI.
        let m = META.lock();
        if m[vector as usize].kind == Kind::Gsi || m[vector as usize].kind == Kind::Legacy {
            let gsi = m[vector as usize].src;
            drop(m);
            set_masked(gsi, true);
        }
    }
}

pub fn count_timer() { COUNTS[48].fetch_add(1, Ordering::Relaxed); }

fn alloc_vectors(count: usize, align: usize) -> Option<u8> {
    let mut m = META.lock();
    let mut v = VEC_DYN_FIRST as usize;
    while v + count - 1 <= VEC_DYN_LAST as usize {
        if v % align == 0 && (0..count).all(|i| m[v + i].kind == Kind::Free) {
            for i in 0..count {
                m[v + i] = Meta { kind: Kind::Gsi, name: "", src: 0, group: v as u8 };
            }
            return Some(v as u8);
        }
        v += 1;
    }
    None
}

fn free_vector_meta(v: u8) {
    META.lock()[v as usize] = Meta::EMPTY;
    for i in 0..HANDLERS_PER_VECTOR {
        HANDLERS[v as usize][i].store(0, Ordering::Release);
    }
}

// ─── GSI routing ──────────────────────────────────────────────────────────────────

/// Route global system interrupt `gsi` to a vector, masked. Returns the vector. A GSI
/// routed twice returns the same vector (shared INTx). GSIs below 16 use the fixed
/// vector 0x20 + gsi. Needs I/O APIC mode.
pub fn route_gsi(gsi: u32, trig: Trigger, pol: Polarity) -> Option<u8> {
    if !ioapic_active() || find_ioapic(gsi).is_none() { return None; }
    if gsi < 256 {
        let cur = GSI_VECTOR[gsi as usize].load(Ordering::Relaxed);
        if cur != 0 { return Some(cur); }
    }
    let vector = if gsi < 16 {
        VEC_LEGACY_BASE + gsi as u8
    } else {
        alloc_vectors(1, 1)?
    };
    {
        let mut m = META.lock();
        m[vector as usize] = Meta { kind: Kind::Gsi, name: m[vector as usize].name, src: gsi, group: vector };
        if m[vector as usize].name.is_empty() {
            m[vector as usize].name = "PCI INTx";
        }
    }
    if !program_entry(gsi, vector, trig, pol, true) { return None; }
    if gsi < 256 { GSI_VECTOR[gsi as usize].store(vector, Ordering::Relaxed); }
    Some(vector)
}

pub fn unmask_gsi(gsi: u32) { set_masked(gsi, false); }
pub fn mask_gsi(gsi: u32) { set_masked(gsi, true); }

/// GSI a PCI function's INTx pin arrives on (see the module comment for the limitation).
pub fn pci_intx_gsi(bus: u8, dev: u8, func: u8) -> Option<(u32, Trigger, Polarity)> {
    let pin = crate::pci::interrupt_pin(bus, dev, func);
    if pin == 0 || pin > 4 { return None; }
    if bus == 0 {
        if let Some((g, f)) = crate::acpi::prt_lookup(dev, pin - 1) {
            let trig = if f & 1 != 0 { Trigger::Edge } else { Trigger::Level };
            let pol = if f & 2 != 0 { Polarity::Low } else { Polarity::High };
            return Some((g, trig, pol));
        }
    }
    let line = crate::pci::interrupt_line(bus, dev, func);
    if line == 0 || line == 0xFF { return None; }
    // The line register holds a PIC IRQ: use the ISA wiring (with its override flags if any).
    let (gsi, trig, pol) = isa_route(line);
    let has_override = crate::acpi::madt().map_or(false, |m| {
        (0..m.override_count).any(|i| m.overrides[i].bus == 0 && m.overrides[i].source == line)
    });
    if has_override { Some((gsi, trig, pol)) } else { Some((gsi, Trigger::Level, Polarity::Low)) }
}

/// Attach `handler` to the INTx interrupt of a PCI function. Uses the I/O APIC (level,
/// active low) or, without one, the PIC line. Returns the vector.
pub fn attach_pci_intx(bus: u8, dev: u8, func: u8, name: &'static str, handler: Handler, ctx: usize) -> Option<u8> {
    if crate::pci::interrupt_pin(bus, dev, func) == 0 { return None; }
    if !ioapic_active() {
        let line = crate::pci::interrupt_line(bus, dev, func);
        if line == 0 || line >= 16 { return None; }
        register(VEC_LEGACY_BASE + line, name, handler, ctx);
        crate::arch::x86_64::pic::enable_irq(line);
        return Some(VEC_LEGACY_BASE + line);
    }
    let (gsi, trig, pol) = pci_intx_gsi(bus, dev, func)?;
    let v = route_gsi(gsi, trig, pol)?;
    register(v, name, handler, ctx);
    unmask_gsi(gsi);
    Some(v)
}

// ─── MSI / MSI-X ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct MsiAlloc {
    pub vector: u8,
    pub count: u8,
    pub msix: bool,
}

fn bdf(bus: u8, dev: u8, func: u8) -> u32 { ((bus as u32) << 8) | ((dev as u32) << 3) | func as u32 }

fn msi_address() -> u32 { 0xFEE0_0000 | ((crate::arch::x86_64::apic::id() as u32) << 12) }

/// Does this function offer MSI or MSI-X, and is one of them already enabled?
pub fn msi_state(bus: u8, dev: u8, func: u8) -> (bool, bool, bool) {
    use crate::pci::*;
    let msix = find_capability(bus, dev, func, CAP_MSIX);
    let msi = find_capability(bus, dev, func, CAP_MSI);
    let enabled = msix.map_or(false, |c| config_read16(bus, dev, func, c + 2) & 0x8000 != 0)
        || msi.map_or(false, |c| config_read16(bus, dev, func, c + 2) & 1 != 0);
    (msix.is_some(), msi.is_some(), enabled)
}

/// Allocate `count` consecutive vectors for a PCI function and enable MSI-X (preferred) or
/// MSI on it. Handlers are attached with `register`. Fails if the function has neither
/// capability, if one is already enabled (another driver owns it) or if no vectors are left.
pub fn alloc_msi(bus: u8, dev: u8, func: u8, count: u8) -> Option<MsiAlloc> {
    use crate::pci::*;
    if count == 0 || count > 32 { return None; }
    let (has_x, has_m, enabled) = msi_state(bus, dev, func);
    if enabled { return None; }
    let src = bdf(bus, dev, func);

    if has_x {
        let cap = find_capability(bus, dev, func, CAP_MSIX)?;
        let ctrl = config_read16(bus, dev, func, cap + 2);
        let table_size = (ctrl & 0x7FF) as u32 + 1;
        if count as u32 > table_size { return None; }
        let tbl = config_read32(bus, dev, func, cap + 4);
        let bar = (tbl & 7) as u8;
        let off = (tbl & !7) as u64;
        let base = match read_bar(bus, dev, func, bar) { BarType::Mmio { base, .. } => base, _ => return None };
        let virt = map_uc(base + off, table_size as u64 * 16)?;
        let first = alloc_vectors(count as usize, 1)?;
        // Function mask + enable while the table is written.
        config_write16(bus, dev, func, cap + 2, (ctrl | 0xC000) & !0);
        let addr = msi_address();
        for i in 0..table_size.min(64) {
            let e = (virt + i as u64 * 16) as *mut u32;
            // SAFETY: the MSI-X table is mapped uncached just above.
            unsafe {
                if i < count as u32 {
                    core::ptr::write_volatile(e, addr);
                    core::ptr::write_volatile(e.add(1), 0);
                    core::ptr::write_volatile(e.add(2), (first as u32) + i);
                    core::ptr::write_volatile(e.add(3), 0); // unmasked
                } else {
                    core::ptr::write_volatile(e.add(3), 1); // masked
                }
            }
        }
        let mut m = META.lock();
        for i in 0..count as usize {
            m[first as usize + i] = Meta { kind: Kind::MsiX, name: "MSI-X", src, group: first };
        }
        drop(m);
        // Enable, clear the function mask; stop the INTx pin.
        config_write16(bus, dev, func, cap + 2, (ctrl | 0x8000) & !0x4000);
        set_command(bus, dev, func, command(bus, dev, func) | 0x0400);
        return Some(MsiAlloc { vector: first, count, msix: true });
    }

    if has_m {
        let cap = find_capability(bus, dev, func, CAP_MSI)?;
        let ctrl = config_read16(bus, dev, func, cap + 2);
        let mmc = ((ctrl >> 1) & 7) as u32; // log2 of vectors the device can use
        let mut n = 1u32;
        let mut log = 0u32;
        while n < count as u32 { n <<= 1; log += 1; }
        if log > mmc { return None; }
        let first = alloc_vectors(n as usize, n as usize)?;
        let addr = msi_address();
        config_write32(bus, dev, func, cap + 4, addr);
        let data_off = if ctrl & 0x80 != 0 {
            config_write32(bus, dev, func, cap + 8, 0);
            cap + 12
        } else {
            cap + 8
        };
        config_write16(bus, dev, func, data_off, first as u16);
        let mut m = META.lock();
        for i in 0..n as usize {
            m[first as usize + i] = Meta { kind: Kind::Msi, name: "MSI", src, group: first };
        }
        drop(m);
        let newctrl = (ctrl & !0x70) | ((log as u16) << 4) | 1;
        config_write16(bus, dev, func, cap + 2, newctrl);
        set_command(bus, dev, func, command(bus, dev, func) | 0x0400);
        return Some(MsiAlloc { vector: first, count: n as u8, msix: false });
    }
    None
}

/// Give one MSI/MSI-X vector back. When the last vector of its block is gone the function's
/// MSI capability is disabled.
pub fn free_msi_vector(vector: u8) {
    use crate::pci::*;
    let (kind, src, group) = {
        let m = META.lock();
        let e = m[vector as usize];
        (e.kind, e.src, e.group)
    };
    if kind != Kind::Msi && kind != Kind::MsiX { return; }
    free_vector_meta(vector);
    let still = {
        let m = META.lock();
        (0..256usize).any(|i| m[i].group == group && (m[i].kind == Kind::Msi || m[i].kind == Kind::MsiX) && i as u8 != vector)
    };
    if still { return; }
    let (b, d, f) = ((src >> 8) as u8, ((src >> 3) & 31) as u8, (src & 7) as u8);
    let cap = if kind == Kind::MsiX { find_capability(b, d, f, CAP_MSIX) } else { find_capability(b, d, f, CAP_MSI) };
    if let Some(c) = cap {
        let ctrl = config_read16(b, d, f, c + 2);
        config_write16(b, d, f, c + 2, if kind == Kind::MsiX { ctrl & !0x8000 } else { ctrl & !1 });
    }
}

// ─── initialisation ─────────────────────────────────────────────────────────────────

unsafe fn inb(p: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", in("dx") p, out("al") v, options(nomem, nostack));
    v
}
unsafe fn outb(p: u16, v: u8) {
    core::arch::asm!("out dx, al", in("dx") p, in("al") v, options(nomem, nostack));
}

/// Switch from the 8259 PIC to the I/O APIC. Call after ACPI, with the heap and paging up.
/// Keeps the PIC if there is no MADT, no I/O APIC or no local APIC.
pub fn init() {
    let m = match crate::acpi::madt() {
        Some(m) => m,
        None => { log("[IRQ] No MADT: staying on the 8259 PIC\r\n"); return; }
    };
    if m.ioapic_count == 0 {
        log("[IRQ] MADT lists no I/O APIC: staying on the 8259 PIC\r\n");
        return;
    }
    if !crate::arch::x86_64::apic::is_present() {
        log("[IRQ] Local APIC not usable: staying on the 8259 PIC\r\n");
        return;
    }
    // Make sure the PML4 slot of the uncached window exists before user address spaces copy it.
    for i in 0..m.ioapic_count {
        let io = m.ioapics[i];
        let virt = match map_uc(io.addr as u64, 0x20) {
            Some(v) => v,
            None => { log("[IRQ] Cannot map an I/O APIC: staying on the PIC\r\n"); return; }
        };
        let mut a = IoApic { base: virt, gsi_base: io.gsi_base, entries: 0 };
        // SAFETY: freshly mapped I/O APIC registers.
        let ver = unsafe { io_read(&a, 1) };
        a.entries = ((ver >> 16) & 0xFF) + 1;
        for pin in 0..a.entries {
            unsafe {
                io_write(&a, 0x10 + pin * 2, ENT_MASK);
                io_write(&a, 0x11 + pin * 2, 0);
            }
        }
        log("[IRQ] IOAPIC ");
        log_dec(io.id as u64);
        log(": GSI ");
        log_dec(a.gsi_base as u64);
        log("-");
        log_dec((a.gsi_base + a.entries - 1) as u64);
        log(", version 0x");
        crate::arch::x86_64::init::serial_hex(ver as u64 & 0xFF);
        log("\r\n");
        // SAFETY: single boot CPU, before the table is published.
        unsafe {
            (*core::ptr::addr_of_mut!(IOAPICS))[IOAPIC_N] = a;
            IOAPIC_N += 1;
        }
    }

    // NMI wiring from the MADT.
    for i in 0..m.nmi_count {
        let n = m.nmis[i];
        if n.cpu == 0xFFFF_FFFF {
            if let Some((a, pin)) = find_ioapic(n.gsi) {
                let mut lo = 0x400u32;
                if n.flags & 3 == 3 { lo |= ENT_LOW; }
                if (n.flags >> 2) & 3 == 3 { lo |= ENT_LEVEL; }
                unsafe { io_write(a, 0x10 + pin * 2, lo); }
            }
        } else if n.cpu == 0xFF || n.cpu == 0 {
            crate::arch::x86_64::apic::set_lint_nmi(n.lint, n.flags);
        }
    }

    // Move every line that is unmasked in the PIC over to the I/O APIC, then silence the PIC.
    let flags = crate::core::sync::irq_save();
    let pic_mask = unsafe { (inb(0xA1) as u16) << 8 | inb(0x21) as u16 };
    IOAPIC_ACTIVE.store(true, Ordering::SeqCst);
    for irq in 0..16u8 {
        if irq == 2 || pic_mask & (1 << irq) != 0 { continue; }
        legacy_unmask(irq);
    }
    unsafe { outb(0x21, 0xFF); outb(0xA1, 0xFF); }
    crate::core::sync::irq_restore(flags);
    log("[IRQ] I/O APIC mode: 8259 PIC masked, ISA IRQ n on vector 0x20+n\r\n");

    // Does the PIT still tick through the I/O APIC (it can be wired to GSI 2 or not at all)?
    let t0 = crate::arch::x86_64::idt::timer_ticks();
    crate::arch::x86_64::tsc::busy_wait_us(60_000);
    let t1 = crate::arch::x86_64::idt::timer_ticks();
    let pit_ok = t1.wrapping_sub(t0) >= 2;
    if !pit_ok {
        log("[IRQ] PIT ticks do not arrive through the I/O APIC; the local APIC timer takes over\r\n");
    }
    // The local APIC timer is the tick source from now on (periodic, 1 kHz, 10 ticks = 100 Hz).
    if crate::arch::x86_64::apic::start_periodic_us(1000) {
        crate::arch::x86_64::idt::PIT_ALIVE.store(false, Ordering::SeqCst);
        legacy_mask(0);
        log("[IRQ] Tick source: local APIC timer, periodic 1 kHz (PIT masked)\r\n");
    } else if !pit_ok {
        crate::arch::x86_64::idt::PIT_ALIVE.store(false, Ordering::SeqCst);
    }
}

// ─── irqstat ────────────────────────────────────────────────────────────────────────

/// Table for `irqstat` and /proc/interrupts.
pub fn stat_text() -> String {
    let mut s = String::new();
    s.push_str(&format!("mode: {}\n", if ioapic_active() { "I/O APIC" } else { "8259 PIC" }));
    s.push_str("VEC  SOURCE        CPU  COUNT       NAME\n");
    {
        let m = META.lock();
        for v in 32..256usize {
            let timer = v == 48;
            let e = m[v];
            let count = COUNTS[v].load(Ordering::Relaxed);
            if e.kind == Kind::Free && !timer && count == 0 { continue; }
            let (src, name): (String, &str) = if timer {
                (String::from("LAPIC"), "local APIC timer")
            } else {
                match e.kind {
                    _ if !ioapic_active() && v < 48 => (
                        format!("IRQ {}", v - 32),
                        if e.name.is_empty() { LEGACY_NAMES[v - 32] } else { e.name },
                    ),
                    Kind::Free => (String::from("-"), "-"),
                    Kind::Legacy | Kind::Gsi => (format!("GSI {}", e.src), if e.name.is_empty() { "-" } else { e.name }),
                    Kind::Msi | Kind::MsiX => (
                        format!("{} {:02x}:{:02x}.{}", if e.kind == Kind::Msi { "MSI" } else { "MSIX" },
                            e.src >> 8, (e.src >> 3) & 31, e.src & 7),
                        e.name,
                    ),
                    _ => (String::from("-"), if e.name.is_empty() { "-" } else { e.name }),
                }
            };
            s.push_str(&format!("{:#04x} {:<13} {:<4} {:<11} {}\n", v, src, 0, count, name));
        }
    }
    s
}

// ─── generic vector stubs ───────────────────────────────────────────────────────────

core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global irq_stubs_start
irq_stubs_start:
    .set stub_vec, 64
    .rept 176
    .p2align 4
    push stub_vec
    jmp {common}
    .set stub_vec, stub_vec + 1
    .endr
    "#,
    common = sym irq_common,
);

unsafe extern "C" {
    fn irq_stubs_start();
}

/// Address of the generic stub for vector `v` (0x40..=0xEF).
pub fn stub_address(v: u8) -> u64 {
    irq_stubs_start as usize as u64 + 16 * (v as u64 - VEC_DYN_FIRST as u64)
}

#[unsafe(naked)]
pub extern "C" fn irq_common() {
    core::arch::naked_asm!(
        // The stub pushed the vector where a CPU error code would be.
        "test qword ptr [rsp + 16], 3",
        "jz 7f",
        "swapgs",
        "7:",
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rbp, rsp",
        "mov rax, [rip + {xsz}]",
        "sub rsp, rax",
        "and rsp, -64",
        "cmp byte ptr [rip + {xen}], 0",
        "je 5f",
        "mov qword ptr [rsp + 512], 0",
        "mov qword ptr [rsp + 520], 0",
        "mov qword ptr [rsp + 528], 0",
        "mov qword ptr [rsp + 536], 0",
        "mov qword ptr [rsp + 544], 0",
        "mov qword ptr [rsp + 552], 0",
        "mov qword ptr [rsp + 560], 0",
        "mov qword ptr [rsp + 568], 0",
        "mov eax, [rip + {xlo}]",
        "mov edx, [rip + {xhi}]",
        "xsave [rsp]",
        "jmp 6f",
        "5:",
        "fxsave [rsp]",
        "6:",
        "movzx esi, byte ptr [rbp + 120]",
        "call {disp}",
        "cmp byte ptr [rip + {xen}], 0",
        "je 3f",
        "mov eax, [rip + {xlo}]",
        "mov edx, [rip + {xhi}]",
        "xrstor [rsp]",
        "jmp 4f",
        "3:",
        "fxrstor [rsp]",
        "4:",
        "mov rsp, rbp",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "add rsp, 8",
        "test qword ptr [rsp + 8], 3",
        "jz 8f",
        "swapgs",
        "8:",
        "iretq",
        disp = sym generic_dispatch,
        xsz = sym crate::arch::x86_64::init::XSAVE_AREA_SIZE,
        xen = sym crate::arch::x86_64::init::XSAVE_ENABLED,
        xlo = sym crate::arch::x86_64::init::XSAVE_MASK_LO,
        xhi = sym crate::arch::x86_64::init::XSAVE_MASK_HI,
    );
}

extern "C" fn generic_dispatch(_unused: u64, vector: u64) {
    dispatch_generic(vector as u8);
    eoi();
}

/// Spurious interrupt vector: no EOI, just return.
#[unsafe(naked)]
pub extern "C" fn spurious_isr() {
    core::arch::naked_asm!("iretq");
}

/// Install the generic stubs and the spurious handler into the IDT.
pub fn install(set: &mut dyn FnMut(usize, u64)) {
    for v in VEC_DYN_FIRST..=VEC_DYN_LAST {
        set(v as usize, stub_address(v));
    }
    set(VEC_SPURIOUS as usize, spurious_isr as usize as u64);
}

/// Count an interrupt that was consumed before the registry (ring-3 owned legacy line).
pub fn count_legacy(vector: u8) { COUNTS[vector as usize].fetch_add(1, Ordering::Relaxed); }

/// Remove the handlers registered with `ctx` from `vector` and, if nothing is left on it,
/// mask its I/O APIC pin (or PIC line).
pub fn detach(vector: u8, ctx: usize) {
    unregister(vector, ctx);
    if has_handlers(vector) { return; }
    let (kind, src) = {
        let m = META.lock();
        (m[vector as usize].kind, m[vector as usize].src)
    };
    if ioapic_active() {
        if kind == Kind::Gsi || kind == Kind::Legacy { set_masked(src, true); }
    } else if (32..48).contains(&vector) {
        crate::arch::x86_64::pic::disable_irq(vector - 32);
    }
}

// ─── per-device convenience for kernel drivers ───────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode { None, Intx, Msi, MsiX }

impl Mode {
    pub fn name(self) -> &'static str {
        match self { Mode::None => "polling", Mode::Intx => "INTx", Mode::Msi => "MSI", Mode::MsiX => "MSI-X" }
    }
}

/// (packed bdf, vector, ctx) of INTx attachments made by `setup_device_irq`.
static INTX_USERS: IrqSpinLock<[(u16, u8); 16]> = IrqSpinLock::new("IRQX", rank::DEV, [(0xFFFF, 0); 16]);

/// Give a kernel driver an interrupt: MSI-X, else MSI, else INTx. `handler` runs with the
/// vector and `ctx = bdf`. In 8259 mode only INTx on the interrupt line is possible.
pub fn setup_device_irq(bus: u8, dev: u8, func: u8, name: &'static str, handler: Handler) -> Mode {
    let id = bdf(bus, dev, func);
    if ioapic_active() {
        if let Some(a) = alloc_msi(bus, dev, func, 1) {
            register(a.vector, name, handler, id as usize);
            {
                let mut m = META.lock();
                m[a.vector as usize].name = name;
            }
            return if a.msix { Mode::MsiX } else { Mode::Msi };
        }
    }
    setup_device_intx(bus, dev, func, name, handler)
}

/// INTx only (for devices whose MSI setup failed).
pub fn setup_device_intx(bus: u8, dev: u8, func: u8, name: &'static str, handler: Handler) -> Mode {
    let id = bdf(bus, dev, func);
    match attach_pci_intx(bus, dev, func, name, handler, id as usize) {
        Some(v) => {
            let mut t = INTX_USERS.lock();
            if let Some(s) = t.iter_mut().find(|s| s.0 == 0xFFFF) { *s = (id as u16, v); }
            Mode::Intx
        }
        None => Mode::None,
    }
}

/// Undo `setup_device_irq`: disable MSI/MSI-X and free its vectors, detach INTx.
pub fn release_device(bus: u8, dev: u8, func: u8) {
    let id = bdf(bus, dev, func);
    for v in VEC_DYN_FIRST..=VEC_DYN_LAST {
        let (k, src) = { let m = META.lock(); (m[v as usize].kind, m[v as usize].src) };
        if (k == Kind::Msi || k == Kind::MsiX) && src == id {
            free_msi_vector(v);
        }
    }
    let mut hit = [0u8; 16];
    let mut n = 0;
    {
        let mut t = INTX_USERS.lock();
        for s in t.iter_mut() {
            if s.0 as u32 == id { hit[n] = s.1; n += 1; *s = (0xFFFF, 0); }
        }
    }
    for v in &hit[..n] { detach(*v, id as usize); }
}

/// Like `legacy_unmask`, but an ISA line without a MADT override is programmed level-triggered
/// (active high). For lines owned by a ring-3 driver: the line is masked while the driver
/// works, and an event that arrives while it is masked must not be lost (an edge-triggered
/// I/O APIC pin does not latch it, the 8259 did).
pub fn legacy_unmask_level(irq: u8) {
    if irq >= 16 { return; }
    let (gsi, mut trig, pol) = isa_route(irq);
    let has_override = crate::acpi::madt().map_or(false, |m| {
        (0..m.override_count).any(|i| m.overrides[i].bus == 0 && m.overrides[i].source == irq)
    });
    if !has_override { trig = Trigger::Level; }
    let v = VEC_LEGACY_BASE + irq;
    {
        let mut m = META.lock();
        if m[v as usize].kind == Kind::Free {
            m[v as usize] = Meta { kind: Kind::Legacy, name: LEGACY_NAMES[irq as usize], src: gsi, group: v };
        }
    }
    program_entry(gsi, v, trig, pol, false);
}

/// Program the pin of ISA IRQ `irq` as level-triggered and masked (see `legacy_unmask_level`).
pub fn legacy_prepare_level(irq: u8) {
    if irq >= 16 { return; }
    let (gsi, mut trig, pol) = isa_route(irq);
    let has_override = crate::acpi::madt().map_or(false, |m| {
        (0..m.override_count).any(|i| m.overrides[i].bus == 0 && m.overrides[i].source == irq)
    });
    if !has_override { trig = Trigger::Level; }
    program_entry(gsi, VEC_LEGACY_BASE + irq, trig, pol, true);
}
