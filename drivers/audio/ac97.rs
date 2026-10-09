/*
 * AC97 Audio Controller Driver — AETERNA Microkernel
 *
 * Supports:
 *   Intel 82801AA AC'97 — PCI 8086:2415 (QEMU default AC97 device)
 *   Intel 82801AB AC'97 — PCI 8086:2425
 *   Intel 82801BA AC'97 — PCI 8086:2445
 *   VIA VT82C686A      — PCI 1106:3058
 *   Generic: PCI class 0x04 / subclass 0x01 (Audio)
 *
 * Architecture:
 *   NAM  (Native Audio Mixer)      — I/O BAR0  — codec registers (volume, rate)
 *   NABM (Native Audio Bus Master) — I/O BAR1  — DMA engine registers
 *
 * DMA pipeline:
 *   write_pcm()  →  PCM ring buffer (32 × 4 KiB = 128 KiB)
 *              →  BDL (Buffer Descriptor List, 32 entries)
 *              →  NABM PCM-Out channel DMA
 *              →  AC97 codec DAC → speaker
 *
 * Buffer management:
 *   • BDL has 32 entries, each pointing to a 4096-byte physical page.
 *   • All pages are allocated from the kernel physical frame allocator.
 *   • FILL_IDX  = next entry the CPU should write audio data into.
 *   • LVI       = last entry the hardware is allowed to play.
 *   • CIV       = hardware's current playing entry (read-only hardware register).
 *   • On each IOC interrupt → advance LVI, signal BUFFER_DONE for write path.
 *
 * Sample rate:
 *   44100 Hz via Variable Rate Audio (VRA) — falls back to 48000 Hz if VRA absent.
 *
 * IRQ:
 *   PCI interrupt line (typically IRQ 5 on QEMU). Registered in idt::irq_dispatch().
 */

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use core::ptr::{read_volatile, write_volatile};
use core::arch::asm;

use crate::arch::x86_64::serial;
use crate::mm::physical;
use crate::mm::r#virtual::phys_to_virt;

// ─── PCI identities ──────────────────────────────────────────────────────────

const PCI_VID_INTEL: u16 = 0x8086;
const PCI_DID_ICH_AC97:  u16 = 0x2415; // 82801AA  (QEMU default)
const PCI_DID_ICH_AC97B: u16 = 0x2425; // 82801AB
const PCI_DID_ICH2_AC97: u16 = 0x2445; // 82801BA
// VIA VT82C686A/B AC97 controller
const PCI_VID_VIA:       u16 = 0x1106;
const PCI_DID_VIA_AC97:  u16 = 0x3058;
// NOTE: Ensoniq ES1371 (1274:1371) is handled by the es1371 driver, NOT here.
// We deliberately omit the generic class/subclass fallback scan to avoid
// grabbing ES1371 and other AudioPCI chips that have different BARs.

// ─── NAM Registers (16-bit R/W at NAM_BASE + offset) ────────────────────────

const NAM_RESET:          u16 = 0x00; // soft reset — write any value
const NAM_MASTER_VOL:     u16 = 0x02; // master volume  [5:0]=dB gain, [15]=mute
const NAM_HEADPHONE_VOL:  u16 = 0x04; // headphone volume
const NAM_MONO_VOL:       u16 = 0x06; // mono out volume
const NAM_PCM_VOL:        u16 = 0x18; // PCM-out volume [4:0]=right, [12:8]=left, [15]=mute
const NAM_EXT_AUDIO_ID:   u16 = 0x28; // Extended Audio ID (read-only capability mask)
const NAM_EXT_AUDIO_CTRL: u16 = 0x2A; // Extended Audio Status/Control
const NAM_PCM_FRONT_RATE: u16 = 0x2C; // PCM front DAC sample rate (44100 / 48000)
const NAM_PCM_LR_ADC_RATE:u16 = 0x32; // PCM L/R ADC sample rate
const NAM_VENDOR_ID1:     u16 = 0x7C; // codec vendor, char [3..0] of ASCII IDs
const NAM_VENDOR_ID2:     u16 = 0x7E; // codec vendor continuation

// Volume control: mute bit
const VOL_MUTE: u16 = 1 << 15;

// Extended Audio ID capability bits
const EXT_ID_VRA:  u16 = 1 << 0;  // Variable Rate Audio
const EXT_ID_DRA:  u16 = 1 << 1;  // Double Rate Audio
const EXT_ID_SPDIF:u16 = 1 << 2;  // S/PDIF
const EXT_ID_VRM:  u16 = 1 << 3;  // Variable Rate Mic

// Extended Audio Control: VRA enable
const EXT_CTRL_VRA: u16 = 1 << 0;

// ─── NABM Registers (PCM-OUT channel at NABM_BASE + 0x10) ───────────────────

// PCM Output channel is at NABM offset 0x10
const PCO_BASE:   u8  = 0x10;

// These are at NABM_BASE + PCO_BASE + sub-offset:
const PCO_OFF_BDBAR: u8 = 0x00; // 32-bit  Buffer Descriptor Base Address Register
const PCO_OFF_CIV:   u8 = 0x04; // 8-bit   Current Index Value (hardware read-only)
const PCO_OFF_LVI:   u8 = 0x05; // 8-bit   Last Valid Index (CPU sets this)
const PCO_OFF_SR:    u8 = 0x06; // 16-bit  Status Register
const PCO_OFF_PICB:  u8 = 0x08; // 16-bit  Position in Current Buffer (samples remaining)
const PCO_OFF_PIV:   u8 = 0x0A; // 8-bit   Prefetched Index Value
const PCO_OFF_CR:    u8 = 0x0B; // 8-bit   Control Register

// Status Register (PCO_SR) bits
const SR_DCH:   u16 = 1 << 0; // DMA Controller Halted
const SR_CELV:  u16 = 1 << 1; // Current Equals Last Valid
const SR_LVBCI: u16 = 1 << 2; // Last Valid Buffer Completion Interrupt (W1C)
const SR_BCIS:  u16 = 1 << 3; // Buffer Completion Interrupt Status     (W1C)
const SR_FIFOE: u16 = 1 << 4; // FIFO Error Interrupt                   (W1C)

// Control Register (PCO_CR) bits
const CR_RPBM:   u8 = 1 << 0; // Run/Pause Bus Master
const CR_RR:     u8 = 1 << 1; // Reset Registers
const CR_LVBIE:  u8 = 1 << 2; // Last Valid Buffer Interrupt Enable
const CR_FEIFIE: u8 = 1 << 3; // FIFO Error Interrupt Enable
const CR_IOCE:   u8 = 1 << 4; // IOC Interrupt On Completion Enable

// Global NABM registers
const NABM_GLBCNT: u8 = 0x2C; // 32-bit Global Control
const NABM_GLBSTS: u8 = 0x30; // 32-bit Global Status

// Global Control bits
const GLBCNT_SUS_OFF:  u32 = 1 << 8;  // Shut off suspended pin
const GLBCNT_WARM_RST: u32 = 1 << 2;  // Warm Reset
const GLBCNT_COLD_RST: u32 = 1 << 1;  // Cold Reset done = drive HIGH to de-assert reset
const GLBCNT_GIE:      u32 = 1 << 0;  // Global Interrupt Enable

// ─── Buffer Descriptor List Entry ────────────────────────────────────────────
//
// Each entry is exactly 8 bytes:
//   [0..3]  paddr:   32-bit physical address of PCM data (must be < 4 GiB)
//   [4..5]  samples: count of 16-bit PCM samples in this buffer (= bytes / 2)
//   [6..7]  flags:   bit15=IOC (interrupt on completion), bit14=BUP (silence on underrun)
//
// NOTE: "samples" means raw 16-bit words, not stereo frames.
//       A 4096-byte buffer holds 2048 16-bit words → samples = 0x0800.

#[repr(C)]
struct BdlEntry {
    paddr:   u32, // physical address
    samples: u16, // number of 16-bit PCM words in this buffer
    flags:   u16, // IOC | BUP flags
}

const BDL_IOC: u16 = 1 << 15; // Interrupt On Completion
const BDL_BUP: u16 = 1 << 14; // Buffer Underrun Policy: hold last sample

// ─── Ring-buffer geometry ─────────────────────────────────────────────────────

const BDL_ENTRIES:    usize = 32;                         // AC97 hardware max
const BUF_BYTES:      usize = 4096;                       // bytes per BDL entry = one 4K page
const BUF_SAMPLES:    u16   = (BUF_BYTES / 2) as u16;   // 2048 16-bit words per entry
const RING_BYTES:     usize = BDL_ENTRIES * BUF_BYTES;   // 128 KiB total DMA ring

// ─── Driver state ─────────────────────────────────────────────────────────────

static AUDIO_READY: AtomicBool = AtomicBool::new(false);

/// I/O base of NAM (Native Audio Mixer)
static NAM_BASE: AtomicU32 = AtomicU32::new(0);

/// I/O base of NABM (Native Audio Bus Master)
static NABM_BASE: AtomicU32 = AtomicU32::new(0);

/// PCI IRQ line for AC97 (default 5 on QEMU, read from PCI config at init)
static AC97_IRQ: AtomicU8 = AtomicU8::new(5);

/// Negotiated sample rate (Hz)
static SAMPLE_RATE_HZ: AtomicU32 = AtomicU32::new(44100);

/// Index of the next BDL entry the CPU should fill (producer cursor, wraps mod 32)
static FILL_IDX: AtomicU8 = AtomicU8::new(0);

/// Set by IRQ handler when hardware finishes a buffer; cleared by write_pcm
static BUFFER_DONE: AtomicBool = AtomicBool::new(false);

/// Whether the AC97 DMA engine is currently running
static DMA_RUNNING: AtomicBool = AtomicBool::new(false);

/// Master volume (0..100)
static MASTER_VOLUME: AtomicU8 = AtomicU8::new(80);

// Per-entry physical addresses (32-bit — AC97 is ISA-DMA-compatible, max 4 GiB)
static mut BUF_PHYS: [u32; BDL_ENTRIES] = [0u32; BDL_ENTRIES];

// Per-entry virtual addresses (for CPU writes into the buffer)
static mut BUF_VIRT: [u64; BDL_ENTRIES] = [0u64; BDL_ENTRIES];

// BDL array physical and virtual addresses
static mut BDL_PHYS: u32 = 0;
static mut BDL_VIRT: u64 = 0;

// ─── I/O port helpers (NAM = 16-bit registers) ────────────────────────────────

#[inline(always)]
unsafe fn nam_read16(off: u16) -> u16 {
    let port = NAM_BASE.load(Ordering::Relaxed) as u16 + off;
    let v: u16;
    asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack));
    v
}

#[inline(always)]
unsafe fn nam_write16(off: u16, val: u16) {
    let port = NAM_BASE.load(Ordering::Relaxed) as u16 + off;
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
}

// ─── I/O port helpers (NABM = mixed 8/16/32-bit registers) ───────────────────

#[inline(always)]
unsafe fn nabm_read8(off: u8) -> u8 {
    let port = NABM_BASE.load(Ordering::Relaxed) as u16 + off as u16;
    let v: u8;
    asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack));
    v
}

#[inline(always)]
unsafe fn nabm_write8(off: u8, val: u8) {
    let port = NABM_BASE.load(Ordering::Relaxed) as u16 + off as u16;
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

#[inline(always)]
unsafe fn nabm_read16(off: u8) -> u16 {
    let port = NABM_BASE.load(Ordering::Relaxed) as u16 + off as u16;
    let v: u16;
    asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack));
    v
}

#[inline(always)]
unsafe fn nabm_write16(off: u8, val: u16) {
    let port = NABM_BASE.load(Ordering::Relaxed) as u16 + off as u16;
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
}

#[inline(always)]
unsafe fn nabm_read32(off: u8) -> u32 {
    let port = NABM_BASE.load(Ordering::Relaxed) as u16 + off as u16;
    let v: u32;
    asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack));
    v
}

#[inline(always)]
unsafe fn nabm_write32(off: u8, val: u32) {
    let port = NABM_BASE.load(Ordering::Relaxed) as u16 + off as u16;
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack));
}

// PCM-Output channel helpers (add PCO_BASE to all offsets)

#[inline(always)]
unsafe fn pco_read_sr() -> u16 {
    nabm_read16(PCO_BASE + PCO_OFF_SR)
}
#[inline(always)]
unsafe fn pco_write_sr(val: u16) {
    nabm_write16(PCO_BASE + PCO_OFF_SR, val);
}
#[inline(always)]
unsafe fn pco_read_civ() -> u8 {
    nabm_read8(PCO_BASE + PCO_OFF_CIV)
}
#[inline(always)]
unsafe fn pco_write_lvi(lvi: u8) {
    nabm_write8(PCO_BASE + PCO_OFF_LVI, lvi & 0x1F); // 5-bit index
}
#[inline(always)]
unsafe fn pco_read_cr() -> u8 {
    nabm_read8(PCO_BASE + PCO_OFF_CR)
}
#[inline(always)]
unsafe fn pco_write_cr(val: u8) {
    nabm_write8(PCO_BASE + PCO_OFF_CR, val);
}

// ─── BDL helpers ─────────────────────────────────────────────────────────────

/// Write one BDL entry: physical address, sample count, flags.
unsafe fn set_bdl_entry(idx: usize, phys: u32, samps: u16, flags: u16) {
    let entry = (BDL_VIRT as *mut BdlEntry).add(idx);
    write_volatile(&mut (*entry).paddr,   phys);
    write_volatile(&mut (*entry).samples, samps);
    write_volatile(&mut (*entry).flags,   flags);
}

// ─── Busy-wait helper ─────────────────────────────────────────────────────────

fn wait_ticks(n: u64) {
    let target = crate::arch::x86_64::idt::timer_ticks() + n;
    while crate::arch::x86_64::idt::timer_ticks() < target {
        unsafe { asm!("pause"); }
    }
}

// ─── Serial log helpers ───────────────────────────────────────────────────────

fn log_u16(v: u16) {
    let h = b"0123456789ABCDEF";
    for sh in [12u16, 8, 4, 0] {
        serial::write_byte(h[((v >> sh) & 0xF) as usize]);
    }
}
fn log_u32(v: u32) {
    log_u16((v >> 16) as u16);
    log_u16(v as u16);
}

// ─── Physical frame allocator with 32-bit constraint check ────────────────────

fn alloc_dma_frame() -> Option<u32> {
    let phys = physical::alloc_frame()?;
    if phys > 0xFFFF_FFFF {
        serial::write_str("[AC97] WARN: physical frame > 4 GiB — cannot use for DMA\r\n");
        return None; // AC97 DMA can only address 32-bit physical space
    }
    Some(phys as u32)
}

// ─── Codec initialization ─────────────────────────────────────────────────────

/// Configure NAM: reset codec, set volumes, enable Variable Rate Audio.
/// Returns the negotiated sample rate (44100 or 48000 Hz).
unsafe fn init_codec() -> u32 {
    // 1. Soft-reset the codec
    nam_write16(NAM_RESET, 0x0000);
    wait_ticks(2); // codec needs ~20 µs; 2 ticks = 20 ms — more than enough

    // 2. Read vendor ID for serial log
    let vid1 = nam_read16(NAM_VENDOR_ID1);
    let vid2 = nam_read16(NAM_VENDOR_ID2);
    serial::write_str("[AC97] Codec vendor ID: 0x");
    log_u16(vid1); serial::write_str(":0x"); log_u16(vid2);
    serial::write_str("\r\n");

    // 3. Unmute master volume: 0x0000 = 0 dB both channels, no mute
    nam_write16(NAM_MASTER_VOL,    0x0000);
    nam_write16(NAM_HEADPHONE_VOL, 0x0000);

    // 4. Set PCM output volume to max with no mute
    //    Format: [4:0] = right gain (0=max), [12:8] = left gain (0=max), [15] = mute
    nam_write16(NAM_PCM_VOL, 0x0808); // 0x08 = 0 dB on AC97 PCM-out (0x00 would be +12 dB), unmuted

    // 5. Check Extended Audio ID for Variable Rate Audio (VRA) support
    let ext_id = nam_read16(NAM_EXT_AUDIO_ID);
    serial::write_str("[AC97] Ext Audio ID: 0x");
    log_u16(ext_id);
    serial::write_str("\r\n");

    if ext_id & EXT_ID_VRA != 0 {
        // Enable VRA in Extended Audio Control register
        let ctrl = nam_read16(NAM_EXT_AUDIO_CTRL);
        nam_write16(NAM_EXT_AUDIO_CTRL, ctrl | EXT_CTRL_VRA);

        // Set PCM front DAC rate to 44100 Hz
        nam_write16(NAM_PCM_FRONT_RATE, 44100);
        wait_ticks(1); // let codec settle

        // Read back the actual programmed rate (codec may round to nearest supported)
        let actual = nam_read16(NAM_PCM_FRONT_RATE);
        serial::write_str("[AC97] Sample rate: ");
        log_u32(actual as u32);
        serial::write_str(" Hz (VRA)\r\n");
        actual as u32
    } else {
        // No VRA: fixed 48000 Hz
        serial::write_str("[AC97] No VRA — fixed 48000 Hz\r\n");
        48000
    }
}

// ─── DMA memory setup ─────────────────────────────────────────────────────────

/// Allocate physical memory for BDL array + the 128 KiB PCM ring.
/// The ring is one physically contiguous block (so the generic stream code in
/// mod.rs can treat it as a flat cyclic buffer); BDL entry i points at
/// ring + i*4096.
unsafe fn alloc_dma_memory() -> bool {
    // Allocate BDL array frame (BDL_ENTRIES × 8 bytes = 256 bytes → fits in one 4K frame)
    let bdl_frame = match alloc_dma_frame() {
        Some(f) => f,
        None => {
            serial::write_str("[AC97] Failed to allocate BDL frame\r\n");
            return false;
        }
    };
    // Zero BDL frame
    let bdl_v = phys_to_virt(bdl_frame as u64);
    core::ptr::write_bytes(bdl_v as *mut u8, 0, 4096);
    BDL_PHYS = bdl_frame;
    BDL_VIRT = bdl_v;

    let ring = match physical::alloc_frames(BDL_ENTRIES as u64) {
        Some(p) if p + RING_BYTES as u64 <= 0x1_0000_0000 => p,
        Some(_) => {
            serial::write_str("[AC97] PCM ring above 4 GiB — AC97 DMA is 32-bit only\r\n");
            return false;
        }
        None => {
            serial::write_str("[AC97] Failed to allocate 128 KiB contiguous PCM ring\r\n");
            return false;
        }
    };
    let ring_v = phys_to_virt(ring);
    core::ptr::write_bytes(ring_v as *mut u8, 0, RING_BYTES);
    for i in 0..BDL_ENTRIES {
        BUF_PHYS[i] = ring as u32 + (i * BUF_BYTES) as u32;
        BUF_VIRT[i] = ring_v + (i * BUF_BYTES) as u64;
    }

    serial::write_str("[AC97] DMA ring allocated: BDL + 128 KiB contiguous PCM ring\r\n");
    true
}

// ─── NABM PCM-Output channel init ─────────────────────────────────────────────

/// Reset the PCM-Output channel, program BDBAR, LVI, and start DMA.
unsafe fn init_nabm() -> bool {
    // (The AC-link cold reset happens in cold_reset() before the codec is
    //  programmed — doing it here would wipe the mixer settings.)

    // 2. Reset the PCM-Output channel registers (CR.RR = 1 → clear → ready)
    pco_write_cr(CR_RR);
    // Wait until reset completes (CR.RR clears)
    let deadline = crate::arch::x86_64::idt::timer_ticks() + 5;
    while pco_read_cr() & CR_RR != 0 {
        if crate::arch::x86_64::idt::timer_ticks() > deadline { break; }
        asm!("pause");
    }

    // 3. Write BDBAR: physical base address of BDL array (must be 32-bit)
    nabm_write32(PCO_BASE + PCO_OFF_BDBAR, BDL_PHYS);

    // 4. Fill all 32 BDL entries (silence).  No IOC: the driver is polled,
    //    the PIC line is never unmasked, so no interrupt must be raised.
    for i in 0..BDL_ENTRIES {
        set_bdl_entry(i, BUF_PHYS[i], BUF_SAMPLES, BDL_BUP);
    }

    // 5. Set LVI = 31 (all entries valid); keepalive() keeps LVI one entry
    //    behind CIV so the ring plays cyclically forever.
    pco_write_lvi((BDL_ENTRIES - 1) as u8);

    // 6. Clear any stale status bits (write 1 to clear W1C bits)
    pco_write_sr(SR_LVBCI | SR_BCIS | SR_FIFOE);

    // 7. Start DMA (run bit only, no interrupt enables)
    pco_write_cr(CR_RPBM);

    DMA_RUNNING.store(true, Ordering::Release);
    serial::write_str("[AC97] NABM PCM-OUT DMA started (polled, cyclic), LVI=31\r\n");
    true
}

/// AC-link cold reset + wait for the primary codec to report ready.
unsafe fn cold_reset() {
    let glbcnt = nabm_read32(NABM_GLBCNT);
    serial::write_str("[AC97] GLBCNT before reset=0x"); log_u32(glbcnt); serial::write_str("\r\n");
    nabm_write32(NABM_GLBCNT, glbcnt & !(GLBCNT_COLD_RST | GLBCNT_GIE));
    wait_ticks(1);
    nabm_write32(NABM_GLBCNT, (glbcnt | GLBCNT_COLD_RST) & !GLBCNT_GIE);
    // GLBSTS bit 8 = primary codec ready
    let deadline = crate::arch::x86_64::idt::timer_ticks() + 50;
    let mut sts = nabm_read32(NABM_GLBSTS);
    while sts & (1 << 8) == 0 && crate::arch::x86_64::idt::timer_ticks() < deadline {
        asm!("pause");
        sts = nabm_read32(NABM_GLBSTS);
    }
    serial::write_str("[AC97] GLBSTS after cold reset=0x"); log_u32(sts);
    serial::write_str(if sts & (1 << 8) != 0 { " (codec ready)\r\n" } else { " (codec NOT ready — continuing)\r\n" });
}

// ─── Public: init ─────────────────────────────────────────────────────────────

/// Scan PCI for an AC97 controller, initialize NAM + NABM, start DMA.
/// Returns true if controller was found and initialized.
pub fn init() -> bool {
    // ── Step 1: PCI discovery ────────────────────────────────────────────────
    //
    // Match only known Intel ICH AC97 and VIA VT82C686 controllers.
    // The generic class/subclass scan has been intentionally removed —
    // it captures ES1371 (1274:1371) and other AudioPCI chips that use
    // a completely different register interface and need their own driver.
    let (bus, dev, func) = {
        let known_ids: [(u16, u16); 4] = [
            (PCI_VID_INTEL, PCI_DID_ICH_AC97),
            (PCI_VID_INTEL, PCI_DID_ICH_AC97B),
            (PCI_VID_INTEL, PCI_DID_ICH2_AC97),
            (PCI_VID_VIA,   PCI_DID_VIA_AC97),
        ];

        let mut found: Option<(u8, u8, u8)> = None;
        'scan: for b in 0..=255u8 {
            for d in 0..32u8 {
                for f in 0..8u8 {
                    let vid = crate::pci::vendor_id(b, d, f);
                    if vid == 0xFFFF { continue; }
                    let did = crate::pci::device_id(b, d, f);

                    // Skip Ensoniq ES1371/1373 — they match the class but need es1371.rs
                    if vid == 0x1274 { continue; }

                    let (class, subclass, _) = crate::pci::class_code(b, d, f);

                    // Check class: 0x04 (Multimedia), 0x01 (Audio Device / AC97)
                    let is_ac97_class = class == 0x04 && subclass == 0x01
                        && matches!(vid, 0x8086 | 0x1106 | 0x1022 | 0x10DE | 0x1039);
                    
                    let mut is_known = false;
                    for &(kv, kd) in &known_ids {
                        if vid == kv && did == kd {
                            is_known = true;
                            break;
                        }
                    }

                    if is_ac97_class || is_known {
                        found = Some((b, d, f));
                        break 'scan;
                    }
                }
            }
        }

        match found {
            Some(p) => p,
            None => {
                serial::write_str("[AC97] No AC97 controller found via class or VID:DID\r\n");
                return false;
            }
        }
    };

    let vid = crate::pci::vendor_id(bus, dev, func);
    let did = crate::pci::device_id(bus, dev, func);
    serial::write_str("[AC97] Found PCI ");
    log_u16(vid); serial::write_str(":"); log_u16(did);
    serial::write_str(" at bus="); log_u8(bus);
    serial::write_str(" dev="); log_u8(dev);
    serial::write_str(" func="); log_u8(func);
    serial::write_str("\r\n");

    // ── Step 2: Read PCI BARs ────────────────────────────────────────────────
    //
    // BAR0 = NAM I/O base (16-bit registers, ~128 byte space)
    // BAR1 = NABM I/O base (8/16/32-bit registers, ~64 byte space)

    let nam_base = match crate::pci::read_bar(bus, dev, func, 0) {
        crate::pci::BarType::Io { base, .. } => base as u32,
        _ => {
            serial::write_str("[AC97] BAR0 is not I/O — aborting\r\n");
            return false;
        }
    };
    let nabm_base = match crate::pci::read_bar(bus, dev, func, 1) {
        crate::pci::BarType::Io { base, .. } => base as u32,
        _ => {
            serial::write_str("[AC97] BAR1 is not I/O — aborting\r\n");
            return false;
        }
    };

    serial::write_str("[AC97] NAM=0x"); log_u32(nam_base);
    serial::write_str(", NABM=0x"); log_u32(nabm_base);
    serial::write_str("\r\n");

    // Store bases as atomics so I/O helpers can read them
    NAM_BASE.store(nam_base, Ordering::Relaxed);
    NABM_BASE.store(nabm_base, Ordering::Relaxed);

    // ── Step 3: Enable PCI bus mastering ───────────────────────────────────────
    crate::pci::enable_bus_master(bus, dev, func);

    // ── Step 4: Read IRQ line from PCI config ───────────────────────────────────
    // PCI config offset 0x3C, bits [7:0] = interrupt_line
    let irq_line = (crate::pci::config_read32(bus, dev, func, 0x3C) & 0xFF) as u8;
    if irq_line < 16 {
        AC97_IRQ.store(irq_line, Ordering::Relaxed);
        serial::write_str("[AC97] PCI IRQ line=");
        log_u8(irq_line);
        serial::write_str("\r\n");
    } else {
        // 0xFF means not connected; keep default of 5 (QEMU AC97 default)
        serial::write_str("[AC97] IRQ unassigned, defaulting to 5\r\n");
    }

    // ── Step 5: AC-link cold reset, then initialize codec (NAM) ─────────────────
    unsafe { cold_reset(); }
    let rate = unsafe { init_codec() };
    SAMPLE_RATE_HZ.store(rate, Ordering::Relaxed);

    // ── Step 6: Allocate DMA memory ────────────────────────────────────────────
    if !unsafe { alloc_dma_memory() } {
        return false;
    }

    // ── Step 7: Initialize NABM and start DMA ─────────────────────────────────
    if !unsafe { init_nabm() } {
        return false;
    }

    AUDIO_READY.store(true, Ordering::Release);
    FILL_IDX.store(0, Ordering::Relaxed);
    serial::write_str("[AC97] Audio driver ready\r\n");

    // Dump diagnostic info to serial at init time
    dump_mem_map();
    dump_status();

    true
}

// ─── Public: polled ring interface (used by audio::mod stream code) ──────────

/// Virtual address of the 128 KiB cyclic PCM ring.
pub fn ring_ptr() -> *mut u8 { unsafe { BUF_VIRT[0] as *mut u8 } }

/// Size of the PCM ring in bytes.
pub fn ring_bytes() -> usize { RING_BYTES }

/// Current hardware play position (byte offset inside the ring).
pub fn hw_pos() -> usize {
    if !AUDIO_READY.load(Ordering::Acquire) { return 0; }
    unsafe {
        // CIV and PICB are separate registers: re-read until stable.
        for _ in 0..4 {
            let civ1 = pco_read_civ() & 0x1F;
            let picb = nabm_read16(PCO_BASE + PCO_OFF_PICB) as usize;
            let civ2 = pco_read_civ() & 0x1F;
            if civ1 == civ2 {
                let played = BUF_BYTES.saturating_sub(picb.min(BUF_SAMPLES as usize) * 2);
                return (civ1 as usize * BUF_BYTES + played) % RING_BYTES;
            }
        }
        (pco_read_civ() as usize & 0x1F) * BUF_BYTES
    }
}

/// Keep the DMA engine running cyclically: LVI = CIV - 1, restart if halted.
pub fn keepalive() {
    if !AUDIO_READY.load(Ordering::Acquire) { return; }
    unsafe {
        let civ = pco_read_civ() & 0x1F;
        pco_write_lvi(civ.wrapping_sub(1) & 0x1F);
        let sr = pco_read_sr();
        if sr & (SR_LVBCI | SR_BCIS | SR_FIFOE) != 0 {
            pco_write_sr(SR_LVBCI | SR_BCIS | SR_FIFOE);
        }
        let cr = pco_read_cr();
        if cr & CR_RPBM == 0 {
            pco_write_cr(CR_RPBM);
            if !DMA_RUNNING.swap(true, Ordering::Relaxed) {
                serial::write_str("[AC97] DMA was stopped — restarted\r\n");
            }
        }
    }
}

/// Kept for compatibility: the driver is polled, interrupts stay disabled.
pub fn enable_interrupts() {}

/// IRQ hook: only acknowledges status bits (no interrupts are enabled).
pub fn handle_irq() {
    if !AUDIO_READY.load(Ordering::Acquire) { return; }
    unsafe {
        let sr = pco_read_sr();
        if sr & (SR_BCIS | SR_LVBCI | SR_FIFOE) != 0 {
            pco_write_sr(SR_LVBCI | SR_BCIS | SR_FIFOE);
        }
    }
}

// ─── Public: status ───────────────────────────────────────────────────────────

/// Returns true when the AC97 controller is initialized and DMA is running.
pub fn is_ready() -> bool {
    AUDIO_READY.load(Ordering::Acquire)
}

/// Returns the IRQ number this driver is attached to.
pub fn irq_line() -> u8 {
    AC97_IRQ.load(Ordering::Relaxed)
}

/// Returns (civ, fill_idx, in_flight) for debugging.
pub fn dma_status() -> (u8, u8, u8) {
    // fill = BDL entry holding the end of queued data, in_flight = whole
    // entries queued ahead of the hardware.
    let civ  = unsafe { if is_ready() { pco_read_civ() & 0x1F } else { 0 } };
    let queued_bytes = super::queued_frames() as usize * 4;
    let in_flight = (queued_bytes / BUF_BYTES) as u8;
    let fill = (civ as usize + (hw_pos() % BUF_BYTES + queued_bytes) / BUF_BYTES) as u8 & 0x1F;
    (civ, fill, in_flight)
}

/// Returns the negotiated sample rate (Hz).
pub fn sample_rate() -> u32 {
    SAMPLE_RATE_HZ.load(Ordering::Relaxed)
}

/// Returns the current master volume (0..100).
pub fn volume() -> u8 {
    MASTER_VOLUME.load(Ordering::Relaxed)
}

/// Set master volume (0..100).
pub fn set_volume(pct: u8) {
    let pct = pct.min(100);
    MASTER_VOLUME.store(pct, Ordering::Relaxed);
    if !AUDIO_READY.load(Ordering::Acquire) { return; }

    // AC97 volume: 0 = max gain, 0x1F = -46.5 dB, bit 15 = mute
    // Convert 0..100 to 0x1F..0 (inverted)
    let attn = (0x1F - (pct as u16 * 0x1F / 100)) & 0x1F;
    let val = attn | (attn << 8); // set both channels
    unsafe {
        nam_write16(NAM_MASTER_VOL, val);
        nam_write16(NAM_HEADPHONE_VOL, val);
    }
}

// ─── Diagnostic: dump AC97 register state to serial ──────────────────────────

fn log_u8(v: u8) {
    let h = b"0123456789ABCDEF";
    serial::write_byte(h[((v >> 4) & 0xF) as usize]);
    serial::write_byte(h[(v & 0xF) as usize]);
}

fn log_u64(v: u64) {
    log_u32((v >> 32) as u32);
    log_u32(v as u32);
}

/// Dump all AC97 hardware status registers to serial (COM1).
/// Call from terminal via a debug command or periodically for diagnosis.
pub fn dump_status() {
    serial::write_str("[AC97-DIAG] === AC97 Status Dump ===\r\n");

    if !AUDIO_READY.load(Ordering::Acquire) {
        serial::write_str("[AC97-DIAG] Driver NOT ready\r\n");
        return;
    }

    unsafe {
        // Global Status Register
        let glb_sts = nabm_read32(NABM_GLBSTS);
        serial::write_str("[AC97-DIAG] GLBSTS=0x"); log_u32(glb_sts); serial::write_str("\r\n");

        // Global Control Register
        let glb_cnt = nabm_read32(NABM_GLBCNT);
        serial::write_str("[AC97-DIAG] GLBCNT=0x"); log_u32(glb_cnt); serial::write_str("\r\n");

        // PCM-Out channel status
        let sr   = pco_read_sr();
        let civ  = pco_read_civ();
        let cr   = pco_read_cr();
        let picb = nabm_read16(PCO_BASE + PCO_OFF_PICB);
        let piv  = nabm_read8(PCO_BASE + PCO_OFF_PIV);
        let bdbar= nabm_read32(PCO_BASE + PCO_OFF_BDBAR);

        serial::write_str("[AC97-DIAG] PCO_SR=0x");   log_u16(sr);   serial::write_str("\r\n");
        serial::write_str("[AC97-DIAG]   DCH=");    serial::write_byte(if sr & SR_DCH   != 0 { b'1' } else { b'0' });
        serial::write_str(" CELV=");   serial::write_byte(if sr & SR_CELV  != 0 { b'1' } else { b'0' });
        serial::write_str(" LVBCI=");  serial::write_byte(if sr & SR_LVBCI != 0 { b'1' } else { b'0' });
        serial::write_str(" BCIS=");   serial::write_byte(if sr & SR_BCIS  != 0 { b'1' } else { b'0' });
        serial::write_str(" FIFOE=");  serial::write_byte(if sr & SR_FIFOE != 0 { b'1' } else { b'0' });
        serial::write_str("\r\n");

        serial::write_str("[AC97-DIAG] PCO_CIV=0x"); log_u8(civ);
        serial::write_str(" PIV=0x"); log_u8(piv);
        serial::write_str(" PICB=0x"); log_u16(picb);
        serial::write_str("\r\n");

        serial::write_str("[AC97-DIAG] PCO_CR=0x"); log_u8(cr);
        serial::write_str("  RPBM="); serial::write_byte(if cr & CR_RPBM != 0 { b'1' } else { b'0' });
        serial::write_str(" IOCE=");  serial::write_byte(if cr & CR_IOCE  != 0 { b'1' } else { b'0' });
        serial::write_str(" LVBIE="); serial::write_byte(if cr & CR_LVBIE != 0 { b'1' } else { b'0' });
        serial::write_str("\r\n");

        serial::write_str("[AC97-DIAG] BDBAR=0x"); log_u32(bdbar); serial::write_str("\r\n");

        // Software state
        let fill = FILL_IDX.load(Ordering::Relaxed);
        let dma  = DMA_RUNNING.load(Ordering::Relaxed);
        serial::write_str("[AC97-DIAG] FILL_IDX="); log_u8(fill);
        serial::write_str(" DMA_RUNNING="); serial::write_byte(if dma { b'1' } else { b'0' });
        serial::write_str("\r\n");

        // NAM registers
        let master = nam_read16(NAM_MASTER_VOL);
        let pcm    = nam_read16(NAM_PCM_VOL);
        let rate   = nam_read16(NAM_PCM_FRONT_RATE);
        serial::write_str("[AC97-DIAG] NAM: MASTER_VOL=0x"); log_u16(master);
        serial::write_str(" PCM_VOL=0x"); log_u16(pcm);
        serial::write_str(" RATE=0x"); log_u16(rate);
        serial::write_str("\r\n");
    }

    serial::write_str("[AC97-DIAG] === End Status Dump ===\r\n");
}

// ─── Diagnostic: memory map dump to serial ────────────────────────────────────

/// Dump audio DMA buffer locations vs. framebuffer to serial.
/// Proves (or disproves) memory isolation between audio and video.
pub fn dump_mem_map() {
    serial::write_str("[AC97-MEM] === Audio Memory Map ===\r\n");

    if !AUDIO_READY.load(Ordering::Acquire) {
        serial::write_str("[AC97-MEM] Driver NOT ready — no DMA buffers allocated\r\n");
        return;
    }

    let mut dma_min: u64 = 0;
    let mut dma_end: u64 = 0;

    unsafe {
        // BDL array
        serial::write_str("[AC97-MEM] BDL  phys=0x"); log_u32(BDL_PHYS);
        serial::write_str("  virt=0x"); log_u64(BDL_VIRT);
        serial::write_str("\r\n");

        // Per-entry DMA buffers (show first, last, and min/max range)
        let mut min_phys: u32 = 0xFFFF_FFFF;
        let mut max_phys: u32 = 0;
        for i in 0..BDL_ENTRIES {
            let p = BUF_PHYS[i];
            if p < min_phys { min_phys = p; }
            if p > max_phys { max_phys = p; }
        }
        serial::write_str("[AC97-MEM] PCM bufs[0] phys=0x"); log_u32(BUF_PHYS[0]);
        serial::write_str("  virt=0x"); log_u64(BUF_VIRT[0]);
        serial::write_str("\r\n");
        serial::write_str("[AC97-MEM] PCM bufs[31] phys=0x"); log_u32(BUF_PHYS[31]);
        serial::write_str("  virt=0x"); log_u64(BUF_VIRT[31]);
        serial::write_str("\r\n");
        serial::write_str("[AC97-MEM] PCM range phys=0x"); log_u32(min_phys);
        serial::write_str(" .. 0x"); log_u32(max_phys + 0x1000);
        serial::write_str("  ("); log_u32((BDL_ENTRIES as u32) * 4096); serial::write_str(" bytes)\r\n");

        dma_min = min_phys as u64;
        dma_end = (max_phys as u64) + 0x1000;
    }

    // Framebuffer info + overlap detection
    if let Some(fb) = crate::arch::x86_64::framebuffer::info() {
        let fb_virt = fb.address as u64;
        let hhdm = crate::arch::x86_64::boot::hhdm_offset().unwrap_or(0);
        let fb_phys = fb_virt.wrapping_sub(hhdm);
        let fb_size = fb.pitch * fb.height;
        serial::write_str("[AC97-MEM] FB   phys=0x"); log_u64(fb_phys);
        serial::write_str("  virt=0x"); log_u64(fb_virt);
        serial::write_str("\r\n");
        serial::write_str("[AC97-MEM] FB   size=0x"); log_u64(fb_size);
        serial::write_str(" ("); log_u64(fb.width); serial::write_str("x"); log_u64(fb.height);
        serial::write_str("  pitch="); log_u64(fb.pitch);
        serial::write_str(")\r\n");

        // Explicit overlap check: DMA range vs LFB MMIO range
        if dma_end > 0 {
            let lfb_end = fb_phys.saturating_add(fb_size);
            let overlap = !(dma_end <= fb_phys || dma_min >= lfb_end);
            if overlap {
                serial::write_str("[AC97-MEM] *** OVERLAP: DMA bufs [0x");
                log_u64(dma_min);
                serial::write_str(", 0x");
                log_u64(dma_end);
                serial::write_str(") intersects LFB [0x");
                log_u64(fb_phys);
                serial::write_str(", 0x");
                log_u64(lfb_end);
                serial::write_str(") ***\r\n");
                serial::write_str("[AC97-MEM] *** This WILL cause graphical corruption in DOOM! ***\r\n");
            } else {
                serial::write_str("[AC97-MEM] DMA/LFB: no overlap (OK)\r\n");
            }
        }
    } else {
        serial::write_str("[AC97-MEM] FB   not available\r\n");
    }

    serial::write_str("[AC97-MEM] === End Memory Map ===\r\n");
}

/// Stop PCM-out DMA (before reset / power-off).
pub fn stop() {
    if NABM_BASE.load(Ordering::Relaxed) == 0 { return; }
    DMA_RUNNING.store(false, Ordering::Release);
    unsafe { pco_write_cr(0); }
}
