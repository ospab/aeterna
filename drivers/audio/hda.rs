/*
 * Intel High Definition Audio (HDA) Driver — AETERNA microkernel
 *
 * Supports: QEMU ICH6-HDA (8086:2668), ICH9-HDA (8086:293E), VMware
 * "hdaudio", Intel ICH8+ — any PCI class 0x04 / subclass 0x03 controller.
 *
 * Pipeline:
 *   audio::mod stream  →  128 KiB cyclic DMA ring  →  output stream 0  →  DAC(s)
 *
 * Configuration:
 *   Format:  48000 Hz, 16-bit, 2-channel (universally supported)
 *   Ring:    32 × 4 KiB BDL entries over one contiguous 128 KiB block,
 *            played cyclically; play position = LPIB.  Polled (no IRQ).
 *
 * Codec communication:
 *   CORB/RIRB ring (what real drivers use; VMware may not implement the
 *   Immediate Command interface).  Falls back to the Immediate Command
 *   interface (ICOI/IRII/ICS) if the CORB/RIRB path never answers.
 *
 * Volume:
 *   All amplifiers are set to 0 dB using the codec's own amp capabilities
 *   (writing gain 0x7F to an amp with fewer steps is undefined).  The user
 *   volume is applied in software by audio::mod.
 */

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, Ordering};
use core::ptr::{read_volatile, write_volatile};

use crate::arch::x86_64::serial;
use crate::mm::r#virtual::phys_to_virt;
use crate::mm::physical;

// ─── HDA Controller Register Offsets (from MMIO base) ───────────────────────
const REG_GCAP:     u32 = 0x00; // 16-bit  Global Capabilities
const REG_VMIN:     u32 = 0x02; // 8-bit   Minor Version
const REG_VMAJ:     u32 = 0x03; // 8-bit   Major Version
const REG_GCTL:     u32 = 0x08; // 32-bit  Global Control
const REG_STATESTS: u32 = 0x0E; // 16-bit  State Change Status (codec presence)
const REG_GSTS:     u32 = 0x10; // 16-bit  Global Status
const REG_INTCTL:   u32 = 0x20; // 32-bit  Interrupt Control
const REG_INTSTS:   u32 = 0x24; // 32-bit  Interrupt Status
const REG_WALCLK:   u32 = 0x30; // 32-bit  Wall Clock Counter

// CORB registers
const REG_CORBLBASE: u32 = 0x40;
const REG_CORBUBASE: u32 = 0x44;
const REG_CORBWP:    u32 = 0x48;
const REG_CORBRP:    u32 = 0x4A;
const REG_CORBCTL:   u32 = 0x4C;
const REG_CORBSTS:   u32 = 0x4D;
const REG_CORBSIZE:  u32 = 0x4E;

// RIRB registers
const REG_RIRBLBASE: u32 = 0x50;
const REG_RIRBUBASE: u32 = 0x54;
const REG_RIRBWP:    u32 = 0x58;
const REG_RINTCNT:   u32 = 0x5A;
const REG_RIRBCTL:   u32 = 0x5C;
const REG_RIRBSTS:   u32 = 0x5D;
const REG_RIRBSIZE:  u32 = 0x5E;

// Immediate Command Interface
const REG_IMMCMD:    u32 = 0x60;
const REG_IMMRES:    u32 = 0x64;
const REG_ICS:       u32 = 0x68;

// ─── GCTL bits ────────────────────────────────────────────────────────────
const GCTL_CRST:  u32 = 1 << 0;
const GCTL_UNSOL: u32 = 1 << 8;

// ─── ICS bits ─────────────────────────────────────────────────────────────
const ICS_ICB:  u16 = 1 << 0;
const ICS_IRV:  u16 = 1 << 1;

// ─── Stream Descriptor offsets (from SD base) ─────────────────────────────
const SD_OFF_CTL:   u32 = 0x00;
const SD_OFF_STS:   u32 = 0x03;
const SD_OFF_LPIB:  u32 = 0x04;
const SD_OFF_CBL:   u32 = 0x08;
const SD_OFF_LVI:   u32 = 0x0C;
const SD_OFF_FMT:   u32 = 0x12;
const SD_OFF_BDPL:  u32 = 0x18;
const SD_OFF_BDPU:  u32 = 0x1C;

const SD_CTL_SRST:  u32 = 1 << 0;
const SD_CTL_RUN:   u32 = 1 << 1;
const SD_STREAM_TAG: u32 = 1 << 20; // stream number 1 (bits 23:20)

// 48 kHz, 16-bit, stereo (base=48k, mult=1, div=1, bits=16 (001), chans-1=1)
const SDFMT_48000_16_STEREO: u16 = (0 << 14) | (0b001 << 4) | 0b0001;

#[repr(C)]
struct BdlEntry {
    addr_lo: u32,
    addr_hi: u32,
    length:  u32,
    ioc:     u32,
}

// ─── Codec verbs ──────────────────────────────────────────────────────────
fn make_verb(codec: u8, nid: u8, verb: u32, payload: u32) -> u32 {
    ((codec as u32) << 28) | ((nid as u32) << 20) | ((verb & 0xFFF) << 8) | (payload & 0xFF)
}
fn make_get_param(codec: u8, nid: u8, param: u8) -> u32 {
    make_verb(codec, nid, 0xF00, param as u32)
}
fn make_set_fmt(codec: u8, nid: u8, fmt: u16) -> u32 {
    ((codec as u32) << 28) | ((nid as u32) << 20) | (0x2u32 << 16) | (fmt as u32)
}
/// SET_AMP_GAIN_MUTE payload: bit15=out, bit14=in, bit13=L, bit12=R,
/// bits11:8=input index, bit7=mute, bits6:0=gain
fn make_set_amp(codec: u8, nid: u8, payload: u16) -> u32 {
    ((codec as u32) << 28) | ((nid as u32) << 20) | (0x3u32 << 16) | (payload as u32)
}

const VERB_SET_POWER_STATE:    u32 = 0x705;
const VERB_SET_STREAM_CHAN:    u32 = 0x706;
const VERB_SET_PIN_WIDGET_CTL: u32 = 0x707;
const VERB_SET_EAPD:           u32 = 0x70C;
const VERB_SET_CONNECT_SEL:    u32 = 0x701;

const PARAM_VENDOR_ID:   u8 = 0x00;
const PARAM_NODE_COUNT:  u8 = 0x04;
const PARAM_FUNC_TYPE:   u8 = 0x05;
const PARAM_AUDIO_CAP:   u8 = 0x09;
const PARAM_PIN_CAP:     u8 = 0x0C;
const PARAM_IN_AMP_CAP:  u8 = 0x0D;
const PARAM_OUT_AMP_CAP: u8 = 0x12;

// ─── Driver state ─────────────────────────────────────────────────────────
static AUDIO_READY: AtomicBool = AtomicBool::new(false);

static mut SAMPLE_RATE_HZ: u32 = 48000;
static mut MMIO_BASE: u64 = 0;
static mut ISS: u8 = 0;
static mut PCI_IRQ: u8 = 0;

const DMA_BUF_SIZE: usize = 4096;
const DMA_ENTRIES:  usize = 32;
const DMA_TOTAL:    usize = DMA_BUF_SIZE * DMA_ENTRIES; // 128 KiB ring

static mut RING_PHYS: u64 = 0;
static mut RING_VIRT: u64 = 0;
static mut BDL_PHYS: u64 = 0;
static mut BDL_VIRT: u64 = 0;

static mut CORB_VIRT: u64 = 0;
static mut RIRB_VIRT: u64 = 0;
static mut RIRB_RP: u16 = 0;
static mut USE_CORB: bool = false;
static mut USE_IMM: bool = true;

static mut MASTER_VOLUME: u8 = 100;
static mut DAC_COUNT: u8 = 0;
static mut OUT_PIN_COUNT: u8 = 0;

// ─── MMIO helpers ─────────────────────────────────────────────────────────
#[inline(always)] unsafe fn read8(o: u32) -> u8 { read_volatile((MMIO_BASE + o as u64) as *const u8) }
#[inline(always)] unsafe fn read16(o: u32) -> u16 { read_volatile((MMIO_BASE + o as u64) as *const u16) }
#[inline(always)] unsafe fn read32(o: u32) -> u32 { read_volatile((MMIO_BASE + o as u64) as *const u32) }
#[inline(always)] unsafe fn write8(o: u32, v: u8) { write_volatile((MMIO_BASE + o as u64) as *mut u8, v) }
#[inline(always)] unsafe fn write16(o: u32, v: u16) { write_volatile((MMIO_BASE + o as u64) as *mut u16, v) }
#[inline(always)] unsafe fn write32(o: u32, v: u32) { write_volatile((MMIO_BASE + o as u64) as *mut u32, v) }

fn ticks() -> u64 { crate::arch::x86_64::idt::timer_ticks() }

fn wait_ticks(n: u64) {
    let target = ticks() + n;
    while ticks() < target { unsafe { core::arch::asm!("pause"); } }
}

// ─── Codec command transport ──────────────────────────────────────────────

/// Immediate Command Interface; None on timeout.
unsafe fn imm_send(verb: u32) -> Option<u32> {
    let deadline = ticks() + 3;
    while read16(REG_ICS) & ICS_ICB != 0 {
        if ticks() > deadline { return None; }
        core::arch::asm!("pause");
    }
    write16(REG_ICS, ICS_IRV); // clear stale result-valid (W1C)
    write32(REG_IMMCMD, verb);
    write16(REG_ICS, ICS_ICB);
    let deadline = ticks() + 3;
    loop {
        let ics = read16(REG_ICS);
        if ics & ICS_IRV != 0 {
            let r = read32(REG_IMMRES);
            write16(REG_ICS, ICS_IRV);
            return Some(r);
        }
        if ticks() > deadline { return None; }
        core::arch::asm!("pause");
    }
}

/// CORB/RIRB transport; None on timeout.
unsafe fn corb_send(verb: u32) -> Option<u32> {
    let wp = (read16(REG_CORBWP) & 0xFF) as usize;
    let next = (wp + 1) & 0xFF;
    write_volatile((CORB_VIRT as *mut u32).add(next), verb);
    write16(REG_CORBWP, next as u16);
    let deadline = ticks() + 3;
    loop {
        let rwp = read16(REG_RIRBWP) & 0xFF;
        if rwp != RIRB_RP {
            RIRB_RP = (RIRB_RP + 1) & 0xFF;
            let resp = read_volatile((RIRB_VIRT as *const u32).add(RIRB_RP as usize * 2));
            let ex = read_volatile((RIRB_VIRT as *const u32).add(RIRB_RP as usize * 2 + 1));
            write8(REG_RIRBSTS, 0x05);
            if ex & 0x10 != 0 { continue; } // unsolicited response — keep waiting
            return Some(resp);
        }
        if ticks() > deadline { return None; }
        core::arch::asm!("pause");
    }
}

/// Send a verb, return the response (0 if the codec did not answer).
unsafe fn cmd(verb: u32) -> u32 {
    if USE_CORB {
        if let Some(r) = corb_send(verb) { return r; }
        serial::write_str("[HDA] CORB/RIRB timeout — switching to Immediate Command interface\r\n");
        USE_CORB = false;
    }
    if USE_IMM {
        if let Some(r) = imm_send(verb) { return r; }
        serial::write_str("[HDA] Immediate Command timeout (verb 0x");
        super::log_hex32(verb);
        serial::write_str(")\r\n");
    }
    0
}

// ─── CORB/RIRB setup ──────────────────────────────────────────────────────

unsafe fn setup_corb_rirb() -> bool {
    let frame = match physical::alloc_frame() {
        Some(f) => f,
        None => {
            serial::write_str("[HDA] CORB/RIRB alloc failed\r\n");
            return false;
        }
    };
    let virt = phys_to_virt(frame);
    core::ptr::write_bytes(virt as *mut u8, 0, 4096);
    CORB_VIRT = virt;
    RIRB_VIRT = virt + 1024;
    let corb_phys = frame;
    let rirb_phys = frame + 1024;

    write8(REG_CORBCTL, 0x00);
    write8(REG_RIRBCTL, 0x00);
    wait_ticks(1);

    let corbsize_cap = read8(REG_CORBSIZE);
    let rirbsize_cap = read8(REG_RIRBSIZE);
    serial::write_str("[HDA] CORBSIZE=0x"); super::log_hex8(corbsize_cap);
    serial::write_str(" RIRBSIZE=0x"); super::log_hex8(rirbsize_cap);
    serial::write_str("\r\n");
    if corbsize_cap & 0x40 == 0 || rirbsize_cap & 0x40 == 0 {
        serial::write_str("[HDA] 256-entry CORB/RIRB not supported — using Immediate Commands only\r\n");
        return true;
    }
    write8(REG_CORBSIZE, (corbsize_cap & 0xF0) | 0x02);
    write8(REG_RIRBSIZE, (rirbsize_cap & 0xF0) | 0x02);

    write32(REG_CORBLBASE, corb_phys as u32);
    write32(REG_CORBUBASE, (corb_phys >> 32) as u32);
    // Reset CORB read pointer: set bit 15, wait, clear, wait.
    write16(REG_CORBRP, 0x8000);
    let t = ticks() + 2;
    while read16(REG_CORBRP) & 0x8000 == 0 && ticks() < t { core::arch::asm!("pause"); }
    write16(REG_CORBRP, 0x0000);
    let t = ticks() + 2;
    while read16(REG_CORBRP) & 0x8000 != 0 && ticks() < t { core::arch::asm!("pause"); }
    write16(REG_CORBWP, 0x0000);

    write32(REG_RIRBLBASE, rirb_phys as u32);
    write32(REG_RIRBUBASE, (rirb_phys >> 32) as u32);
    write16(REG_RIRBWP, 0x8000); // reset RIRB write pointer
    write16(REG_RINTCNT, 0x01);
    RIRB_RP = 0;

    write8(REG_CORBCTL, 0x02); // CORBRUN
    // RIRBDMAEN + RINTCTL.  RINTCTL only sets RIRBSTS.RINTFL (no IRQ is
    // raised: INTCTL stays 0), but QEMU stops the CORB after RINTCNT
    // responses until software clears RINTFL, which needs RINTCTL set.
    write8(REG_RIRBCTL, 0x03);
    wait_ticks(1);

    USE_CORB = true;
    serial::write_str("[HDA] CORB/RIRB running\r\n");
    true
}

// ─── Output stream setup ──────────────────────────────────────────────────

unsafe fn output_sd_base() -> u32 {
    // Input SDs come first (ISS × 0x20), then output SDs.
    0x80 + (ISS as u32) * 0x20
}

unsafe fn setup_output_stream() -> bool {
    let ring = match physical::alloc_frames(DMA_ENTRIES as u64) {
        Some(p) => p,
        None => {
            serial::write_str("[HDA] 128 KiB DMA ring alloc failed\r\n");
            return false;
        }
    };
    RING_PHYS = ring;
    RING_VIRT = phys_to_virt(ring);
    core::ptr::write_bytes(RING_VIRT as *mut u8, 0, DMA_TOTAL);

    let bdl_frame = match physical::alloc_frame() {
        Some(f) => f,
        None => {
            serial::write_str("[HDA] BDL alloc failed\r\n");
            return false;
        }
    };
    BDL_PHYS = bdl_frame;
    BDL_VIRT = phys_to_virt(bdl_frame);
    core::ptr::write_bytes(BDL_VIRT as *mut u8, 0, 4096);

    let bdl = BDL_VIRT as *mut BdlEntry;
    for i in 0..DMA_ENTRIES {
        let phys = RING_PHYS + (i * DMA_BUF_SIZE) as u64;
        write_volatile(bdl.add(i), BdlEntry {
            addr_lo: phys as u32,
            addr_hi: (phys >> 32) as u32,
            length:  DMA_BUF_SIZE as u32,
            ioc:     0, // polled: no interrupt on completion
        });
    }

    let sd = output_sd_base();

    // Stream reset: set SRST, wait until it reads 1, clear, wait until 0.
    let ctl = read32(sd + SD_OFF_CTL) & 0x00FF_FFFF;
    write32(sd + SD_OFF_CTL, (ctl & !SD_CTL_RUN) | SD_CTL_SRST);
    let t = ticks() + 5;
    while read8(sd + SD_OFF_CTL) & (SD_CTL_SRST as u8) == 0 && ticks() < t { core::arch::asm!("pause"); }
    write32(sd + SD_OFF_CTL, ctl & !(SD_CTL_SRST | SD_CTL_RUN));
    let t = ticks() + 5;
    while read8(sd + SD_OFF_CTL) & (SD_CTL_SRST as u8) != 0 && ticks() < t { core::arch::asm!("pause"); }

    write16(sd + SD_OFF_FMT, SDFMT_48000_16_STEREO);
    write32(sd + SD_OFF_CBL, DMA_TOTAL as u32);
    write16(sd + SD_OFF_LVI, (DMA_ENTRIES - 1) as u16);
    write32(sd + SD_OFF_BDPL, BDL_PHYS as u32);
    write32(sd + SD_OFF_BDPU, (BDL_PHYS >> 32) as u32);

    // Stream tag 1, no interrupt enables, not running yet.
    let ctl = read32(sd + SD_OFF_CTL) & 0x000F_FFFF & !(0x1C); // clear IOCE/FEIE/DEIE
    write32(sd + SD_OFF_CTL, ctl | SD_STREAM_TAG);

    serial::write_str("[HDA] Output SD @0x"); super::log_hex32(sd);
    serial::write_str(": 48000Hz/16-bit/2ch, CBL="); super::log_dec(DMA_TOTAL as u64);
    serial::write_str(" LVI="); super::log_dec((DMA_ENTRIES - 1) as u64);
    serial::write_str(" ring phys=0x"); super::log_hex32((RING_PHYS >> 32) as u32); super::log_hex32(RING_PHYS as u32);
    serial::write_str("\r\n");
    true
}

// ─── Codec configuration ──────────────────────────────────────────────────

/// Amp payload that sets 0 dB (or the closest step) and unmutes.
fn amp_0db(caps: u32) -> u16 {
    let offset = (caps & 0x7F) as u16;          // gain value that equals 0 dB
    let steps  = ((caps >> 8) & 0x7F) as u16;   // highest valid gain value
    offset.min(steps)
}

unsafe fn configure_codec(codec: u8) -> bool {
    let vendor = cmd(make_get_param(codec, 0x00, PARAM_VENDOR_ID));
    serial::write_str("[HDA] Codec "); super::log_dec(codec as u64);
    serial::write_str(" vendor/device = 0x"); super::log_hex32(vendor);
    serial::write_str("\r\n");
    if vendor == 0 || vendor == 0xFFFF_FFFF { return false; }

    // Find the Audio Function Group among the root's function groups.
    let root_nc = cmd(make_get_param(codec, 0x00, PARAM_NODE_COUNT));
    let fg_start = ((root_nc >> 16) & 0xFF) as u8;
    let fg_count = (root_nc & 0xFF) as u8;
    let mut afg = 0u8;
    for nid in fg_start..fg_start.saturating_add(fg_count) {
        let ft = cmd(make_get_param(codec, nid, PARAM_FUNC_TYPE)) & 0xFF;
        if ft == 0x01 { afg = nid; break; }
    }
    if afg == 0 {
        serial::write_str("[HDA] No Audio Function Group on this codec\r\n");
        return false;
    }

    cmd(make_verb(codec, afg, VERB_SET_POWER_STATE, 0x00));
    wait_ticks(2);

    let afg_nc = cmd(make_get_param(codec, afg, PARAM_NODE_COUNT));
    let w_start = ((afg_nc >> 16) & 0xFF) as u8;
    let w_count = (afg_nc & 0xFF) as u8;
    let w_end = w_start.saturating_add(w_count);
    let afg_out_caps = cmd(make_get_param(codec, afg, PARAM_OUT_AMP_CAP));
    let afg_in_caps  = cmd(make_get_param(codec, afg, PARAM_IN_AMP_CAP));

    serial::write_str("[HDA] AFG NID=0x"); super::log_hex8(afg);
    serial::write_str(" widgets 0x"); super::log_hex8(w_start);
    serial::write_str("..0x"); super::log_hex8(w_end.saturating_sub(1));
    serial::write_str("\r\n");

    for nid in w_start..w_end {
        cmd(make_verb(codec, nid, VERB_SET_POWER_STATE, 0x00));
    }
    wait_ticks(2);

    let mut dacs = 0u8;
    let mut pins = 0u8;
    for nid in w_start..w_end {
        let wcap = cmd(make_get_param(codec, nid, PARAM_AUDIO_CAP));
        let wtype = (wcap >> 20) & 0xF;
        let has_in_amp  = wcap & (1 << 1) != 0;
        let has_out_amp = wcap & (1 << 2) != 0;
        let override_amp = wcap & (1 << 3) != 0;
        let out_caps = if override_amp { cmd(make_get_param(codec, nid, PARAM_OUT_AMP_CAP)) } else { afg_out_caps };
        let in_caps  = if override_amp { cmd(make_get_param(codec, nid, PARAM_IN_AMP_CAP)) } else { afg_in_caps };

        // Unmute + 0 dB on every amp along possible output paths.
        if has_out_amp && wtype != 0x1 {
            cmd(make_set_amp(codec, nid, 0xB000 | amp_0db(out_caps)));
        }
        if has_in_amp && (wtype == 0x2 || wtype == 0x3 || wtype == 0x4) {
            for idx in 0u16..8 {
                cmd(make_set_amp(codec, nid, 0x7000 | (idx << 8) | amp_0db(in_caps)));
            }
        }

        match wtype {
            0x0 => {
                // Audio Output converter: every DAC follows stream tag 1,
                // so whichever DAC the pins are wired to gets the samples.
                cmd(make_set_fmt(codec, nid, SDFMT_48000_16_STEREO));
                cmd(make_verb(codec, nid, VERB_SET_STREAM_CHAN, (1 << 4) | 0));
                dacs += 1;
                serial::write_str("[HDA]   DAC   NID=0x"); super::log_hex8(nid);
                serial::write_str(" -> stream 1\r\n");
            }
            0x3 => {
                cmd(make_verb(codec, nid, VERB_SET_CONNECT_SEL, 0x00));
            }
            0x4 => {
                let pincap = cmd(make_get_param(codec, nid, PARAM_PIN_CAP));
                if pincap & (1 << 4) != 0 {
                    // Output-capable: OUT_EN (+HP_EN if headphone-capable).
                    let ctl = 0x40 | if pincap & (1 << 3) != 0 { 0x80 } else { 0 };
                    cmd(make_verb(codec, nid, VERB_SET_PIN_WIDGET_CTL, ctl));
                    if pincap & (1 << 16) != 0 {
                        cmd(make_verb(codec, nid, VERB_SET_EAPD, 0x02));
                    }
                    cmd(make_verb(codec, nid, VERB_SET_CONNECT_SEL, 0x00));
                    pins += 1;
                    serial::write_str("[HDA]   PIN   NID=0x"); super::log_hex8(nid);
                    serial::write_str(" output enabled (pincap=0x"); super::log_hex32(pincap);
                    serial::write_str(")\r\n");
                }
            }
            _ => {}
        }
    }
    DAC_COUNT = dacs;
    OUT_PIN_COUNT = pins;
    serial::write_str("[HDA] Codec configured: ");
    super::log_dec(dacs as u64); serial::write_str(" DAC(s), ");
    super::log_dec(pins as u64); serial::write_str(" output pin(s), amps at 0 dB\r\n");
    dacs > 0
}

// ─── Public init ──────────────────────────────────────────────────────────

pub fn init() -> bool {
    let (b, d, f) = if let Some(dev) = crate::pci::find_by_class(0x04, 0x03, 0x00) {
        (dev.bus, dev.device, dev.function)
    } else {
        let mut found = None;
        'scan: for bus in 0..=255u8 {
            for dev in 0..32u8 {
                for func in 0..8u8 {
                    if crate::pci::vendor_id(bus, dev, func) == 0xFFFF { continue; }
                    let (class, subclass, _) = crate::pci::class_code(bus, dev, func);
                    if class == 0x04 && subclass == 0x03 {
                        found = Some((bus, dev, func));
                        break 'scan;
                    }
                }
            }
        }
        match found {
            Some(p) => p,
            None => {
                serial::write_str("[HDA] No HD Audio controller found\r\n");
                return false;
            }
        }
    };

    let vid = crate::pci::vendor_id(b, d, f);
    let did = crate::pci::device_id(b, d, f);
    serial::write_str("[HDA] Found ");
    super::log_hex16(vid); serial::write_str(":"); super::log_hex16(did);
    serial::write_str(" at "); super::log_hex8(b); serial::write_str(":");
    super::log_hex8(d); serial::write_str("."); super::log_dec(f as u64);
    serial::write_str("\r\n");

    crate::pci::enable_bus_master(b, d, f);
    unsafe { PCI_IRQ = crate::pci::interrupt_line(b, d, f); }

    let bar0 = match crate::pci::read_bar(b, d, f, 0) {
        crate::pci::BarType::Mmio { base, .. } => base,
        _ => {
            serial::write_str("[HDA] BAR0 is not MMIO — aborting\r\n");
            return false;
        }
    };
    serial::write_str("[HDA] MMIO BAR0=0x");
    super::log_hex32((bar0 >> 32) as u32); super::log_hex32(bar0 as u32);
    serial::write_str("\r\n");

    unsafe {
        MMIO_BASE = phys_to_virt(bar0);

        // Controller reset: CRST=0, wait, CRST=1, wait until it reads 1.
        write32(REG_INTCTL, 0);
        write8(REG_CORBCTL, 0);
        write8(REG_RIRBCTL, 0);
        let gctl = read32(REG_GCTL);
        write32(REG_GCTL, gctl & !GCTL_CRST);
        let t = ticks() + 10;
        while read32(REG_GCTL) & GCTL_CRST != 0 && ticks() < t { core::arch::asm!("pause"); }
        wait_ticks(1);
        write32(REG_GCTL, read32(REG_GCTL) | GCTL_CRST);
        let t = ticks() + 10;
        while read32(REG_GCTL) & GCTL_CRST == 0 && ticks() < t { core::arch::asm!("pause"); }
        if read32(REG_GCTL) & GCTL_CRST == 0 {
            serial::write_str("[HDA] Controller did not leave reset (GCTL.CRST=0)\r\n");
            return false;
        }
        wait_ticks(2); // codecs need >521 µs to request a state change

        let mut codec_mask = 0u16;
        let deadline = ticks() + 20;
        while ticks() < deadline {
            codec_mask = read16(REG_STATESTS);
            if codec_mask != 0 { break; }
            core::arch::asm!("pause");
        }
        if codec_mask == 0 {
            serial::write_str("[HDA] No codecs detected (STATESTS=0)\r\n");
            return false;
        }
        serial::write_str("[HDA] STATESTS=0x"); super::log_hex16(codec_mask);
        serial::write_str("\r\n");
        write16(REG_STATESTS, codec_mask);

        let gcap = read16(REG_GCAP);
        ISS = ((gcap >> 8) & 0xF) as u8;
        let oss = ((gcap >> 12) & 0xF) as u8;
        serial::write_str("[HDA] GCAP=0x"); super::log_hex16(gcap);
        serial::write_str(" ISS="); super::log_dec(ISS as u64);
        serial::write_str(" OSS="); super::log_dec(oss as u64);
        serial::write_str(" version "); super::log_dec(read8(REG_VMAJ) as u64);
        serial::write_str("."); super::log_dec(read8(REG_VMIN) as u64);
        serial::write_str("\r\n");
        if oss == 0 {
            serial::write_str("[HDA] No output streams available\r\n");
            return false;
        }

        if !setup_corb_rirb() { return false; }
        if !setup_output_stream() { return false; }

        let mut ok = false;
        for codec in 0..15u8 {
            if codec_mask & (1 << codec) == 0 { continue; }
            if configure_codec(codec) { ok = true; }
        }
        if !ok {
            serial::write_str("[HDA] No codec with an output converter could be configured\r\n");
            return false;
        }

        let sd = output_sd_base();
        let ctl = read32(sd + SD_OFF_CTL) & 0x00FF_FFFF;
        write32(sd + SD_OFF_CTL, ctl | SD_CTL_RUN);
        wait_ticks(2);
        let lpib0 = read32(sd + SD_OFF_LPIB);
        wait_ticks(3);
        let lpib1 = read32(sd + SD_OFF_LPIB);
        serial::write_str("[HDA] Stream running: SDCTL=0x"); super::log_hex32(read32(sd + SD_OFF_CTL));
        serial::write_str(" LPIB "); super::log_dec(lpib0 as u64);
        serial::write_str(" -> "); super::log_dec(lpib1 as u64);
        serial::write_str(if lpib0 != lpib1 { " (DMA advancing)\r\n" } else { " (WARNING: DMA position not moving)\r\n" });

        AUDIO_READY.store(true, Ordering::Release);
    }

    serial::write_str("[HDA] Audio driver initialized — 48000 Hz s16 stereo\r\n");
    true
}

// ─── Polled ring interface (audio::mod) ───────────────────────────────────

pub fn ring_ptr() -> *mut u8 { unsafe { RING_VIRT as *mut u8 } }
pub fn ring_bytes() -> usize { DMA_TOTAL }

pub fn hw_pos() -> usize {
    if !AUDIO_READY.load(Ordering::Relaxed) { return 0; }
    unsafe { (read32(output_sd_base() + SD_OFF_LPIB) as usize) % DMA_TOTAL }
}

pub fn is_ready() -> bool { AUDIO_READY.load(Ordering::Relaxed) }
pub fn sample_rate() -> u32 { unsafe { SAMPLE_RATE_HZ } }
pub fn irq_line() -> u8 { unsafe { PCI_IRQ } }
pub fn volume() -> u8 { unsafe { MASTER_VOLUME } }

/// Volume is applied in software by audio::mod; just remember it here.
pub fn set_volume(pct: u8) { unsafe { MASTER_VOLUME = pct.min(100); } }

pub fn dump_status() {
    if !AUDIO_READY.load(Ordering::Relaxed) {
        serial::write_str("[HDA] Not initialized\r\n");
        return;
    }
    unsafe {
        let sd = output_sd_base();
        serial::write_str("[HDA] GCTL=0x"); super::log_hex32(read32(REG_GCTL));
        serial::write_str(" GSTS=0x"); super::log_hex16(read16(REG_GSTS));
        serial::write_str(" INTSTS=0x"); super::log_hex32(read32(REG_INTSTS));
        serial::write_str(" WALCLK=0x"); super::log_hex32(read32(REG_WALCLK));
        serial::write_str("\r\n[HDA] SD CTL=0x"); super::log_hex32(read32(sd + SD_OFF_CTL) & 0x00FF_FFFF);
        serial::write_str(" STS=0x"); super::log_hex8(read8(sd + SD_OFF_STS));
        serial::write_str(" LPIB="); super::log_dec(read32(sd + SD_OFF_LPIB) as u64);
        serial::write_str(" CBL="); super::log_dec(read32(sd + SD_OFF_CBL) as u64);
        serial::write_str(" LVI="); super::log_dec(read16(sd + SD_OFF_LVI) as u64);
        serial::write_str(" FMT=0x"); super::log_hex16(read16(sd + SD_OFF_FMT));
        serial::write_str("\r\n[HDA] cmd transport: ");
        serial::write_str(if USE_CORB { "CORB/RIRB" } else { "Immediate" });
        serial::write_str(", DACs="); super::log_dec(DAC_COUNT as u64);
        serial::write_str(" out-pins="); super::log_dec(OUT_PIN_COUNT as u64);
        serial::write_str(" volume="); super::log_dec(MASTER_VOLUME as u64);
        serial::write_str("% (software)\r\n");
    }
}

/// Current DMA link position (LPIB) in bytes, ring size is ring_bytes().
pub fn dma_position() -> u32 {
    if !AUDIO_READY.load(Ordering::Relaxed) { return 0; }
    unsafe { read32(output_sd_base() + SD_OFF_LPIB) }
}

/// Stop the output stream DMA (before reset / power-off).
pub fn stop() {
    unsafe {
        if MMIO_BASE == 0 { return; }
        let sd = output_sd_base();
        let ctl = read32(sd + SD_OFF_CTL) & 0x00FF_FFFF;
        write32(sd + SD_OFF_CTL, ctl & !SD_CTL_RUN);
    }
}
