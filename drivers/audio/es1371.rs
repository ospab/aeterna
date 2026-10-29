/*
 * Ensoniq AudioPCI ES1371 / ES1373 / CT5880 (and ES1370) — AETERNA
 *
 * PCI IDs:  1274:1371  ES1371 / ES1373 (by revision) — VMware "es1371"
 *           1274:5880  Creative CT5880 (ES1373 core)
 *           1274:5000  ES1370 (AK4531 codec, no SRC) — QEMU `-device ES1370`;
 *                      supported mainly so the DMA path can be tested in QEMU
 *
 * Register map follows the Linux snd-ens1371 driver (sound/pci/ens1370.c)
 * and NetBSD eap(4).  All offsets are from the BAR0 I/O base:
 *
 *   0x00 CONTROL   DAC2_EN = bit 5, SYNC_RES (1371 warm AC97 reset) = bit 14
 *                  ES1370: CDC_EN bit 1, PCLKDIV bits 28:16 (DAC2 rate)
 *   0x04 STATUS    read-only except 1371 AC97 cold-reset bit 29; INTR = bit 31,
 *                  DAC2 = bit 1.  Interrupts are acknowledged by toggling
 *                  P2_INT_EN in SERIAL, not by writing STATUS.
 *   0x0C MEM_PAGE  page for 0x30..0x3F
 *   0x10 SMPRATE   1371: sample-rate-converter RAM interface
 *                  (addr 31:25, WE 24, BUSY 23, DIS 22..19, data 15:0)
 *                  1370: AK4531 codec write register (16-bit)
 *   0x14 CODEC     1371: AC97 access — RDY bit 31, WIP bit 30, read bit 23,
 *                  addr 22:16, data 15:0
 *   0x18 LEGACY    1371 legacy (SB/joystick) control — written 0
 *   0x20 SERIAL    P2 mode bits 3:2 (3 = 16-bit stereo), P2_INT_EN bit 9,
 *                  P2_PAUSE bit 12, P2_LOOP_SEL bit 14 (0 = loop),
 *                  P2_ST_INC 18:16, P2_END_INC 21:19 (2 for 16-bit)
 *   0x28 DAC2_COUNT  sample frames per interrupt - 1 (current count in 31:16)
 *   0x38 DAC2_FRAME  (page 0x0C) physical buffer address (32-bit)
 *   0x3C DAC2_SIZE   (page 0x0C) buffer size in dwords - 1 (bits 15:0);
 *                    bits 31:16 = current dword position (play pointer)
 *
 * Operation: one physically contiguous 128 KiB buffer below 4 GiB is played
 * by DAC2 in loop mode forever; audio::mod writes ahead of the play pointer
 * read from DAC2_SIZE.  No interrupts are used (P2_INT_EN stays 0).
 *
 * The ES1371 has a sample-rate converter between DAC2 and the AC97 link
 * (which always runs at 48 kHz).  Its RAM must be initialised exactly like
 * Linux does or the chip stays silent / locks up; DAC2 is then programmed
 * to 48000 Hz (SRC ratio 1:1).
 */

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use core::arch::asm;

use crate::arch::x86_64::serial;
use crate::mm::physical;
use crate::mm::r#virtual::phys_to_virt;
use super::{log_hex8, log_hex16, log_hex32, log_dec};

// ─── PCI IDs ─────────────────────────────────────────────────────────────────

const VID_ENSONIQ: u16 = 0x1274;
const DID_ES1371:  u16 = 0x1371;
const DID_CT5880:  u16 = 0x5880;
const DID_ES1370:  u16 = 0x5000;

// ─── Registers ───────────────────────────────────────────────────────────────

const REG_CONTROL:   u16 = 0x00;
const REG_STATUS:    u16 = 0x04;
const REG_UART_CTRL: u16 = 0x09;
const REG_UART_RES:  u16 = 0x0A;
const REG_MEM_PAGE:  u16 = 0x0C;
const REG_SMPRATE:   u16 = 0x10; // 1371 SRC
const REG_1370_CODEC:u16 = 0x10; // 1370 AK4531
const REG_CODEC:     u16 = 0x14; // 1371 AC97
const REG_LEGACY:    u16 = 0x18;
const REG_SERIAL:    u16 = 0x20;
const REG_DAC2_COUNT:u16 = 0x28;
const REG_DAC2_FRAME:u16 = 0x38; // page 0x0C
const REG_DAC2_SIZE: u16 = 0x3C; // page 0x0C
const PAGE_DAC:      u32 = 0x0C;

// CONTROL
const CTRL_1371_SYNC_RES: u32 = 1 << 14;
const CTRL_DAC2_EN:       u32 = 1 << 5;
const CTRL_DAC1_EN:       u32 = 1 << 6;
const CTRL_ADC_EN:        u32 = 1 << 4;
const CTRL_1370_CDC_EN:   u32 = 1 << 1;
const CTRL_1370_SERR_DIS: u32 = 1 << 0;
const fn ctrl_1370_pclkdiv(d: u32) -> u32 { (d & 0x1FFF) << 16 }
const ES1370_SRCLOCK: u32 = 1_411_200;

// STATUS
const STAT_INTR:          u32 = 1 << 31;
const STAT_1371_AC97_RST: u32 = 1 << 29;
const STAT_1370_CSTAT:    u32 = 1 << 10;
const STAT_1371_SYNC_ERR: u32 = 1 << 8;
const STAT_DAC2:          u32 = 1 << 1;

// SERIAL
const SER_P2_END_INC_MASK: u32 = 7 << 19;
const SER_P2_ST_INC_MASK:  u32 = 7 << 16;
const SER_P2_LOOP_SEL:     u32 = 1 << 14;
const SER_P2_PAUSE:        u32 = 1 << 12;
const SER_P2_INT_EN:       u32 = 1 << 9;
const SER_P2_DAC_SEN:      u32 = 1 << 6;
const SER_P2_MODE_MASK:    u32 = 3 << 2;
const fn ser_p2_end_inc(v: u32) -> u32 { (v & 7) << 19 }
const fn ser_p2_mode(v: u32) -> u32 { (v & 3) << 2 }

// CODEC (1371)
const CODEC_RDY:  u32 = 1 << 31;
const CODEC_WIP:  u32 = 1 << 30;
const CODEC_PIRD: u32 = 1 << 23;

// SMPRATE (1371 SRC)
const SRC_RAM_WE:   u32 = 1 << 24;
const SRC_RAM_BUSY: u32 = 1 << 23;
const SRC_DISABLE:  u32 = 1 << 22;
const SRC_DIS_P1:   u32 = 1 << 21;
const SRC_DIS_P2:   u32 = 1 << 20;
const SRC_DIS_R1:   u32 = 1 << 19;
const SRC_STATE_MASK: u32 = SRC_DISABLE | SRC_DIS_P1 | SRC_DIS_P2 | SRC_DIS_R1;
const fn src_addr(a: u32) -> u32 { (a & 0x7F) << 25 }

// SRC RAM layout
const SMPREG_DAC1: u32 = 0x70;
const SMPREG_DAC2: u32 = 0x74;
const SMPREG_ADC:  u32 = 0x78;
const SMPREG_VOL_ADC:  u32 = 0x6C;
const SMPREG_VOL_DAC1: u32 = 0x7C;
const SMPREG_VOL_DAC2: u32 = 0x7E;
const SMPREG_TRUNC_N:    u32 = 0x00;
const SMPREG_INT_REGS:   u32 = 0x01;
const SMPREG_VFREQ_FRAC: u32 = 0x03;

const POLL_COUNT: u32 = 0xA000;

// ─── Buffer ──────────────────────────────────────────────────────────────────

const RING_BYTES: usize = 128 * 1024;          // 32 frames, contiguous
const RING_DWORDS: u32 = (RING_BYTES / 4) as u32;
const PERIOD_FRAMES: u32 = 1024;               // DAC2_COUNT (no IRQ used)
const DAC2_RATE: u32 = 48000;

static mut DMA_PHYS: u32 = 0;
static mut DMA_VIRT: u64 = 0;

// ─── Driver state ────────────────────────────────────────────────────────────

static AUDIO_READY:    AtomicBool = AtomicBool::new(false);
static IO_BASE:        AtomicU32  = AtomicU32::new(0);
static ES_IRQ:         AtomicU8   = AtomicU8::new(0);
static SAMPLE_RATE_HZ: AtomicU32  = AtomicU32::new(DAC2_RATE);
static MASTER_VOLUME:  AtomicU8   = AtomicU8::new(100);
static IS_1370:        AtomicBool = AtomicBool::new(false);
static CHIP:           AtomicU8   = AtomicU8::new(0); // 0=ES1371 1=ES1373 2=CT5880 3=ES1370
static CODEC_TIMEOUTS: AtomicU32  = AtomicU32::new(0);
static mut CTRL: u32 = 0;
static mut SCTRL: u32 = 0;

// ─── I/O helpers ─────────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn inl(off: u16) -> u32 {
    let port = IO_BASE.load(Ordering::Relaxed) as u16 + off;
    let v: u32;
    asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack));
    v
}
#[inline(always)]
unsafe fn outl(off: u16, val: u32) {
    let port = IO_BASE.load(Ordering::Relaxed) as u16 + off;
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack));
}
#[inline(always)]
unsafe fn outw(off: u16, val: u16) {
    let port = IO_BASE.load(Ordering::Relaxed) as u16 + off;
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
}
#[inline(always)]
unsafe fn outb(off: u16, val: u8) {
    let port = IO_BASE.load(Ordering::Relaxed) as u16 + off;
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

fn udelay(us: u64) { crate::arch::x86_64::tsc::busy_wait_us(us); }

fn mdelay(ms: u64) {
    // PIT ticks are 10 ms; use them for long waits when interrupts run.
    let start = crate::arch::x86_64::idt::timer_ticks();
    let target = start + (ms + 9) / 10;
    let mut spins = 0u64;
    while crate::arch::x86_64::idt::timer_ticks() < target {
        unsafe { asm!("pause"); }
        spins += 1;
        if spins > ms * 200_000 { break; } // interrupts off: don't hang
    }
}

// ─── ES1371 sample-rate converter ────────────────────────────────────────────

/// Wait until the SRC RAM is not busy; returns the register value (0 on timeout).
unsafe fn src_wait_ready() -> u32 {
    for _ in 0..POLL_COUNT {
        let r = inl(REG_SMPRATE);
        if r & SRC_RAM_BUSY == 0 { return r; }
    }
    serial::write_str("[ES1371] SRC busy timeout (SMPRATE=0x");
    log_hex32(inl(REG_SMPRATE));
    serial::write_str(")\r\n");
    0
}

unsafe fn src_write(reg: u32, data: u16) {
    let r = (src_wait_ready() & SRC_STATE_MASK) | src_addr(reg) | (data as u32);
    outl(REG_SMPRATE, r | SRC_RAM_WE);
}

unsafe fn src_read(reg: u32) -> u16 {
    let orig = src_wait_ready();
    let r = (orig & SRC_STATE_MASK) | src_addr(reg) | 0x10000;
    outl(REG_SMPRATE, r);
    let mut temp = src_wait_ready();
    if temp & 0x0087_0000 != 0x0001_0000 {
        for _ in 0..POLL_COUNT {
            temp = inl(REG_SMPRATE);
            if temp & 0x0087_0000 == 0x0001_0000 { break; }
        }
    }
    let r = (orig & SRC_STATE_MASK) | src_addr(reg);
    outl(REG_SMPRATE, r);
    (temp & 0xFFFF) as u16
}

unsafe fn src_set_dac_rate(base: u32, dis_bit: u32, rate: u32) {
    let freq = ((rate << 15) + 1500) / 3000;
    let keep = SRC_DISABLE | SRC_DIS_P1 | SRC_DIS_P2 | SRC_DIS_R1;
    let r = (src_wait_ready() & (keep & !dis_bit)) | dis_bit;
    outl(REG_SMPRATE, r);
    let ir = src_read(base + SMPREG_INT_REGS);
    src_write(base + SMPREG_INT_REGS, (ir & 0x00FF) | (((freq >> 5) & 0xFC00) as u16));
    src_write(base + SMPREG_VFREQ_FRAC, (freq & 0x7FFF) as u16);
    let r = src_wait_ready() & (keep & !dis_bit);
    outl(REG_SMPRATE, r);
}

unsafe fn src_set_adc_rate(rate: u32) {
    let mut n = rate / 3000;
    if (1u32 << n) & ((1 << 15) | (1 << 13) | (1 << 11) | (1 << 9)) != 0 { n -= 1; }
    let mut truncm = (21 * n - 1) | 1;
    let freq = ((48000u32 << 15) / rate) * n;
    if rate >= 24000 {
        if truncm > 239 { truncm = 239; }
        src_write(SMPREG_ADC + SMPREG_TRUNC_N, ((((239 - truncm) >> 1) << 9) | (n << 4)) as u16);
    } else {
        if truncm > 119 { truncm = 119; }
        src_write(SMPREG_ADC + SMPREG_TRUNC_N, (0x8000 | (((119 - truncm) >> 1) << 9) | (n << 4)) as u16);
    }
    let ir = src_read(SMPREG_ADC + SMPREG_INT_REGS);
    src_write(SMPREG_ADC + SMPREG_INT_REGS, (ir & 0x00FF) | (((freq >> 5) & 0xFC00) as u16));
    src_write(SMPREG_ADC + SMPREG_VFREQ_FRAC, (freq & 0x7FFF) as u16);
    src_write(SMPREG_VOL_ADC, (n << 8) as u16);
    src_write(SMPREG_VOL_ADC + 1, (n << 8) as u16);
}

/// Full SRC initialisation (Linux snd_ensoniq_chip_init, CHIP1371 branch).
unsafe fn src_init() -> bool {
    src_wait_ready();
    outl(REG_SMPRATE, SRC_DISABLE);
    for idx in 0..0x80u32 { src_write(idx, 0); }
    src_write(SMPREG_DAC1 + SMPREG_TRUNC_N, 16 << 4);
    src_write(SMPREG_DAC1 + SMPREG_INT_REGS, 16 << 10);
    src_write(SMPREG_DAC2 + SMPREG_TRUNC_N, 16 << 4);
    src_write(SMPREG_DAC2 + SMPREG_INT_REGS, 16 << 10);
    src_write(SMPREG_VOL_ADC, 1 << 12);
    src_write(SMPREG_VOL_ADC + 1, 1 << 12);
    src_write(SMPREG_VOL_DAC1, 1 << 12);
    src_write(SMPREG_VOL_DAC1 + 1, 1 << 12);
    src_write(SMPREG_VOL_DAC2, 1 << 12);
    src_write(SMPREG_VOL_DAC2 + 1, 1 << 12);
    src_set_adc_rate(22050);
    src_set_dac_rate(SMPREG_DAC1, SRC_DIS_P1, 22050);
    src_set_dac_rate(SMPREG_DAC2, SRC_DIS_P2, DAC2_RATE);
    // Enabling the SRC with unprogrammed parameters locks the chip up —
    // everything above must have been written first.
    src_wait_ready();
    outl(REG_SMPRATE, 0);

    // Read back what we programmed.
    let vol_l = src_read(SMPREG_VOL_DAC2);
    let vol_r = src_read(SMPREG_VOL_DAC2 + 1);
    let ir    = src_read(SMPREG_DAC2 + SMPREG_INT_REGS);
    let vf    = src_read(SMPREG_DAC2 + SMPREG_VFREQ_FRAC);
    let freq  = ((DAC2_RATE << 15) + 1500) / 3000;
    serial::write_str("[ES1371] SRC readback: DAC2 vol L=0x"); log_hex16(vol_l);
    serial::write_str(" R=0x"); log_hex16(vol_r);
    serial::write_str(" INT_REGS=0x"); log_hex16(ir);
    serial::write_str(" VFREQ_FRAC=0x"); log_hex16(vf);
    serial::write_str(" (expect vol 0x1000, INT_REGS hi=0x"); log_hex16(((freq >> 5) & 0xFC00) as u16);
    serial::write_str(", FRAC=0x"); log_hex16((freq & 0x7FFF) as u16);
    serial::write_str(") SMPRATE=0x"); log_hex32(inl(REG_SMPRATE));
    serial::write_str("\r\n");
    let ok = vol_l == 0x1000 && vol_r == 0x1000;
    if !ok {
        serial::write_str("[ES1371] WARNING: SRC RAM readback mismatch — SRC may not be emulated/working\r\n");
    }
    ok
}

// ─── ES1371 AC97 codec access ────────────────────────────────────────────────

/// Wait for the codec interface to be idle (WIP=0).
unsafe fn codec_idle() -> bool {
    for _ in 0..POLL_COUNT {
        if inl(REG_CODEC) & CODEC_WIP == 0 { return true; }
    }
    false
}

/// Linux snd_es1371_codec_write/read: the access must be issued while the
/// SRC is in a "safe" state, otherwise the AC-link slot timing corrupts it.
unsafe fn codec_issue(word: u32) {
    let x = src_wait_ready();
    outl(REG_SMPRATE, (x & SRC_STATE_MASK) | 0x0001_0000);
    for _ in 0..POLL_COUNT {
        if inl(REG_SMPRATE) & 0x0087_0000 == 0 { break; }
    }
    for _ in 0..POLL_COUNT {
        if inl(REG_SMPRATE) & 0x0087_0000 == 0x0001_0000 { break; }
    }
    outl(REG_CODEC, word);
    src_wait_ready();
    outl(REG_SMPRATE, x);
}

unsafe fn ac97_write(reg: u8, val: u16) {
    if !codec_idle() {
        CODEC_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        serial::write_str("[ES1371] codec write timeout (WIP stuck), reg 0x"); log_hex8(reg);
        serial::write_str(" CODEC=0x"); log_hex32(inl(REG_CODEC)); serial::write_str("\r\n");
        return;
    }
    codec_issue(((reg as u32 & 0x7F) << 16) | val as u32);
}

/// Returns None on timeout.
unsafe fn ac97_read(reg: u8) -> Option<u16> {
    for _attempt in 0..3 {
        if !codec_idle() { continue; }
        codec_issue(((reg as u32 & 0x7F) << 16) | CODEC_PIRD);
        codec_idle();
        for _ in 0..POLL_COUNT {
            let x = inl(REG_CODEC);
            if x & CODEC_RDY != 0 { return Some((x & 0xFFFF) as u16); }
        }
    }
    CODEC_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    serial::write_str("[ES1371] codec read timeout, reg 0x"); log_hex8(reg);
    serial::write_str(" CODEC=0x"); log_hex32(inl(REG_CODEC)); serial::write_str("\r\n");
    None
}

unsafe fn ac97_write_verify(name: &str, reg: u8, val: u16) {
    let mut rb = None;
    for _ in 0..4 {
        ac97_write(reg, val);
        rb = ac97_read(reg);
        if rb == Some(val) { break; }
        mdelay(10);
    }
    serial::write_str("[ES1371]   AC97 "); serial::write_str(name);
    serial::write_str(" (0x"); log_hex8(reg); serial::write_str(") <- 0x"); log_hex16(val);
    match rb {
        Some(v) => {
            serial::write_str(" readback 0x"); log_hex16(v);
            if v != val { serial::write_str(" (differs: codec ignores some bits or reg absent)"); }
        }
        None => serial::write_str(" readback TIMEOUT"),
    }
    serial::write_str("\r\n");
}

// ─── ES1370 AK4531 codec ─────────────────────────────────────────────────────

unsafe fn ak4531_write(reg: u8, val: u8) {
    for _ in 0..POLL_COUNT {
        if inl(REG_STATUS) & STAT_1370_CSTAT == 0 { break; }
    }
    outw(REG_1370_CODEC, ((reg as u16) << 8) | val as u16);
}

// ─── PCI discovery ───────────────────────────────────────────────────────────

fn find_device() -> Option<(u8, u8, u8, u16)> {
    for &did in &[DID_ES1371, DID_CT5880, DID_ES1370] {
        if let Some(d) = crate::pci::find_by_vendor_device(VID_ENSONIQ, did) {
            return Some((d.bus, d.device, d.function, did));
        }
    }
    // Raw scan of every bus (devices may sit behind PCI-PCI bridges).
    for b in 0u8..=255 {
        for d in 0u8..32 {
            for f in 0u8..8 {
                if crate::pci::vendor_id(b, d, f) != VID_ENSONIQ { continue; }
                let did = crate::pci::device_id(b, d, f);
                if did == DID_ES1371 || did == DID_CT5880 || did == DID_ES1370 {
                    return Some((b, d, f, did));
                }
            }
        }
    }
    None
}

// ─── Init ────────────────────────────────────────────────────────────────────

pub fn init() -> bool {
    let (bus, dev, func, did) = match find_device() {
        Some(x) => x,
        None => {
            serial::write_str("[ES1371] No Ensoniq AudioPCI (1274:1371/5880/5000) found\r\n");
            return false;
        }
    };
    let rev = (crate::pci::config_read32(bus, dev, func, 0x08) & 0xFF) as u8;
    let is1370 = did == DID_ES1370;
    IS_1370.store(is1370, Ordering::Relaxed);
    let chip = match (did, rev) {
        (DID_ES1370, _) => 3,
        (DID_CT5880, _) => 2,
        (_, 0x07) => 2,               // CT5880 rev A reports 1371
        (_, 0x04) | (_, 0x06) | (_, 0x08) => 1, // ES1373
        _ => 0,
    };
    CHIP.store(chip, Ordering::Relaxed);

    serial::write_str("[ES1371] Found 1274:"); log_hex16(did);
    serial::write_str(" rev 0x"); log_hex8(rev);
    serial::write_str(" ("); serial::write_str(chip_name());
    serial::write_str(") at "); log_hex8(bus); serial::write_str(":");
    log_hex8(dev); serial::write_str("."); log_dec(func as u64);
    serial::write_str("\r\n");

    // ── BAR0 must be I/O space ────────────────────────────────────────────
    let (io_base, io_size) = match crate::pci::read_bar(bus, dev, func, 0) {
        crate::pci::BarType::Io { base, size } => (base, size),
        other => {
            serial::write_str("[ES1371] BAR0 is not an I/O BAR (raw 0x");
            log_hex32(crate::pci::config_read32(bus, dev, func, 0x10));
            serial::write_str(") — aborting\r\n");
            let _ = other;
            return false;
        }
    };
    serial::write_str("[ES1371] BAR0 I/O base=0x"); log_hex32(io_base);
    serial::write_str(" size="); log_dec(io_size as u64);
    serial::write_str("\r\n");
    if io_base == 0 || io_base > 0xFFFF {
        serial::write_str("[ES1371] BAR0 not assigned by firmware — aborting\r\n");
        return false;
    }
    IO_BASE.store(io_base, Ordering::Relaxed);

    // ── PCI command: I/O space + bus master (memory space is unused) ──────
    let cmd0 = crate::pci::command(bus, dev, func);
    crate::pci::set_command(bus, dev, func, (cmd0 | 0x0001 | 0x0004) & !0x0400);
    let cmd1 = crate::pci::command(bus, dev, func);
    serial::write_str("[ES1371] PCI CMD 0x"); log_hex16(cmd0);
    serial::write_str(" -> 0x"); log_hex16(cmd1);
    serial::write_str(if cmd1 & 0x5 == 0x5 { " (IO+BM on)\r\n" } else { " (WARNING: IO/BM did not stick)\r\n" });
    let lat = crate::pci::config_read8(bus, dev, func, 0x0D);
    if lat < 0x20 { crate::pci::config_write8(bus, dev, func, 0x0D, 0x40); }

    let irq = crate::pci::interrupt_line(bus, dev, func);
    ES_IRQ.store(irq, Ordering::Relaxed);
    serial::write_str("[ES1371] PCI IRQ line="); log_dec(irq as u64);
    serial::write_str(" (unused: driver is polled)\r\n");

    unsafe {
        serial::write_str("[ES1371] Initial CONTROL=0x"); log_hex32(inl(REG_CONTROL));
        serial::write_str(" STATUS=0x"); log_hex32(inl(REG_STATUS));
        serial::write_str(" SERIAL=0x"); log_hex32(inl(REG_SERIAL));
        serial::write_str("\r\n");
        if inl(REG_STATUS) == 0xFFFF_FFFF {
            serial::write_str("[ES1371] Registers read 0xFFFFFFFF — I/O decode not working\r\n");
            return false;
        }

        let ok = if is1370 { init_es1370() } else { init_es1371(did, rev) };
        if !ok { return false; }

        // ── DMA buffer: 128 KiB contiguous below 4 GiB ─────────────────────
        let phys = match physical::alloc_frames((RING_BYTES / 4096) as u64) {
            Some(p) if p + RING_BYTES as u64 <= 0x1_0000_0000 => p,
            Some(p) => {
                serial::write_str("[ES1371] DMA buffer at 0x"); log_hex32((p >> 32) as u32);
                log_hex32(p as u32); serial::write_str(" is above 4 GiB — unusable\r\n");
                return false;
            }
            None => {
                serial::write_str("[ES1371] 128 KiB contiguous DMA alloc failed\r\n");
                return false;
            }
        };
        DMA_PHYS = phys as u32;
        DMA_VIRT = phys_to_virt(phys);
        core::ptr::write_bytes(DMA_VIRT as *mut u8, 0, RING_BYTES);

        // ── Program DAC2 (Linux snd_ensoniq_playback2_prepare) ─────────────
        CTRL &= !CTRL_DAC2_EN;
        outl(REG_CONTROL, CTRL);
        outl(REG_MEM_PAGE, PAGE_DAC);
        outl(REG_DAC2_FRAME, DMA_PHYS);
        outl(REG_DAC2_SIZE, RING_DWORDS - 1);
        SCTRL &= !(SER_P2_LOOP_SEL | SER_P2_PAUSE | SER_P2_DAC_SEN | SER_P2_END_INC_MASK
                   | SER_P2_ST_INC_MASK | SER_P2_MODE_MASK | SER_P2_INT_EN);
        // 16-bit stereo, loop.  P2_INT_EN is set exactly like Linux does (some
        // emulations, VMware included, only run the DAC with it on); the PIC
        // line stays masked and the status is acknowledged by ack_irq().
        SCTRL |= ser_p2_mode(3) | ser_p2_end_inc(2) | SER_P2_INT_EN;
        outl(REG_SERIAL, SCTRL);
        outl(REG_DAC2_COUNT, PERIOD_FRAMES - 1);

        outl(REG_MEM_PAGE, PAGE_DAC);
        let fr = inl(REG_DAC2_FRAME);
        let sz = inl(REG_DAC2_SIZE);
        serial::write_str("[ES1371] DAC2 FRAME=0x"); log_hex32(fr);
        serial::write_str(" SIZE=0x"); log_hex32(sz);
        serial::write_str(" SERIAL=0x"); log_hex32(inl(REG_SERIAL));
        serial::write_str(" COUNT=0x"); log_hex32(inl(REG_DAC2_COUNT));
        serial::write_str(if fr == DMA_PHYS && sz & 0xFFFF == RING_DWORDS - 1 { " (OK)\r\n" } else { " (MISMATCH)\r\n" });

        // ── Start ─────────────────────────────────────────────────────────
        CTRL |= CTRL_DAC2_EN;
        outl(REG_CONTROL, CTRL);
        serial::write_str("[ES1371] DAC2 enabled, CONTROL=0x"); log_hex32(inl(REG_CONTROL));
        serial::write_str("\r\n");

        // Verify the play pointer moves (proves DMA + clocking work).
        let p0 = hw_pos_raw();
        mdelay(50);
        let p1 = hw_pos_raw();
        serial::write_str("[ES1371] DAC2 position after 50 ms: "); log_dec(p0 as u64);
        serial::write_str(" -> "); log_dec(p1 as u64);
        if p0 == p1 {
            serial::write_str(" — WARNING: play pointer NOT moving (DMA not running)\r\n");
        } else {
            let moved = (p1 + RING_BYTES - p0) % RING_BYTES;
            serial::write_str(" bytes (");
            log_dec((moved as u64) / 4 * 20); // frames per second estimate (50 ms)
            serial::write_str(" frames/s est.)\r\n");
        }
    }

    AUDIO_READY.store(true, Ordering::Release);
    serial::write_str("[ES1371] Driver ready — ");
    log_dec(SAMPLE_RATE_HZ.load(Ordering::Relaxed) as u64);
    serial::write_str(" Hz 16-bit stereo, polled DMA loop\r\n");
    true
}

/// ES1371/ES1373/CT5880: reset, SRC init, AC97 codec init.
unsafe fn init_es1371(did: u16, rev: u8) -> bool {
    // Linux es1371_ac97_reset_hack: CT5880 and ES1373 rev 8 need the cold
    // reset bit in STATUS and 20 ms for the codec to wake.
    let mut cssr = 0u32;
    if did == DID_CT5880 || rev == 0x07 || rev == 0x08 {
        cssr |= STAT_1371_AC97_RST;
    }

    CTRL = 0;
    SCTRL = 0;
    outl(REG_CONTROL, CTRL);
    outl(REG_SERIAL, SCTRL);
    outl(REG_LEGACY, 0);
    if cssr != 0 {
        outl(REG_STATUS, cssr);
        mdelay(20);
        serial::write_str("[ES1371] AC97 cold reset via STATUS bit 29 (CT5880/ES1373 quirk)\r\n");
    }

    // AC97 warm reset to start BITCLK.
    outl(REG_CONTROL, CTRL | CTRL_1371_SYNC_RES);
    let _ = inl(REG_CONTROL);
    udelay(20);
    outl(REG_CONTROL, CTRL);
    mdelay(20);
    serial::write_str("[ES1371] Warm AC97 reset done, STATUS=0x"); log_hex32(inl(REG_STATUS));
    serial::write_str("\r\n");

    // Sample-rate converter.
    serial::write_str("[ES1371] Initialising SRC RAM (DAC2 = 48000 Hz)\r\n");
    src_init();

    // Codec reset (write reg 0) then wait for the codec to report ready.
    outl(REG_CODEC, 0); // CODEC_WRITE(0, 0), as Linux does
    mdelay(20);
    outb(REG_UART_CTRL, 0);
    outb(REG_UART_RES, 0);
    outl(REG_STATUS, cssr);

    let mut ready = false;
    let mut pwr = 0u16;
    for _ in 0..50 {
        if let Some(v) = ac97_read(0x26) {
            pwr = v;
            if v & 0x000F == 0x000F { ready = true; break; }
        }
        mdelay(10);
    }
    serial::write_str("[ES1371] AC97 powerdown/status reg 0x26 = 0x"); log_hex16(pwr);
    serial::write_str(if ready { " (ADC/DAC/ANL/REF ready)\r\n" } else { " (codec NOT reporting ready — continuing anyway)\r\n" });

    let reset = ac97_read(0x00).unwrap_or(0xFFFF);
    let v1 = ac97_read(0x7C).unwrap_or(0xFFFF);
    let v2 = ac97_read(0x7E).unwrap_or(0xFFFF);
    serial::write_str("[ES1371] AC97 codec caps(0x00)=0x"); log_hex16(reset);
    serial::write_str(" vendor=0x"); log_hex16(v1); log_hex16(v2);
    if v1 != 0xFFFF && v1 != 0 {
        serial::write_str(" '");
        serial::write_byte((v1 >> 8) as u8); serial::write_byte(v1 as u8);
        serial::write_byte((v2 >> 8) as u8);
        serial::write_str("'");
    }
    serial::write_str("\r\n");

    // Unmute everything on the PCM → line-out path (0 dB).
    ac97_write_verify("master", 0x02, 0x0000);
    ac97_write_verify("headphone", 0x04, 0x0000);
    ac97_write_verify("mono", 0x06, 0x0000);
    ac97_write_verify("PCM out", 0x18, 0x0808);
    let ext = ac97_read(0x28).unwrap_or(0);
    serial::write_str("[ES1371] AC97 ext id(0x28)=0x"); log_hex16(ext);
    serial::write_str(" — codec left at its fixed 48 kHz link rate (SRC converts)\r\n");

    let st = inl(REG_STATUS);
    if st & STAT_1371_SYNC_ERR != 0 {
        serial::write_str("[ES1371] WARNING: STATUS.SYNC_ERR set (AC-link sync error)\r\n");
    }
    let to = CODEC_TIMEOUTS.load(Ordering::Relaxed);
    if to != 0 {
        serial::write_str("[ES1371] WARNING: "); log_dec(to as u64);
        serial::write_str(" codec access timeouts during init\r\n");
    }
    SAMPLE_RATE_HZ.store(DAC2_RATE, Ordering::Relaxed);
    true
}

/// ES1370: codec enable + DAC2 clock divider (no SRC).
unsafe fn init_es1370() -> bool {
    let div = ES1370_SRCLOCK / 44100 - 2; // = 30 → exactly 44100 Hz
    CTRL = CTRL_1370_CDC_EN | CTRL_1370_SERR_DIS | ctrl_1370_pclkdiv(div);
    SCTRL = 0;
    outl(REG_CONTROL, CTRL);
    outl(REG_SERIAL, SCTRL);
    // AK4531: reset release, clocks, master & voice at 0 dB, voice → output mixer.
    ak4531_write(0x16, 0x03); // RESET: power on, reset release
    mdelay(1);
    ak4531_write(0x17, 0x00); // CLOCK select
    ak4531_write(0x00, 0x00); // master L 0 dB
    ak4531_write(0x01, 0x00); // master R
    ak4531_write(0x02, 0x06); // voice L 0 dB
    ak4531_write(0x03, 0x06); // voice R
    ak4531_write(0x11, 0x0C); // OUT_SW2: voice L/R on
    SAMPLE_RATE_HZ.store(ES1370_SRCLOCK / (div + 2), Ordering::Relaxed);
    serial::write_str("[ES1370] Codec enabled, DAC2 divider "); log_dec(div as u64);
    serial::write_str(" -> "); log_dec((ES1370_SRCLOCK / (div + 2)) as u64);
    serial::write_str(" Hz, CONTROL=0x"); log_hex32(inl(REG_CONTROL)); serial::write_str("\r\n");
    true
}

// ─── Polled ring interface (audio::mod) ──────────────────────────────────────

unsafe fn hw_pos_raw() -> usize {
    outl(REG_MEM_PAGE, PAGE_DAC);
    let v = inl(REG_DAC2_SIZE);
    (((v >> 16) as usize) * 4) % RING_BYTES
}

pub fn ring_ptr() -> *mut u8 { unsafe { DMA_VIRT as *mut u8 } }
pub fn ring_bytes() -> usize { RING_BYTES }

pub fn hw_pos() -> usize {
    if !AUDIO_READY.load(Ordering::Acquire) { return 0; }
    unsafe { hw_pos_raw() }
}

pub fn is_ready() -> bool { AUDIO_READY.load(Ordering::Acquire) }
pub fn irq_line() -> u8 { ES_IRQ.load(Ordering::Relaxed) }
pub fn sample_rate() -> u32 { SAMPLE_RATE_HZ.load(Ordering::Relaxed) }
pub fn volume() -> u8 { MASTER_VOLUME.load(Ordering::Relaxed) }

pub fn chip_name() -> &'static str {
    match CHIP.load(Ordering::Relaxed) {
        1 => "ES1373",
        2 => "CT5880",
        3 => "ES1370",
        _ => "ES1371",
    }
}

/// Set master volume (0..100) through the codec master attenuator.
pub fn set_volume(pct: u8) {
    let pct = pct.min(100);
    MASTER_VOLUME.store(pct, Ordering::Relaxed);
    if !AUDIO_READY.load(Ordering::Acquire) { return; }
    unsafe {
        if IS_1370.load(Ordering::Relaxed) {
            let att = if pct == 0 { 0x80 } else { ((100 - pct as u32) * 0x1F / 100) as u8 };
            ak4531_write(0x00, att);
            ak4531_write(0x01, att);
        } else {
            // AC97 master: 6-bit attenuation in 1.5 dB steps (use 0..31), bit 15 mute.
            let val = if pct == 0 { 0x8000 } else {
                let att = ((100 - pct as u16) * 0x1F / 100) & 0x1F;
                att | (att << 8)
            };
            ac97_write(0x02, val);
            ac97_write(0x04, val);
        }
    }
}

/// IRQ hook: interrupts are never enabled, but acknowledge defensively by
/// toggling P2_INT_EN (the ES137x way to clear a DAC2 interrupt).
pub fn handle_irq() {
    if !AUDIO_READY.load(Ordering::Acquire) { return; }
    unsafe {
        let st = inl(REG_STATUS);
        if st & STAT_INTR == 0 { return; }
        outl(REG_SERIAL, SCTRL & !SER_P2_INT_EN & !(1 << 8) & !(1 << 10));
        outl(REG_SERIAL, SCTRL);
    }
}

/// Called from the 100 Hz timer: clears the (masked) DAC2 interrupt so the
/// chip keeps streaming with P2_INT_EN set.
pub fn ack_irq() { handle_irq(); }

pub fn dump_status() {
    serial::write_str("[ES1371-DIAG] === "); serial::write_str(chip_name());
    serial::write_str(" status ===\r\n");
    if !AUDIO_READY.load(Ordering::Acquire) {
        serial::write_str("[ES1371-DIAG] Driver NOT ready\r\n");
        return;
    }
    unsafe {
        let ctrl = inl(REG_CONTROL);
        let st = inl(REG_STATUS);
        let ser = inl(REG_SERIAL);
        let cnt = inl(REG_DAC2_COUNT);
        outl(REG_MEM_PAGE, PAGE_DAC);
        let fr = inl(REG_DAC2_FRAME);
        let sz = inl(REG_DAC2_SIZE);
        serial::write_str("[ES1371-DIAG] CONTROL=0x"); log_hex32(ctrl);
        serial::write_str(" (DAC2_EN="); serial::write_byte(if ctrl & CTRL_DAC2_EN != 0 { b'1' } else { b'0' });
        serial::write_str(") STATUS=0x"); log_hex32(st);
        serial::write_str(" SERIAL=0x"); log_hex32(ser);
        serial::write_str("\r\n[ES1371-DIAG] DAC2 FRAME=0x"); log_hex32(fr);
        serial::write_str(" SIZE=0x"); log_hex32(sz);
        serial::write_str(" (pos "); log_dec(((sz >> 16) as u64) * 4);
        serial::write_str("/"); log_dec(RING_BYTES as u64);
        serial::write_str(") COUNT=0x"); log_hex32(cnt);
        serial::write_str("\r\n");
        if !IS_1370.load(Ordering::Relaxed) {
            serial::write_str("[ES1371-DIAG] SMPRATE=0x"); log_hex32(inl(REG_SMPRATE));
            serial::write_str(" CODEC=0x"); log_hex32(inl(REG_CODEC));
            let m = ac97_read(0x02).unwrap_or(0xFFFF);
            let p = ac97_read(0x18).unwrap_or(0xFFFF);
            let pw = ac97_read(0x26).unwrap_or(0xFFFF);
            serial::write_str("\r\n[ES1371-DIAG] AC97 master=0x"); log_hex16(m);
            serial::write_str(" pcm=0x"); log_hex16(p);
            serial::write_str(" pwr=0x"); log_hex16(pw);
            serial::write_str(" codec timeouts="); log_dec(CODEC_TIMEOUTS.load(Ordering::Relaxed) as u64);
            serial::write_str("\r\n");
        }
    }
}

/// Stop DAC2 DMA (before reset / power-off).
pub fn stop() {
    unsafe {
        if IO_BASE.load(Ordering::Relaxed) == 0 { return; }
        CTRL &= !CTRL_DAC2_EN;
        outl(REG_CONTROL, CTRL);
    }
}
