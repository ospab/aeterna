/*
 * Audio subsystem for AETERNA microkernel
 *
 * Supported controllers, probed in this order:
 *
 *   1. ac97   — Intel ICH AC'97 (QEMU `-device AC97`, PCI 8086:2415)
 *   2. hda    — Intel High Definition Audio (QEMU `-device intel-hda`,
 *               VMware `sound.virtualDev = "hdaudio"`)
 *   3. es1371 — Ensoniq AudioPCI ES1371/ES1373/CT5880 (VMware default
 *               `es1371`, PCI 1274:1371) and ES1370 (QEMU `-device ES1370`)
 *
 * Every driver exposes the same thing: one cyclic DMA ring of 16-bit stereo
 * little-endian PCM that the hardware plays forever, plus the hardware's
 * current play position inside that ring.  The stream logic below (shared
 * by all drivers) keeps a write cursor ahead of the play position:
 *
 *   - queued bytes  = data written but not yet played
 *   - everything the hardware has already played is zeroed on the next call,
 *     so on an underrun the hardware plays silence, never stale audio
 *   - underruns (producer too slow) are detected and the write cursor is
 *     re-synchronised just ahead of the play position
 *
 * Nothing depends on the sound cards' interrupts: their PIC lines are never
 * unmasked.  Bookkeeping is driven by the producer (write_pcm / submit /
 * pump) and by timer_tick() from the PIT interrupt (100 Hz), which wipes
 * played data even when nobody is producing — so a finished sound is never
 * replayed when the hardware wraps around the ring.  STREAM_LOCK keeps the
 * two apart; the timer path only try-locks and skips if busy.
 *
 * APIs:
 *   write_pcm(data)  — blocking: waits for ring space until everything is
 *                      queued, returns while the tail is still playing
 *                      (used by soundtest and /dev/audio).
 *   submit(data)     — non-blocking: queues what fits, returns bytes taken
 *                      (used by the DOOM mixer together with queued_frames()).
 *   queued_frames()  — frames buffered ahead of the hardware.
 *   clear_buffer()   — silence everything immediately.
 */

pub mod ac97;
pub mod hda;
pub mod es1371;

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use crate::arch::x86_64::serial;

// 0 = none, 1 = AC97, 2 = HDA, 3 = ES1371/ES1370
static ACTIVE_DRIVER: AtomicU8 = AtomicU8::new(0);

/// Software volume (0..100) — applied to samples for drivers without a usable
/// hardware mixer (HDA).
static SW_VOLUME: AtomicU8 = AtomicU8::new(100);

/// Number of underruns (producer did not keep up) since boot.
static UNDERRUNS: AtomicU32 = AtomicU32::new(0);

/// Serialises STREAM between producers and the timer interrupt.
static STREAM_LOCK: AtomicBool = AtomicBool::new(false);

fn lock() {
    while STREAM_LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
}
fn try_lock() -> bool { !STREAM_LOCK.swap(true, Ordering::Acquire) }
fn unlock() { STREAM_LOCK.store(false, Ordering::Release); }

// ─── Stream state (single producer, no IRQ involvement) ─────────────────────

struct Stream {
    ring: *mut u8,   // virtual address of the cyclic DMA ring
    size: usize,     // ring size in bytes (multiple of 4)
    write_pos: usize,// ring offset where the next byte goes
    queued: usize,   // bytes between play position and write_pos
    last_hw: usize,  // play position seen by the previous update()
    last_tick: u64,  // PIT tick of the previous update()
    stuck_since: u64,// PIT tick at which the play position stopped moving (0 = moving)
    stuck_logged: bool,
    total_bytes: u64,
    dropped_bytes: u64,
}

static mut STREAM: Stream = Stream {
    ring: core::ptr::null_mut(), size: 0, write_pos: 0, queued: 0,
    last_hw: 0, last_tick: 0, stuck_since: 0, stuck_logged: false,
    total_bytes: 0, dropped_bytes: 0,
};

fn ticks() -> u64 { crate::arch::x86_64::idt::timer_ticks() }

fn interrupts_enabled() -> bool {
    let flags: u64;
    unsafe { core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags)); }
    flags & (1 << 9) != 0
}

/// Sleep roughly one timer tick (or spin when interrupts are off).
fn short_wait() {
    if interrupts_enabled() {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
    } else {
        for _ in 0..20_000 { unsafe { core::arch::asm!("pause", options(nomem, nostack)); } }
    }
}

fn hw_pos() -> usize {
    let p = match ACTIVE_DRIVER.load(Ordering::Relaxed) {
        1 => ac97::hw_pos(),
        2 => hda::hw_pos(),
        3 => es1371::hw_pos(),
        _ => 0,
    };
    let size = unsafe { STREAM.size };
    if size == 0 { 0 } else { (p % size) & !3 }
}

fn keepalive() {
    if ACTIVE_DRIVER.load(Ordering::Relaxed) == 1 { ac97::keepalive(); }
}

/// Bytes per second of the active stream.
fn byte_rate() -> usize { (sample_rate() as usize).max(8000) * 4 }

/// Silence lead inserted after an underrun (≈5 ms) so the first new samples
/// are not written under the hardware's read pointer.
fn lead_bytes() -> usize { ((byte_rate() / 200) + 3) & !3 }

unsafe fn ring_zero(off: usize, len: usize) {
    let s = &mut *core::ptr::addr_of_mut!(STREAM);
    if s.ring.is_null() || len == 0 { return; }
    let len = len.min(s.size);
    let first = len.min(s.size - off);
    core::ptr::write_bytes(s.ring.add(off), 0, first);
    if len > first { core::ptr::write_bytes(s.ring, 0, len - first); }
}

/// Register the ring of the driver that just initialised.
unsafe fn stream_attach(ring: *mut u8, size: usize) {
    let s = &mut *core::ptr::addr_of_mut!(STREAM);
    s.ring = ring;
    s.size = size & !3;
    core::ptr::write_bytes(ring, 0, s.size);
    let hw = hw_pos();
    s.last_hw = hw;
    s.write_pos = (hw + lead_bytes()) % s.size;
    s.queued = lead_bytes();
    s.last_tick = ticks();
    s.stuck_since = 0;
    s.stuck_logged = false;
}

/// Advance the bookkeeping to the current hardware position.
/// `from_timer`: called by the PIT tick — the stream simply running dry is
/// then not counted as an underrun, and no diagnostics are printed.
unsafe fn update(from_timer: bool) {
    let s = &mut *core::ptr::addr_of_mut!(STREAM);
    if s.ring.is_null() { return; }
    let size = s.size;
    let hw = hw_pos();
    let now = ticks();
    let adv = (hw + size - s.last_hw) % size;

    // Everything between last_hw and hw has been played: wipe it.
    ring_zero(s.last_hw, adv);

    let elapsed_ms = now.saturating_sub(s.last_tick) * 10;
    let ring_ms = (size as u64 * 1000) / byte_rate() as u64;
    let lapped = elapsed_ms + 30 >= ring_ms; // position may have wrapped unseen

    if lapped || adv >= s.queued {
        if s.queued > lead_bytes() && !from_timer {
            UNDERRUNS.fetch_add(1, Ordering::Relaxed);
        }
        if lapped { ring_zero(0, size); }
        s.write_pos = (hw + lead_bytes()) % size;
        s.queued = lead_bytes();
    } else {
        s.queued -= adv;
    }

    // Stall detection: data pending but the play position does not move.
    if adv == 0 && s.queued > lead_bytes() {
        if s.stuck_since == 0 {
            s.stuck_since = now.max(1);
        } else if now.saturating_sub(s.stuck_since) > 50 && !s.stuck_logged && !from_timer {
            s.stuck_logged = true;
            serial::write_str("[AUDIO] WARNING: DMA play position stuck at ");
            log_dec(hw as u64);
            serial::write_str(" for >500 ms (driver ");
            serial::write_str(active_driver_name());
            serial::write_str(") — hardware is not consuming samples\r\n");
            dump_status();
        }
    } else if adv != 0 {
        if s.stuck_logged {
            serial::write_str("[AUDIO] DMA play position moving again\r\n");
        }
        s.stuck_since = 0;
        s.stuck_logged = false;
    }

    s.last_hw = hw;
    s.last_tick = now;
    keepalive();
}

/// Copy samples into the ring at write_pos (applies software volume).
unsafe fn ring_put(data: &[u8]) {
    let s = &mut *core::ptr::addr_of_mut!(STREAM);
    let vol = if ACTIVE_DRIVER.load(Ordering::Relaxed) == 2 {
        SW_VOLUME.load(Ordering::Relaxed) as i32
    } else { 100 };
    let mut off = s.write_pos;
    if vol >= 100 {
        let first = data.len().min(s.size - off);
        core::ptr::copy_nonoverlapping(data.as_ptr(), s.ring.add(off), first);
        if data.len() > first {
            core::ptr::copy_nonoverlapping(data.as_ptr().add(first), s.ring, data.len() - first);
        }
    } else {
        // Perceptual curve: gain = (vol/100)^2, Q15.
        let g = (vol * vol * 32768) / 10000;
        let mut i = 0;
        while i + 1 < data.len() {
            let v = i16::from_le_bytes([data[i], data[i + 1]]) as i32;
            let o = ((v * g) >> 15) as i16;
            let b = o.to_le_bytes();
            *s.ring.add(off) = b[0];
            *s.ring.add(off + 1) = b[1];
            off = (off + 2) % s.size;
            i += 2;
        }
    }
    s.write_pos = (s.write_pos + data.len()) % s.size;
    s.queued += data.len();
    s.total_bytes += data.len() as u64;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Initialize audio subsystem during boot.  Returns true if a device works.
pub fn init() -> bool {
    serial::write_str("[AUDIO] Probing sound controllers (AC97, HDA, ES1371/ES1370)...\r\n");
    let (drv, ring, size) = if ac97::init() {
        (1u8, ac97::ring_ptr(), ac97::ring_bytes())
    } else if hda::init() {
        (2u8, hda::ring_ptr(), hda::ring_bytes())
    } else if es1371::init() {
        (3u8, es1371::ring_ptr(), es1371::ring_bytes())
    } else {
        report_unsupported();
        return false;
    };
    ACTIVE_DRIVER.store(drv, Ordering::Relaxed);
    lock();
    unsafe { stream_attach(ring, size); }
    unlock();
    serial::write_str("[AUDIO] Active driver: ");
    serial::write_str(active_driver_name());
    serial::write_str(", ");
    log_dec(sample_rate() as u64);
    serial::write_str(" Hz 16-bit stereo, DMA ring ");
    log_dec(size as u64);
    serial::write_str(" bytes (");
    log_dec((size as u64 * 1000) / byte_rate() as u64);
    serial::write_str(" ms)\r\n");
    true
}

/// List multimedia PCI functions nobody claimed (truthful "why no sound").
fn report_unsupported() {
    let mut any = false;
    for i in 0..crate::pci::device_count() {
        if let Some(d) = crate::pci::get_device(i) {
            let (class, sub, _) = crate::pci::class_code(d.bus, d.device, d.function);
            if class == 0x04 {
                any = true;
                serial::write_str("[AUDIO] Unsupported/failed multimedia device ");
                log_hex16(d.vendor_id); serial::write_str(":"); log_hex16(d.device_id);
                serial::write_str(" class 04:"); log_hex8(sub);
                serial::write_str(" at "); log_hex8(d.bus); serial::write_str(":");
                log_hex8(d.device); serial::write_str(".");
                log_dec(d.function as u64); serial::write_str("\r\n");
            }
        }
    }
    if !any {
        serial::write_str("[AUDIO] No PCI multimedia (class 04) device present\r\n");
    }
    serial::write_str("[AUDIO] No working sound device — audio disabled\r\n");
}

/// Non-blocking submit: queues as much as fits, returns the number of bytes
/// accepted (always a multiple of 4).  Format: sample_rate() Hz, s16le stereo.
pub fn submit(data: &[u8]) -> usize {
    if !is_ready() { return 0; }
    lock();
    let n = unsafe {
        update(false);
        let s = &mut *core::ptr::addr_of_mut!(STREAM);
        let free = s.size.saturating_sub(s.queued + 64) & !3;
        let n = data.len().min(free) & !3;
        if n > 0 { ring_put(&data[..n]); }
        if n < data.len() { s.dropped_bytes += (data.len() - n) as u64; }
        keepalive();
        n
    };
    unlock();
    n
}

/// Frames (4-byte stereo samples) currently queued ahead of the hardware.
pub fn queued_frames() -> u32 {
    if !is_ready() { return 0; }
    lock();
    let q = unsafe {
        update(false);
        ((*core::ptr::addr_of!(STREAM)).queued / 4) as u32
    };
    unlock();
    q
}

/// Ring capacity in frames.
pub fn capacity_frames() -> u32 {
    unsafe { ((*core::ptr::addr_of!(STREAM)).size / 4) as u32 }
}

/// Keep the stream bookkeeping current without writing (wipes played data).
pub fn pump() {
    if is_ready() {
        lock();
        unsafe { update(false); }
        unlock();
    }
}

/// PIT interrupt hook (100 Hz): wipe played data / keep the DMA alive even
/// when no producer is running.  Skips if a producer holds the stream.
pub fn timer_tick() {
    if ACTIVE_DRIVER.load(Ordering::Relaxed) == 0 || !is_ready() { return; }
    if try_lock() {
        unsafe { update(true); }
        unlock();
    }
}

/// Blocking write: queues all of `data`, waiting for ring space as needed,
/// and returns as soon as the last byte is queued (the tail keeps playing;
/// consecutive calls are gapless).  Played data is wiped by the timer tick,
/// so nothing is replayed afterwards.  Gives up if the hardware stops
/// consuming samples.
pub fn write_pcm(data: &[u8]) {
    if !is_ready() || data.is_empty() { return; }
    let mut rest = &data[..data.len() & !3];
    let mut last_progress = ticks();
    let mut last_q = u32::MAX;
    while !rest.is_empty() {
        let n = submit(rest);
        rest = &rest[n..];
        if rest.is_empty() { break; }
        let q = queued_frames();
        if n > 0 || q != last_q { last_progress = ticks(); last_q = q; }
        if ticks().saturating_sub(last_progress) > 50 {
            serial::write_str("[AUDIO] write_pcm: no DMA progress for 500 ms — dropping ");
            log_dec(rest.len() as u64);
            serial::write_str(" bytes\r\n");
            clear_buffer();
            return;
        }
        short_wait();
    }
}

/// Submit one audio frame (non-blocking).  Returns true if all was accepted.
pub fn play_sample(data: &[u8]) -> bool {
    submit(data) == (data.len() & !3)
}

/// Silence the output immediately (wipes the whole ring).
pub fn clear_buffer() {
    if !is_ready() { return; }
    lock();
    unsafe {
        let s = &mut *core::ptr::addr_of_mut!(STREAM);
        ring_zero(0, s.size);
        let hw = hw_pos();
        s.last_hw = hw;
        s.write_pos = (hw + lead_bytes()) % s.size;
        s.queued = lead_bytes();
        s.last_tick = ticks();
        keepalive();
    }
    unlock();
}

/// Returns true if any audio driver is initialized and streaming.
pub fn is_ready() -> bool {
    match ACTIVE_DRIVER.load(Ordering::Relaxed) {
        1 => ac97::is_ready(),
        2 => hda::is_ready(),
        3 => es1371::is_ready(),
        _ => false,
    }
}

/// Stop playback DMA and detach the driver. Called before reboot / power-off:
/// a sound card left looping its buffer through a platform reset has hung VMware.
pub fn stop() {
    match ACTIVE_DRIVER.swap(0, Ordering::AcqRel) {
        1 => ac97::stop(),
        2 => hda::stop(),
        3 => es1371::stop(),
        _ => return,
    }
    serial::write_str("[AUDIO] Playback stopped\r\n");
}

/// Legacy IRQ hooks (idt.rs).  Audio runs fully polled; these only
/// acknowledge a device that raised an interrupt anyway.
pub fn handle_ac97_irq() {
    if ACTIVE_DRIVER.load(Ordering::Relaxed) == 1 { ac97::handle_irq(); }
}

pub fn handle_es1371_irq() {
    if ACTIVE_DRIVER.load(Ordering::Relaxed) == 3 { es1371::handle_irq(); }
}

/// Returns a static string identifying the active audio driver.
pub fn active_driver_name() -> &'static str {
    match ACTIVE_DRIVER.load(Ordering::Relaxed) {
        1 => "AC97",
        2 => "HDA",
        3 => es1371::chip_name(),
        _ => "none",
    }
}

/// Dump driver-specific diagnostics to serial (soundtest).
pub fn dump_status() {
    match ACTIVE_DRIVER.load(Ordering::Relaxed) {
        1 => ac97::dump_status(),
        2 => hda::dump_status(),
        3 => es1371::dump_status(),
        _ => serial::write_str("[AUDIO] No active audio driver\r\n"),
    }
    unsafe {
        let s = &*core::ptr::addr_of!(STREAM);
        serial::write_str("[AUDIO] stream: hw_pos=");
        log_dec(hw_pos() as u64);
        serial::write_str(" write_pos="); log_dec(s.write_pos as u64);
        serial::write_str(" queued="); log_dec(s.queued as u64);
        serial::write_str("/"); log_dec(s.size as u64);
        serial::write_str(" total="); log_dec(s.total_bytes);
        serial::write_str(" dropped="); log_dec(s.dropped_bytes);
        serial::write_str(" underruns="); log_dec(UNDERRUNS.load(Ordering::Relaxed) as u64);
        serial::write_str("\r\n");
    }
}

/// Dump driver memory map to serial (where applicable).
pub fn dump_mem_map() {
    if ACTIVE_DRIVER.load(Ordering::Relaxed) == 1 { ac97::dump_mem_map(); }
}

/// Returns the PCI IRQ line of the active device (informational; unused).
pub fn irq_line() -> u8 {
    match ACTIVE_DRIVER.load(Ordering::Relaxed) {
        1 => ac97::irq_line(),
        2 => hda::irq_line(),
        3 => es1371::irq_line(),
        _ => 0,
    }
}

/// Returns the PCM sample rate used by the active driver (Hz).
pub fn sample_rate() -> u32 {
    match ACTIVE_DRIVER.load(Ordering::Relaxed) {
        1 => ac97::sample_rate(),
        2 => hda::sample_rate(),
        3 => es1371::sample_rate(),
        _ => 44100,
    }
}

/// Returns the current master volume (0..100).
pub fn volume() -> u8 {
    match ACTIVE_DRIVER.load(Ordering::Relaxed) {
        1 => ac97::volume(),
        2 => SW_VOLUME.load(Ordering::Relaxed),
        3 => es1371::volume(),
        _ => 0,
    }
}

/// Set master volume (0..100).
pub fn set_volume(pct: u8) {
    let pct = pct.min(100);
    match ACTIVE_DRIVER.load(Ordering::Relaxed) {
        1 => ac97::set_volume(pct),
        2 => { SW_VOLUME.store(pct, Ordering::Relaxed); hda::set_volume(pct); }
        3 => es1371::set_volume(pct),
        _ => {}
    }
}

/// Number of detected underruns since boot.
pub fn underruns() -> u32 { UNDERRUNS.load(Ordering::Relaxed) }

// ─── Logging helpers (shared by the drivers) ────────────────────────────────

pub(crate) fn log_hex8(v: u8) {
    let h = b"0123456789ABCDEF";
    serial::write_byte(h[((v >> 4) & 0xF) as usize]);
    serial::write_byte(h[(v & 0xF) as usize]);
}
pub(crate) fn log_hex16(v: u16) { log_hex8((v >> 8) as u8); log_hex8(v as u8); }
pub(crate) fn log_hex32(v: u32) { log_hex16((v >> 16) as u16); log_hex16(v as u16); }
pub(crate) fn log_dec(mut v: u64) {
    if v == 0 { serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while v > 0 { buf[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
    for j in (0..i).rev() { serial::write_byte(buf[j]); }
}
