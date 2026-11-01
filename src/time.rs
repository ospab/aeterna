/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
*/
//! System wall clock.
//!
//! Time is an `i64` count of nanoseconds since the ospab epoch,
//! **2012-08-09 00:00:00 UTC**. Earlier moments are negative; the range is
//! roughly 1720..2304, which covers every real file timestamp.
//!
//! Unix time is only an interchange format at the edges (NTP, TLS, HTTP,
//! file systems) — use `from_unix` / `to_unix_secs` there.
//!
//! The clock is seeded from the CMOS RTC at boot (`init`) and corrected by
//! NTP (`set(.., Source::Ntp)`). Between updates it advances by the TSC.

use core::arch::asm;
use crate::arch::x86_64::{idt, serial, tsc};

/// Seconds between 1970-01-01 and the ospab epoch (2012-08-09).
pub const EPOCH_UNIX_SECS: i64 = 1_344_470_400;
pub const NS_PER_SEC: i64 = 1_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// Never set — `now()` counts from the epoch.
    None,
    /// CMOS real-time clock (assumed UTC), 1 s resolution.
    Rtc,
    /// Synchronised over the network.
    Ntp,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::None => "unset",
            Source::Rtc  => "CMOS RTC",
            Source::Ntp  => "NTP",
        }
    }
}

// ─── State ───────────────────────────────────────────────────────────────────

/// Wall-clock base, behind one lock (class TIME) so a reader never sees a half-updated pair.
struct Clock {
    /// Wall time at the moment `mono` was taken.
    base_ns: i64,
    base_mono: u64,
    source: Source,
    /// RTC - UTC, learned from NTP.
    rtc_offset_secs: i64,
}

static CLOCK: crate::core::sync::IrqSpinLock<Clock> = crate::core::sync::IrqSpinLock::new(
    "TIME",
    crate::core::sync::rank::TIME,
    Clock { base_ns: 0, base_mono: 0, source: Source::None, rtc_offset_secs: 0 },
);

/// TSC value our monotonic clock counts from, and its MHz (0 = TSC not calibrated, use PIT
/// ticks). Written once by `init`.
static MONO_TSC0: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static MONO_MHZ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Monotonic nanoseconds since `init`. 128-bit math, so it does not wrap after
/// a few weeks of uptime the way `cycles * 1000` in u64 would.
pub fn monotonic_ns() -> u64 {
    let mhz = MONO_MHZ.load(core::sync::atomic::Ordering::Relaxed);
    if mhz == 0 {
        return idt::timer_ticks().saturating_mul(10_000_000); // 100 Hz PIT
    }
    let tsc0 = MONO_TSC0.load(core::sync::atomic::Ordering::Relaxed);
    let cycles = tsc::read().wrapping_sub(tsc0) as u128;
    (cycles * 1000 / mhz as u128) as u64
}

/// Current time, ns since 2012-08-09 00:00:00 UTC.
pub fn now() -> i64 {
    let mono = monotonic_ns();
    let c = CLOCK.lock();
    let elapsed = mono.wrapping_sub(c.base_mono);
    c.base_ns.saturating_add(elapsed.min(i64::MAX as u64) as i64)
}

/// Whole seconds since the ospab epoch (floor, also for negative times).
pub fn now_secs() -> i64 { now().div_euclid(NS_PER_SEC) }

pub fn source() -> Source { CLOCK.lock().source }

/// Set the wall clock.
pub fn set(ns: i64, src: Source) {
    let mono = monotonic_ns();
    let mut c = CLOCK.lock();
    c.base_mono = mono;
    c.base_ns = ns;
    c.source = src;
}

/// Seed the clock from the CMOS RTC. Call once the TSC is calibrated.
pub fn init() {
    MONO_TSC0.store(tsc::read(), core::sync::atomic::Ordering::Relaxed);
    MONO_MHZ.store(tsc::mhz(), core::sync::atomic::Ordering::Relaxed);
    let (y, mo, d, h, mi, s) = read_rtc();
    if (1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && s < 61 {
        // RTC_OFFSET_SECS is still 0 here; the saved offset is applied once the VFS is up.
        set(from_civil(y, mo, d, h, mi, s), Source::Rtc);
        let mut buf = [0u8; 40];
        let n = format(now(), 0, &mut buf);
        serial::write_str("[TIME] RTC: ");
        serial::write_str(core::str::from_utf8(&buf[..n]).unwrap_or("?"));
        serial::write_str("\r\n");
    } else {
        serial::write_str("[TIME] RTC returned garbage, clock left unset\r\n");
    }
}

// ─── RTC kept in local time ─────────────────────────────────────────────────
//
// Windows and VMware keep the CMOS clock in local time. We never write the RTC
// (that would break a Windows dual boot); instead the offset RTC − UTC is learned
// when NTP succeeds and saved to /etc/rtc_offset, then applied at the next boot.

pub const RTC_OFFSET_FILE: &str = "/etc/rtc_offset";

pub fn rtc_offset() -> i64 { CLOCK.lock().rtc_offset_secs }

/// Set the RTC − UTC offset; a clock still running on the RTC is corrected at once.
pub fn set_rtc_offset(secs: i64) {
    let mut c = CLOCK.lock();
    let delta = secs - c.rtc_offset_secs;
    c.rtc_offset_secs = secs;
    if c.source == Source::Rtc {
        c.base_ns = c.base_ns.saturating_sub(delta.saturating_mul(NS_PER_SEC));
    }
}

/// `/etc/rtc_mode`: `utc` or `local` (written by the installer; absent = learn the offset from NTP).
pub const RTC_MODE_FILE: &str = "/etc/rtc_mode";
/// `/etc/timezone`: an IANA name from `ZONES` (e.g. `Europe/Berlin`) or `UTC+H[:MM]`.
pub const TIMEZONE_FILE: &str = "/etc/timezone";

/// True when `/etc/rtc_mode` says `utc`: the RTC is trusted as UTC and no offset is learned.
static RTC_UTC_FORCED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Apply `/etc/rtc_mode`, `/etc/timezone` and `/etc/rtc_offset` (call once the VFS is up).
///
/// * `utc`: the CMOS clock is UTC; the offset is 0 and NTP never changes that.
/// * `local`: the CMOS clock shows local time (Windows dual boot). The offset RTC - UTC is the one
///   learned from NTP and saved in `/etc/rtc_offset`, or else the offset of the time zone.
/// * no file: the offset saved by an earlier NTP sync, if any (the behaviour before the installer
///   wrote `rtc_mode`).
pub fn load_config() {
    let read = |p: &str| crate::fs::read_file(p).and_then(|d| core::str::from_utf8(&d).ok().map(|s| alloc::string::String::from(s.trim())));
    let saved = read(RTC_OFFSET_FILE).and_then(|s| s.parse::<i64>().ok());
    match read(RTC_MODE_FILE).as_deref() {
        Some("utc") => {
            RTC_UTC_FORCED.store(true, core::sync::atomic::Ordering::Relaxed);
            set_rtc_offset(0);
        }
        Some("local") => {
            let off = saved.unwrap_or_else(|| {
                let tz = read(TIMEZONE_FILE).unwrap_or_default();
                // The RTC shows local time: undo the standard offset to get a UTC guess for the DST rule.
                let rtc = read_rtc_utc_guess();
                zone_offset_secs(&tz, rtc - zone_offset_secs(&tz, rtc))
            });
            set_rtc_offset(off);
        }
        _ => { if let Some(off) = saved { set_rtc_offset(off); } }
    }
}

fn read_rtc_utc_guess() -> i64 {
    let (y, mo, d, h, mi, s) = read_rtc();
    from_civil(y, mo, d, h, mi, s).div_euclid(NS_PER_SEC) + EPOCH_UNIX_SECS
}

/// After an NTP sync: compare with the raw RTC and learn a local-time offset.
/// Offsets are rounded to 15 minutes (all real time zones); anything else is drift.
/// Returns Some(offset) when it changed.
pub fn learn_rtc_offset() -> Option<i64> {
    if source() != Source::Ntp { return None; }
    if RTC_UTC_FORCED.load(core::sync::atomic::Ordering::Relaxed) { return None; }
    let (y, mo, d, h, mi, s) = read_rtc();
    let rtc = from_civil(y, mo, d, h, mi, s).div_euclid(NS_PER_SEC);
    let diff = rtc - now_secs();
    let quarter = 15 * 60;
    let rounded = (diff + quarter / 2).div_euclid(quarter) * quarter;
    if (diff - rounded).abs() > 120 || rounded.abs() > 14 * 3600 {
        return None; // RTC is simply off; not a time-zone offset
    }
    if rounded == rtc_offset() { return None; }
    CLOCK.lock().rtc_offset_secs = rounded;
    Some(rounded)
}

// ─── Time zones ──────────────────────────────────────────────────────────────
//
// A short list of common zones with their standard UTC offset and a simple daylight-saving rule.
// The installer offers this list and writes the name to /etc/timezone; `net::sntp` and the
// RTC code turn the name into an offset with `zone_offset_secs`. Zones that are not in the list
// can still be set as `UTC+H[:MM]`.

/// Daylight-saving rule of a zone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dst {
    /// No daylight saving.
    None,
    /// EU: last Sunday of March 01:00 UTC to last Sunday of October 01:00 UTC.
    Eu,
    /// US/Canada: second Sunday of March 02:00 to first Sunday of November 02:00 (local time).
    Us,
    /// Australia (south-east): first Sunday of October 02:00 to first Sunday of April 03:00 (local).
    Au,
    /// New Zealand: last Sunday of September 02:00 to first Sunday of April 03:00 (local).
    Nz,
}

#[derive(Clone, Copy)]
pub struct Zone {
    pub name: &'static str,
    /// Standard (winter) offset from UTC in minutes.
    pub std_min: i16,
    pub dst: Dst,
}

const fn z(name: &'static str, std_min: i16, dst: Dst) -> Zone { Zone { name, std_min, dst } }

pub const ZONES: &[Zone] = &[
    z("UTC", 0, Dst::None),
    z("Europe/London", 0, Dst::Eu),
    z("Europe/Dublin", 0, Dst::Eu),
    z("Europe/Lisbon", 0, Dst::Eu),
    z("Europe/Berlin", 60, Dst::Eu),
    z("Europe/Paris", 60, Dst::Eu),
    z("Europe/Madrid", 60, Dst::Eu),
    z("Europe/Rome", 60, Dst::Eu),
    z("Europe/Warsaw", 60, Dst::Eu),
    z("Europe/Prague", 60, Dst::Eu),
    z("Europe/Stockholm", 60, Dst::Eu),
    z("Africa/Lagos", 60, Dst::None),
    z("Europe/Athens", 120, Dst::Eu),
    z("Europe/Helsinki", 120, Dst::Eu),
    z("Europe/Kyiv", 120, Dst::Eu),
    z("Europe/Kaliningrad", 120, Dst::None),
    z("Africa/Cairo", 120, Dst::None),
    z("Africa/Johannesburg", 120, Dst::None),
    z("Europe/Istanbul", 180, Dst::None),
    z("Europe/Moscow", 180, Dst::None),
    z("Europe/Minsk", 180, Dst::None),
    z("Europe/Samara", 240, Dst::None),
    z("Asia/Dubai", 240, Dst::None),
    z("Asia/Yekaterinburg", 300, Dst::None),
    z("Asia/Tashkent", 300, Dst::None),
    z("Asia/Karachi", 300, Dst::None),
    z("Asia/Kolkata", 330, Dst::None),
    z("Asia/Omsk", 360, Dst::None),
    z("Asia/Dhaka", 360, Dst::None),
    z("Asia/Novosibirsk", 420, Dst::None),
    z("Asia/Krasnoyarsk", 420, Dst::None),
    z("Asia/Bangkok", 420, Dst::None),
    z("Asia/Irkutsk", 480, Dst::None),
    z("Asia/Shanghai", 480, Dst::None),
    z("Asia/Singapore", 480, Dst::None),
    z("Asia/Yakutsk", 540, Dst::None),
    z("Asia/Tokyo", 540, Dst::None),
    z("Asia/Seoul", 540, Dst::None),
    z("Asia/Vladivostok", 600, Dst::None),
    z("Australia/Sydney", 600, Dst::Au),
    z("Asia/Magadan", 660, Dst::None),
    z("Pacific/Auckland", 720, Dst::Nz),
    z("Asia/Kamchatka", 720, Dst::None),
    z("America/Sao_Paulo", -180, Dst::None),
    z("America/Buenos_Aires", -180, Dst::None),
    z("America/New_York", -300, Dst::Us),
    z("America/Toronto", -300, Dst::Us),
    z("America/Chicago", -360, Dst::Us),
    z("America/Mexico_City", -360, Dst::None),
    z("America/Denver", -420, Dst::Us),
    z("America/Los_Angeles", -480, Dst::Us),
    z("America/Anchorage", -540, Dst::Us),
    z("Pacific/Honolulu", -600, Dst::None),
];

pub fn zone_by_name(name: &str) -> Option<&'static Zone> {
    ZONES.iter().find(|z| z.name == name)
}

/// Day of month (1-based) of the `n`-th Sunday of `month`; `n == 0` means the last Sunday.
fn sunday_of(year: i64, month: u32, n: u32) -> u32 {
    let first = days_from_civil(year, month, 1);
    let wd = (first + 4).rem_euclid(7) as u32; // 0 = Sunday (1970-01-01 was a Thursday)
    let first_sun = 1 + (7 - wd) % 7;
    if n > 0 { return first_sun + 7 * (n - 1); }
    let (ny, nm) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    let len = (days_from_civil(ny, nm, 1) - first) as u32;
    first_sun + 7 * ((len - first_sun) / 7)
}

fn utc_secs_of(year: i64, month: u32, day: u32, hour: i64) -> i64 {
    days_from_civil(year, month, day) * 86_400 + hour * 3600
}

impl Zone {
    /// True if daylight saving is in effect at the Unix time `utc`.
    pub fn is_dst(&self, utc: i64) -> bool {
        let std = self.std_min as i64 * 60;
        let year = civil_from_days((utc + std).div_euclid(86_400)).0;
        match self.dst {
            Dst::None => false,
            Dst::Eu => {
                let start = utc_secs_of(year, 3, sunday_of(year, 3, 0), 1);
                let end = utc_secs_of(year, 10, sunday_of(year, 10, 0), 1);
                utc >= start && utc < end
            }
            Dst::Us => {
                let start = utc_secs_of(year, 3, sunday_of(year, 3, 2), 2) - std;
                let end = utc_secs_of(year, 11, sunday_of(year, 11, 1), 2) - (std + 3600);
                utc >= start && utc < end
            }
            // Southern hemisphere: DST spans the new year.
            Dst::Au => {
                let end = utc_secs_of(year, 4, sunday_of(year, 4, 1), 3) - (std + 3600);
                let start = utc_secs_of(year, 10, sunday_of(year, 10, 1), 2) - std;
                utc < end || utc >= start
            }
            Dst::Nz => {
                let end = utc_secs_of(year, 4, sunday_of(year, 4, 1), 3) - (std + 3600);
                let start = utc_secs_of(year, 9, sunday_of(year, 9, 0), 2) - std;
                utc < end || utc >= start
            }
        }
    }

    /// Offset from UTC in seconds at the Unix time `utc`.
    pub fn offset_at(&self, utc: i64) -> i64 {
        self.std_min as i64 * 60 + if self.is_dst(utc) { 3600 } else { 0 }
    }
}

/// Offset in seconds for the contents of /etc/timezone at the Unix time `utc`:
/// a name from `ZONES`, or `UTC`, `UTC+3`, `UTC-5`, `UTC+5:30`. Anything else is 0.
pub fn zone_offset_secs(tz: &str, utc: i64) -> i64 {
    let tz = tz.trim();
    if let Some(z) = zone_by_name(tz) { return z.offset_at(utc); }
    let rest = match tz.strip_prefix("UTC") { Some(r) => r, None => return 0 };
    let (sign, rest) = match rest.as_bytes().first() {
        Some(b'+') => (1i64, &rest[1..]),
        Some(b'-') => (-1i64, &rest[1..]),
        _ => return 0,
    };
    let (h, m) = match rest.split_once(':') { Some((h, m)) => (h, m), None => (rest, "0") };
    match (h.parse::<i64>(), m.parse::<i64>()) {
        (Ok(h), Ok(m)) if (0..=14).contains(&h) && (0..60).contains(&m) => sign * (h * 3600 + m * 60),
        _ => 0,
    }
}

// ─── Unix interchange ───────────────────────────────────────────────────────

/// Unix seconds (+ nanoseconds) → ospab time. Saturates outside the range.
pub fn from_unix(secs: i64, nanos: u32) -> i64 {
    secs.saturating_sub(EPOCH_UNIX_SECS)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(nanos as i64)
}

/// ospab time → Unix seconds.
pub fn to_unix_secs(ns: i64) -> i64 {
    ns.div_euclid(NS_PER_SEC) + EPOCH_UNIX_SECS
}

/// Current Unix time in seconds.
pub fn unix_secs() -> i64 { to_unix_secs(now()) }

// ─── Calendar ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DateTime {
    pub year:   i64,
    pub month:  u32, // 1..=12
    pub day:    u32, // 1..=31
    pub hour:   u32,
    pub minute: u32,
    pub second: u32,
    pub nanos:  u32,
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

/// UTC calendar date/time → ospab time.
pub fn from_civil(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> i64 {
    let secs = days_from_civil(year, month, day) * 86_400
        + (hour * 3600 + minute * 60 + second) as i64;
    from_unix(secs, 0)
}

/// ospab time → UTC calendar date/time.
pub fn to_civil(ns: i64) -> DateTime {
    let unix = to_unix_secs(ns);
    let (days, sod) = (unix.div_euclid(86_400), unix.rem_euclid(86_400) as u32);
    let (year, month, day) = civil_from_days(days);
    DateTime {
        year, month, day,
        hour: sod / 3600, minute: (sod % 3600) / 60, second: sod % 60,
        nanos: ns.rem_euclid(NS_PER_SEC) as u32,
    }
}

/// Format as `"YYYY-MM-DD HH:MM:SS UTC[+H[:MM]]"`, shifted by `tz_secs` for display.
/// Returns bytes written.
pub fn format(ns: i64, tz_secs: i64, buf: &mut [u8; 40]) -> usize {
    let t = to_civil(ns.saturating_add(tz_secs.saturating_mul(NS_PER_SEC)));
    let mut p = 0usize;
    let mut put = |c: u8, p: &mut usize| { buf[*p] = c; *p += 1; };
    let mut y = t.year;
    if y < 0 { put(b'-', &mut p); y = -y; }
    for div in [1000i64, 100, 10, 1] { put(b'0' + ((y / div) % 10) as u8, &mut p); }
    for (sep, v) in [(b'-', t.month), (b'-', t.day), (b' ', t.hour), (b':', t.minute), (b':', t.second)] {
        put(sep, &mut p);
        put(b'0' + (v / 10) as u8, &mut p);
        put(b'0' + (v % 10) as u8, &mut p);
    }
    for &c in b" UTC" { put(c, &mut p); }
    if tz_secs != 0 {
        let abs = tz_secs.unsigned_abs();
        put(if tz_secs > 0 { b'+' } else { b'-' }, &mut p);
        let (hh, mm) = (abs / 3600, (abs % 3600) / 60);
        if hh >= 10 { put(b'0' + (hh / 10) as u8, &mut p); }
        put(b'0' + (hh % 10) as u8, &mut p);
        if mm > 0 {
            put(b':', &mut p);
            put(b'0' + (mm / 10) as u8, &mut p);
            put(b'0' + (mm % 10) as u8, &mut p);
        }
    }
    p
}

// ─── CMOS RTC ───────────────────────────────────────────────────────────────

fn cmos_read(reg: u8) -> u8 {
    unsafe {
        let val: u8;
        asm!("out 0x70, al", in("al") reg, options(nomem, nostack));
        asm!("in al, 0x71", out("al") val, options(nomem, nostack));
        val
    }
}

/// Read the RTC as (year, month, day, hour, min, sec). Assumes the RTC keeps UTC.
pub fn read_rtc() -> (i64, u32, u32, u32, u32, u32) {
    fn snapshot() -> [u8; 6] {
        // Wait while an update is in progress.
        let mut spins = 0;
        while cmos_read(0x0A) & 0x80 != 0 && spins < 100_000 { spins += 1; }
        [cmos_read(0x09), cmos_read(0x08), cmos_read(0x07),
         cmos_read(0x04), cmos_read(0x02), cmos_read(0x00)]
    }
    // Read until two snapshots agree, so we do not catch a rollover.
    let mut a = snapshot();
    for _ in 0..5 {
        let b = snapshot();
        if a == b { break; }
        a = b;
    }
    let status_b = cmos_read(0x0B);
    let bcd = status_b & 0x04 == 0;
    let h12 = status_b & 0x02 == 0;
    let conv = |v: u8| -> u32 {
        if bcd { ((v >> 4) * 10 + (v & 0x0F)) as u32 } else { v as u32 }
    };
    let pm = a[3] & 0x80 != 0;
    let mut hour = conv(a[3] & 0x7F);
    if h12 {
        if pm && hour < 12 { hour += 12; }
        if !pm && hour == 12 { hour = 0; }
    }
    (2000 + conv(a[0]) as i64, conv(a[1]), conv(a[2]), hour, conv(a[4]), conv(a[5]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn epoch_is_zero() {
        assert_eq!(from_civil(2012, 8, 9, 0, 0, 0), 0);
    }
    #[test] fn unix_round_trip() {
        assert_eq!(from_unix(EPOCH_UNIX_SECS, 0), 0);
        assert_eq!(to_unix_secs(from_unix(0, 0)), 0);
        assert_eq!(to_unix_secs(-1), EPOCH_UNIX_SECS - 1);
    }
    #[test] fn before_epoch_is_negative() {
        let t = to_civil(from_civil(1980, 1, 1, 0, 0, 0));
        assert_eq!((t.year, t.month, t.day), (1980, 1, 1));
        assert!(from_civil(1980, 1, 1, 0, 0, 0) < 0);
    }
    fn unix(y: i64, mo: u32, d: u32, h: u32, mi: u32) -> i64 {
        to_unix_secs(from_civil(y, mo, d, h, mi, 0))
    }
    #[test] fn sundays() {
        assert_eq!(sunday_of(2024, 3, 0), 31);
        assert_eq!(sunday_of(2024, 10, 0), 27);
        assert_eq!(sunday_of(2024, 3, 2), 10);
        assert_eq!(sunday_of(2024, 11, 1), 3);
        assert_eq!(sunday_of(2024, 4, 1), 7);
    }
    #[test] fn eu_dst() {
        let z = zone_by_name("Europe/Berlin").unwrap();
        assert_eq!(z.offset_at(unix(2024, 1, 15, 12, 0)), 3600);
        assert_eq!(z.offset_at(unix(2024, 7, 1, 12, 0)), 7200);
        assert_eq!(z.offset_at(unix(2024, 3, 31, 0, 59)), 3600);
        assert_eq!(z.offset_at(unix(2024, 3, 31, 1, 0)), 7200);
        assert_eq!(z.offset_at(unix(2024, 10, 27, 1, 0)), 3600);
    }
    #[test] fn us_and_south_dst() {
        let ny = zone_by_name("America/New_York").unwrap();
        assert_eq!(ny.offset_at(unix(2024, 3, 10, 6, 59)), -18000);
        assert_eq!(ny.offset_at(unix(2024, 3, 10, 7, 0)), -14400);
        assert_eq!(ny.offset_at(unix(2024, 11, 3, 5, 59)), -14400);
        assert_eq!(ny.offset_at(unix(2024, 11, 3, 6, 0)), -18000);
        let sy = zone_by_name("Australia/Sydney").unwrap();
        assert_eq!(sy.offset_at(unix(2024, 1, 1, 0, 0)), 11 * 3600);
        assert_eq!(sy.offset_at(unix(2024, 7, 1, 0, 0)), 10 * 3600);
        let nz = zone_by_name("Pacific/Auckland").unwrap();
        assert_eq!(nz.offset_at(unix(2024, 12, 1, 0, 0)), 13 * 3600);
        assert_eq!(nz.offset_at(unix(2024, 6, 1, 0, 0)), 12 * 3600);
        let msk = zone_by_name("Europe/Moscow").unwrap();
        assert_eq!(msk.offset_at(unix(2024, 7, 1, 0, 0)), 3 * 3600);
    }
    #[test] fn tz_strings() {
        assert_eq!(zone_offset_secs("UTC", 0), 0);
        assert_eq!(zone_offset_secs("UTC+3", 0), 10800);
        assert_eq!(zone_offset_secs("UTC-5:30", 0), -19800);
        assert_eq!(zone_offset_secs("Europe/Moscow\n", 0), 10800);
        assert_eq!(zone_offset_secs("Nowhere/Land", 0), 0);
    }
    #[test] fn leap_day() {
        let t = to_civil(from_civil(2024, 2, 29, 23, 59, 59));
        assert_eq!((t.year, t.month, t.day, t.hour, t.minute, t.second), (2024, 2, 29, 23, 59, 59));
    }
}
