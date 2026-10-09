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

/// Wall time at the moment `BASE_MONO` was taken.
static mut BASE_NS:   i64 = 0;
static mut BASE_MONO: u64 = 0;
static mut SOURCE:    Source = Source::None;

/// TSC value our monotonic clock counts from (0 = TSC not calibrated, use PIT ticks).
static mut MONO_TSC0: u64 = 0;
static mut MONO_MHZ:  u64 = 0;

/// Monotonic nanoseconds since `init`. 128-bit math, so it does not wrap after
/// a few weeks of uptime the way `cycles * 1000` in u64 would.
pub fn monotonic_ns() -> u64 {
    unsafe {
        if MONO_MHZ == 0 {
            return idt::timer_ticks().saturating_mul(10_000_000); // 100 Hz PIT
        }
        let cycles = tsc::read().wrapping_sub(MONO_TSC0) as u128;
        (cycles * 1000 / MONO_MHZ as u128) as u64
    }
}

/// Current time, ns since 2012-08-09 00:00:00 UTC.
pub fn now() -> i64 {
    unsafe {
        let elapsed = monotonic_ns().wrapping_sub(BASE_MONO);
        BASE_NS.saturating_add(elapsed.min(i64::MAX as u64) as i64)
    }
}

/// Whole seconds since the ospab epoch (floor, also for negative times).
pub fn now_secs() -> i64 { now().div_euclid(NS_PER_SEC) }

pub fn source() -> Source { unsafe { SOURCE } }

/// Set the wall clock.
pub fn set(ns: i64, src: Source) {
    unsafe {
        BASE_MONO = monotonic_ns();
        BASE_NS   = ns;
        SOURCE    = src;
    }
}

/// Seed the clock from the CMOS RTC. Call once the TSC is calibrated.
pub fn init() {
    unsafe {
        MONO_MHZ  = tsc::mhz();
        MONO_TSC0 = tsc::read();
    }
    let (y, mo, d, h, mi, s) = read_rtc();
    if (1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && s < 61 {
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
    #[test] fn leap_day() {
        let t = to_civil(from_civil(2024, 2, 29, 23, 59, 59));
        assert_eq!((t.year, t.month, t.day, t.hour, t.minute, t.second), (2024, 2, 29, 23, 59, 59));
    }
}
