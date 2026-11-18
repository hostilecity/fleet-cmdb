//! RFC 3339 UTC timestamps for payloads (`agent_time`, `collected_at`, task and update records, the
//! ledger, recovery state) and for reading the server's `server_time` (DEC-08).
//!
//! The calendar arithmetic is the `time` crate's (review of #68: no calendar arithmetic of our own).
//! Only the fixed-width text layout is ours: the contract's one shape, `YYYY-MM-DDTHH:MM:SS[.f]Z`
//! (the `pattern` of the timestamps in `docs/api/schemas/v1`). It replaced `humantime`, which RustSec
//! marked unmaintained (RUSTSEC-2026-0542); the text written is byte-for-byte what `humantime` wrote.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// The latest instant the contract's four-digit year can carry: 9999-12-31T23:59:59.999Z.
const MAX_UNIX_MILLIS: u64 = 253_402_300_799_999;

/// `time` as RFC 3339 UTC with milliseconds (truncated, never rounded up), for example
/// `2026-01-01T12:00:01.250Z`.
///
/// A clock set before 1970 is written as the epoch, and one past year 9999 as the end of 9999, so the
/// payload always matches the contract's pattern; the server never uses these values for liveness.
pub fn rfc3339(time: SystemTime) -> String {
    let latest = UNIX_EPOCH + Duration::from_millis(MAX_UNIX_MILLIS);
    // In range after the clamp: `time` handles years -9999 to 9999 without its `large-dates` feature.
    let t = OffsetDateTime::from(time.clamp(UNIX_EPOCH, latest));
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

/// Parses the contract's timestamp, `YYYY-MM-DDTHH:MM:SS[.fraction]Z` with one to nine fraction
/// digits, from 1970 on: the server's `server_time` and the agent's own `rfc3339` text (ledger and
/// recovery records). Anything else is `None`: an impossible date such as 30 February, an offset
/// other than `Z`, a lowercase `t` or `z`, a space for `T`. A leap second (`:60`, which the
/// contract's pattern allows) reads as `:59`, as before; it only ever feeds the clock-skew warning
/// and the ledger's retention, where a second does not matter.
pub fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let b = text.as_bytes();
    if b.len() < 20 || b.last() != Some(&b'Z') {
        return None;
    }
    let literals = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if literals.iter().any(|&(at, want)| b[at] != want) {
        return None;
    }
    let year = digits(&b[0..4])?;
    let month = digits(&b[5..7])?;
    let day = digits(&b[8..10])?;
    let hour = digits(&b[11..13])?;
    let minute = digits(&b[14..16])?;
    let second = digits(&b[17..19])?;
    let nanos = match &b[19..b.len() - 1] {
        [] => 0,
        [b'.', fraction @ ..] if (1..=9).contains(&fraction.len()) => {
            digits(fraction)? * 10u32.pow(9 - fraction.len() as u32)
        }
        _ => return None,
    };
    if year < 1970 || second > 60 {
        return None;
    }
    let date = Date::from_calendar_date(
        i32::try_from(year).ok()?,
        Month::try_from(u8::try_from(month).ok()?).ok()?,
        u8::try_from(day).ok()?,
    )
    .ok()?;
    let clock = Time::from_hms_nano(
        u8::try_from(hour).ok()?,
        u8::try_from(minute).ok()?,
        u8::try_from(second.min(59)).ok()?,
        nanos,
    )
    .ok()?;
    Some(PrimitiveDateTime::new(date, clock).assume_utc().into())
}

/// The value of a run of ASCII digits (at most nine, so it fits); `None` if any byte is not one.
fn digits(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0u32, |value, &byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

#[cfg(test)]
mod tests;
