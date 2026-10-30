//! RFC 3339 UTC timestamps for payloads (`agent_time`, `collected_at`) and for reading the server's
//! `server_time` (DEC-08). The agent has no date library, so the civil-date conversion is here
//! (Howard Hinnant's `days_from_civil` and `civil_from_days`, proleptic Gregorian calendar).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The latest instant the contract's four-digit year can carry: 9999-12-31T23:59:59.999Z.
const MAX_UNIX_MILLIS: u64 = 253_402_300_799_999;

/// `time` as RFC 3339 UTC with milliseconds, for example `2026-01-01T12:00:01.250Z`.
///
/// A clock set before 1970 is written as the epoch, and one past year 9999 as the end of 9999, so the
/// payload always matches the contract's pattern; the server never uses these values for liveness.
pub fn rfc3339(time: SystemTime) -> String {
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .min(MAX_UNIX_MILLIS);
    let secs = millis / 1000;
    let (year, month, day) = civil_from_days(secs / 86_400);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        millis % 1000
    )
}

/// Parses an RFC 3339 UTC timestamp of the contract's form (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`, from
/// 1970 on). Anything else, including an impossible date such as 30 February, is `None`.
pub fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let b = text.as_bytes();
    if b.len() < 20 || b.len() > 35 || b[b.len() - 1] != b'Z' {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<u64> {
        let digits = b.get(range)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse().ok()
    };
    let sep = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(sep(4, b'-') && sep(7, b'-') && sep(10, b'T') && sep(13, b':') && sep(16, b':')) {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if year < 1970
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut nanos = 0u32;
    let rest = &b[19..b.len() - 1];
    if !rest.is_empty() {
        let fraction = rest.strip_prefix(b".")?;
        if fraction.is_empty() || fraction.len() > 9 || !fraction.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut scaled = 0u32;
        for i in 0..9 {
            scaled = scaled * 10 + fraction.get(i).map_or(0, |d| u32::from(d - b'0'));
        }
        nanos = scaled;
    }
    // A leap second (:60) is read as the following second.
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
}

fn is_leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a date on or after it.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, millis: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(millis)
    }

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(at(1_767_268_801, 250)), "2026-01-01T12:00:01.250Z");
        // Leap day and the end of a leap year.
        assert_eq!(rfc3339(at(951_782_400, 0)), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(at(1_735_689_599, 999)), "2024-12-31T23:59:59.999Z");
    }

    #[test]
    fn out_of_range_clocks_stay_within_the_contract() {
        assert_eq!(
            rfc3339(UNIX_EPOCH - Duration::from_secs(10)),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(400_000_000_000)),
            "9999-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn every_day_round_trips() {
        // 1970 to past 2100 (not a leap year), one instant per day.
        for day in 0..50_000u64 {
            let time = at(day * 86_400 + 45_296, 7);
            let text = rfc3339(time);
            assert_eq!(parse_rfc3339(&text), Some(time), "{text}");
        }
    }

    #[test]
    fn parses_the_servers_form() {
        assert_eq!(
            parse_rfc3339("2026-01-01T12:00:00Z"),
            Some(at(1_767_268_800, 0))
        );
        assert_eq!(
            parse_rfc3339("2026-01-01T12:00:00.123456789Z"),
            Some(at(1_767_268_800, 0) + Duration::from_nanos(123_456_789))
        );
    }

    #[test]
    fn rejects_malformed_or_impossible_timestamps() {
        for bad in [
            "",
            "2026-01-01T12:00:00",
            "2026-01-01T12:00:00+00:00",
            "2026-01-01 12:00:00Z",
            "2026-02-30T12:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T12:60:00Z",
            "2026-01-01T12:00:61Z",
            "2026-01-01T12:00:00.Z",
            "2026-01-01T12:00:00.1234567890Z",
            "1969-12-31T23:59:59Z",
            "+026-01-01T12:00:00Z",
            "2026-01-01T12:00:0xZ",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
        assert!(parse_rfc3339("2024-02-29T00:00:00Z").is_some());
    }
}
