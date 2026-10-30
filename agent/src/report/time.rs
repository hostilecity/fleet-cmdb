//! RFC 3339 UTC timestamps for payloads (`agent_time`, `collected_at`) and for reading the server's
//! `server_time` (DEC-08), through `humantime` (review of #68: no calendar arithmetic of our own).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The latest instant the contract's four-digit year can carry: 9999-12-31T23:59:59.999Z.
const MAX_UNIX_MILLIS: u64 = 253_402_300_799_999;

/// `time` as RFC 3339 UTC with milliseconds, for example `2026-01-01T12:00:01.250Z`.
///
/// A clock set before 1970 is written as the epoch, and one past year 9999 as the end of 9999, so the
/// payload always matches the contract's pattern (and `humantime`, which panics past 9999, is never
/// given such a time); the server never uses these values for liveness.
pub fn rfc3339(time: SystemTime) -> String {
    let latest = UNIX_EPOCH + Duration::from_millis(MAX_UNIX_MILLIS);
    humantime::format_rfc3339_millis(time.clamp(UNIX_EPOCH, latest)).to_string()
}

/// Parses an RFC 3339 timestamp from 1970 on, such as the server's `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
/// An impossible date such as 30 February is `None`. Used only for the clock-skew warning, so the
/// parser's small leniencies (a `+00:00` offset, an empty fraction) do no harm.
pub fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    humantime::parse_rfc3339(text).ok()
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
            "2026-01-01 12:00:00Z",
            "2026-02-30T12:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T12:60:00Z",
            "2026-01-01T12:00:61Z",
            "1969-12-31T23:59:59Z",
            "+026-01-01T12:00:00Z",
            "2026-01-01T12:00:0xZ",
            // Never misread a non-UTC offset as UTC.
            "2026-01-01T12:00:00-05:00",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
        assert!(parse_rfc3339("2024-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn the_few_lenient_forms_all_mean_the_same_utc_instant() {
        // `humantime` accepts these; each is the instant the strict form names, so a server sending
        // one cannot cause a wrong clock-skew reading.
        let noon = parse_rfc3339("2026-01-01T12:00:00Z");
        assert!(noon.is_some());
        for lenient in [
            "2026-01-01T12:00:00+00:00",
            "2026-01-01T12:00:00.Z",
            "2026-01-01T12:00:00.0000000001Z",
        ] {
            assert_eq!(parse_rfc3339(lenient), noon, "{lenient}");
        }
    }
}
