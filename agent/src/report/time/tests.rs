use super::*;

fn at(secs: u64, millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(millis)
}

fn nanos(secs: u64, nanos: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(nanos)
}

/// Golden values: the text `humantime::format_rfc3339_millis` wrote for each instant (recorded from
/// humantime 2.4.0 before it was replaced), so the wire format is byte-for-byte unchanged.
const GOLDEN: &[(u64, u32, &str)] = &[
    (0, 0, "1970-01-01T00:00:00.000Z"),
    (0, 999_999_999, "1970-01-01T00:00:00.999Z"),
    (59, 1_000_000, "1970-01-01T00:00:59.001Z"),
    (86_399, 0, "1970-01-01T23:59:59.000Z"),
    (68_169_600, 0, "1972-02-29T00:00:00.000Z"),
    (951_782_400, 0, "2000-02-29T00:00:00.000Z"),
    (951_868_799, 999_000_000, "2000-02-29T23:59:59.999Z"),
    (951_868_800, 0, "2000-03-01T00:00:00.000Z"),
    (1_709_164_800, 0, "2024-02-29T00:00:00.000Z"),
    (1_735_689_599, 999_000_000, "2024-12-31T23:59:59.999Z"),
    (1_767_268_801, 250_000_000, "2026-01-01T12:00:01.250Z"),
    // Truncated, never rounded: .1239999 is .123, and .9999999 never carries into the next second.
    (1_767_268_800, 123_999_999, "2026-01-01T12:00:00.123Z"),
    (1_767_268_799, 999_999_999, "2026-01-01T11:59:59.999Z"),
    (4_107_542_400, 0, "2100-03-01T00:00:00.000Z"),
    (4_107_456_000, 0, "2100-02-28T00:00:00.000Z"),
    (253_402_300_799, 999_000_000, "9999-12-31T23:59:59.999Z"),
];

#[test]
fn formats_the_golden_instants_byte_for_byte() {
    for &(secs, nano, text) in GOLDEN {
        assert_eq!(
            rfc3339(nanos(secs, u64::from(nano))),
            text,
            "{secs}.{nano:09}"
        );
    }
}

#[test]
fn the_golden_texts_parse_back_to_the_millisecond() {
    for &(secs, nano, text) in GOLDEN {
        let millis = Duration::from_millis(u64::from(nano / 1_000_000));
        assert_eq!(
            parse_rfc3339(text),
            Some(UNIX_EPOCH + Duration::from_secs(secs) + millis),
            "{text}"
        );
    }
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
    // 1970 to past 2100 (not a leap year), one instant per day, with a fraction.
    for day in 0..50_000u64 {
        let time = at(day * 86_400 + 45_296, 7);
        let text = rfc3339(time);
        assert_eq!(text.len(), 24, "{text}");
        assert_eq!(parse_rfc3339(&text), Some(time), "{text}");
    }
}

#[test]
fn every_millisecond_of_a_second_round_trips() {
    for millis in 0..1_000u64 {
        let time = at(1_709_164_800 + 86_399, millis);
        let text = rfc3339(time);
        assert!(text.starts_with("2024-02-29T23:59:59."), "{text}");
        assert_eq!(parse_rfc3339(&text), Some(time), "{text}");
    }
}

#[test]
fn parses_the_servers_form() {
    // The server writes `Time#utc.iso8601`: whole seconds and `Z`.
    assert_eq!(
        parse_rfc3339("2026-01-01T12:00:00Z"),
        Some(at(1_767_268_800, 0))
    );
    assert_eq!(
        parse_rfc3339("2024-02-29T00:00:00Z"),
        Some(at(1_709_164_800, 0))
    );
}

#[test]
fn parses_every_fraction_width_the_contract_allows() {
    let base = at(1_767_268_800, 0);
    for (text, nano) in [
        ("2026-01-01T12:00:00.1Z", 100_000_000),
        ("2026-01-01T12:00:00.12Z", 120_000_000),
        ("2026-01-01T12:00:00.123Z", 123_000_000),
        ("2026-01-01T12:00:00.000001Z", 1_000),
        ("2026-01-01T12:00:00.123456789Z", 123_456_789),
        ("2026-01-01T12:00:00.000000000Z", 0),
    ] {
        assert_eq!(
            parse_rfc3339(text),
            Some(base + Duration::from_nanos(nano)),
            "{text}"
        );
    }
}

#[test]
fn a_leap_second_reads_as_the_second_before() {
    assert_eq!(
        parse_rfc3339("2016-12-31T23:59:60Z"),
        parse_rfc3339("2016-12-31T23:59:59Z")
    );
    assert_eq!(
        parse_rfc3339("2016-12-31T23:59:60.5Z"),
        Some(at(1_483_228_799, 500))
    );
}

#[test]
fn rejects_malformed_or_impossible_timestamps() {
    for bad in [
        "",
        "Z",
        "2026-01-01T12:00:00",
        "2026-01-01 12:00:00Z",
        "2026-01-01t12:00:00Z",
        "2026-01-01T12:00:00z",
        "2026-02-30T12:00:00Z",
        "2025-02-29T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-00-01T00:00:00Z",
        "2026-01-00T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T12:60:00Z",
        "2026-01-01T12:00:61Z",
        "1969-12-31T23:59:59Z",
        "+026-01-01T12:00:00Z",
        "-026-01-01T12:00:00Z",
        "2026-01-01T12:00:0xZ",
        "2026-1-01T12:00:00Z",
        "2026-01-01T12:00:00.Z",
        "2026-01-01T12:00:00.1234567890Z",
        "2026-01-01T12:00:00.12a4Z",
        "2026-01-01T12:00:00,123Z",
        "2026-01-01T12:00:00ZZ",
        "2026-01-01T12:00:00.123ZZ",
        " 2026-01-01T12:00:00Z",
        "2026-01-01T12:00:00Z ",
        "２０２６-01-01T12:00:00Z",
        // Never misread an offset as UTC: the contract's timestamps all end in `Z`.
        "2026-01-01T12:00:00-05:00",
        "2026-01-01T12:00:00+05:30",
        "2026-01-01T12:00:00+00:00",
        "2026-01-01T12:00:00.123+00:00",
    ] {
        assert_eq!(parse_rfc3339(bad), None, "{bad}");
    }
}
