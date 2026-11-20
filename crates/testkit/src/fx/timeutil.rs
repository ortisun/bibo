//! Calendar arithmetic for the fixtures, without a date library.
//!
//! The fake registry needs "first published three days ago", and the fake GitHub server needs
//! `expires_at` strings and the `iat` and `exp` claims of a JWT. The testkit may use only the
//! external crates on its allow list, and that list has no date crate, so this file holds the
//! two conversions that matter. They use the civil-date algorithms of Howard Hinnant
//! (days since 1970-01-01), which are exact for every proleptic Gregorian date.

/// Days from 1970-01-01 to the given civil date. Negative before the epoch.
#[must_use]
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date `(year, month, day)` of a day count since 1970-01-01.
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Formats seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn format_rfc3339(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let seconds_of_day = epoch_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3_600,
        seconds_of_day % 3_600 / 60,
        seconds_of_day % 60
    )
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ` into seconds since the Unix epoch. Any other spelling, an
/// impossible date or a time zone offset gives `None`.
#[must_use]
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<i64> {
        let digits = text.get(from..to)?;
        if digits.bytes().all(|b| b.is_ascii_digit()) {
            digits.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    // Reject a date such as February 30 by converting back.
    if civil_from_days(days) != (year, month, day) {
        return None;
    }
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_and_known_dates_convert_both_ways() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2026-10-27T08:30:00Z, the testkit clock's default start.
        let start = parse_rfc3339("2026-10-27T08:30:00Z").unwrap();
        // Value from Python's calendar.timegm, an implementation that shares no code with this one.
        assert_eq!(start, 1_793_089_800);
        assert_eq!(format_rfc3339(start), "2026-10-27T08:30:00Z");
        // A leap day and the day before the epoch.
        assert_eq!(
            format_rfc3339(parse_rfc3339("2028-02-29T23:59:59Z").unwrap()),
            "2028-02-29T23:59:59Z"
        );
        assert_eq!(format_rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn subtracting_days_crosses_month_and_year_ends() {
        let base = parse_rfc3339("2027-01-02T00:00:00Z").unwrap();
        assert_eq!(format_rfc3339(base - 3 * 86_400), "2026-12-30T00:00:00Z");
    }

    #[test]
    fn impossible_or_unusual_spellings_are_refused() {
        for bad in [
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-27T24:00:00Z",
            "2026-10-27 08:30:00Z",
            "2026-10-27T08:30:00+00:00",
            "2026-10-27T08:30:00",
            "26-10-27T08:30:00Z",
            "2026-1a-27T08:30:00Z",
            "",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad:?} must be refused");
        }
    }
}
