//! A UTC instant that keeps the exact spelling of the document it came from.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use time::{Date, Month, PrimitiveDateTime, Time};

use crate::error::ValueError;
use crate::patterns;

static SHAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(patterns::TIMESTAMP).expect("a schema pattern is a valid regex"));

const WHAT: &str = "timestamp";
const RULE: &str =
    "use a real UTC time as `YYYY-MM-DDTHH:MM:SS` with up to 9 fraction digits and a `Z` suffix";

/// A UTC instant in RFC 3339 form with a `Z` suffix, for example `2026-10-27T08:30:01Z`.
///
/// The number of fraction digits is kept, so `...01.5Z` and `...01.500Z` read back as written and
/// a document serializes to the same text it was read from. The value is never read from a
/// clock: it comes from the `Clock` port or from a document.
///
/// The schema pattern lets impossible dates such as `2026-02-30` through, because it checks
/// digits only. This type also checks the calendar and the clock, and refuses leap seconds.
///
/// # Equality, hashing and order
///
/// `PartialEq`, `Eq`, `Hash`, `PartialOrd` and `Ord` look at the instant only (ADR 0011), so
/// `10:00:00Z` equals `10:00:00.000Z`, the two hash alike, and neither sorts before the other.
/// The spelling is not part of the comparison. `Serialize` and [`as_text`](Self::as_text) do use
/// the spelling, so two equal values can serialize differently. Code that needs a byte-identical
/// document check compares `as_text()`, and the ledger hash is always taken over the stored text.
/// A value built by [`from_utc`](Self::from_utc) uses the shortest spelling, so two such values
/// for one instant are byte-identical too.
#[derive(Debug, Clone, Copy)]
pub struct Timestamp {
    instant: PrimitiveDateTime,
    fraction_digits: u8,
}

impl Timestamp {
    /// Reads the schema form.
    ///
    /// # Errors
    /// Returns a [`ValueError`] when the text does not match the pattern or names a date or a
    /// time of day that does not exist.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let fail = || ValueError::new(WHAT, text, RULE);
        if !SHAPE.is_match(text) {
            return Err(fail());
        }
        // The pattern guarantees the layout, so these slices are in range and all digits.
        let number = |from: usize, to: usize| -> Result<u32, ValueError> {
            text.get(from..to)
                .and_then(|part| part.parse::<u32>().ok())
                .ok_or_else(fail)
        };
        let year = i32::try_from(number(0, 4)?).map_err(|_| fail())?;
        let month = Month::try_from(u8::try_from(number(5, 7)?).map_err(|_| fail())?)
            .map_err(|_| fail())?;
        let day = u8::try_from(number(8, 10)?).map_err(|_| fail())?;
        let hour = u8::try_from(number(11, 13)?).map_err(|_| fail())?;
        let minute = u8::try_from(number(14, 16)?).map_err(|_| fail())?;
        let second = u8::try_from(number(17, 19)?).map_err(|_| fail())?;

        let fraction = text
            .get(19..text.len() - 1)
            .and_then(|rest| rest.strip_prefix('.'))
            .unwrap_or("");
        let fraction_digits = u8::try_from(fraction.len()).map_err(|_| fail())?;
        let nanosecond = if fraction.is_empty() {
            0
        } else {
            format!("{fraction:0<9}")
                .parse::<u32>()
                .map_err(|_| fail())?
        };

        let date = Date::from_calendar_date(year, month, day).map_err(|_| fail())?;
        let time_of_day =
            Time::from_hms_nano(hour, minute, second, nanosecond).map_err(|_| fail())?;
        Ok(Self {
            instant: PrimitiveDateTime::new(date, time_of_day),
            fraction_digits,
        })
    }

    /// Whole seconds since 1970-01-01T00:00:00Z. Negative before that.
    #[must_use]
    pub const fn unix_seconds(&self) -> i64 {
        self.instant.assume_utc().unix_timestamp()
    }

    /// Nanoseconds within the second, 0 to 999,999,999.
    #[must_use]
    pub const fn subsecond_nanos(&self) -> u32 {
        self.instant.nanosecond()
    }

    /// Builds a timestamp from an instant that a `Clock` implementation produced. Trailing zero
    /// digits of the fraction are left out.
    #[must_use]
    pub fn from_utc(instant: time::OffsetDateTime) -> Self {
        let utc = instant.to_offset(time::UtcOffset::UTC);
        let nanos = utc.nanosecond();
        let mut digits = 9_u8;
        let mut rest = nanos;
        while digits > 0 && rest.is_multiple_of(10) {
            rest /= 10;
            digits -= 1;
        }
        Self {
            instant: PrimitiveDateTime::new(utc.date(), utc.time()),
            fraction_digits: digits,
        }
    }

    /// The instant, for arithmetic and comparison with other `time` values.
    #[must_use]
    pub const fn to_utc(&self) -> time::OffsetDateTime {
        self.instant.assume_utc()
    }

    /// The text form, which is also the form in documents.
    #[must_use]
    pub fn as_text(&self) -> String {
        self.to_string()
    }

    /// The instant `d` after this one, or `None` when it would pass the last date this type
    /// holds. Reads no clock. The result uses the shortest spelling of its fraction.
    #[must_use]
    pub fn checked_add(&self, d: std::time::Duration) -> Option<Timestamp> {
        let d = time::Duration::try_from(d).ok()?;
        let moved = self.instant.checked_add(d)?;
        Self::shortest(moved)
    }

    /// The instant `d` before this one, or `None` when it would pass the first date this type
    /// holds. Reads no clock. The result uses the shortest spelling of its fraction.
    #[must_use]
    pub fn checked_sub(&self, d: std::time::Duration) -> Option<Timestamp> {
        let d = time::Duration::try_from(d).ok()?;
        let moved = self.instant.checked_sub(d)?;
        Self::shortest(moved)
    }

    /// The first instant of the UTC calendar day this instant is in. This is the day that the
    /// ceilings "per day" of the budget policy count over: the canonical time is UTC (ADR 0011),
    /// so a day starts at 00:00:00Z whatever the zone of the host or of the people.
    #[must_use]
    pub fn start_of_utc_day(&self) -> Timestamp {
        let midnight = self.instant.replace_time(time::Time::MIDNIGHT);
        // Midnight of a date this type holds is a date this type holds.
        Self::shortest(midnight).unwrap_or(*self)
    }

    /// The gap from `earlier` to `self`, or `None` when `earlier` is later than `self`.
    #[must_use]
    pub fn duration_since(&self, earlier: &Timestamp) -> Option<std::time::Duration> {
        let gap = self.instant - earlier.instant;
        std::time::Duration::try_from(gap).ok()
    }

    /// A timestamp for `instant` with the fewest fraction digits that hold it, or `None` when the
    /// year is outside `0000` to `9999`, the years the text form can spell.
    fn shortest(instant: PrimitiveDateTime) -> Option<Self> {
        if !(0..=9999).contains(&instant.year()) {
            return None;
        }
        let mut digits = 9_u8;
        let mut rest = instant.nanosecond();
        while digits > 0 && rest.is_multiple_of(10) {
            rest /= 10;
            digits -= 1;
        }
        Some(Self {
            instant,
            fraction_digits: digits,
        })
    }
}

impl PartialEq for Timestamp {
    fn eq(&self, other: &Self) -> bool {
        self.instant == other.instant
    }
}

impl Eq for Timestamp {}

impl Hash for Timestamp {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // The same fields as the comparison, so values that are equal hash alike. The number of
        // fraction digits is left out on purpose.
        self.instant.hash(state);
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.instant.cmp(&other.instant)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let date = self.instant.date();
        let time_of_day = self.instant.time();
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            date.year(),
            u8::from(date.month()),
            date.day(),
            time_of_day.hour(),
            time_of_day.minute(),
            time_of_day.second(),
        )?;
        if self.fraction_digits > 0 {
            let nanos = format!("{:09}", time_of_day.nanosecond());
            let digits = usize::from(self.fraction_digits);
            write!(f, ".{}", &nanos[..digits])?;
        }
        f.write_str("Z")
    }
}

impl FromStr for Timestamp {
    type Err = ValueError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod arithmetic_tests {
    use std::time::Duration;

    use super::Timestamp;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a valid timestamp")
    }

    #[test]
    fn adding_a_duration_moves_the_instant_forward() {
        let later = at("2026-10-27T10:00:00Z")
            .checked_add(Duration::from_secs(90))
            .expect("no overflow");
        assert_eq!(later, at("2026-10-27T10:01:30Z"));
    }

    #[test]
    fn subtracting_a_duration_moves_the_instant_back_across_midnight() {
        let earlier = at("2026-10-27T00:00:10Z")
            .checked_sub(Duration::from_secs(20))
            .expect("no overflow");
        assert_eq!(earlier, at("2026-10-26T23:59:50Z"));
    }

    #[test]
    fn the_day_starts_at_midnight_utc() {
        for (instant, start) in [
            ("2026-11-10T23:59:59.999Z", "2026-11-10T00:00:00Z"),
            ("2026-11-11T00:00:00Z", "2026-11-11T00:00:00Z"),
            ("2026-11-11T00:00:00.001Z", "2026-11-11T00:00:00Z"),
            ("2024-02-29T12:30:00Z", "2024-02-29T00:00:00Z"),
        ] {
            assert_eq!(at(instant).start_of_utc_day(), at(start), "{instant}");
        }
    }

    #[test]
    fn a_fraction_survives_arithmetic() {
        let later = at("2026-10-27T10:00:00.250Z")
            .checked_add(Duration::from_millis(500))
            .expect("no overflow");
        assert_eq!(later.subsecond_nanos(), 750_000_000);
    }

    #[test]
    fn arithmetic_past_the_largest_date_returns_none() {
        let last = at("9999-12-31T23:59:59Z");
        assert_eq!(last.checked_add(Duration::from_secs(1)), None);
        assert_eq!(last.checked_add(Duration::MAX), None);
    }

    #[test]
    fn arithmetic_before_the_smallest_date_returns_none() {
        let first = at("0000-01-01T00:00:00Z");
        assert_eq!(first.checked_sub(Duration::from_secs(1)), None);
    }

    #[test]
    fn the_gap_between_two_instants_is_a_duration() {
        let a = at("2026-10-27T10:00:00Z");
        let b = at("2026-10-27T10:00:07.5Z");
        assert_eq!(b.duration_since(&a), Some(Duration::from_millis(7_500)));
        assert_eq!(a.duration_since(&a), Some(Duration::ZERO));
    }

    #[test]
    fn the_gap_to_a_later_instant_is_none() {
        let a = at("2026-10-27T10:00:00Z");
        let b = at("2026-10-27T10:00:07Z");
        assert_eq!(a.duration_since(&b), None);
    }
}
