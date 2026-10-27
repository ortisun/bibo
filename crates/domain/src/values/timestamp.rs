//! A UTC instant that keeps the exact spelling of the document it came from.

use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use time::{Date, Month, PrimitiveDateTime, Time};

use crate::error::ValueError;
use crate::patterns;

static SHAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(patterns::TIMESTAMP).expect("a schema pattern is a valid regex"));

const WHAT: &str = "timestamp";
const RULE: &str = "use a real UTC time as `YYYY-MM-DDTHH:MM:SS` with up to 9 fraction digits and a `Z` suffix";

/// A UTC instant in RFC 3339 form with a `Z` suffix, for example `2026-10-27T08:30:01Z`.
///
/// The number of fraction digits is kept, so `...01.5Z` and `...01.500Z` read back as written and
/// a document serializes to the same text it was read from. The value is never read from a
/// clock: it comes from the `Clock` port or from a document.
///
/// The schema pattern lets impossible dates such as `2026-02-30` through, because it checks
/// digits only. This type also checks the calendar and the clock, and refuses leap seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
            format!("{fraction:0<9}").parse::<u32>().map_err(|_| fail())?
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
        while digits > 0 && rest % 10 == 0 {
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
