//! Numbers with a range.
//!
//! JSON has one number type, and the schemas use plain `number` for money, rates and
//! confidence. Reading those as `f64` would turn `5` into `5.0` on the way back out and the
//! document would no longer equal the one that was read. These types keep the original
//! `serde_json::Number`, so the spelling survives, and check the range on the way in.

use std::fmt;

use serde_json::Number;

use crate::error::ValueError;

/// An integer between `MIN` and `MAX`, both included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bounded<const MIN: i64, const MAX: i64>(i64);

/// An integer of at least 1, such as a version counter.
pub type PositiveInt = Bounded<1, { i64::MAX }>;
/// An integer of at least 0, such as a count.
pub type NonNegativeInt = Bounded<0, { i64::MAX }>;

impl<const MIN: i64, const MAX: i64> Bounded<MIN, MAX> {
    /// Checks the range.
    ///
    /// # Errors
    /// Returns a [`ValueError`] naming both ends when `value` is outside them.
    pub fn new(value: i64) -> Result<Self, ValueError> {
        if (MIN..=MAX).contains(&value) {
            Ok(Self(value))
        } else if MAX == i64::MAX {
            Err(ValueError::new(
                "integer",
                &value.to_string(),
                format!("use a whole number of at least {MIN}"),
            ))
        } else {
            Err(ValueError::new(
                "integer",
                &value.to_string(),
                format!("use a whole number from {MIN} to {MAX}"),
            ))
        }
    }

    /// The value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl<const MIN: i64, const MAX: i64> fmt::Display for Bounded<MIN, MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<const MIN: i64, const MAX: i64> serde::Serialize for Bounded<MIN, MAX> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

impl<'de, const MIN: i64, const MAX: i64> serde::Deserialize<'de> for Bounded<MIN, MAX> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <i64 as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// The version counter of an aggregate (a job, stage run, attempt or task node), from 1.
///
/// ADR 0007: every mutable row carries a version, and an update says which version it read
/// (`WHERE id = $1 AND version = $2`). Zero rows updated is a conflict. A new aggregate starts at
/// [`FIRST`](Self::FIRST) and each accepted change moves it to [`next`](Self::next). A domain
/// event carries the version after the change, so a consumer can spot reordering and gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AggregateVersion(i64);

impl AggregateVersion {
    /// The version of a new aggregate.
    pub const FIRST: Self = Self(1);

    /// Checks that the version is at least 1.
    ///
    /// # Errors
    /// Returns a [`ValueError`] for 0 or a negative number.
    pub fn new(value: i64) -> Result<Self, ValueError> {
        if value >= 1 {
            Ok(Self(value))
        } else {
            Err(ValueError::new(
                "aggregate version",
                &value.to_string(),
                "use a whole number of at least 1",
            ))
        }
    }

    /// The version after one more accepted change.
    ///
    /// # Errors
    /// Returns a [`ValueError`] if the counter would overflow, which no real aggregate reaches.
    pub fn next(self) -> Result<Self, ValueError> {
        self.0.checked_add(1).map(Self).ok_or_else(|| {
            ValueError::new(
                "aggregate version",
                &self.0.to_string(),
                "the counter cannot go higher",
            )
        })
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for AggregateVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl serde::Serialize for AggregateVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> serde::Deserialize<'de> for AggregateVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <i64 as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A whole number of any size that JSON can hold without a fraction, such as a random seed.
///
/// A plain `i64` would refuse a seed above 2^63, which the schema allows. `5.0` is not accepted,
/// because it would not read back as it was written.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Integer(Number);

impl Integer {
    /// Checks that the number has no fraction.
    ///
    /// # Errors
    /// Returns a [`ValueError`] for a number with a fraction or an exponent.
    pub fn new(number: Number) -> Result<Self, ValueError> {
        if number.is_i64() || number.is_u64() {
            Ok(Self(number))
        } else {
            Err(ValueError::new(
                "integer",
                &number.to_string(),
                "use a whole number without a fraction",
            ))
        }
    }

    /// The number exactly as written in the document.
    #[must_use]
    pub const fn number(&self) -> &Number {
        &self.0
    }
}

impl serde::Serialize for Integer {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.0, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Integer {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let number = <Number as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(number).map_err(serde::de::Error::custom)
    }
}

/// Defines a wrapper around `serde_json::Number` that accepts a range of values.
macro_rules! ranged_number {
    ($(#[$meta:meta])* $name:ident ($what:literal), $rule:literal, |$value:ident| $accepts:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name(Number);

        impl $name {
            /// Checks the range.
            ///
            /// # Errors
            /// Returns a [`ValueError`] that states the range.
            pub fn new(number: Number) -> Result<Self, ValueError> {
                let accepted = number.as_f64().is_some_and(|$value| $accepts);
                if accepted {
                    Ok(Self(number))
                } else {
                    Err(ValueError::new($what, &number.to_string(), $rule))
                }
            }

            /// The value as a float, for comparison and arithmetic.
            #[must_use]
            pub fn as_f64(&self) -> f64 {
                self.0.as_f64().unwrap_or(f64::NAN)
            }

            /// The number exactly as written in the document.
            #[must_use]
            pub const fn number(&self) -> &Number {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde::Serialize::serialize(&self.0, serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let number = <Number as serde::Deserialize>::deserialize(deserializer)?;
                Self::new(number).map_err(serde::de::Error::custom)
            }
        }
    };
}

ranged_number! {
    /// A number from 0 to 1, both included, such as a confidence.
    UnitInterval("number from 0 to 1"), "use a number from 0 to 1", |v| (0.0..=1.0).contains(&v)
}

ranged_number! {
    /// A number above 0 and at most 1, such as the pass rate an evaluation suite must reach.
    PositiveFraction("number above 0 and at most 1"),
    "use a number above 0 and at most 1",
    |v| v > 0.0 && v <= 1.0
}

ranged_number! {
    /// A number of at least 0, such as a money limit.
    NonNegativeNumber("number of at least 0"), "use a number of at least 0", |v| v >= 0.0
}

ranged_number! {
    /// A number above 0, such as a money limit that must leave room to work.
    PositiveNumber("number above 0"), "use a number above 0", |v| v > 0.0
}
