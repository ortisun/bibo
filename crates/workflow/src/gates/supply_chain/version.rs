//! Package versions, enough of semver to order them.
//!
//! `semver` is not on the external allow list of this crate, and the gate needs one thing from it:
//! to tell an upgrade from a downgrade. A version this reader cannot parse is never ordered, and
//! the caller treats that as a finding (a lockfile with a version that is not a version is not
//! trusted).

use std::cmp::Ordering;

/// A parsed version: `MAJOR.MINOR.PATCH`, an optional pre-release, and build metadata that is
/// kept out of the order, as semver says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Identifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Identifier {
    Numeric(u64),
    Text(String),
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.cmp(b),
            (Self::Numeric(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Text(a), Self::Text(b)) => a.cmp(b),
        }
    }
}

impl Version {
    /// Reads `1.2.3`, `1.2.3-rc.1` and `1.2.3+build`. Anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let without_build = text.split_once('+').map_or(text, |(core, _)| core);
        let (core, pre) = match without_build.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (without_build, None),
        };
        let mut numbers = core.split('.');
        let major = number(numbers.next()?)?;
        let minor = number(numbers.next()?)?;
        let patch = number(numbers.next()?)?;
        if numbers.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(list) => list
                .split('.')
                .map(identifier)
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// The compatibility series: the versions cargo treats as one for `^` requirements. Two
    /// versions in one series replace each other, so a lower one after a higher one is a
    /// downgrade. A version in another series is a different package copy.
    #[must_use]
    pub fn series(&self) -> (u64, u64, u64) {
        if self.major > 0 {
            (self.major, 0, 0)
        } else if self.minor > 0 {
            (0, self.minor, 0)
        } else {
            (0, 0, self.patch)
        }
    }
}

fn number(text: &str) -> Option<u64> {
    let plain = !text.is_empty()
        && text.chars().all(|c| c.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if plain { text.parse().ok() } else { None }
}

fn identifier(text: &str) -> Option<Identifier> {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    if text.chars().all(|c| c.is_ascii_digit()) {
        return number(text).map(Identifier::Numeric);
    }
    Some(Identifier::Text(text.to_owned()))
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A release is later than any of its pre-releases.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).expect("a version")
    }

    #[test]
    fn versions_are_ordered_as_semver_orders_them() {
        assert!(v("1.2.3") < v("1.2.4"));
        assert!(v("1.10.0") > v("1.9.9"));
        assert!(v("1.0.0-rc.1") < v("1.0.0"));
        assert!(v("1.0.0-alpha") < v("1.0.0-beta"));
        assert!(v("1.0.0-1") < v("1.0.0-alpha"));
        assert_eq!(v("1.0.0+build.5").cmp(&v("1.0.0")), Ordering::Equal);
    }

    #[test]
    fn text_that_is_not_a_version_is_not_read() {
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.2.x",
            "1.2.3-",
            "v1.2.3",
            "1.2.3-a_b",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn compatible_versions_share_a_series() {
        assert_eq!(v("1.2.3").series(), v("1.9.0").series());
        assert_ne!(v("1.2.3").series(), v("2.0.0").series());
        assert_eq!(v("0.3.1").series(), v("0.3.9").series());
        assert_ne!(v("0.3.1").series(), v("0.4.0").series());
        assert_ne!(v("0.0.1").series(), v("0.0.2").series());
    }
}
