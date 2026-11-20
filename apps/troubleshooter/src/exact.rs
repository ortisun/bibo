//! Exact comparison of an observed value with a probe's threshold.
//!
//! A probe trips when `<observed> <comparator> <threshold>` holds. The observed value comes as
//! decimal text (a PromQL sample is a string such as `"0.25000000000000006"`, a count is an
//! integer), and the threshold is the policy's number. Comparing them as `f64` would make
//! `0.1 + 0.2` and `0.3` a matter of luck, so both sides are compared as exact decimals: the
//! threshold through its shortest round-trip text (`0.25` stays `0.25`), the observed value as
//! written. `NaN` never trips; `+Inf` and `-Inf` order as infinities.

use std::cmp::Ordering;

use factory_domain::policy::troubleshooting::Comparator;

/// A number read from decimal text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exact {
    /// Not a number.
    NaN,
    /// Minus infinity.
    NegInf,
    /// Plus infinity.
    PosInf,
    /// `(-1)^negative * digits * 10^exponent`, with no leading or trailing zero digit; zero has no
    /// digits and is never negative.
    Finite {
        /// The sign.
        negative: bool,
        /// The significant digits, most significant first, each 0 to 9.
        digits: Vec<u8>,
        /// The power of ten of the last digit.
        exponent: i64,
    },
}

/// The longest text read as a number. A sample is never longer; a longer text is refused.
const MAX_TEXT: usize = 128;

impl Exact {
    /// Reads decimal text: an optional sign, digits with an optional point, an optional exponent
    /// (`e` or `E`), or `NaN`, `Inf`, `+Inf`, `-Inf` (case ignored). `None` for anything else.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_TEXT {
            return None;
        }
        let (negative, body) = match text.as_bytes()[0] {
            b'-' => (true, &text[1..]),
            b'+' => (false, &text[1..]),
            _ => (false, text),
        };
        let lower = body.to_ascii_lowercase();
        match lower.as_str() {
            "nan" => return Some(Self::NaN),
            "inf" | "infinity" => {
                return Some(if negative { Self::NegInf } else { Self::PosInf });
            }
            _ => {}
        }
        let (mantissa, exponent_text) = match lower.find('e') {
            Some(at) => (&lower[..at], Some(&lower[at + 1..])),
            None => (lower.as_str(), None),
        };
        let mut exponent: i64 = match exponent_text {
            Some(e) => {
                let digits = e.strip_prefix(['+', '-']).unwrap_or(e);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                e.parse().ok()?
            }
            None => 0,
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if (whole.is_empty() && fraction.is_empty())
            || !whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit())
        {
            return None;
        }
        exponent = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
        let mut digits: Vec<u8> = whole
            .bytes()
            .chain(fraction.bytes())
            .map(|b| b - b'0')
            .skip_while(|d| *d == 0)
            .collect();
        while digits.last() == Some(&0) {
            digits.pop();
            exponent = exponent.checked_add(1)?;
        }
        if digits.is_empty() {
            return Some(Self::Finite {
                negative: false,
                digits,
                exponent: 0,
            });
        }
        Some(Self::Finite {
            negative,
            digits,
            exponent,
        })
    }

    /// The threshold of the policy, read through its shortest round-trip text.
    #[must_use]
    pub fn of_threshold(threshold: f64) -> Self {
        if threshold.is_nan() {
            return Self::NaN;
        }
        if threshold.is_infinite() {
            return if threshold > 0.0 {
                Self::PosInf
            } else {
                Self::NegInf
            };
        }
        // `LowerExp` of f64 writes the shortest digits that read back to the same value, with an
        // exponent (`2.5e-1`, `1e300`), so even a huge threshold is a short text.
        Self::parse(&format!("{threshold:e}")).unwrap_or(Self::NaN)
    }

    /// The value as `f64`, for the agent's input document. Infinities become the largest finite
    /// values (JSON has no infinity); `None` for `NaN`.
    #[must_use]
    pub fn approximate(&self) -> Option<f64> {
        match self {
            Self::NaN => None,
            Self::NegInf => Some(f64::MIN),
            Self::PosInf => Some(f64::MAX),
            Self::Finite { .. } => self.canonical().parse().ok(),
        }
    }

    /// The canonical text: `NaN`, `+Inf`, `-Inf`, or digits with an exponent (`25e-2`).
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::NaN => "NaN".to_owned(),
            Self::NegInf => "-Inf".to_owned(),
            Self::PosInf => "+Inf".to_owned(),
            Self::Finite {
                negative,
                digits,
                exponent,
            } => {
                if digits.is_empty() {
                    return "0".to_owned();
                }
                let sign = if *negative { "-" } else { "" };
                let text: String = digits.iter().map(|d| char::from(b'0' + d)).collect();
                if *exponent == 0 {
                    format!("{sign}{text}")
                } else {
                    format!("{sign}{text}e{exponent}")
                }
            }
        }
    }

    /// The order of two numbers, `None` when either is `NaN`.
    #[must_use]
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        let rank = |value: &Self| match value {
            Self::NaN => None,
            Self::NegInf => Some(-1),
            Self::Finite { .. } => Some(0),
            Self::PosInf => Some(1),
        };
        let (left, right) = (rank(self)?, rank(other)?);
        if left != right || left != 0 {
            return Some(left.cmp(&right));
        }
        Some(compare_finite(self, other))
    }
}

fn sign_of(value: &Exact) -> i8 {
    match value {
        Exact::Finite {
            negative, digits, ..
        } => {
            if digits.is_empty() {
                0
            } else if *negative {
                -1
            } else {
                1
            }
        }
        _ => 0,
    }
}

fn compare_finite(left: &Exact, right: &Exact) -> Ordering {
    let (
        Exact::Finite {
            digits: ld,
            exponent: le,
            ..
        },
        Exact::Finite {
            digits: rd,
            exponent: re,
            ..
        },
    ) = (left, right)
    else {
        return Ordering::Equal;
    };
    let (ls, rs) = (sign_of(left), sign_of(right));
    if ls != rs {
        return ls.cmp(&rs);
    }
    if ls == 0 {
        return Ordering::Equal;
    }
    let magnitude = compare_magnitude(ld, *le, rd, *re);
    if ls < 0 {
        magnitude.reverse()
    } else {
        magnitude
    }
}

/// Compares two positive magnitudes `digits * 10^exponent`.
fn compare_magnitude(ld: &[u8], le: i64, rd: &[u8], re: i64) -> Ordering {
    // The position of the leading digit: the larger one is the larger number.
    let lead = |digits: &[u8], exponent: i64| {
        exponent.saturating_add(i64::try_from(digits.len()).unwrap_or(i64::MAX))
    };
    match lead(ld, le).cmp(&lead(rd, re)) {
        Ordering::Equal => {}
        other => return other,
    }
    // Same leading position: compare digit by digit, a missing digit is zero.
    let length = ld.len().max(rd.len());
    for index in 0..length {
        let l = ld.get(index).copied().unwrap_or(0);
        let r = rd.get(index).copied().unwrap_or(0);
        match l.cmp(&r) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// Whether `observed <comparator> threshold` holds, exactly. `NaN` never trips.
#[must_use]
pub fn trips(comparator: Comparator, observed: &Exact, threshold: f64) -> bool {
    let Some(order) = observed.compare(&Exact::of_threshold(threshold)) else {
        return false;
    };
    match comparator {
        Comparator::Gt => order == Ordering::Greater,
        Comparator::Ge => order != Ordering::Less,
        Comparator::Lt => order == Ordering::Less,
        Comparator::Le => order != Ordering::Greater,
        Comparator::Eq => order == Ordering::Equal,
        Comparator::Ne => order != Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> Exact {
        Exact::parse(text).unwrap_or_else(|| panic!("{text} parses"))
    }

    #[test]
    fn a_value_just_over_the_threshold_trips_and_one_equal_to_it_does_not() {
        // 0.1 + 0.2 in f64 is 0.30000000000000004: over 0.3 exactly, not "about equal".
        assert!(trips(Comparator::Gt, &value("0.30000000000000004"), 0.3));
        assert!(!trips(Comparator::Gt, &value("0.3"), 0.3));
        assert!(!trips(Comparator::Gt, &value("0.300"), 0.3));
        assert!(trips(Comparator::Ge, &value("3e-1"), 0.3));
        assert!(trips(Comparator::Eq, &value("30E-2"), 0.3));
        assert!(!trips(Comparator::Gt, &value("0.25"), 0.25));
        assert!(trips(Comparator::Gt, &value("0.2500000000000001"), 0.25));
    }

    #[test]
    fn counts_and_statuses_compare_as_whole_numbers() {
        assert!(!trips(Comparator::Gt, &value("10"), 10.0));
        assert!(trips(Comparator::Gt, &value("11"), 10.0));
        assert!(trips(Comparator::Ge, &value("1"), 1.0));
        assert!(!trips(Comparator::Gt, &value("0"), 0.0));
        assert!(trips(Comparator::Gt, &value("1"), 0.0));
        assert!(!trips(Comparator::Ne, &value("200"), 200.0));
        assert!(trips(Comparator::Ne, &value("503"), 200.0));
        assert!(trips(Comparator::Ne, &value("0"), 200.0));
    }

    #[test]
    fn signs_zeros_and_infinities_order_correctly() {
        assert!(trips(Comparator::Lt, &value("-0.5"), 0.0));
        assert!(!trips(Comparator::Lt, &value("-0"), 0.0));
        assert!(trips(Comparator::Lt, &value("-2"), -1.0));
        assert!(trips(Comparator::Gt, &value("-1"), -2.0));
        assert!(trips(Comparator::Gt, &value("+Inf"), 1e300));
        assert!(trips(Comparator::Lt, &value("-Inf"), -1e300));
        assert!(trips(Comparator::Gt, &value("1e400"), 1e300));
    }

    #[test]
    fn nan_and_garbage_never_trip() {
        assert!(!trips(Comparator::Ne, &value("NaN"), 1.0));
        assert!(!trips(Comparator::Gt, &value("NaN"), 0.0));
        for bad in ["", "1.2.3", "abc", "1e", "e5", "--1", "0x10", "1,5"] {
            assert_eq!(Exact::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_canonical_text_reads_back_to_the_same_number() {
        for text in ["0.25", "1000", "-0.001", "12.5e3", "0"] {
            let first = value(text);
            assert_eq!(value(&first.canonical()), first, "{text}");
        }
        assert_eq!(value("0.250").canonical(), "25e-2");
        assert_eq!(value("12").approximate(), Some(12.0));
    }
}
