//! What a plain (unquoted) scalar means.
//!
//! The YAML parser reports a scalar as text plus the style it was written in. It does not say
//! whether `no` is a string or a boolean, because that depends on the YAML version of the reader:
//! YAML 1.1 reads `no`, `yes`, `on`, `off`, `y` and `n` as booleans, `0777` as an octal number,
//! `1:30` as a base-60 number and `2027-01-31` as a date, while YAML 1.2 reads them as strings
//! or as decimal numbers. A document that means different things to different readers is a
//! document nobody can review with confidence, so this module decides, once, and refuses
//! everything it would be unsure about.
//!
//! # The rules for a plain scalar
//!
//! | Text | Result |
//! |---|---|
//! | `true`, `false` (lower case only) | boolean |
//! | `-?(0\|[1-9][0-9]*)` | integer, within 64 bits |
//! | `-?(0\|[1-9][0-9]*)\.[0-9]+` | float |
//! | `y n yes no on off` in any case | refused: a YAML 1.1 boolean |
//! | `True TRUE False FALSE` and other spellings of true and false | refused |
//! | `~`, `null`, `Null`, `NULL`, empty | refused: null |
//! | any other number-like text: `+1`, `007`, `0777`, `0o7`, `0x1F`, `0b11`, `1_000`, `1e3`, `1.`, `.5`, `.inf`, `.nan`, `1:30`, or an integer beyond 64 bits | refused |
//! | a date or time such as `2027-01-31` or `2026-10-27T10:00:00Z` | refused |
//! | anything else | string |
//!
//! A refused scalar is not lost: wrapping it in quotes turns it into the string it looks like.
//! A quoted scalar and a block scalar (`|` or `>`) are always strings.

use std::sync::OnceLock;

use regex::Regex;

/// Why a plain scalar is refused. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmbiguousScalar {
    /// `y`, `n`, `yes`, `no`, `on` or `off` in any case.
    LegacyBoolean,
    /// `True`, `TRUE`, `False`, `FALSE` or another spelling that is not lower-case `true` or
    /// `false`.
    BooleanSpelling,
    /// A number written in a form other than plain decimal.
    Number,
    /// A date or a time.
    Timestamp,
}

/// What a plain scalar resolved to.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    /// `true` or `false`.
    Bool(bool),
    /// An integer that fits `i64`.
    Int(i64),
    /// An integer above `i64::MAX` that fits `u64`.
    UInt(u64),
    /// A decimal number with a fractional part.
    Float(f64),
    /// Text.
    Str,
}

/// Why a plain scalar cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Empty, `~` or `null`.
    Null,
    /// A form that readers disagree on.
    Ambiguous(AmbiguousScalar),
}

struct Patterns {
    integer: Regex,
    float: Regex,
    number_like: Regex,
    timestamp: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        integer: compile(r"^-?(?:0|[1-9][0-9]*)$"),
        float: compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]+$"),
        // Every other way a reader might take the text for a number. Anchored at both ends.
        number_like: compile(concat!(
            r"^[-+]?(?:",
            r"\.[0-9][0-9_]*(?:[eE][-+]?[0-9]+)?", // .5  .5e3
            r"|[0-9][0-9_]*\.[0-9_]*(?:[eE][-+]?[0-9]+)?", // 1.  1.5e3  1_0.5
            r"|[0-9][0-9_]*[eE][-+]?[0-9]+",       // 1e3
            r"|0[xX][0-9a-fA-F_]+",                // 0x1F
            r"|0[oO][0-7_]+",                      // 0o7
            r"|0[bB][01_]+",                       // 0b11
            r"|[0-9][0-9_]*",                      // +1  007  0777  1_000
            r"|\.(?:inf|Inf|INF|nan|NaN|NAN)",     // .inf  .nan
            r"|[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?", // 1:30  base 60
            r")$"
        )),
        timestamp: compile(concat!(
            r"^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}",
            r"(?:(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?",
            r"(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?)?$"
        )),
    })
}

/// The patterns are constants in this file. A unit test compiles each, so a typo fails the
/// tests and never reaches a caller.
fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a constant pattern in this module compiles")
}

/// Decides what a plain scalar means, or refuses it. See the module notes for the rules.
///
/// # Errors
/// [`Refusal`] when the text is null or ambiguous.
pub fn resolve_plain(text: &str) -> Result<Resolved, Refusal> {
    let patterns = patterns();
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return Err(Refusal::Null),
        "true" => return Ok(Resolved::Bool(true)),
        "false" => return Ok(Resolved::Bool(false)),
        _ => {}
    }
    if matches!(
        text.to_ascii_lowercase().as_str(),
        "y" | "n" | "yes" | "no" | "on" | "off"
    ) {
        return Err(Refusal::Ambiguous(AmbiguousScalar::LegacyBoolean));
    }
    if matches!(text.to_ascii_lowercase().as_str(), "true" | "false") {
        return Err(Refusal::Ambiguous(AmbiguousScalar::BooleanSpelling));
    }
    if patterns.integer.is_match(text) {
        if let Ok(whole) = text.parse::<i64>() {
            return Ok(Resolved::Int(whole));
        }
        if let Ok(whole) = text.parse::<u64>() {
            return Ok(Resolved::UInt(whole));
        }
        return Err(Refusal::Ambiguous(AmbiguousScalar::Number));
    }
    if patterns.float.is_match(text) {
        return match text.parse::<f64>() {
            Ok(number) if number.is_finite() => Ok(Resolved::Float(number)),
            _ => Err(Refusal::Ambiguous(AmbiguousScalar::Number)),
        };
    }
    if patterns.number_like.is_match(text) {
        return Err(Refusal::Ambiguous(AmbiguousScalar::Number));
    }
    if patterns.timestamp.is_match(text) {
        return Err(Refusal::Ambiguous(AmbiguousScalar::Timestamp));
    }
    Ok(Resolved::Str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_constant_patterns_compile() {
        let _ = patterns();
    }

    #[test]
    fn canonical_numbers_resolve() {
        assert_eq!(resolve_plain("0"), Ok(Resolved::Int(0)));
        assert_eq!(resolve_plain("-0"), Ok(Resolved::Int(0)));
        assert_eq!(resolve_plain("-17"), Ok(Resolved::Int(-17)));
        assert_eq!(
            resolve_plain("9223372036854775808"),
            Ok(Resolved::UInt(9_223_372_036_854_775_808))
        );
        assert_eq!(resolve_plain("1.0"), Ok(Resolved::Float(1.0)));
        assert_eq!(resolve_plain("-0.25"), Ok(Resolved::Float(-0.25)));
    }

    #[test]
    fn version_like_and_path_like_text_stays_text() {
        for text in [
            "1.1.2",
            "1.2.3.4",
            "127.0.0.0/8",
            "--bare",
            "a1",
            "v1",
            "1a",
            "-",
            "L0",
            "10x",
        ] {
            assert_eq!(resolve_plain(text), Ok(Resolved::Str), "{text}");
        }
    }
}
