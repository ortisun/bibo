//! The spellings in which a registered secret can leak.
//!
//! A secret that the factory loaded or issued is looked for in these forms, which are the ones
//! named by `secrets.exact_values.encodings` in `policies/security.yaml`. Each form is a byte
//! string. The matcher searches for all of them at once.
//!
//! Base64 needs the most care, because the text that holds a secret is often not the secret
//! alone. `Basic` authentication encodes `user:secret`, and a JSON document may be encoded whole.
//! Then the secret starts at byte 0, 1 or 2 of a three byte group, and the letters it produces
//! differ for each of the three positions. For each alphabet this module builds:
//!
//! * three interior forms, one per start position. They hold only the base64 letters that are
//!   fully decided by the secret, so they appear in the encoding of any longer message that
//!   contains the secret at that position, whatever comes before and after it;
//! * three tail forms, one per start position, with and without padding. They hold the letters
//!   decided by the secret when the secret is the end of the message. At position 0 this is the
//!   plain base64 of the secret.
//!
//! The functions here are pure and make no allocation that depends on anything but the size of
//! the secret.

use std::collections::BTreeSet;

/// One of the encodings named by the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Encoding {
    /// The value as written.
    Raw,
    /// Standard base64: the interior forms and the padded tail forms.
    Base64Std,
    /// URL-safe base64: the interior forms and the padded tail forms.
    Base64Url,
    /// Base64 tail forms without padding, in both alphabets.
    Base64NoPad,
    /// Lowercase hexadecimal.
    HexLower,
    /// Uppercase hexadecimal.
    HexUpper,
    /// Percent-encoding in the styles of URL builders, form encoders and scripting languages.
    UrlPercent,
    /// Escaped to sit inside a JSON string, in the styles of the common JSON encoders.
    JsonEscaped,
}

impl Encoding {
    /// Every encoding, in the order the policy lists them.
    pub const ALL: [Encoding; 8] = [
        Encoding::Raw,
        Encoding::Base64Std,
        Encoding::Base64Url,
        Encoding::Base64NoPad,
        Encoding::HexLower,
        Encoding::HexUpper,
        Encoding::UrlPercent,
        Encoding::JsonEscaped,
    ];

    /// The name the policy uses for this encoding.
    #[must_use]
    pub const fn policy_name(self) -> &'static str {
        match self {
            Encoding::Raw => "raw",
            Encoding::Base64Std => "base64_std",
            Encoding::Base64Url => "base64_url",
            Encoding::Base64NoPad => "base64_no_pad",
            Encoding::HexLower => "hex_lower",
            Encoding::HexUpper => "hex_upper",
            Encoding::UrlPercent => "url_percent",
            Encoding::JsonEscaped => "json_escaped",
        }
    }

    /// The encoding with this policy name, if there is one.
    #[must_use]
    pub fn from_policy_name(name: &str) -> Option<Encoding> {
        Encoding::ALL.into_iter().find(|e| e.policy_name() == name)
    }
}

/// Every distinct byte string in which `value` can appear, for the given encodings.
///
/// The JSON forms need text. A value that is not valid UTF-8 has none.
pub(super) fn forms(value: &[u8], encodings: &[Encoding]) -> BTreeSet<Vec<u8>> {
    let mut found = BTreeSet::new();
    for encoding in encodings {
        match encoding {
            Encoding::Raw => {
                found.insert(value.to_vec());
            }
            Encoding::Base64Std => base64_forms(value, &STD, true, &mut found),
            Encoding::Base64Url => base64_forms(value, &URL, true, &mut found),
            Encoding::Base64NoPad => {
                for alphabet in [&STD, &URL] {
                    for offset in 0..3 {
                        found.insert(base64_tail(value, alphabet, offset, false));
                    }
                }
            }
            Encoding::HexLower => {
                found.insert(hex(value, false));
            }
            Encoding::HexUpper => {
                found.insert(hex(value, true));
            }
            Encoding::UrlPercent => percent_forms(value, &mut found),
            Encoding::JsonEscaped => {
                if let Ok(text) = std::str::from_utf8(value) {
                    json_forms(text, &mut found);
                }
            }
        }
    }
    found
}

// ---- Base64 ------------------------------------------------------------------------------

const STD: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn letter(alphabet: &[u8; 64], six_bits: u8) -> u8 {
    alphabet
        .get(usize::from(six_bits & 0x3f))
        .copied()
        .unwrap_or(b'=')
}

/// The base64 letters of `bytes`, with no padding. A last group of one or two bytes gives two or
/// three letters, with the unused bits taken as zero.
fn base64_letters(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for group in bytes.chunks(3) {
        let b0 = group.first().copied().unwrap_or(0);
        let b1 = group.get(1).copied().unwrap_or(0);
        let b2 = group.get(2).copied().unwrap_or(0);
        out.push(letter(alphabet, b0 >> 2));
        out.push(letter(alphabet, (b0 << 4) | (b1 >> 4)));
        if group.len() > 1 {
            out.push(letter(alphabet, (b1 << 2) | (b2 >> 6)));
        }
        if group.len() > 2 {
            out.push(letter(alphabet, b2));
        }
    }
    out
}

/// The index of the first base64 letter that is decided entirely by the value. Letter `j` covers
/// bits `6j` to `6j + 5` of the message, and the value starts at bit `8 * offset`.
fn first_decided_letter(offset: usize) -> usize {
    offset.saturating_mul(8).saturating_add(5) / 6
}

/// The letters decided by the value alone when more bytes may follow it: the value starts at byte
/// `offset` of a three byte group and the message goes on after it.
fn base64_interior(value: &[u8], alphabet: &[u8; 64], offset: usize) -> Vec<u8> {
    let mut message = vec![0u8; offset];
    message.extend_from_slice(value);
    while !message.len().is_multiple_of(3) {
        message.push(0);
    }
    let letters = base64_letters(&message, alphabet);
    let end = offset.saturating_add(value.len()).saturating_mul(8) / 6;
    letters
        .get(first_decided_letter(offset)..end)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// The letters decided by the value when it is the end of the message, with or without the
/// padding that completes the last group of four.
fn base64_tail(value: &[u8], alphabet: &[u8; 64], offset: usize, padded: bool) -> Vec<u8> {
    let mut message = vec![0u8; offset];
    message.extend_from_slice(value);
    let letters = base64_letters(&message, alphabet);
    let mut out = letters
        .get(first_decided_letter(offset)..)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    if padded {
        let missing = (4 - letters.len() % 4) % 4;
        out.extend(std::iter::repeat_n(b'=', missing));
    }
    out
}

fn base64_forms(value: &[u8], alphabet: &[u8; 64], padded: bool, found: &mut BTreeSet<Vec<u8>>) {
    for offset in 0..3 {
        found.insert(base64_interior(value, alphabet, offset));
        found.insert(base64_tail(value, alphabet, offset, padded));
    }
}

// ---- Hexadecimal -------------------------------------------------------------------------

fn hex_digit(upper: bool, nibble: u8) -> u8 {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    digits
        .get(usize::from(nibble & 0x0f))
        .copied()
        .unwrap_or(b'0')
}

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(hex_digit(upper, byte >> 4));
        out.push(hex_digit(upper, *byte));
    }
    out
}

// ---- Percent-encoding --------------------------------------------------------------------

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// The characters RFC 3986 calls unreserved.
fn is_unreserved(b: u8) -> bool {
    is_alnum(b) || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// The same set without the tilde, which older encoders escape.
fn is_unreserved_without_tilde(b: u8) -> bool {
    is_alnum(b) || matches!(b, b'-' | b'.' | b'_')
}

/// The characters that `encodeURIComponent` leaves alone.
fn is_script_safe(b: u8) -> bool {
    is_unreserved(b) || matches!(b, b'!' | b'*' | b'\'' | b'(' | b')')
}

fn is_nothing_safe(_b: u8) -> bool {
    false
}

fn percent_encode(bytes: &[u8], safe: fn(u8) -> bool, upper: bool, space_as_plus: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(3));
    for &byte in bytes {
        if byte == b' ' && space_as_plus {
            out.push(b'+');
        } else if byte.is_ascii() && safe(byte) {
            out.push(byte);
        } else {
            out.push(b'%');
            out.push(hex_digit(upper, byte >> 4));
            out.push(hex_digit(upper, byte));
        }
    }
    out
}

fn percent_forms(value: &[u8], found: &mut BTreeSet<Vec<u8>>) {
    let safe_sets: [fn(u8) -> bool; 5] = [
        is_unreserved,
        is_unreserved_without_tilde,
        is_script_safe,
        is_alnum,
        is_nothing_safe,
    ];
    for safe in safe_sets {
        for upper in [true, false] {
            for space_as_plus in [false, true] {
                found.insert(percent_encode(value, safe, upper, space_as_plus));
            }
        }
    }
}

// ---- JSON --------------------------------------------------------------------------------

/// How a JSON encoder escapes text.
#[derive(Clone, Copy)]
struct JsonStyle {
    /// Write the slash as backslash and slash.
    slash: bool,
    /// Write the angle brackets, the ampersand and the two Unicode line separators as `\uXXXX`,
    /// as encoders made for HTML do.
    html: bool,
    /// Write every character outside ASCII as `\uXXXX`, with this letter case for the digits
    /// (`true` for capitals).
    ascii_only: Option<bool>,
}

fn push_unit(out: &mut String, unit: u32, upper: bool) {
    let escaped = if upper {
        format!("\\u{unit:04X}")
    } else {
        format!("\\u{unit:04x}")
    };
    out.push_str(&escaped);
}

fn json_escape(text: &str, style: JsonStyle) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(text.len() / 4));
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' if style.slash => out.push_str("\\/"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' if style.html => {
                push_unit(&mut out, u32::from(c), false);
            }
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => push_unit(&mut out, u32::from(c), false),
            c if !c.is_ascii() => match style.ascii_only {
                Some(upper) => {
                    let mut units = [0u16; 2];
                    for unit in c.encode_utf16(&mut units) {
                        push_unit(&mut out, u32::from(*unit), upper);
                    }
                }
                None => out.push(c),
            },
            c => out.push(c),
        }
    }
    out
}

fn json_forms(text: &str, found: &mut BTreeSet<Vec<u8>>) {
    let minimal = JsonStyle {
        slash: false,
        html: false,
        ascii_only: None,
    };
    let styles = [
        minimal,
        JsonStyle {
            slash: true,
            ..minimal
        },
        JsonStyle {
            html: true,
            ..minimal
        },
        JsonStyle {
            ascii_only: Some(false),
            ..minimal
        },
        JsonStyle {
            ascii_only: Some(true),
            ..minimal
        },
        // The defaults of some scripting-language encoders: slash and non-ASCII both escaped.
        JsonStyle {
            slash: true,
            ascii_only: Some(false),
            ..minimal
        },
        JsonStyle {
            slash: true,
            ascii_only: Some(true),
            ..minimal
        },
    ];
    for style in styles {
        found.insert(json_escape(text, style).into_bytes());
    }
    // A JSON string that was itself put inside a JSON string.
    found.insert(json_escape(&json_escape(text, minimal), minimal).into_bytes());
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    /// A second, independent base64 encoder: it goes through a string of bits, where the module
    /// under test goes through groups of three bytes.
    fn reference_base64(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
        let mut bits = String::new();
        for b in bytes {
            bits.push_str(&format!("{b:08b}"));
        }
        while !bits.len().is_multiple_of(6) {
            bits.push('0');
        }
        let mut out: Vec<u8> = bits
            .as_bytes()
            .chunks(6)
            .map(|six| {
                let index = usize::from_str_radix(std::str::from_utf8(six).unwrap(), 2).unwrap();
                alphabet[index]
            })
            .collect();
        if pad {
            while !out.len().is_multiple_of(4) {
                out.push(b'=');
            }
        }
        out
    }

    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// A value with bytes that make the two alphabets differ and that need escaping everywhere.
    fn sample_value() -> Vec<u8> {
        b"Zk>?~~>>/pw d\"x\\y&<z\xc3\xa9!".to_vec()
    }

    fn all_forms(value: &[u8]) -> BTreeSet<Vec<u8>> {
        forms(value, &Encoding::ALL)
    }

    #[test]
    fn the_raw_form_is_the_value() {
        let value = sample_value();
        assert!(forms(&value, &[Encoding::Raw]).contains(&value));
    }

    #[test]
    fn a_value_in_the_middle_of_a_larger_base64_message_is_found_at_every_alignment() {
        let value = sample_value();
        let found = all_forms(&value);
        for prefix_len in 0..7usize {
            for suffix_len in 0..7usize {
                let mut message = vec![b'#'; prefix_len];
                message.extend_from_slice(&value);
                message.extend(std::iter::repeat_n(b'~', suffix_len));
                for alphabet in [STD, URL] {
                    for pad in [true, false] {
                        let encoded = reference_base64(&message, alphabet, pad);
                        assert!(
                            found.iter().any(|f| contains(&encoded, f)),
                            "prefix {prefix_len}, suffix {suffix_len}, pad {pad}: no form of the value is in {}",
                            String::from_utf8_lossy(&encoded)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_whole_base64_of_the_value_is_one_of_the_forms() {
        let value = sample_value();
        let found = all_forms(&value);
        for alphabet in [STD, URL] {
            for pad in [true, false] {
                assert!(found.contains(&reference_base64(&value, alphabet, pad)));
            }
        }
    }

    #[test]
    fn each_base64_form_is_long_enough_to_be_distinctive() {
        // A secret has at least eight bytes, and a form shorter than eight letters would match
        // by accident. The shortest form is an interior form.
        let value = b"12345678".to_vec();
        for form in all_forms(&value) {
            assert!(form.len() >= 8, "a form of {} bytes", form.len());
        }
    }

    #[test]
    fn hex_comes_in_both_cases() {
        let found = all_forms(b"\x00\xabsecret");
        assert!(found.contains(b"00ab736563726574".as_slice()));
        assert!(found.contains(b"00AB736563726574".as_slice()));
    }

    #[test]
    fn percent_encoding_covers_the_common_styles() {
        let found = all_forms(b"a b/c+d~e!");
        for expected in [
            // RFC 3986: only unreserved characters stay.
            "a%20b%2Fc%2Bd~e%21",
            "a%20b%2fc%2bd~e%21",
            // A form encoder writes a space as a plus sign.
            "a+b%2Fc%2Bd~e%21",
            // A script runtime that keeps its own list of safe punctuation.
            "a%20b%2Fc%2Bd~e!",
            // Older encoders also escape the tilde.
            "a%20b%2Fc%2Bd%7Ee%21",
            // Everything escaped.
            "%61%20%62%2F%63%2B%64%7E%65%21",
        ] {
            assert!(
                found.contains(expected.as_bytes()),
                "missing the percent form {expected}"
            );
        }
    }

    #[test]
    fn json_escaping_covers_the_common_styles() {
        let found = all_forms("q\"b\\s/<>&\u{e9}\n-padding".as_bytes());
        for expected in [
            // The minimal escapes.
            "q\\\"b\\\\s/<>&\u{e9}\\n-padding",
            // An encoder that also escapes the slash.
            "q\\\"b\\\\s\\/<>&\u{e9}\\n-padding",
            // An encoder for HTML, which escapes the angle brackets and the ampersand.
            "q\\\"b\\\\s/\\u003c\\u003e\\u0026\u{e9}\\n-padding",
            // An encoder that writes only ASCII.
            "q\\\"b\\\\s/<>&\\u00e9\\n-padding",
            "q\\\"b\\\\s/<>&\\u00E9\\n-padding",
            // A JSON string inside a JSON string.
            "q\\\\\\\"b\\\\\\\\s/<>&\u{e9}\\\\n-padding",
        ] {
            assert!(
                found.contains(expected.as_bytes()),
                "missing the JSON form {expected}"
            );
        }
    }

    #[test]
    fn a_value_that_needs_no_escaping_adds_only_the_escape_everything_forms() {
        // The plain text is also its own percent form and its own JSON form. The only other
        // spellings are "every byte escaped", in capital and lowercase digits.
        let found = forms(
            b"onlyLettersAndDigits12345",
            &[Encoding::UrlPercent, Encoding::JsonEscaped],
        );
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found.contains(b"onlyLettersAndDigits12345".as_slice()));
        let escaped =
            b"%6F%6E%6C%79%4C%65%74%74%65%72%73%41%6E%64%44%69%67%69%74%73%31%32%33%34%35";
        assert!(found.contains(escaped.as_slice()));
    }

    #[test]
    fn an_encoding_that_is_left_out_adds_no_forms() {
        let value = sample_value();
        let without_url = forms(
            &value,
            &[
                Encoding::Raw,
                Encoding::Base64Std,
                Encoding::Base64NoPad,
                Encoding::HexLower,
                Encoding::HexUpper,
                Encoding::UrlPercent,
                Encoding::JsonEscaped,
            ],
        );
        let url_padded = reference_base64(&value, URL, true);
        let std_padded = reference_base64(&value, STD, true);
        assert!(without_url.contains(&std_padded));
        assert!(!without_url.contains(&url_padded));
    }

    #[test]
    fn json_forms_are_skipped_for_bytes_that_are_not_text() {
        let found = forms(
            b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8",
            &[Encoding::JsonEscaped],
        );
        assert!(found.is_empty());
    }

    #[test]
    fn the_policy_names_round_trip() {
        for e in Encoding::ALL {
            assert_eq!(Encoding::from_policy_name(e.policy_name()), Some(e));
        }
        assert_eq!(Encoding::from_policy_name("rot13"), None);
    }
}
