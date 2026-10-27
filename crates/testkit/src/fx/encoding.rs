//! The encoders the canary sweeper needs, written by hand.
//!
//! A leaked secret rarely shows up as plain text. It is base64 inside a header, hex inside a
//! hash-like field, percent-encoded inside a URL, escaped inside a JSON log line, or broken up by
//! colour codes. The sweeper builds every one of those spellings of every canary and looks for
//! them. The testkit may use only the external crates on its allow list, which has no encoding
//! crate, so the encoders are here, small, and checked against the vectors of RFC 4648.
//!
//! Nothing in this file is used by production code.

const BASE64_STANDARD: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Which 64 characters a base64 text uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base64Alphabet {
    /// `+` and `/` (RFC 4648 section 4).
    Standard,
    /// `-` and `_` (RFC 4648 section 5).
    UrlSafe,
}

impl Base64Alphabet {
    fn table(self) -> &'static [u8; 64] {
        match self {
            Base64Alphabet::Standard => BASE64_STANDARD,
            Base64Alphabet::UrlSafe => BASE64_URL_SAFE,
        }
    }
}

/// Encodes `input` as base64, with `=` padding when `padded` is true.
#[must_use]
pub fn base64_encode(input: &[u8], alphabet: Base64Alphabet, padded: bool) -> String {
    let table = alphabet.table();
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let group = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(table[(group >> 18) as usize & 63]));
        out.push(char::from(table[(group >> 12) as usize & 63]));
        if chunk.len() > 1 {
            out.push(char::from(table[(group >> 6) as usize & 63]));
        } else if padded {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(table[group as usize & 63]));
        } else if padded {
            out.push('=');
        }
    }
    out
}

/// Decodes base64 text, with or without padding. Returns `None` for a character outside the
/// alphabet, a misplaced `=` or an impossible length.
#[must_use]
pub fn base64_decode(text: &str, alphabet: Base64Alphabet) -> Option<Vec<u8>> {
    let table = alphabet.table();
    let trimmed = text.trim_end_matches('=');
    if text.len() - trimmed.len() > 2 || trimmed.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in trimmed.bytes() {
        let value = table.iter().position(|&c| c == byte)? as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// The base64 text of `needle` that stays the same wherever the needle sits in a longer message.
///
/// A secret inside a larger base64 blob is encoded differently depending on how many bytes come
/// before it (modulo three). `offset` is that number, 0, 1 or 2. The first and last characters
/// are dropped when they also depend on a neighbouring byte, so what is left is a substring of
/// every encoding of any message that holds `needle` at that alignment.
#[must_use]
pub fn base64_interior(needle: &[u8], alphabet: Base64Alphabet, offset: usize) -> String {
    let mut message = vec![0u8; offset];
    message.extend_from_slice(needle);
    let text = base64_encode(&message, alphabet, false);
    // A character is fully inside the needle when all six of its bits are.
    let first = (8 * offset).div_ceil(6);
    let last = (8 * (offset + needle.len())) / 6;
    text.get(first..last).unwrap_or_default().to_owned()
}

/// Lowercase or uppercase hexadecimal.
#[must_use]
pub fn hex_encode(input: &[u8], upper: bool) -> String {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        out.push(char::from(digits[usize::from(byte >> 4)]));
        out.push(char::from(digits[usize::from(byte & 15)]));
    }
    out
}

/// Decodes hexadecimal of either case. `None` for an odd length or a character that is not a digit.
#[must_use]
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// How `percent_encode` spells the bytes it escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PercentStyle {
    /// Escape everything outside the RFC 3986 unreserved set, with uppercase hex digits.
    Upper,
    /// The same, with lowercase hex digits.
    Lower,
    /// Like `Upper`, but a space becomes `+` (the `application/x-www-form-urlencoded` form).
    FormPlus,
    /// Escape every byte, even letters and digits, with uppercase hex digits.
    EveryByte,
}

/// Percent-encodes `input`.
#[must_use]
pub fn percent_encode(input: &[u8], style: PercentStyle) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for &byte in input {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if style == PercentStyle::FormPlus && byte == b' ' {
            out.push('+');
        } else if unreserved && style != PercentStyle::EveryByte {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&hex_encode(&[byte], style != PercentStyle::Lower));
        }
    }
    out
}

/// How `json_escape` treats the characters JSON allows to be escaped but does not require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonStyle {
    /// Escape only the quote, the backslash and control characters.
    Minimal,
    /// The same, and write `/` as `\/`, as PHP and some Java encoders do.
    EscapedSlash,
    /// The same as `Minimal`, and write every non-ASCII character as `\uXXXX`.
    AsciiOnly,
}

/// Escapes `text` the way it appears between the quotes of a JSON string.
#[must_use]
pub fn json_escape(text: &str, style: JsonStyle) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '/' if style == JsonStyle::EscapedSlash => out.push_str("\\/"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if style == JsonStyle::AsciiOnly && !c.is_ascii() => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Removes terminal control sequences and invisible characters from a byte stream, one chunk at a
/// time, so an attacker cannot hide a secret by sprinkling them between its characters.
///
/// What it drops:
///
/// * CSI sequences (`ESC [ ... final`), the colour and cursor codes;
/// * OSC sequences (`ESC ] ... BEL` or `ESC ] ... ESC \`), such as a window title or a hyperlink;
/// * other two-byte `ESC` sequences, with their intermediate bytes;
/// * the zero-width and direction-control characters U+200B to U+200F, U+202A to U+202E, U+2060
///   to U+2064, U+2066 to U+2069, U+FEFF and the soft hyphen U+00AD.
///
/// State is kept between calls, so a sequence cut in half by a chunk boundary is still removed.
#[derive(Debug, Default, Clone)]
pub struct ControlStripper {
    state: StripState,
    /// The first bytes of a multi-byte character that has not ended yet.
    pending: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum StripState {
    #[default]
    Text,
    /// After `ESC`.
    Escape,
    /// After `ESC` and some intermediate bytes (0x20 to 0x2F), waiting for the final byte.
    EscapeIntermediate,
    /// Inside `ESC [`.
    Csi,
    /// Inside `ESC ]`.
    Osc,
    /// Inside an OSC, just after an `ESC` that may start the `ESC \` terminator.
    OscEscape,
}

impl ControlStripper {
    /// A stripper at the start of a stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one chunk and appends what is left to `out`.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        for &byte in chunk {
            self.step(byte, out);
        }
    }

    /// Ends the stream. Bytes of an unfinished character are passed through unchanged, because a
    /// half character is not invisible text.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.pending);
        self.state = StripState::Text;
    }

    fn step(&mut self, byte: u8, out: &mut Vec<u8>) {
        match self.state {
            StripState::Text => self.step_text(byte, out),
            StripState::Escape => match byte {
                b'[' => self.state = StripState::Csi,
                b']' => self.state = StripState::Osc,
                0x20..=0x2F => self.state = StripState::EscapeIntermediate,
                // Any other byte ends a two-byte escape such as `ESC c` or `ESC =`.
                _ => self.state = StripState::Text,
            },
            StripState::EscapeIntermediate => {
                if !(0x20..=0x2F).contains(&byte) {
                    self.state = StripState::Text;
                }
            }
            StripState::Csi => {
                if (0x40..=0x7E).contains(&byte) {
                    self.state = StripState::Text;
                }
            }
            StripState::Osc => match byte {
                0x07 => self.state = StripState::Text,
                0x1B => self.state = StripState::OscEscape,
                _ => {}
            },
            StripState::OscEscape => {
                // `ESC \` ends the sequence. Anything else was part of its text.
                self.state = if byte == b'\\' {
                    StripState::Text
                } else {
                    StripState::Osc
                };
            }
        }
    }

    fn step_text(&mut self, byte: u8, out: &mut Vec<u8>) {
        if !self.pending.is_empty() {
            if (0x80..=0xBF).contains(&byte) {
                self.pending.push(byte);
                let wanted = if self.pending[0] == 0xC2 { 2 } else { 3 };
                if self.pending.len() < wanted {
                    return;
                }
                if !is_invisible(&self.pending) {
                    out.append(&mut self.pending);
                }
                self.pending.clear();
                return;
            }
            // A lead byte that was not followed by a continuation byte is not a character. Pass
            // it on and handle this byte normally, so a stray lead byte cannot swallow an
            // escape sequence that follows it.
            out.append(&mut self.pending);
        }
        match byte {
            0x1B => self.state = StripState::Escape,
            // The first byte of a character that might be invisible. U+00AD starts with 0xC2,
            // and the others with 0xE2 or 0xEF.
            0xC2 | 0xE2 | 0xEF => self.pending.push(byte),
            _ => out.push(byte),
        }
    }
}

/// True for the UTF-8 bytes of an invisible character that hides text.
fn is_invisible(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        [0xC2, 0xAD] // soft hyphen
            | [0xE2, 0x80, 0x8B..=0x8F] // zero-width space to right-to-left mark
            | [0xE2, 0x80, 0xAA..=0xAE] // embeddings and overrides
            | [0xE2, 0x81, 0xA0..=0xA4] // word joiner and invisible operators
            | [0xE2, 0x81, 0xA6..=0xA9] // isolates
            | [0xEF, 0xBB, 0xBF] // byte order mark
    )
}

/// Strips a whole buffer at once. See [`ControlStripper`].
#[must_use]
pub fn strip_control(input: &[u8]) -> Vec<u8> {
    let mut stripper = ControlStripper::new();
    let mut out = Vec::with_capacity(input.len());
    stripper.push(input, &mut out);
    stripper.finish(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_vectors_of_rfc_4648() {
        for (plain, padded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                base64_encode(plain.as_bytes(), Base64Alphabet::Standard, true),
                padded
            );
            assert_eq!(
                base64_encode(plain.as_bytes(), Base64Alphabet::Standard, false),
                padded.trim_end_matches('=')
            );
            assert_eq!(
                base64_decode(padded, Base64Alphabet::Standard).unwrap(),
                plain.as_bytes()
            );
            assert_eq!(
                base64_decode(padded.trim_end_matches('='), Base64Alphabet::Standard).unwrap(),
                plain.as_bytes()
            );
        }
    }

    #[test]
    fn the_two_alphabets_differ_exactly_where_they_should() {
        let bytes = [0xfb, 0xff, 0xfe];
        assert_eq!(
            base64_encode(&bytes, Base64Alphabet::Standard, true),
            "+//+"
        );
        assert_eq!(base64_encode(&bytes, Base64Alphabet::UrlSafe, true), "-__-");
        assert_eq!(
            base64_decode("-__-", Base64Alphabet::UrlSafe).unwrap(),
            bytes
        );
        assert_eq!(base64_decode("-__-", Base64Alphabet::Standard), None);
    }

    #[test]
    fn base64_refuses_bad_input() {
        assert_eq!(base64_decode("Zm9v!", Base64Alphabet::Standard), None);
        assert_eq!(base64_decode("Z", Base64Alphabet::Standard), None);
        assert_eq!(base64_decode("Zg===", Base64Alphabet::Standard), None);
    }

    #[test]
    fn the_interior_of_an_embedded_needle_is_found_at_every_alignment() {
        let needle = b"CANARY-needle-0123456789";
        for alphabet in [Base64Alphabet::Standard, Base64Alphabet::UrlSafe] {
            for prefix_len in 0..6usize {
                let mut message = vec![b'.'; prefix_len];
                message.extend_from_slice(needle);
                message.extend_from_slice(b"tail bytes");
                let text = base64_encode(&message, alphabet, true);
                let interior = base64_interior(needle, alphabet, prefix_len % 3);
                assert!(
                    text.contains(&interior),
                    "{alphabet:?}, prefix {prefix_len}: {interior} not in {text}"
                );
            }
        }
    }

    #[test]
    fn a_wrong_alignment_does_not_match() {
        // Deliberate break: the interior for alignment 0 must not appear in a message that holds
        // the needle at alignment 1, or the three alignments would be one and the same.
        let needle = b"CANARY-needle-0123456789";
        let mut message = vec![b'.'];
        message.extend_from_slice(needle);
        let text = base64_encode(&message, Base64Alphabet::Standard, true);
        assert!(!text.contains(&base64_interior(needle, Base64Alphabet::Standard, 0)));
        assert!(text.contains(&base64_interior(needle, Base64Alphabet::Standard, 1)));
    }

    #[test]
    fn hex_round_trips_in_both_cases() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff], false), "00abff");
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff], true), "00ABFF");
        assert_eq!(hex_decode("00ABff").unwrap(), [0x00, 0xab, 0xff]);
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn percent_encoding_covers_the_four_styles() {
        let text = b"a b/c+d=e~f";
        assert_eq!(
            percent_encode(text, PercentStyle::Upper),
            "a%20b%2Fc%2Bd%3De~f"
        );
        assert_eq!(
            percent_encode(text, PercentStyle::Lower),
            "a%20b%2fc%2bd%3de~f"
        );
        assert_eq!(
            percent_encode(text, PercentStyle::FormPlus),
            "a+b%2Fc%2Bd%3De~f"
        );
        assert_eq!(percent_encode(b"ab", PercentStyle::EveryByte), "%61%62");
    }

    #[test]
    fn json_escaping_follows_the_three_styles() {
        let text = "a\"b\\c/d\ne\t\u{1}é😀";
        assert_eq!(
            json_escape(text, JsonStyle::Minimal),
            "a\\\"b\\\\c/d\\ne\\t\\u0001é😀"
        );
        assert_eq!(
            json_escape(text, JsonStyle::EscapedSlash),
            "a\\\"b\\\\c\\/d\\ne\\t\\u0001é😀"
        );
        assert_eq!(
            json_escape(text, JsonStyle::AsciiOnly),
            "a\\\"b\\\\c/d\\ne\\t\\u0001\\u00e9\\ud83d\\ude00"
        );
    }

    #[test]
    fn colour_codes_titles_and_invisible_characters_are_removed() {
        let dirty = "gh\u{1b}[31ms_\u{200b}ab\u{1b}]0;title\u{7}cd\u{feff}\u{1b}]8;;http://x\u{1b}\\ef\u{ad}g\u{1b}c!";
        assert_eq!(strip_control(dirty.as_bytes()), b"ghs_abcdefg!");
    }

    #[test]
    fn ordinary_text_with_multibyte_characters_is_untouched() {
        let text = "café 日本語 😀 100% \u{c2}\u{a0}ok";
        assert_eq!(strip_control(text.as_bytes()), text.as_bytes());
    }

    #[test]
    fn a_sequence_cut_by_a_chunk_boundary_is_still_removed() {
        let input = "ab\u{1b}[1;31mcd\u{200b}ef".as_bytes();
        for cut in 0..input.len() {
            let mut stripper = ControlStripper::new();
            let mut out = Vec::new();
            stripper.push(&input[..cut], &mut out);
            stripper.push(&input[cut..], &mut out);
            stripper.finish(&mut out);
            assert_eq!(out, b"abcdef", "cut at {cut}");
        }
    }

    #[test]
    fn a_stray_lead_byte_cannot_hide_an_escape_sequence() {
        // Deliberate break: 0xE2 then ESC. A stripper that waited for three bytes would let the
        // colour code through and the canary behind it would stay split.
        let input = [b'g', b'h', 0xE2, 0x1B, b'[', b'3', b'1', b'm', b's', b'_'];
        assert_eq!(strip_control(&input), [b'g', b'h', 0xE2, b's', b'_']);
    }

    #[test]
    fn an_unfinished_character_at_the_end_is_kept() {
        let mut stripper = ControlStripper::new();
        let mut out = Vec::new();
        stripper.push(&[b'a', 0xE2, 0x80], &mut out);
        stripper.finish(&mut out);
        assert_eq!(out, [b'a', 0xE2, 0x80]);
    }
}
