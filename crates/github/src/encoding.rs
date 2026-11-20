//! Small encoders the adapter needs and no allowed crate provides: base64url without padding (the
//! JWT parts), strict base64 (the body of a PEM key), and percent-encoding of one URL component.
//!
//! They are tiny and covered by known-answer tests, which keeps three more crates out of the
//! dependency list.

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url (RFC 4648 section 5) without padding, as the parts of a JWT are written.
#[must_use]
pub fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let take = chunk.len() + 1;
        for index in 0..take {
            let shift = 18 - 6 * index;
            let value = usize::try_from((triple >> shift) & 0x3f).unwrap_or(0);
            out.push(char::from(URL_ALPHABET.get(value).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// Decodes standard base64 (RFC 4648 section 4) with padding. White space is skipped, as in a
/// PEM body. Returns `None` for any other character, for a bad length and for bad padding.
#[must_use]
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut sextets = Vec::with_capacity(input.len());
    let mut padding = 0_usize;
    for byte in input.bytes().filter(|b| !b.is_ascii_whitespace()) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            _ => return None,
        };
        if padding > 0 {
            // A data character after padding.
            return None;
        }
        sextets.push(value);
    }
    if padding > 2 || !(sextets.len() + padding).is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for group in sextets.chunks(4) {
        let a = u32::from(group.first().copied()?);
        let b = u32::from(group.get(1).copied()?);
        let c = group.get(2).copied().map(u32::from);
        let d = group.get(3).copied().map(u32::from);
        let triple = (a << 18) | (b << 12) | (c.unwrap_or(0) << 6) | d.unwrap_or(0);
        out.push(u8::try_from((triple >> 16) & 0xff).ok()?);
        if c.is_some() {
            out.push(u8::try_from((triple >> 8) & 0xff).ok()?);
        }
        if d.is_some() {
            out.push(u8::try_from(triple & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Percent-encodes one component of a URL (a path segment or a query value). Only the unreserved
/// characters of RFC 3986 stay as they are, so a `/`, `?`, `&`, `#` or `%` in the input cannot
/// change the shape of the URL.
#[must_use]
pub fn percent_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_the_rfc_4648_vectors_without_padding() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url_encode(plain.as_bytes()), encoded, "{plain:?}");
        }
    }

    #[test]
    fn base64url_uses_the_url_safe_alphabet() {
        assert_eq!(base64url_encode(&[0xfb, 0xff, 0xfe]), "-__-");
    }

    #[test]
    fn base64_decode_matches_the_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_decode(encoded), Some(plain.as_bytes().to_vec()));
        }
        assert_eq!(base64_decode("Zm9v\nYmFy\n"), Some(b"foobar".to_vec()));
    }

    #[test]
    fn base64_decode_refuses_bad_input() {
        for bad in ["Zg", "Zg=", "Z", "Zm9v!", "Zg==Zg==", "=Zg=", "Zm9vY==="] {
            assert_eq!(base64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn percent_encoding_cannot_change_the_shape_of_a_url() {
        assert_eq!(percent_encode_component("factory/job-1"), "factory%2Fjob-1");
        assert_eq!(
            percent_encode_component("a b&c=d#e?f%"),
            "a%20b%26c%3Dd%23e%3Ff%25"
        );
        assert_eq!(percent_encode_component("Az09-._~"), "Az09-._~");
        assert_eq!(percent_encode_component("é"), "%C3%A9");
    }
}
