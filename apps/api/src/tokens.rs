//! API tokens: opaque, random, stored only as a hash.
//!
//! A token is `sfat_` and the 43 characters of the URL-safe base64 of 32 random bytes: 256 bits.
//! There is nothing in it to decode, no algorithm to choose and no claim to forge, so the attacks
//! on bearer tokens that carry structure (`alg: none`, a swapped key, a stretched expiry) have
//! nothing to work on: a string that is not in the table is simply unknown. The database stores
//! the SHA-256 of the token with an audience, an expiry and a revocation time, and
//! `Store::resolve_token` is the only lookup. The application never compares a token with
//! another value, so there is no comparison to make constant-time: equality is decided by the
//! unique index on the hash, over a 256-bit preimage an attacker cannot steer.
//!
//! The API does not make tokens: the store port has no operation for it (the application role can
//! insert a row, and no port method does). An operator issues a token with [`format_token`] on
//! random bytes from the operating system, shows it once, and stores [`hash_token`] of it.
//! Revocation is `revoked_at` on the row and takes effect on the next request; there is no cache.

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use factory_domain::values::Sha256Digest;
use factory_ports::store::TokenHash;

/// The start of every API token. It makes a token recognizable to a secret scanner.
pub const PREFIX: &str = "sfat_";

/// Random bytes in a token.
pub const SECRET_BYTES: usize = 32;

/// Characters after the prefix: 32 bytes in unpadded base64.
const BODY_CHARS: usize = 43;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Writes 32 random bytes as a token.
#[must_use]
pub fn format_token(secret: &[u8; SECRET_BYTES]) -> String {
    let mut text = String::with_capacity(PREFIX.len() + BODY_CHARS);
    text.push_str(PREFIX);
    for chunk in secret.chunks(3) {
        let mut word = 0_u32;
        for (index, byte) in chunk.iter().enumerate() {
            word |= u32::from(*byte) << (16 - 8 * index);
        }
        // 1 byte gives 2 characters, 2 bytes give 3, 3 bytes give 4.
        for index in 0..=chunk.len() {
            let sextet = (word >> (18 - 6 * index)) & 0x3f;
            text.push(char::from(ALPHABET[sextet as usize]));
        }
    }
    text
}

/// True when the text has the exact shape of a token. A request whose credential has any other
/// shape is refused before the database is asked.
#[must_use]
pub fn is_well_formed(text: &str) -> bool {
    text.strip_prefix(PREFIX).is_some_and(|body| {
        body.len() == BODY_CHARS && body.bytes().all(|byte| ALPHABET.contains(&byte))
    })
}

/// The SHA-256 of a token, as the database stores it.
#[must_use]
pub fn hash_token(token: &str) -> TokenHash {
    TokenHash(digest_bytes(&Sha256Digest::of(token.as_bytes())))
}

/// The 32 bytes of a SHA-256 digest.
#[must_use]
pub fn digest_bytes(digest: &Sha256Digest) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (slot, pair) in bytes.iter_mut().zip(digest.hex().as_bytes().chunks(2)) {
        *slot = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    bytes
}

const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => 0,
    }
}

/// The token in an `Authorization: Bearer <token>` header, if there is exactly one header, the
/// scheme is `Bearer` (any case), one space follows and the rest has the shape of a token. Any
/// other header is the same as no header.
#[must_use]
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let text = value.to_str().ok()?;
    let (scheme, token) = text.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && is_well_formed(token)).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn token() -> String {
        format_token(&[7_u8; SECRET_BYTES])
    }

    #[test]
    fn a_token_has_the_prefix_and_43_url_safe_characters() {
        let text = token();
        assert!(text.starts_with(PREFIX));
        assert_eq!(text.len(), PREFIX.len() + BODY_CHARS);
        assert!(is_well_formed(&text));
    }

    #[test]
    fn different_secrets_give_different_tokens_and_different_hashes() {
        let a = format_token(&[1_u8; SECRET_BYTES]);
        let b = format_token(&[2_u8; SECRET_BYTES]);
        assert_ne!(a, b);
        assert_ne!(hash_token(&a).0, hash_token(&b).0);
    }

    #[test]
    fn the_hash_is_the_sha256_of_the_whole_token() {
        let text = token();
        let expected = Sha256Digest::of(text.as_bytes());
        let hash = hash_token(&text);
        let hex: String = hash.0.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, expected.hex());
    }

    #[test]
    fn a_string_of_the_wrong_shape_is_not_a_token() {
        for bad in [
            "",
            "sfat_",
            "sfat_short",
            "xxxx_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            // A JWT is not a token of this API, whatever its algorithm.
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
        ] {
            assert!(!is_well_formed(bad), "{bad:?}");
        }
        let too_long = format!("{}A", token());
        assert!(!is_well_formed(&too_long));
        let with_symbol = format!("{}!", &token()[..token().len() - 1]);
        assert!(!is_well_formed(&with_symbol));
    }

    #[test]
    fn exactly_one_bearer_header_with_a_well_formed_token_is_read() {
        let text = token();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {text}")).expect("header"),
        );
        assert_eq!(bearer(&headers), Some(text.as_str()));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("bEaReR {text}")).expect("header"),
        );
        assert_eq!(bearer(&headers), Some(text.as_str()));
        for bad in [
            format!("Basic {text}"),
            format!("Bearer  {text}"),
            format!("Bearer {text} extra"),
            text.clone(),
        ] {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&bad).expect("header"));
            assert_eq!(bearer(&headers), None, "{bad:?}");
        }
        let mut two = HeaderMap::new();
        for _ in 0..2 {
            two.append(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {text}")).expect("header"),
            );
        }
        assert_eq!(bearer(&two), None);
    }
}
