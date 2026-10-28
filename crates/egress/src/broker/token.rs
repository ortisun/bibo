//! The job token: how it is made, what shape it has and how only a hash of it is kept.
//!
//! `docs/security/secrets-and-credentials.md` section 4.2: `sfjt_` followed by at least 256 bits
//! from a random source, bound to a job, kept by the broker only as a hash, never logged. The
//! random source is injected ([`TokenEntropy`]) so a test can supply a fixed one and the real
//! broker uses the operating system's.

use std::fmt;

use sha2::{Digest, Sha256};

/// The prefix that lets the secret scanner find a job token (`secrets.patterns`,
/// `factory_job_token`).
pub const TOKEN_PREFIX: &str = "sfjt_";

/// The most characters of a credential the broker will look at. A longer one cannot be a token.
pub const MAX_PRESENTED_LEN: usize = 256;

/// The random source of the token secret.
pub trait TokenEntropy: Send + Sync {
    /// Fills `out` with random bytes.
    ///
    /// # Errors
    /// [`EntropyError`] when the source cannot supply them. The broker then refuses to issue a
    /// token; it never falls back to a weaker source.
    fn fill(&self, out: &mut [u8]) -> Result<(), EntropyError>;
}

/// The random source failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the random source failed")]
pub struct EntropyError;

/// The operating system's random source, through `ring`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEntropy;

impl TokenEntropy for SystemEntropy {
    fn fill(&self, out: &mut [u8]) -> Result<(), EntropyError> {
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), out)
            .map_err(|_| EntropyError)
    }
}

/// The SHA-256 of a token secret: all the broker keeps.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// Hashes a secret.
    #[must_use]
    pub fn of(secret: &str) -> Self {
        let digest = Sha256::digest(secret.as_bytes());
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash(..)")
    }
}

/// Makes a new secret: the prefix and 32 random bytes in lower-case hexadecimal, so 64
/// characters carrying 256 bits.
///
/// # Errors
/// [`EntropyError`] when the random source fails.
pub fn mint_secret(entropy: &dyn TokenEntropy) -> Result<String, EntropyError> {
    let mut bytes = [0_u8; 32];
    entropy.fill(&mut bytes)?;
    let mut secret = String::with_capacity(TOKEN_PREFIX.len() + 64);
    secret.push_str(TOKEN_PREFIX);
    for byte in bytes {
        secret.push(hex_digit(byte >> 4));
        secret.push(hex_digit(byte & 0x0f));
    }
    Ok(secret)
}

fn hex_digit(nibble: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(nibble & 0x0f)])
}

/// True when `presented` has the shape of a job token. A credential of another shape is refused
/// without being hashed or looked up.
#[must_use]
pub fn has_token_shape(presented: &str) -> bool {
    presented.len() > TOKEN_PREFIX.len()
        && presented.len() <= MAX_PRESENTED_LEN
        && presented.starts_with(TOKEN_PREFIX)
        && presented
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(u8);
    impl TokenEntropy for Fixed {
        fn fill(&self, out: &mut [u8]) -> Result<(), EntropyError> {
            out.fill(self.0);
            Ok(())
        }
    }
    struct Broken;
    impl TokenEntropy for Broken {
        fn fill(&self, _: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError)
        }
    }

    #[test]
    fn a_minted_secret_has_the_prefix_and_256_bits_of_hex() {
        let secret = mint_secret(&Fixed(0xab)).expect("a secret");
        assert!(secret.starts_with(TOKEN_PREFIX));
        assert_eq!(secret.len(), TOKEN_PREFIX.len() + 64);
        assert!(
            secret[TOKEN_PREFIX.len()..]
                .bytes()
                .all(|b| b"0123456789abcdef".contains(&b))
        );
        assert!(has_token_shape(&secret));
    }

    #[test]
    fn a_failing_random_source_makes_no_secret() {
        assert_eq!(mint_secret(&Broken), Err(EntropyError));
    }

    #[test]
    fn two_system_secrets_differ_and_the_hash_depends_on_every_character() {
        let a = mint_secret(&SystemEntropy).expect("a secret");
        let b = mint_secret(&SystemEntropy).expect("a secret");
        assert_ne!(a, b);
        assert_ne!(TokenHash::of(&a), TokenHash::of(&b));
        assert_eq!(TokenHash::of(&a), TokenHash::of(&a));
    }

    #[test]
    fn the_hash_shows_nothing_in_debug_output() {
        let shown = format!("{:?}", TokenHash::of("sfjt_x"));
        assert_eq!(shown, "TokenHash(..)");
    }

    #[test]
    fn only_the_right_shape_is_looked_up() {
        assert!(!has_token_shape(""));
        assert!(!has_token_shape("sfjt_"));
        assert!(!has_token_shape("a-credential-of-another-shape"));
        assert!(!has_token_shape("sfjt_with space"));
        assert!(!has_token_shape("sfjt_with\nnewline"));
        assert!(!has_token_shape(&format!("sfjt_{}", "a".repeat(300))));
        assert!(has_token_shape("sfjt_abc-DEF_123"));
    }
}
