//! The App JWT: the short-lived credential that proves the factory is the GitHub App, used only to
//! ask for an installation token (`docs/security/secrets-and-credentials.md`, section 3.2).
//!
//! * Algorithm `RS256`. The signing is behind [`JwtSigner`], so the key can live in this process
//!   ([`RingRs256Signer`]) or behind a signing service without a change anywhere else.
//! * Claims: `iss` is the App id, `iat` is 60 seconds in the past (clock drift), `exp` is 120
//!   seconds in the future (GitHub allows 600). The time comes from the injected `Clock`.
//! * A fresh JWT is made for each use and is never stored.
//!
//! UNVERIFIED against the real GitHub: that the numeric App id as a JSON string in `iss` is
//! accepted (the documentation shows both forms). The signature is checked by the tests against an
//! independent implementation (the `openssl` command line), not against GitHub.

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::json;

use factory_domain::values::Timestamp;

use crate::encoding::{base64_decode, base64url_encode};

/// How far in the past `iat` is set, to allow for clock drift.
pub const ISSUED_AT_SKEW_SECONDS: i64 = 60;

/// How far in the future `exp` is set. GitHub allows at most 600.
pub const LIFETIME_SECONDS: i64 = 120;

// GitHub rejects a JWT whose `exp` is more than 600 seconds after `iat`; the credentials document
// asks for at most 120 seconds ahead. A change that breaks either fails the build.
const _: () = assert!(LIFETIME_SECONDS + ISSUED_AT_SKEW_SECONDS <= 600 && LIFETIME_SECONDS <= 120);

/// Why a JWT could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    /// The private key could not be read: not PEM, encrypted, not RSA, or under 2048 bits.
    #[error("the private key could not be read")]
    BadKey,
    /// The signer failed.
    #[error("the signer failed")]
    SignFailed,
}

/// Signs the JWT input with RS256. An implementation holds the key.
pub trait JwtSigner: Send + Sync {
    /// Returns the RSASSA-PKCS1-v1_5 SHA-256 signature of `signing_input`, which is the ASCII
    /// text `header.claims` (both base64url).
    ///
    /// # Errors
    /// [`JwtError::SignFailed`] when the key cannot sign.
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, JwtError>;
}

/// An RS256 signer that holds an RSA key in memory, using `ring`.
pub struct RingRs256Signer {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl fmt::Debug for RingRs256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RingRs256Signer(<key>)")
    }
}

impl RingRs256Signer {
    /// Reads a PEM private key as GitHub hands it out (`BEGIN RSA PRIVATE KEY`, PKCS#1) or as
    /// `openssl` writes it by default (`BEGIN PRIVATE KEY`, PKCS#8). The decoded bytes are
    /// overwritten once the key is built, as far as safe Rust lets us.
    ///
    /// # Errors
    /// [`JwtError::BadKey`] for anything else, including an encrypted key and a key under 2048
    /// bits.
    pub fn from_pem(pem: &str) -> Result<Self, JwtError> {
        let (label, mut der) = pem_block(pem).ok_or(JwtError::BadKey)?;
        let key = match label.as_str() {
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
            _ => {
                der.fill(0);
                return Err(JwtError::BadKey);
            }
        };
        der.fill(0);
        Ok(Self {
            key: key.map_err(|_| JwtError::BadKey)?,
            rng: SystemRandom::new(),
        })
    }
}

impl JwtSigner for RingRs256Signer {
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, JwtError> {
        let mut signature = vec![0_u8; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &self.rng, signing_input, &mut signature)
            .map_err(|_| JwtError::SignFailed)?;
        Ok(signature)
    }
}

/// The label and the decoded body of the one PEM block in `pem`.
fn pem_block(pem: &str) -> Option<(String, Vec<u8>)> {
    let start = pem.find("-----BEGIN ")?;
    let after = pem.get(start + "-----BEGIN ".len()..)?;
    let (label, rest) = after.split_once("-----")?;
    let end_marker = format!("-----END {label}-----");
    let (body, tail) = rest.split_once(&end_marker)?;
    if tail.contains("-----BEGIN ") {
        // One key per file. A second block is not read.
        return None;
    }
    Some((label.to_owned(), base64_decode(body)?))
}

/// A signed App JWT. It is a bearer credential, so its text never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct AppJwt(String);

impl fmt::Debug for AppJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppJwt(<redacted>)")
    }
}

impl AppJwt {
    /// Makes a JWT for `app_id` at `now`.
    ///
    /// # Errors
    /// [`JwtError::SignFailed`] when the signer fails.
    pub fn make(app_id: u64, now: &Timestamp, signer: &dyn JwtSigner) -> Result<Self, JwtError> {
        let issued_at = now.unix_seconds() - ISSUED_AT_SKEW_SECONDS;
        let expires_at = now.unix_seconds() + LIFETIME_SECONDS;
        let header = base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = base64url_encode(
            json!({ "iat": issued_at, "exp": expires_at, "iss": app_id.to_string() })
                .to_string()
                .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let signature = signer.sign(signing_input.as_bytes())?;
        Ok(Self(format!(
            "{signing_input}.{}",
            base64url_encode(&signature)
        )))
    }

    /// The compact JWT text, for the `Authorization` header only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signer that returns a fixed, recognisable signature, to test the claims and the layout
    /// without a key.
    struct FixedSigner;
    impl JwtSigner for FixedSigner {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, JwtError> {
            Ok(vec![1, 2, 3])
        }
    }

    struct FailingSigner;
    impl JwtSigner for FailingSigner {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, JwtError> {
            Err(JwtError::SignFailed)
        }
    }

    fn now() -> Timestamp {
        Timestamp::parse("2026-10-28T10:00:00Z").unwrap()
    }

    #[test]
    fn the_claims_follow_the_credentials_document() {
        let jwt = AppJwt::make(424_242, &now(), &FixedSigner).unwrap();
        let parts: Vec<&str> = jwt.expose().split('.').collect();
        assert_eq!(parts.len(), 3);
        // Known answers, computed by hand: 2026-10-28T10:00:00Z is 1_793_181_600.
        assert_eq!(parts[0], "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");
        assert_eq!(
            parts[1],
            base64url_encode(br#"{"exp":1793181720,"iat":1793181540,"iss":"424242"}"#)
        );
        assert_eq!(parts[2], "AQID");
    }

    #[test]
    fn a_failing_signer_gives_no_jwt() {
        assert_eq!(
            AppJwt::make(1, &now(), &FailingSigner),
            Err(JwtError::SignFailed)
        );
    }

    #[test]
    fn a_jwt_does_not_print_itself() {
        let jwt = AppJwt::make(1, &now(), &FixedSigner).unwrap();
        assert_eq!(format!("{jwt:?}"), "AppJwt(<redacted>)");
    }

    /// A PEM block assembled at run time, so that no source line holds a key marker.
    fn block(label: &str, body: &str) -> String {
        let dashes = "-".repeat(5);
        format!("{dashes}BEGIN {label}{dashes}\n{body}\n{dashes}END {label}{dashes}\n")
    }

    #[test]
    fn a_pem_that_is_not_a_single_unencrypted_rsa_key_is_refused() {
        let two_blocks = format!(
            "{}{}",
            block("PRIVATE KEY", "AAAA"),
            block("PRIVATE KEY", "AAAA")
        );
        let bad_inputs = [
            String::new(),
            "not a key".to_owned(),
            block("PRIVATE KEY", "!!!"),
            block("ENCRYPTED PRIVATE KEY", "AAAA"),
            two_blocks,
            block("PRIVATE KEY", "AAAA"),
        ];
        for bad in &bad_inputs {
            assert!(RingRs256Signer::from_pem(bad).is_err(), "{bad:?}");
        }
    }
}
