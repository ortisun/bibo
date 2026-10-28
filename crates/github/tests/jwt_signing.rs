//! The App JWT signed with a throwaway key and checked by an independent implementation.

mod common;

use common::keys::{Form, Throwaway};
use factory_domain::values::Timestamp;
use factory_github::{AppJwt, JwtSigner, RingRs256Signer, base64_decode};

fn now() -> Timestamp {
    Timestamp::parse("2026-10-28T10:00:00Z").unwrap()
}

fn base64url_to_bytes(part: &str) -> Vec<u8> {
    let standard: String = part
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let padded = format!("{standard}{}", "=".repeat((4 - standard.len() % 4) % 4));
    base64_decode(&padded).expect("valid base64url")
}

#[test]
fn a_jwt_signed_with_a_pkcs1_key_verifies_under_openssl() {
    let key = Throwaway::new(Form::Pkcs1);
    let signer = RingRs256Signer::from_pem(&key.private_pem).expect("a PKCS#1 key");
    let jwt = AppJwt::make(424_242, &now(), &signer).expect("a jwt");
    let (signing_input, signature) = jwt.expose().rsplit_once('.').expect("three parts");
    assert!(
        key.openssl_verifies(signing_input.as_bytes(), &base64url_to_bytes(signature)),
        "openssl must verify the signature"
    );
}

#[test]
fn a_jwt_signed_with_a_pkcs8_key_verifies_under_openssl() {
    let key = Throwaway::new(Form::Pkcs8);
    let signer = RingRs256Signer::from_pem(&key.private_pem).expect("a PKCS#8 key");
    let jwt = AppJwt::make(7, &now(), &signer).expect("a jwt");
    let (signing_input, signature) = jwt.expose().rsplit_once('.').expect("three parts");
    assert!(key.openssl_verifies(signing_input.as_bytes(), &base64url_to_bytes(signature)));
}

#[test]
fn a_tampered_jwt_does_not_verify() {
    let key = Throwaway::new(Form::Pkcs1);
    let signer = RingRs256Signer::from_pem(&key.private_pem).expect("a key");
    let jwt = AppJwt::make(1, &now(), &signer).expect("a jwt");
    let (signing_input, signature) = jwt.expose().rsplit_once('.').expect("three parts");
    // Change the last character of the claims, as an attacker changing `exp` would.
    let mut other = signing_input.to_owned();
    let last = other.pop().expect("a non-empty input");
    other.push(if last == 'A' { 'B' } else { 'A' });
    assert!(!key.openssl_verifies(other.as_bytes(), &base64url_to_bytes(signature)));
}

#[test]
fn the_signature_is_deterministic_for_the_same_input() {
    // RSASSA-PKCS1-v1_5 has no randomness, so the same key and input give the same signature.
    let key = Throwaway::new(Form::Pkcs8);
    let signer = RingRs256Signer::from_pem(&key.private_pem).expect("a key");
    assert_eq!(
        signer.sign(b"abc").unwrap(),
        signer.sign(b"abc").unwrap(),
        "PKCS#1 v1.5 is deterministic"
    );
}

#[test]
fn the_signer_does_not_print_the_key() {
    let key = Throwaway::new(Form::Pkcs8);
    let signer = RingRs256Signer::from_pem(&key.private_pem).expect("a key");
    let shown = format!("{signer:?}");
    let body: String = key
        .private_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    assert!(!shown.contains(&body[..40]), "{shown}");
}
