//! The canaries of the cross-cutting security tests: one for each class of secret that
//! `policies/security.yaml` names, plus the values the factory registers itself.
//!
//! Every secret value is built at run time from parts, so that no secret-shaped literal sits in
//! the source. The classes are the ones of `secrets.patterns`, plus the job tokens, the webhook
//! secret, the key that signs decisions and the database passwords. A canary of a class that has
//! a pattern has the shape of the pattern, so the pattern can find it even when nothing registered
//! its value.
//!
//! This file depends on the testkit and on nothing else, so the workflow target (`security`) and
//! the composed run of the API (`apps/api/tests/negative_composed.rs`) include the same one.

use factory_testkit::fx::canary::{Canary, CanarySet};

const ALNUM: &[u8] = b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

/// `n` letters and digits that look random and are the same on every run.
fn filler(n: usize, offset: usize) -> String {
    (0..n)
        .map(|i| ALNUM[(i * 7 + offset * 13 + i / 5) % ALNUM.len()] as char)
        .collect()
}

fn upper_digits(n: usize, offset: usize) -> String {
    filler(n, offset)
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// A canary for every class of secret that the policy names, with the label of its class.
pub fn every_class() -> CanarySet {
    let join = |prefix: &str, rest: String| format!("{prefix}{rest}");
    let make = |label: &str, value: String| Canary::custom(label, &value);
    CanarySet::generate()
        .with(make(
            "api_token",
            join(&format!("{}{}", "sf", "at_"), filler(43, 1)),
        ))
        .with(make(
            "github_token_classic",
            join(&format!("{}{}", "gh", "p_"), filler(36, 2)),
        ))
        .with(make(
            "github_fine_grained",
            join(&format!("{}{}", "github", "_pat_"), filler(40, 3)),
        ))
        .with(make(
            "openai_api_key",
            join(&format!("{}{}", "sk", "-proj-"), filler(40, 4)),
        ))
        .with(make(
            "aws_access_key_id",
            join(&format!("{}{}", "AK", "IA"), upper_digits(16, 5)),
        ))
        .with(make(
            "gcp_api_key",
            join(&format!("{}{}", "AI", "za"), filler(35, 6)),
        ))
        .with(make(
            "slack_token",
            join(&format!("{}{}", "xo", "xb-"), filler(24, 7)),
        ))
        .with(make(
            "npm_token",
            join(&format!("{}{}", "np", "m_"), filler(36, 8)),
        ))
        .with(make(
            "jwt",
            format!(
                "{}.{}.{}",
                join(&format!("{}{}", "ey", "J"), filler(20, 9)),
                join(&format!("{}{}", "ey", "J"), filler(24, 10)),
                filler(30, 11)
            ),
        ))
        .with(make(
            "url_with_credentials",
            format!(
                "https://deploy:{}@registry.internal.test/path",
                filler(18, 12)
            ),
        ))
        .with(make(
            "database_url",
            format!(
                "postgres://factory:{}@db.internal.test:5432/factory",
                filler(20, 13)
            ),
        ))
        .with(make(
            "decision_signing_key",
            filler(64, 14).to_ascii_lowercase(),
        ))
        .with(make(
            "authorization_header",
            format!("Authorization: Bearer {}", filler(32, 15)),
        ))
}
