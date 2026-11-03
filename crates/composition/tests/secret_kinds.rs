//! The check that every kind of secret the policy lists has a value registered (LB-05).
//!
//! The policy lists the kinds for the factory as a whole. A binary holds some of them: the API holds
//! the webhook secret, the worker does not. The worker used to warn about the webhook secret on
//! every start, a warning that is always there and so is ignored when it matters. The check now
//! skips the kinds a binary says it does not hold, and still fails closed in the production profile
//! for a kind that the binary does hold and that has no value.

use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::assemble::{WORKER_DOES_NOT_HOLD, check_kinds, missing_kinds};
use factory_composition::profile::Profile;
use factory_composition::redaction::{FactorySecrets, SecretKind, redactor_from_policy};
use factory_composition::startup::{StartupFailure, load_policy};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// An empty registry over the repository policy, which lists all six kinds.
fn empty() -> FactorySecrets {
    let policies = load_policy(&root(), &[]).expect("the repository policy loads");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("a redactor"));
    FactorySecrets::new(redactor, &policies.security)
}

/// A registry in which every kind but those in `except` has a value. The values are made here, so
/// no secret-shaped literal sits in the source.
fn registered_except(except: &[SecretKind]) -> FactorySecrets {
    let mut secrets = empty();
    for kind in [
        SecretKind::WebhookSecret,
        SecretKind::AppPrivateKey,
        SecretKind::DatabaseCredentials,
        SecretKind::BrokerKeys,
        SecretKind::ObjectStoreKeys,
    ] {
        if !except.contains(&kind) {
            secrets
                .register(kind, &["value-for-", kind.label(), "-1234"].concat())
                .expect("registers");
        }
    }
    secrets
}

#[test]
fn the_worker_does_not_hold_the_webhook_secret_and_nothing_else() {
    assert_eq!(WORKER_DOES_NOT_HOLD, [SecretKind::WebhookSecret]);
}

#[test]
fn a_kind_the_binary_does_not_hold_is_not_missing() {
    let secrets = registered_except(&[SecretKind::WebhookSecret]);
    // The registry itself still says the kind has no value ...
    assert_eq!(secrets.unregistered_kinds(), [SecretKind::WebhookSecret]);
    // ... and the worker's check does not count it.
    assert!(missing_kinds(&secrets, &WORKER_DOES_NOT_HOLD).is_empty());
    for profile in [Profile::Production, Profile::Local, Profile::Test] {
        assert!(
            check_kinds(&secrets, profile, &WORKER_DOES_NOT_HOLD).is_ok(),
            "{profile:?}"
        );
    }
}

#[test]
fn production_stops_for_a_kind_the_binary_holds_and_that_has_no_value() {
    // The webhook secret is missing and the binary holds it (the API's case): production stops.
    let secrets = registered_except(&[SecretKind::WebhookSecret]);
    assert!(matches!(
        check_kinds(&secrets, Profile::Production, &[]),
        Err(StartupFailure::SecretKindMissing("webhook_secret"))
    ));
    // The worker's own kinds: a missing App key stops it, whether or not the webhook secret is
    // also missing, and the line names the kind it holds.
    for except in [
        vec![SecretKind::AppPrivateKey],
        vec![SecretKind::AppPrivateKey, SecretKind::WebhookSecret],
    ] {
        let secrets = registered_except(&except);
        assert!(matches!(
            check_kinds(&secrets, Profile::Production, &WORKER_DOES_NOT_HOLD),
            Err(StartupFailure::SecretKindMissing("app_private_key"))
        ));
    }
    let secrets = registered_except(&[SecretKind::BrokerKeys, SecretKind::WebhookSecret]);
    assert!(matches!(
        check_kinds(&secrets, Profile::Production, &WORKER_DOES_NOT_HOLD),
        Err(StartupFailure::SecretKindMissing("broker_keys"))
    ));
}

#[test]
fn the_other_profiles_go_on_for_a_missing_kind_they_hold_and_report_it() {
    let secrets = registered_except(&[SecretKind::AppPrivateKey, SecretKind::WebhookSecret]);
    assert_eq!(
        missing_kinds(&secrets, &WORKER_DOES_NOT_HOLD),
        [SecretKind::AppPrivateKey]
    );
    assert!(check_kinds(&secrets, Profile::Local, &WORKER_DOES_NOT_HOLD).is_ok());
}

#[test]
fn a_registry_with_nothing_registered_names_every_kind_the_binary_holds() {
    let secrets = empty();
    // JobTokens are registered when issued, so they never count; the webhook secret is not held.
    assert_eq!(
        missing_kinds(&secrets, &WORKER_DOES_NOT_HOLD),
        [
            SecretKind::AppPrivateKey,
            SecretKind::DatabaseCredentials,
            SecretKind::BrokerKeys,
            SecretKind::ObjectStoreKeys
        ]
    );
}
