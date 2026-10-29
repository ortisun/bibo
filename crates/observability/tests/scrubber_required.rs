//! A binary cannot start telemetry without a scrubber (ADR 0013, decision 2).
//!
//! The checks below are about the shape of the API. Most of them fail to compile, not to run, when
//! the shape is wrong, so a change that gives the scrubber a default or makes it optional is
//! caught before any test body executes.

mod common;

use factory_observability::redact::Scrub;
use factory_observability::telemetry::{InitError, TelemetryConfig};
use std::sync::Arc;

/// `TelemetryConfig::new` takes the scrubber as its third argument. Coercing the function to a
/// pointer of exactly this type fails to compile when the argument is missing, optional or typed
/// as something weaker.
#[test]
fn telemetry_config_new_requires_the_scrubber() {
    let new: fn(&str, &str, Arc<dyn Scrub>) -> TelemetryConfig = TelemetryConfig::new;
    let config = new("factory-test", "1.0.0", common::policy_scrubber());
    assert_eq!(config.service_name(), "factory-test");
}

type FromEnv = fn(&str, &str, Arc<dyn Scrub>) -> Result<TelemetryConfig, InitError>;

/// The two ways to read settings from the environment take the scrubber too. A closure type cannot
/// be named in a function pointer, so these are calls: they stop compiling if the parameter goes.
#[test]
fn reading_the_settings_from_the_environment_requires_the_scrubber() {
    let from_lookup =
        TelemetryConfig::from_lookup("factory-test", "1.0.0", common::policy_scrubber(), |_| None);
    assert!(from_lookup.is_ok());

    let from_env: FromEnv = TelemetryConfig::from_env;
    let _ = from_env;
}

/// A configuration has no `Default`, so nobody can write `TelemetryConfig::default()` and get a
/// pipeline with a weaker scrubber. The trait below has two candidate implementations for any
/// type that implements `Default`, which makes the call ambiguous, and the test fail to
/// compile. For a type without `Default`, only the first applies.
trait AmbiguousIfDefault<A> {
    fn check() {}
}
impl<T: ?Sized> AmbiguousIfDefault<()> for T {}
impl<T: Default> AmbiguousIfDefault<u8> for T {}

#[test]
fn a_telemetry_config_cannot_be_made_with_default() {
    <TelemetryConfig as AmbiguousIfDefault<_>>::check();
}

/// The source of the crate names no scrubber of its own, and has no setter that swaps the one
/// given at construction for another. The deleted stopgap must not come back under a new name.
#[test]
fn the_crate_holds_no_scrubber_of_its_own_besides_the_seam_over_the_redactor() {
    let redact = include_str!("../src/redact.rs");
    let telemetry = include_str!("../src/telemetry.rs");
    let implementors = redact.matches("impl Scrub for ").count();
    assert_eq!(
        implementors, 1,
        "exactly one type implements Scrub in the crate: the seam over domain::redaction::Redactor"
    );
    assert!(redact.contains("impl Scrub for RedactorScrubber"));
    // The old name is assembled here so that this file does not itself match the repository-wide
    // search that proves the name is gone.
    let stopgap = ["Policy", "Pattern", "Scrubber"].concat();
    for forbidden in [stopgap.as_str(), "fn with_scrubber", "Default::default()"] {
        assert!(
            !telemetry.contains(forbidden),
            "src/telemetry.rs must not contain `{forbidden}`"
        );
    }
    assert!(
        !redact.contains(&stopgap),
        "src/redact.rs must not bring back the stopgap scrubber"
    );
}
