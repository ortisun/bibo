//! The control-off switch.
//!
//! Principle 2 of the negative-test catalog: every test must be able to fail. A test that checks
//! "the redactor removed the secret" is worth something only if it fails when the redactor is
//! switched off. If it still passes, it was checking something else, and it is rejected.
//!
//! A test that wants this property is written as a *scenario*: a function that takes a
//! [`Controls`] value, asks `controls.is_on("redactor")` at the one place where the control under
//! test would act, and returns `Ok(())` when everything the test asserts holds. Then
//! [`prove_control_matters`] runs it twice:
//!
//! 1. with every control on, where it must pass;
//! 2. with the named control off, where it must fail.
//!
//! Anything else is an error, and the test that builds the proof fails with it. A
//! [`ControlLedger`] collects the proofs of many tests and can print them as JSON, which is the
//! input the security review package needs for "each P0 test has a control-off variant that fails".

use std::collections::BTreeSet;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// The controls a scenario may find switched off.
#[derive(Debug, Clone, Default)]
pub struct Controls {
    off: BTreeSet<String>,
}

impl Controls {
    /// Every control on. This is what production looks like.
    #[must_use]
    pub fn all_on() -> Self {
        Self::default()
    }

    /// Every control on except `name`.
    #[must_use]
    pub fn with_off(name: &str) -> Self {
        Self {
            off: BTreeSet::from([name.to_owned()]),
        }
    }

    /// True while the named control is active.
    #[must_use]
    pub fn is_on(&self, name: &str) -> bool {
        !self.off.contains(name)
    }

    /// True when the named control has been switched off for this run.
    #[must_use]
    pub fn is_off(&self, name: &str) -> bool {
        self.off.contains(name)
    }

    /// The controls that are off, in name order.
    pub fn off_names(&self) -> impl Iterator<Item = &str> {
        self.off.iter().map(String::as_str)
    }
}

/// Why a test was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOffError {
    /// The scenario fails even with every control on, so the test is broken before the control
    /// is involved.
    FailsWithControlOn {
        /// The catalog identifier or name of the test.
        test: String,
        /// The control that was meant to be the subject.
        control: String,
        /// What the scenario said.
        reason: String,
    },
    /// The scenario still passes with the control off. The test does not depend on the control
    /// it claims to check, and a regression that removes the control would go unnoticed.
    PassesWithControlOff {
        /// The catalog identifier or name of the test.
        test: String,
        /// The control that was switched off.
        control: String,
    },
}

impl fmt::Display for ControlOffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlOffError::FailsWithControlOn {
                test,
                control,
                reason,
            } => write!(
                f,
                "{test}: the scenario fails with every control on (subject: {control}): {reason}"
            ),
            ControlOffError::PassesWithControlOff { test, control } => write!(
                f,
                "{test}: the scenario still passes with the control '{control}' off, so it does not test that control"
            ),
        }
    }
}

impl std::error::Error for ControlOffError {}

/// Evidence that a test depends on its control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlProof {
    /// The catalog identifier or name of the test.
    pub test: String,
    /// The control that was switched off.
    pub control: String,
    /// What the scenario reported with the control off.
    pub failure_with_control_off: String,
}

/// Runs `scenario` with every control on and then with `control` off.
///
/// # Errors
/// [`ControlOffError::FailsWithControlOn`] when the first run fails, and
/// [`ControlOffError::PassesWithControlOff`] when the second run passes.
pub fn prove_control_matters<F>(
    test: &str,
    control: &str,
    scenario: F,
) -> Result<ControlProof, ControlOffError>
where
    F: Fn(&Controls) -> Result<(), String>,
{
    if let Err(reason) = scenario(&Controls::all_on()) {
        return Err(ControlOffError::FailsWithControlOn {
            test: test.to_owned(),
            control: control.to_owned(),
            reason,
        });
    }
    match scenario(&Controls::with_off(control)) {
        Ok(()) => Err(ControlOffError::PassesWithControlOff {
            test: test.to_owned(),
            control: control.to_owned(),
        }),
        Err(reason) => Ok(ControlProof {
            test: test.to_owned(),
            control: control.to_owned(),
            failure_with_control_off: reason,
        }),
    }
}

/// Like [`prove_control_matters`], for a scenario written with plain `assert!` calls. A panic is
/// a failure. The panic message still reaches the test output, which is noise, not a problem.
///
/// # Errors
/// The same as [`prove_control_matters`].
pub fn prove_control_matters_by_panic<F>(
    test: &str,
    control: &str,
    scenario: F,
) -> Result<ControlProof, ControlOffError>
where
    F: Fn(&Controls),
{
    prove_control_matters(test, control, |controls| {
        catch_unwind(AssertUnwindSafe(|| scenario(controls))).map_err(|payload| {
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "the scenario panicked".to_owned())
        })
    })
}

/// The proofs, and the rejections, of a group of tests.
#[derive(Debug, Default)]
pub struct ControlLedger {
    proofs: Vec<ControlProof>,
    rejected: Vec<ControlOffError>,
}

impl ControlLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs the scenario both ways and records the result.
    pub fn check<F>(&mut self, test: &str, control: &str, scenario: F) -> &mut Self
    where
        F: Fn(&Controls) -> Result<(), String>,
    {
        match prove_control_matters(test, control, scenario) {
            Ok(proof) => self.proofs.push(proof),
            Err(error) => self.rejected.push(error),
        }
        self
    }

    /// The tests that depend on their control.
    #[must_use]
    pub fn proofs(&self) -> &[ControlProof] {
        &self.proofs
    }

    /// The tests that were rejected.
    #[must_use]
    pub fn rejected(&self) -> &[ControlOffError] {
        &self.rejected
    }

    /// Fails when any test was rejected.
    ///
    /// # Panics
    /// Panics, listing each rejected test, when there is one.
    pub fn assert_all_proven(&self) {
        assert!(
            self.rejected.is_empty(),
            "{} test(s) rejected by the control-off check:\n{}",
            self.rejected.len(),
            self.rejected
                .iter()
                .map(|e| format!("  {e}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The ledger as JSON: `{"fidelity": "fake", "proven": [...], "rejected": [...]}`.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fidelity": "fake",
            "proven": self.proofs.iter().map(|p| serde_json::json!({
                "test": p.test,
                "control": p.control,
                "failure_with_control_off": p.failure_with_control_off,
            })).collect::<Vec<_>>(),
            "rejected": self.rejected.iter().map(ToString::to_string).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for a redactor: with the control on it removes the secret, with it off it does
    /// not. The scenario asserts that no secret reaches the output.
    fn redaction_scenario(controls: &Controls) -> Result<(), String> {
        let secret = "ghs_secret";
        let output = if controls.is_on("redactor") {
            "token=[REDACTED]".to_owned()
        } else {
            format!("token={secret}")
        };
        if output.contains(secret) {
            Err("the secret reached the output".to_owned())
        } else {
            Ok(())
        }
    }

    #[test]
    fn a_test_that_depends_on_its_control_is_accepted() {
        let proof = prove_control_matters("NT-SEC-02", "redactor", redaction_scenario).unwrap();
        assert_eq!(proof.control, "redactor");
        assert!(
            proof
                .failure_with_control_off
                .contains("reached the output")
        );
    }

    #[test]
    fn a_test_that_still_passes_with_its_control_off_is_rejected() {
        // Deliberate break: this scenario never looks at the control, as a test that checks the
        // wrong thing would not.
        let error = prove_control_matters("NT-SEC-02", "redactor", |_| Ok(())).unwrap_err();
        assert!(matches!(
            error,
            ControlOffError::PassesWithControlOff { .. }
        ));
        assert!(error.to_string().contains("does not test that control"));
    }

    #[test]
    fn a_test_that_fails_with_every_control_on_is_rejected_for_that_reason() {
        let error =
            prove_control_matters("NT-SEC-02", "redactor", |_| Err("always".into())).unwrap_err();
        assert!(matches!(error, ControlOffError::FailsWithControlOn { .. }));
    }

    #[test]
    fn only_the_named_control_is_switched_off() {
        let controls = Controls::with_off("redactor");
        assert!(controls.is_off("redactor"));
        assert!(controls.is_on("policy"));
        assert_eq!(controls.off_names().collect::<Vec<_>>(), ["redactor"]);
        assert!(Controls::all_on().is_on("redactor"));
    }

    #[test]
    fn a_scenario_written_with_assertions_can_be_proven_too() {
        let proof = prove_control_matters_by_panic("NT-X", "gate", |controls| {
            assert!(controls.is_on("gate"), "the gate is off");
        })
        .unwrap();
        assert!(proof.failure_with_control_off.contains("the gate is off"));
    }

    #[test]
    fn the_ledger_collects_proofs_and_rejections_and_prints_json() {
        let mut ledger = ControlLedger::new();
        ledger
            .check("NT-SEC-02", "redactor", redaction_scenario)
            .check("NT-BROKEN", "redactor", |_| Ok(()));
        assert_eq!(ledger.proofs().len(), 1);
        assert_eq!(ledger.rejected().len(), 1);
        let json = ledger.to_json();
        assert_eq!(json["fidelity"], "fake");
        assert_eq!(json["proven"][0]["test"], "NT-SEC-02");
        assert!(json["rejected"][0].as_str().unwrap().contains("NT-BROKEN"));
    }

    #[test]
    #[should_panic(expected = "rejected by the control-off check")]
    fn the_ledger_fails_the_test_that_holds_a_rejection() {
        let mut ledger = ControlLedger::new();
        ledger.check("NT-BROKEN", "redactor", |_| Ok(()));
        ledger.assert_all_proven();
    }
}
