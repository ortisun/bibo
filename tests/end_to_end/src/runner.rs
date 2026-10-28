//! Runs a scenario through a wiring and judges the evidence it returns.
//!
//! A wiring is the thing that drives the factory: it files the issue, lets the factory work, and
//! reads the stored records and GitHub back into a [`RunEvidence`]. The composition package
//! supplies the real one. The scripted one in [`crate::scripted`] stands in until then.
//!
//! The runner decides three things before it trusts any evidence:
//!
//! 1. A scenario defined for real adapters runs only on a wiring that uses them, and only when the
//!    prerequisites are in place. Otherwise it is `BLOCKED`, with the missing item named.
//! 2. A scenario that opens a pull request runs only against a remote whose protection passes the
//!    preflight. Otherwise it is `BLOCKED`.
//! 3. The evidence must say which scenario and which wiring made it.
//!
//! `BLOCKED` is not a pass and not a failure. It means there is no evidence either way.

use std::time::Instant;

use crate::check::{Env, Verdict};
use crate::evidence::{Mode, ProtectionFacts, RunEvidence};
use crate::preflight::{missing_needs, protection_problems};
use crate::scenarios::{Adapters, Scenario};

/// Why a scenario could not run: one sentence for each missing item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked(pub Vec<String>);

impl Blocked {
    /// A block with one reason.
    pub fn because(reason: impl Into<String>) -> Self {
        Self(vec![reason.into()])
    }
}

/// The thing that drives the factory and reads back what happened.
pub trait Wiring {
    /// `scripted` or `composed`. It goes on the evidence.
    fn name(&self) -> &'static str;

    /// True when the adapters are real.
    fn real(&self) -> bool;

    /// The protection of the default branch of the fixture remote, read from the remote.
    ///
    /// # Errors
    /// [`Blocked`] when the remote cannot be reached or read.
    fn protection(&mut self) -> Result<ProtectionFacts, Blocked>;

    /// Drives the factory through the scenario and returns the evidence.
    ///
    /// # Errors
    /// [`Blocked`] when something the scenario needs is not available.
    fn run(&mut self, scenario: &Scenario) -> Result<RunEvidence, Blocked>;
}

/// How the scenario ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Every check held.
    Passed,
    /// A check failed.
    Failed,
    /// It could not run.
    Blocked,
}

impl Status {
    /// The word in the report.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// The result of one scenario.
#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioReport {
    /// The scenario id.
    pub id: &'static str,
    /// The title.
    pub title: &'static str,
    /// The outcome.
    pub status: Status,
    /// How it ran, in words: which adapters and which wiring. Never left out.
    pub label: String,
    /// The verdict of every check.
    pub verdicts: Vec<Verdict>,
    /// Why it could not run.
    pub blocked: Vec<String>,
    /// How long it took.
    pub seconds: f64,
}

/// What a caller may switch.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunOptions {
    /// Run a scenario that is defined for real adapters on a wiring with labelled fakes. The
    /// result is labelled test mode and is not the real proof.
    pub test_mode_for_real_scenarios: bool,
}

fn blocked_report(
    scenario: &Scenario,
    label: String,
    blocked: Vec<String>,
    started: Instant,
) -> ScenarioReport {
    ScenarioReport {
        id: scenario.id,
        title: scenario.title,
        status: Status::Blocked,
        label,
        verdicts: Vec::new(),
        blocked,
        seconds: started.elapsed().as_secs_f64(),
    }
}

/// Runs one scenario.
///
/// `lookup` reads an environment variable, so a test can give it a fixed environment.
#[must_use]
pub fn run_scenario(
    wiring: &mut dyn Wiring,
    scenario: &Scenario,
    env: &Env,
    options: RunOptions,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> ScenarioReport {
    let started = Instant::now();
    let mut label = format!("{}; {} wiring", scenario.adapters.label(), wiring.name());

    if scenario.adapters == Adapters::Real {
        if wiring.real() {
            let missing = missing_needs(lookup);
            if !missing.is_empty() {
                return blocked_report(scenario, label, missing, started);
            }
        } else if options.test_mode_for_real_scenarios {
            label = format!(
                "TEST MODE with labelled fakes, {} wiring (the scenario is defined for real adapters, so this is not the real proof)",
                wiring.name()
            );
        } else {
            let mut reasons = vec![format!(
                "the {} wiring uses labelled fakes, and {} is defined for real adapters",
                wiring.name(),
                scenario.id
            )];
            reasons.extend(missing_needs(lookup));
            return blocked_report(scenario, label, reasons, started);
        }
    }

    if scenario.needs_protected_remote {
        match wiring.protection() {
            Err(Blocked(reasons)) => return blocked_report(scenario, label, reasons, started),
            Ok(protection) => {
                let problems = protection_problems(&protection);
                if !problems.is_empty() {
                    let reasons = problems
                        .into_iter()
                        .map(|p| format!("the fixture remote fails the protection preflight: {p}"))
                        .collect();
                    return blocked_report(scenario, label, reasons, started);
                }
            }
        }
    }

    let evidence = match wiring.run(scenario) {
        Ok(evidence) => evidence,
        Err(Blocked(reasons)) => return blocked_report(scenario, label, reasons, started),
    };

    let mut verdicts = vec![provenance(&evidence, scenario, wiring)];
    verdicts.extend(
        scenario
            .checks()
            .iter()
            .map(|check| check.apply(&evidence, env)),
    );
    let status = if verdicts.iter().all(|v| v.pass) {
        Status::Passed
    } else {
        Status::Failed
    };
    ScenarioReport {
        id: scenario.id,
        title: scenario.title,
        status,
        label,
        verdicts,
        blocked: Vec::new(),
        seconds: started.elapsed().as_secs_f64(),
    }
}

/// The evidence must come from this scenario and this wiring, and a real scenario's evidence must
/// be production evidence unless the caller asked for a labelled test-mode run.
fn provenance(evidence: &RunEvidence, scenario: &Scenario, wiring: &dyn Wiring) -> Verdict {
    const ID: &str = "R.provenance";
    if evidence.scenario != scenario.id {
        return Verdict::fail(
            ID,
            format!(
                "the evidence is about {}, not {}",
                evidence.scenario, scenario.id
            ),
        );
    }
    if evidence.wiring != wiring.name() {
        return Verdict::fail(
            ID,
            format!(
                "the evidence says it came from the {} wiring, not the {} wiring",
                evidence.wiring,
                wiring.name()
            ),
        );
    }
    if wiring.real() && evidence.mode != Mode::Production && scenario.adapters == Adapters::Real {
        return Verdict::fail(ID, "a real run produced test-mode evidence");
    }
    if !wiring.real() && evidence.mode != Mode::Test {
        return Verdict::fail(
            ID,
            "a wiring with fakes produced evidence that claims production mode",
        );
    }
    Verdict::pass(
        ID,
        format!(
            "the evidence is about {} from the {} wiring in {} mode",
            evidence.scenario,
            evidence.wiring,
            evidence.mode.as_str()
        ),
    )
}

/// The exit code for a set of reports: 1 when anything failed, 3 when nothing failed and
/// something is blocked, 0 otherwise.
#[must_use]
pub fn exit_code(reports: &[ScenarioReport]) -> i32 {
    if reports.iter().any(|r| r.status == Status::Failed) {
        1
    } else if reports.iter().any(|r| r.status == Status::Blocked) {
        3
    } else {
        0
    }
}

/// The report as plain text.
#[must_use]
pub fn render(report: &ScenarioReport) -> String {
    let mut out = format!(
        "{} {} - {} [{}] ({:.2}s)\n",
        report.id,
        report.status.word(),
        report.title,
        report.label,
        report.seconds
    );
    for verdict in &report.verdicts {
        out.push_str(&format!("  {verdict}\n"));
    }
    for reason in &report.blocked {
        out.push_str(&format!("  BLOCKED: {reason}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canned::{Options, honest};
    use crate::preflight::compliant_protection;
    use crate::scenarios;

    struct Stub {
        real: bool,
        protection: Result<ProtectionFacts, Blocked>,
        runs: usize,
        evidence: Option<RunEvidence>,
    }

    impl Wiring for Stub {
        fn name(&self) -> &'static str {
            if self.real { "composed" } else { "scripted" }
        }
        fn real(&self) -> bool {
            self.real
        }
        fn protection(&mut self) -> Result<ProtectionFacts, Blocked> {
            self.protection.clone()
        }
        fn run(&mut self, _scenario: &Scenario) -> Result<RunEvidence, Blocked> {
            self.runs += 1;
            self.evidence
                .clone()
                .ok_or_else(|| Blocked::because("no evidence"))
        }
    }

    fn env() -> Env {
        Env::load(&crate::repository_root()).expect("the state machine file loads")
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn a_real_scenario_on_a_fake_wiring_is_blocked_and_the_wiring_is_not_run() {
        let mut stub = Stub {
            real: false,
            protection: Ok(compliant_protection()),
            runs: 0,
            evidence: None,
        };
        let report = run_scenario(
            &mut stub,
            scenarios::by_id("E1").expect("E1"),
            &env(),
            RunOptions::default(),
            &no_env,
        );
        assert_eq!(report.status, Status::Blocked);
        assert_eq!(stub.runs, 0);
        assert!(report.blocked[0].contains("defined for real adapters"));
        assert_eq!(report.blocked.len(), 1 + crate::preflight::REAL_NEEDS.len());
    }

    #[test]
    fn a_real_wiring_without_the_prerequisites_is_blocked_with_each_item_named() {
        let mut stub = Stub {
            real: true,
            protection: Ok(compliant_protection()),
            runs: 0,
            evidence: None,
        };
        let report = run_scenario(
            &mut stub,
            scenarios::by_id("E2").expect("E2"),
            &env(),
            RunOptions::default(),
            &no_env,
        );
        assert_eq!(report.status, Status::Blocked);
        assert_eq!(stub.runs, 0);
        assert_eq!(report.blocked.len(), crate::preflight::REAL_NEEDS.len());
        assert!(
            report
                .blocked
                .iter()
                .any(|b| b.contains("FACTORY_E2E_MODEL_API_KEY"))
        );
        assert!(
            report
                .blocked
                .iter()
                .any(|b| b.contains("FACTORY_E2E_GITHUB_APP_ID"))
        );
        assert!(
            report
                .blocked
                .iter()
                .any(|b| b.contains("FACTORY_E2E_FIXTURE_REPO"))
        );
        assert_eq!(exit_code(&[report]), 3);
    }

    #[test]
    fn a_remote_that_fails_the_protection_preflight_is_blocked_and_nothing_runs() {
        let mut weak = compliant_protection();
        weak.required_checks[0].pinned_to_app = false;
        weak.app_may_bypass = true;
        let mut stub = Stub {
            real: false,
            protection: Ok(weak),
            runs: 0,
            evidence: None,
        };
        let report = run_scenario(
            &mut stub,
            scenarios::by_id("E3").expect("E3"),
            &env(),
            RunOptions::default(),
            &no_env,
        );
        assert_eq!(report.status, Status::Blocked);
        assert_eq!(
            stub.runs, 0,
            "the scenario must not run against a remote that fails the preflight"
        );
        assert_eq!(report.blocked.len(), 2);
        assert!(
            report
                .blocked
                .iter()
                .all(|b| b.contains("protection preflight"))
        );
    }

    #[test]
    fn a_remote_that_cannot_be_read_is_blocked() {
        let mut stub = Stub {
            real: false,
            protection: Err(Blocked::because("the remote does not answer")),
            runs: 0,
            evidence: None,
        };
        let report = run_scenario(
            &mut stub,
            scenarios::by_id("E3").expect("E3"),
            &env(),
            RunOptions::default(),
            &no_env,
        );
        assert_eq!(report.status, Status::Blocked);
        assert_eq!(report.blocked, ["the remote does not answer"]);
    }

    #[test]
    fn a_scenario_that_needs_no_remote_ignores_a_weak_protection() {
        let mut weak = compliant_protection();
        weak.require_pull_request = false;
        let mut stub = Stub {
            real: false,
            protection: Ok(weak),
            runs: 0,
            evidence: None,
        };
        let _ = run_scenario(
            &mut stub,
            scenarios::by_id("E6").expect("E6"),
            &env(),
            RunOptions::default(),
            &no_env,
        );
        assert_eq!(stub.runs, 1);
    }

    #[test]
    fn evidence_from_another_scenario_or_another_wiring_fails_the_provenance_check() {
        let env = env();
        let mut evidence = honest(&env, Options::e1_test_mode());
        evidence.wiring = "scripted".to_owned();
        evidence.scenario = "E4".to_owned();
        let mut stub = Stub {
            real: false,
            protection: Ok(compliant_protection()),
            runs: 0,
            evidence: Some(evidence),
        };
        let options = RunOptions {
            test_mode_for_real_scenarios: true,
        };
        let report = run_scenario(
            &mut stub,
            scenarios::by_id("E1").expect("E1"),
            &env,
            options,
            &no_env,
        );
        assert_eq!(report.status, Status::Failed);
        assert!(report.verdicts[0].reason.contains("is about E4"));
    }

    #[test]
    fn a_test_mode_run_of_a_real_scenario_is_labelled_and_never_the_real_proof() {
        let env = env();
        let mut evidence = honest(&env, Options::e1_test_mode());
        evidence.wiring = "scripted".to_owned();
        let mut stub = Stub {
            real: false,
            protection: Ok(compliant_protection()),
            runs: 0,
            evidence: Some(evidence),
        };
        let options = RunOptions {
            test_mode_for_real_scenarios: true,
        };
        let report = run_scenario(
            &mut stub,
            scenarios::by_id("E1").expect("E1"),
            &env,
            options,
            &no_env,
        );
        assert!(
            report.label.starts_with("TEST MODE with labelled fakes"),
            "{}",
            report.label
        );
        assert!(report.label.contains("not the real proof"));
        assert_eq!(report.status, Status::Passed, "{}", render(&report));
    }

    #[test]
    fn the_exit_code_is_one_for_a_failure_three_for_blocked_and_zero_otherwise() {
        let make = |status| ScenarioReport {
            id: "E0",
            title: "t",
            status,
            label: String::new(),
            verdicts: Vec::new(),
            blocked: Vec::new(),
            seconds: 0.0,
        };
        assert_eq!(exit_code(&[make(Status::Passed)]), 0);
        assert_eq!(exit_code(&[make(Status::Passed), make(Status::Blocked)]), 3);
        assert_eq!(exit_code(&[make(Status::Blocked), make(Status::Failed)]), 1);
        assert_eq!(exit_code(&[]), 0);
    }
}
