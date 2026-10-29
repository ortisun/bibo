//! The command line of the harness: `scripts/e2e.sh` calls it.
//!
//! Exit codes: 0 everything passed, 1 something failed, 2 wrong usage, 3 BLOCKED (something could
//! not run, so there is no evidence either way). A failure wins over a block.

use std::path::{Path, PathBuf};

use crate::check::Env;
use crate::evidence::ProtectionFacts;
use crate::external::External;
use crate::mutations;
use crate::preflight::{compliant_protection, missing_needs};
use crate::report_check;
use crate::runner::{
    Blocked, RunOptions, ScenarioReport, Status, Wiring, exit_code, render, run_scenario,
};
use crate::scenarios::{Adapters, SCENARIOS, Scenario};
use crate::{RunEvidence, repository_root};

const USAGE: &str = "\
Usage: e2e COMMAND [OPTIONS]

Commands:
  list                      List the scenarios E1 to E13.
  run --scenario ID ...     Run scenarios. Repeat --scenario. Options:
                              --test-mode        Run a scenario that is defined for real adapters
                                                 (E1, E2) on the scripted wiring, labelled test mode.
                              --wiring W         auto (default), scripted, composed or recorded.
                                                 auto replays the recording of the composed pipeline
                                                 for E3 to E9, runs the scripted wiring for E10 to
                                                 E13, and needs the real prerequisites for E1, E2.
                              --evidence-dir D   Write the evidence of each run to D/ID.json.
  self-test                 Prove the assertions: the honest evidence passes, and every deliberate
                            corruption makes the assertion that guards it fail.
  blocked-self-test         Prove that a missing prerequisite is BLOCKED and not a pass.
  preflight-self-test       Prove that a remote that fails the protection preflight is BLOCKED.
  check-report [PATH]       Check the acceptance report against the recordings it cites.
  report-self-test          Prove that the report check fails on a report that claims more than
                            the recordings show.
  readability PATH...       Run the readability gate over Markdown documents (the first heading is
                            the title). Exit 1 when a rule that blocks is broken; warnings are
                            printed and do not change the exit code.
  help                      Show this text.

Exit codes: 0 passed, 1 failed, 2 wrong usage, 3 BLOCKED.
";

/// Runs the command line and returns the exit code.
#[must_use]
pub fn main(args: &[String]) -> i32 {
    let root =
        std::env::var("FACTORY_E2E_REPO_ROOT").map_or_else(|_| repository_root(), PathBuf::from);
    match args.first().map(String::as_str) {
        None | Some("help" | "--help" | "-h") => {
            print!("{USAGE}");
            if args.is_empty() { 2 } else { 0 }
        }
        Some("list") => list(),
        Some("self-test") => self_test(&root),
        Some("blocked-self-test") => blocked_self_test(&root),
        Some("preflight-self-test") => preflight_self_test(&root),
        Some("check-report") => check_report(&root, args.get(1).map(String::as_str)),
        Some("report-self-test") => report_self_test(),
        Some("readability") => readability(&root, &args[1..]),
        Some("run") => run(&root, &args[1..]),
        Some(other) => {
            eprintln!("e2e: unknown command '{other}'\n");
            eprint!("{USAGE}");
            2
        }
    }
}

fn list() -> i32 {
    for scenario in &SCENARIOS {
        println!(
            "{:<4} {:<30} {}",
            scenario.id,
            scenario.adapters.label(),
            scenario.title
        );
    }
    0
}

fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn self_test(root: &Path) -> i32 {
    let env = match Env::load(root) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("e2e: {error}");
            return 2;
        }
    };
    println!(
        "The assertions A1 to A14 read the stages from docs/architecture/state-machine.json: {} stages in Slice 1.",
        env.stages.len()
    );
    let report = mutations::self_test(&env);
    for problem in &report.honest_problems {
        println!("FAIL honest evidence: {problem}");
    }
    if report.honest_problems.is_empty() {
        println!(
            "PASS honest evidence: the canned passing sets (E1 and E2 with real adapters, E1 in test mode) hold all 14 assertions"
        );
    }
    for assertion in crate::assertions::all() {
        let mine: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.assertion == assertion.id)
            .collect();
        let detected = mine.iter().filter(|r| r.detected).count();
        let word = if detected == mine.len() && !mine.is_empty() {
            "PASS"
        } else {
            "FAIL"
        };
        println!(
            "{word} {:<4} fails on {detected} of {} corrupted evidence sets",
            assertion.id,
            mine.len()
        );
        for result in mine.iter().filter(|r| !r.detected) {
            println!("       not detected: {} ({})", result.name, result.reason);
        }
    }
    for id in &report.uncovered {
        println!("FAIL {id} has no mutation");
    }
    println!(
        "{} mutations, {} detected",
        report.results.len(),
        report.results.iter().filter(|r| r.detected).count()
    );
    if report.passed() { 0 } else { 1 }
}

/// A wiring that must never be run: it stands for the real one, which does not exist yet.
struct NeverRuns {
    protection: ProtectionFacts,
}

impl Wiring for NeverRuns {
    fn name(&self) -> &'static str {
        "composed"
    }
    fn real(&self) -> bool {
        true
    }
    fn protection(&mut self) -> Result<ProtectionFacts, Blocked> {
        Ok(self.protection.clone())
    }
    fn run(&mut self, _scenario: &Scenario) -> Result<RunEvidence, Blocked> {
        panic!("a blocked scenario must not run");
    }
}

fn blocked_self_test(root: &Path) -> i32 {
    let env = match Env::load(root) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("e2e: {error}");
            return 2;
        }
    };
    let mut ok = true;
    let mut check = |name: &str, holds: bool| {
        println!("{} {name}", if holds { "PASS" } else { "FAIL" });
        ok &= holds;
    };
    // No GitHub App, no fixture remote, no key, no allowlist: nothing in the environment.
    let none = |_: &str| -> Option<String> { None };
    let mut wiring = NeverRuns {
        protection: compliant_protection(),
    };
    for id in ["E1", "E2"] {
        let scenario = crate::scenarios::by_id(id).expect("a scenario");
        let report = run_scenario(&mut wiring, scenario, &env, RunOptions::default(), &none);
        check(
            &format!("{id} is BLOCKED when the environment has no prerequisite"),
            report.status == Status::Blocked,
        );
        let text = render(&report);
        for needed in [
            "FACTORY_E2E_GITHUB_APP_ID",
            "FACTORY_E2E_GITHUB_APP_KEY_FILE",
            "FACTORY_E2E_FIXTURE_REPO",
            "FACTORY_E2E_MODEL_API_KEY",
        ] {
            check(&format!("{id} names {needed}"), text.contains(needed));
        }
        check(
            &format!("{id} has no verdict, so nothing was passed"),
            report.verdicts.is_empty(),
        );
        check(&format!("{id} exits with 3"), exit_code(&[report]) == 3);
    }
    // With the variables set to blank values the answer is the same.
    let blank = |_: &str| -> Option<String> { Some(String::new()) };
    let report = run_scenario(
        &mut wiring,
        crate::scenarios::by_id("E1").expect("E1"),
        &env,
        RunOptions::default(),
        &blank,
    );
    check(
        "a blank value counts as missing",
        report.status == Status::Blocked,
    );
    check(
        "the list of what is missing is the list of what E1 and E2 need",
        missing_needs(none).len() == crate::preflight::REAL_NEEDS.len(),
    );
    // No composed program either.
    check(
        "without the composed program the real wiring is BLOCKED and says how to get it",
        matches!(External::from_lookup(&none), Err(Blocked(reasons)) if reasons[0].contains("FACTORY_E2E_COMPOSED")),
    );
    i32::from(!ok)
}

#[cfg(feature = "scripted")]
fn preflight_self_test(root: &Path) -> i32 {
    use crate::scripted::Scripted;
    let env = match Env::load(root) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("e2e: {error}");
            return 2;
        }
    };
    let none = |_: &str| -> Option<String> { None };
    let scenario = crate::scenarios::by_id("E3").expect("E3");
    let mut ok = true;
    let mut check = |name: &str, holds: bool| {
        println!("{} {name}", if holds { "PASS" } else { "FAIL" });
        ok &= holds;
    };
    type Weaken = fn(&mut factory_testkit::fx::github::Protection);
    let weak: [(&str, Weaken); 4] = [
        ("the App may bypass the pull request rule", |p| {
            p.bypass_apps.push("factory-test-app".to_owned())
        }),
        ("the required check is not pinned to the App", |p| {
            p.required_checks[0].app_id = None
        }),
        ("a pull request is not required", |p| {
            p.require_pull_request = false
        }),
        ("force pushes are allowed", |p| p.allow_force_pushes = true),
    ];
    for (name, change) in weak {
        let Ok(wiring) = Scripted::new(root) else {
            eprintln!("e2e: the scripted wiring did not start");
            return 2;
        };
        let mut wiring = wiring.with_weak_protection(change);
        let report = run_scenario(&mut wiring, scenario, &env, RunOptions::default(), &none);
        check(
            &format!("a remote where {name} is BLOCKED and nothing runs against it"),
            report.status == Status::Blocked
                && report.verdicts.is_empty()
                && report
                    .blocked
                    .iter()
                    .all(|b| b.contains("protection preflight")),
        );
    }
    let Ok(mut compliant) = Scripted::new(root) else {
        return 2;
    };
    let report = run_scenario(&mut compliant, scenario, &env, RunOptions::default(), &none);
    check(
        "a compliant remote lets the scenario run",
        report.status == Status::Passed,
    );
    i32::from(!ok)
}

#[cfg(not(feature = "scripted"))]
fn preflight_self_test(_root: &Path) -> i32 {
    eprintln!("e2e: this build has no scripted wiring (the `scripted` feature is off)");
    2
}

fn readability(root: &Path, paths: &[String]) -> i32 {
    use factory_workflow::gates::readability::{Artifact, DocumentType, Options, Severity, check};
    if paths.is_empty() {
        return usage("readability needs at least one path");
    }
    let env = match Env::load(root) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("e2e: {error}");
            return 2;
        }
    };
    let mut blocked = false;
    for path in paths {
        let Ok(text) = std::fs::read_to_string(path) else {
            eprintln!("e2e: cannot read {path}");
            return 2;
        };
        let title = text
            .lines()
            .find_map(|line| line.strip_prefix("# "))
            .unwrap_or("Untitled document")
            .trim()
            .to_owned();
        let artifact = Artifact::documentation(&title, DocumentType::Reference, &text).at(path);
        let findings = match check(&env.catalog, &Options::new(), &[artifact]) {
            Ok(findings) => findings,
            Err(error) => {
                eprintln!("e2e: the readability gate could not run: {error:?}");
                return 2;
            }
        };
        let blocks = findings
            .iter()
            .filter(|finding| finding.severity == Severity::Block)
            .count();
        for finding in &findings {
            println!(
                "{} {path}: {} ({}): {}",
                if finding.severity == Severity::Block {
                    "BLOCK"
                } else {
                    "warn"
                },
                finding.rule.as_str(),
                finding.line.map_or_else(
                    || finding.part.as_str().to_owned(),
                    |line| format!("line {line}")
                ),
                finding.message
            );
        }
        println!(
            "{} {path}: {} blocking finding(s), {} warning(s)",
            if blocks == 0 { "PASS" } else { "FAIL" },
            blocks,
            findings.len() - blocks
        );
        blocked |= blocks > 0;
    }
    i32::from(blocked)
}

fn report_self_test() -> i32 {
    let mut ok = true;
    for (name, holds) in report_check::self_test() {
        println!("{} {name}", if holds { "PASS" } else { "FAIL" });
        ok &= holds;
    }
    i32::from(!ok)
}

fn check_report(root: &Path, path: Option<&str>) -> i32 {
    let path = path.map_or_else(
        || root.join("docs/reports/slice-1-acceptance.md"),
        PathBuf::from,
    );
    let Ok(text) = std::fs::read_to_string(&path) else {
        println!(
            "BLOCKED: {} does not exist yet; the package s1-end-to-end-run writes it after the scenarios have run",
            path.display()
        );
        return 3;
    };
    let problems = report_check::problems(&text, root);
    if problems.is_empty() {
        println!(
            "PASS: every PASSED line of {} cites a recording and says how it ran",
            path.display()
        );
        0
    } else {
        for problem in &problems {
            println!("FAIL: {problem}");
        }
        1
    }
}

fn run(root: &Path, args: &[String]) -> i32 {
    let mut ids: Vec<String> = Vec::new();
    let mut test_mode = false;
    let mut wiring_choice = "auto".to_owned();
    let mut evidence_dir: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--scenario" => match iter.next() {
                Some(id) => ids.push(id.clone()),
                None => return usage("--scenario needs an id"),
            },
            "--test-mode" => test_mode = true,
            "--wiring" => match iter.next() {
                Some(choice)
                    if ["auto", "scripted", "composed", "recorded"].contains(&choice.as_str()) =>
                {
                    wiring_choice.clone_from(choice);
                }
                _ => return usage("--wiring needs auto, scripted, composed or recorded"),
            },
            "--evidence-dir" => match iter.next() {
                Some(dir) => evidence_dir = Some(PathBuf::from(dir)),
                None => return usage("--evidence-dir needs a directory"),
            },
            other => return usage(&format!("unknown option '{other}'")),
        }
    }
    if ids.is_empty() {
        return usage("give at least one --scenario");
    }
    let env = match Env::load(root) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("e2e: {error}");
            return 2;
        }
    };
    let mut reports: Vec<ScenarioReport> = Vec::new();
    for id in &ids {
        let Some(scenario) = crate::scenarios::by_id(id) else {
            return usage(&format!("there is no scenario {id}; run `e2e list`"));
        };
        let report = run_one(
            root,
            scenario,
            &env,
            &wiring_choice,
            test_mode,
            evidence_dir.as_deref(),
        );
        print!("{}", render(&report));
        reports.push(report);
    }
    let count = |status| reports.iter().filter(|r| r.status == status).count();
    println!(
        "SUMMARY: {} passed, {} failed, {} blocked",
        count(Status::Passed),
        count(Status::Failed),
        count(Status::Blocked)
    );
    exit_code(&reports)
}

fn usage(message: &str) -> i32 {
    eprintln!("e2e: {message}\n");
    eprint!("{USAGE}");
    2
}

fn run_one(
    root: &Path,
    scenario: &'static Scenario,
    env: &Env,
    choice: &str,
    test_mode: bool,
    evidence_dir: Option<&Path>,
) -> ScenarioReport {
    let options = RunOptions {
        test_mode_for_real_scenarios: test_mode,
    };
    let recorded = choice == "recorded"
        || (choice == "auto"
            && !test_mode
            && crate::scenarios::COMPOSED_TEST.contains(&scenario.id)
            && env_lookup(crate::external::PROGRAM_VARIABLE).is_none());
    let prefer_scripted = !recorded
        && (choice == "scripted"
            || test_mode
            || (choice == "auto"
                && scenario.adapters != Adapters::Real
                && env_lookup(crate::external::PROGRAM_VARIABLE).is_none()));
    let mut wiring: Box<dyn Wiring> = if recorded {
        match crate::recorded::Recorded::new(root, scenario.id) {
            Ok(wiring) => Box::new(wiring),
            Err(why) => return blocked_report(scenario, Blocked::because(why)),
        }
    } else if prefer_scripted {
        match scripted_wiring(root) {
            Ok(wiring) => wiring,
            Err(blocked) => return blocked_report(scenario, blocked),
        }
    } else {
        // A real run. Every prerequisite is looked for, and every one that is missing is named,
        // before anything starts.
        let external = External::from_lookup(&env_lookup);
        let mut reasons = Vec::new();
        if let Err(Blocked(found)) = &external {
            reasons.extend(found.iter().cloned());
        }
        if scenario.adapters == Adapters::Real {
            reasons.extend(missing_needs(env_lookup));
            reasons.extend(host_problems(root));
        }
        match external {
            Ok(wiring) if reasons.is_empty() => Box::new(wiring),
            _ => return blocked_report(scenario, Blocked(reasons)),
        }
    };
    let report = run_scenario(wiring.as_mut(), scenario, env, options, &env_lookup);
    if let Some(dir) = evidence_dir {
        record_report(dir, &report);
    }
    report
}

/// What the machine, the repository and Docker show to be missing for a real run.
fn host_problems(root: &Path) -> Vec<String> {
    let git = |args: &[&str]| crate::prerequisites::system_git(root, args);
    crate::prerequisites::problems(&crate::prerequisites::Host {
        root,
        env: &env_lookup,
        docker: &crate::prerequisites::system_docker,
        git: &git,
    })
}

fn blocked_report(scenario: &'static Scenario, Blocked(reasons): Blocked) -> ScenarioReport {
    ScenarioReport {
        id: scenario.id,
        title: scenario.title,
        status: Status::Blocked,
        label: format!("{}; no wiring available", scenario.adapters.label()),
        verdicts: Vec::new(),
        blocked: reasons,
        seconds: 0.0,
    }
}

fn record_report(dir: &Path, report: &ScenarioReport) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let verdicts: Vec<_> = report
        .verdicts
        .iter()
        .map(|v| serde_json::json!({ "id": v.id, "pass": v.pass, "reason": v.reason }))
        .collect();
    let document = serde_json::json!({
        "scenario": report.id,
        "title": report.title,
        "status": report.status.word(),
        "label": report.label,
        "verdicts": verdicts,
        "blocked": report.blocked,
        "seconds": report.seconds,
    });
    let _ = std::fs::write(
        dir.join(format!("{}.json", report.id)),
        format!("{document:#}\n"),
    );
}

#[cfg(feature = "scripted")]
fn scripted_wiring(root: &Path) -> Result<Box<dyn Wiring>, Blocked> {
    crate::scripted::Scripted::new(root)
        .map(|wiring| Box::new(wiring) as Box<dyn Wiring>)
        .map_err(Blocked::because)
}

#[cfg(not(feature = "scripted"))]
fn scripted_wiring(_root: &Path) -> Result<Box<dyn Wiring>, Blocked> {
    Err(Blocked::because(
        "this build has no scripted wiring (the `scripted` feature is off)",
    ))
}
