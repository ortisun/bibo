//! The canned honest evidence passes every assertion, in production mode for the English and the
//! Portuguese request and in test mode with labelled fakes.

use factory_e2e::assertions::run_all;
use factory_e2e::canned::{Options, honest};
use factory_e2e::{Env, repository_root};

fn env() -> Env {
    Env::load(&repository_root()).expect("the state machine file loads")
}

fn assert_all_pass(options: Options) {
    let env = env();
    let evidence = honest(&env, options);
    let verdicts = run_all(&evidence, &env);
    assert_eq!(verdicts.len(), 14);
    let failures: Vec<String> = verdicts
        .iter()
        .filter(|verdict| !verdict.pass)
        .map(ToString::to_string)
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn the_honest_english_run_with_real_adapters_passes_all_fourteen() {
    assert_all_pass(Options::e1_production());
}

#[test]
fn the_honest_portuguese_run_with_real_adapters_passes_all_fourteen() {
    assert_all_pass(Options::e2_production());
}

#[test]
fn the_honest_english_run_in_test_mode_passes_all_fourteen() {
    assert_all_pass(Options::e1_test_mode());
}

#[test]
fn the_stage_list_comes_from_the_state_machine_file_and_is_not_counted_in_code() {
    let env = env();
    let kinds: Vec<&str> = env.stages.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds.first(), Some(&"INTAKE"));
    assert_eq!(kinds.last(), Some(&"APPROVAL"));
    assert!(!kinds.contains(&"MERGE"), "MERGE belongs to a later slice");
    let evidence = honest(&env, Options::e1_production());
    assert_eq!(evidence.stage_runs.len(), env.stages.len());
}

/// The owner works alone: with the solo mode on (`policies/approval.yaml`, `solo_mode.enabled`,
/// ADR 0022), an honest run in which the requester approves their own request holds A9, whatever
/// the tier, because the engine grants that approval only with the solo fact. With the mode off
/// the same approval does not hold A9.
#[test]
fn the_owner_may_approve_their_own_request_when_the_solo_mode_is_on() {
    let env = env();
    assert!(
        env.solo_mode,
        "the repository policy switches the solo mode on"
    );
    let mut evidence = honest(&env, Options::e1_production());
    let requester = evidence.job.requester.clone();
    let requester_id = requester.trim_start_matches("human:").to_owned();
    for record in evidence
        .audit
        .iter_mut()
        .filter(|r| r.action == "approval_granted_or_rejected.granted")
    {
        record.actor.clone_from(&requester);
    }
    for entry in &mut evidence.ledger {
        if let Some(items) = entry
            .pointer_mut("/evidence")
            .and_then(serde_json::Value::as_array_mut)
        {
            for item in items {
                if item
                    .pointer("/attestor/role")
                    .and_then(serde_json::Value::as_str)
                    == Some("approver")
                {
                    item["attestor"]["principal_id"] = serde_json::json!(requester_id);
                }
            }
        }
    }
    factory_e2e::mutations::reseal(&mut evidence);
    let a9 = |evidence: &factory_e2e::RunEvidence, env: &Env| {
        run_all(evidence, env)
            .into_iter()
            .find(|verdict| verdict.id == "A9")
            .expect("A9 runs")
    };
    let solo = a9(&evidence, &env);
    assert!(solo.pass, "{solo}");
    let strict = Env {
        solo_mode: false,
        ..env
    };
    let refused = a9(&evidence, &strict);
    assert!(!refused.pass, "{refused}");
}

/// The shapes real run 36 of E1 left (2026-11-20), which the assertions first misread: the head
/// hash written as bare digits in the pull request body (A4), a specification kept only in the
/// job's store and not on the head branch (A5), and a link check and an example check that are
/// `NOT_APPLICABLE` with the rule recorded as an object (A12). Each holds.
#[test]
fn the_shapes_of_real_run_36_hold_a4_a5_and_a12() {
    use factory_e2e::assertions::by_id;
    use serde_json::json;
    let env = env();
    let mut evidence = honest(&env, Options::e1_production());
    evidence.github.head_files.clear();
    for record in &mut evidence.contracts.gate_reports {
        let gate = record.report["metadata"]["gate_id"].as_str().unwrap_or("");
        if gate == "docs-links" || gate == "docs-examples" {
            record.report["outcome"] = json!("NOT_APPLICABLE");
            record.report["not_applicable_reason"] = json!({
                "code": "no_matching_files",
                "decided_by": "deterministic_rule",
                "justification": "The changed documents contain no internal links.",
            });
        }
    }
    let body = &evidence.github.pull_requests[0].body;
    assert!(!body.contains("sha256:"), "the body writes bare digits");
    for id in ["A4", "A5", "A12"] {
        let verdict = by_id(id).expect("an assertion").apply(&evidence, &env);
        assert!(verdict.pass, "{verdict}");
    }
}

/// A page that no task owns holds A6 only when the documentation stage wrote it: that stage's
/// own scope gate judges it against the documentation plan.
#[test]
fn a6_leaves_the_pages_of_the_documentation_stage_to_that_stage() {
    use factory_e2e::assertions::by_id;
    let env = env();
    let mut evidence = honest(&env, Options::e1_production());
    evidence
        .github
        .changed_paths
        .push("docs/json-output.md".to_owned());
    let a6 = by_id("A6").expect("A6");
    let stray = a6.apply(&evidence, &env);
    assert!(
        !stray.pass && stray.to_string().contains("docs/json-output.md"),
        "{stray}"
    );
    evidence.facts.insert(
        "documentation_paths".to_owned(),
        serde_json::json!(["docs/json-output.md"]),
    );
    let written = a6.apply(&evidence, &env);
    assert!(written.pass, "{written}");
}

/// A line of the job that carries no correlation id still fails A11; a line written outside any
/// job (the token sweep) does not.
#[test]
fn a11_judges_the_lines_of_the_job_and_leaves_the_lines_outside_it() {
    use factory_e2e::assertions::by_id;
    let env = env();
    let evidence = honest(&env, Options::e1_production());
    assert!(
        evidence
            .telemetry
            .correlated
            .iter()
            .any(|line| !line.in_job && line.correlation_id.is_none())
    );
    let a11 = by_id("A11").expect("A11");
    assert!(a11.apply(&evidence, &env).pass);
    let mut broken = evidence;
    if let Some(line) = broken
        .telemetry
        .correlated
        .iter_mut()
        .find(|line| line.in_job && line.source == "log")
    {
        line.correlation_id = None;
    }
    let verdict = a11.apply(&broken, &env);
    assert!(
        !verdict.pass && verdict.to_string().contains("None"),
        "{verdict}"
    );
}
