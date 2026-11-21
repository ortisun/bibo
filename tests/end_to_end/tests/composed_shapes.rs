//! The shapes a run of the composed pipeline has that the scripted wiring does not, and the
//! checks that learned to read them. Each shape has an honest case that must pass and a corrupted
//! case that must fail for the right reason, so reading a new shape did not lower a bar.

use factory_e2e::assertions::by_id;
use factory_e2e::canned::{Options, honest};
use factory_e2e::evidence::RunEvidence;
use factory_e2e::runner::Wiring;
use factory_e2e::scenarios;
use factory_e2e::scripted::Scripted;
use factory_e2e::{Env, repository_root, scenario_checks};

fn env() -> Env {
    Env::load(&repository_root()).expect("the state machine file loads")
}

fn skipped_domain_stage() -> RunEvidence {
    // The composed pipeline skips DOMAIN_DISCOVERY by a rule (ADR 0010). The run has no attempt
    // and the ledger holds the entry that records the skip.
    let mut evidence = honest(&env(), Options::e1_production());
    let id = evidence
        .stage_runs
        .iter()
        .find(|run| run.kind == "DOMAIN_DISCOVERY")
        .map(|run| run.id.clone())
        .expect("a DOMAIN_DISCOVERY run");
    for run in &mut evidence.stage_runs {
        if run.id == id {
            run.status = "SKIPPED".to_owned();
            run.attempts.clear();
        }
    }
    for entry in &mut evidence.timeline {
        if entry.subject_id == id && entry.to == "PASSED" {
            entry.to = "SKIPPED".to_owned();
        }
    }
    evidence
}

#[test]
fn a_stage_that_a_rule_skips_settles_its_place_when_the_ledger_records_the_skip() {
    let env = env();
    let evidence = skipped_domain_stage();
    for id in ["A1", "A13"] {
        let verdict = by_id(id).expect("an assertion").apply(&evidence, &env);
        assert!(verdict.pass, "{verdict}");
    }
}

#[test]
fn a_skipped_stage_with_no_record_of_the_skip_settles_nothing() {
    let env = env();
    let mut evidence = skipped_domain_stage();
    let id = evidence
        .stage_runs
        .iter()
        .find(|run| run.kind == "DOMAIN_DISCOVERY")
        .map(|run| run.id.clone())
        .expect("a run");
    evidence
        .ledger
        .retain(|entry| entry["metadata"]["stage_run_id"].as_str() != Some(id.as_str()));
    let verdict = by_id("A1").expect("A1").apply(&evidence, &env);
    assert!(!verdict.pass, "{verdict}");
    assert!(verdict.reason.contains("SKIPPED"), "{verdict}");
}

#[test]
fn a_run_resumed_after_a_wait_may_have_a_stage_run_span_for_each_claim_but_not_none() {
    let env = env();
    let mut evidence = honest(&env, Options::e1_production());
    let a11 = by_id("A11").expect("A11");
    assert!(a11.apply(&evidence, &env).pass);
    // A second claim of a run opens a second stage run span. The attempts hang under the first.
    let first = evidence
        .telemetry
        .spans
        .iter()
        .find(|span| span.name == "factory.stage_run")
        .cloned()
        .expect("a stage run span");
    let mut second = first.clone();
    second.id = "second-claim".to_owned();
    evidence.telemetry.spans.push(second);
    assert!(a11.apply(&evidence, &env).pass);
    // With no stage run span at all, the attempt hangs under nothing.
    let run = first.stage_run_id.clone();
    evidence
        .telemetry
        .spans
        .retain(|span| !(span.name == "factory.stage_run" && span.stage_run_id == run));
    let verdict = a11.apply(&evidence, &env);
    assert!(
        !verdict.pass && verdict.reason.contains("no stage run span"),
        "{verdict}"
    );
}

#[test]
fn an_attempt_under_the_stage_run_span_of_another_run_fails() {
    let env = env();
    let mut evidence = honest(&env, Options::e1_production());
    let other = evidence
        .telemetry
        .spans
        .iter()
        .filter(|span| span.name == "factory.stage_run")
        .nth(1)
        .map(|span| span.id.clone())
        .expect("a second stage run span");
    let attempt = evidence
        .telemetry
        .spans
        .iter_mut()
        .find(|span| span.name == "factory.attempt")
        .expect("an attempt span");
    attempt.parent_id = Some(other);
    let verdict = by_id("A11").expect("A11").apply(&evidence, &env);
    assert!(!verdict.pass, "{verdict}");
}

#[test]
fn two_approvals_are_read_with_the_last_one_as_the_approval_of_the_pull_request() {
    // A job has two human gates. The honest run has one approval record; add an earlier one by
    // the same approver and A9 still passes, then make that earlier one the requester's: with the
    // solo mode on (ADR 0022) that is the owner approving their own specification, and with it off
    // A9 refuses it.
    let env = env();
    let mut evidence = honest(&env, Options::e1_production());
    let first = evidence
        .audit
        .iter()
        .position(|r| r.action == "approval_granted_or_rejected.granted")
        .expect("an approval record");
    let mut earlier = evidence.audit[first].clone();
    earlier.seq = 0;
    evidence.audit.insert(first, earlier);
    let a9 = by_id("A9").expect("A9");
    assert!(
        a9.apply(&evidence, &env).pass,
        "{}",
        a9.apply(&evidence, &env)
    );
    evidence.audit[first]
        .actor
        .clone_from(&evidence.job.requester);
    assert!(
        env.solo_mode,
        "the repository policy switches the solo mode on"
    );
    let solo = a9.apply(&evidence, &env);
    assert!(solo.pass, "{solo}");
    let strict = factory_e2e::check::Env {
        solo_mode: false,
        ..env
    };
    let verdict = a9.apply(&evidence, &strict);
    assert!(
        !verdict.pass && verdict.reason.contains("their own request"),
        "{verdict}"
    );
}

// ---- E8 at the ingestion of the builder's patch ----------------------------------------------

/// The scripted E8 evidence reshaped the way the composed pipeline leaves it: no gate report, the
/// implementation run blocked, the validation run never started, and the refusal named in a fact.
fn e8_at_ingestion() -> RunEvidence {
    let root = repository_root();
    let mut wiring = Scripted::new(&root).expect("wiring");
    let mut evidence = wiring
        .run(scenarios::by_id("E8").expect("E8"))
        .expect("the scenario runs");
    evidence.contracts.gate_reports.clear();
    for run in &mut evidence.stage_runs {
        match run.kind.as_str() {
            "IMPLEMENTATION" => run.status = "BLOCKED".to_owned(),
            "VALIDATION" => {
                run.status = "PENDING".to_owned();
                run.attempts.clear();
            }
            _ => {}
        }
    }
    let attempted = evidence.facts["attempted_paths"].clone();
    evidence.facts.insert("refused_paths".to_owned(), attempted);
    evidence
}

#[test]
fn a_refusal_at_ingestion_passes_when_the_path_is_named_and_nothing_later_started() {
    let env = env();
    let check = scenario_checks::by_id("E8.scope-gate").expect("E8.scope-gate");
    let verdict = check.apply(&e8_at_ingestion(), &env);
    assert!(verdict.pass, "{verdict}");
    assert!(verdict.reason.contains("at the ingestion"), "{verdict}");
}

#[test]
fn a_refusal_at_ingestion_fails_when_it_is_weakened_in_any_way() {
    let env = env();
    let check = scenario_checks::by_id("E8.scope-gate").expect("E8.scope-gate");
    type Weaken = fn(&mut RunEvidence);
    let cases: [(&str, &str, Weaken); 5] = [
        (
            "the path is not named",
            "did not stop with a refusal",
            |ev| {
                ev.facts.remove("refused_paths");
            },
        ),
        (
            "the implementation run passed",
            "did not stop with a refusal",
            |ev| {
                for run in &mut ev.stage_runs {
                    if run.kind == "IMPLEMENTATION" {
                        run.status = "PASSED".to_owned();
                    }
                }
            },
        ),
        (
            "the denial is not audited",
            "protected-path decision",
            |ev| {
                ev.audit
                    .retain(|r| !r.action.starts_with("protected_path_decision"));
            },
        ),
        ("the branch changed the path", "the branch changes", |ev| {
            ev.github.changed_paths.push("CODEOWNERS".to_owned());
        }),
        ("the job completed", "completed although", |ev| {
            ev.job.status = "COMPLETED".to_owned();
        }),
    ];
    for (name, expect, weaken) in cases {
        let mut evidence = e8_at_ingestion();
        weaken(&mut evidence);
        let verdict = check.apply(&evidence, &env);
        assert!(!verdict.pass, "{name}: still passes: {verdict}");
        assert!(verdict.reason.contains(expect), "{name}: {verdict}");
    }
}

// ---- E6: a label from someone who may not ask makes no job -------------------------------------

#[test]
fn a_rejection_is_judged_by_its_audit_record_its_one_plain_reply_and_the_absence_of_a_job() {
    let env = env();
    let root = repository_root();
    let mut wiring = Scripted::new(&root).expect("wiring");
    let evidence = wiring
        .run(scenarios::by_id("E6").expect("E6"))
        .expect("the scenario runs");
    let check = scenario_checks::by_id("E6.rejected").expect("E6.rejected");
    assert!(
        check.apply(&evidence, &env).pass,
        "{}",
        check.apply(&evidence, &env)
    );
    assert_eq!(evidence.job.id, "none", "the shape has no job");

    // The old shape: the engine rejected a job. It leaves a job, and that is now a failure, because
    // the label of someone who may not ask must not make one.
    let mut with_a_job = evidence.clone();
    with_a_job.job.id = "a-job".to_owned();
    with_a_job.job.status = "REJECTED".to_owned();
    let verdict = check.apply(&with_a_job, &env);
    assert!(
        !verdict.pass && verdict.reason.contains("a job exists"),
        "{verdict}"
    );

    // With no record of the rejection, it fails, whatever else is right.
    let mut no_record = evidence.clone();
    no_record.audit.clear();
    let verdict = check.apply(&no_record, &env);
    assert!(
        !verdict.pass && verdict.reason.contains("0 intake.rejected records"),
        "{verdict}"
    );

    // An engine denial is not the record of the rejection: it has another action.
    let mut engine_denial_only = evidence.clone();
    engine_denial_only.audit[0].action = "authorization_decision.denied".to_owned();
    let verdict = check.apply(&engine_denial_only, &env);
    assert!(
        !verdict.pass && verdict.reason.contains("0 intake.rejected records"),
        "{verdict}"
    );

    // With no reply, it fails.
    let mut no_reply = evidence;
    no_reply.github.comments.clear();
    let verdict = check.apply(&no_reply, &env);
    assert!(
        !verdict.pass && verdict.reason.contains("0 comments"),
        "{verdict}"
    );
}

// ---- A3: documentation written with the code -------------------------------------------------

/// The head branch of real run 38: the plan's documentation tasks wrote the README and the
/// changelog in commits of their own before the code, and the documenting stage, finding them
/// covered, wrote nothing.
fn documentation_written_by_the_plan() -> RunEvidence {
    let mut evidence = honest(&env(), Options::e1_production());
    let documentation = evidence
        .github
        .head_commits
        .pop()
        .expect("the documentation commit");
    evidence.github.head_commits.insert(0, documentation);
    evidence.github.pull_requests[0].head_sha = evidence
        .github
        .head_commits
        .last()
        .map(|commit| commit.sha.clone())
        .expect("a tip");
    evidence
        .facts
        .insert("documentation_paths".to_owned(), serde_json::json!([]));
    evidence
}

#[test]
fn documentation_written_by_the_plan_before_the_code_passes_when_the_review_judged_it() {
    let env = env();
    let verdict = by_id("A3")
        .expect("A3")
        .apply(&documentation_written_by_the_plan(), &env);
    assert!(
        verdict.pass && verdict.reason.contains("written with the code"),
        "{verdict}"
    );
}

#[test]
fn documentation_before_the_code_fails_when_the_evidence_does_not_say_what_the_stage_wrote() {
    let env = env();
    let mut evidence = documentation_written_by_the_plan();
    evidence.facts.remove("documentation_paths");
    let verdict = by_id("A3").expect("A3").apply(&evidence, &env);
    assert!(
        !verdict.pass
            && verdict
                .reason
                .contains("no commit that changes only documentation"),
        "{verdict}"
    );
}

#[test]
fn documentation_before_the_code_fails_when_the_stage_says_it_wrote_a_page() {
    let env = env();
    let mut evidence = documentation_written_by_the_plan();
    evidence.facts.insert(
        "documentation_paths".to_owned(),
        serde_json::json!(["CHANGELOG.md"]),
    );
    let verdict = by_id("A3").expect("A3").apply(&evidence, &env);
    assert!(
        !verdict.pass && verdict.reason.contains("wrote CHANGELOG.md"),
        "{verdict}"
    );
}

// ---- A13: one stage run with several attempts -------------------------------------------------

/// The shape of the specification run of real run 38: several attempts in one run. The earlier
/// ones failed their gates and waited at the rework limit, a person answered, and the newest
/// passed. The canned run gives the build gate's run that shape.
fn specification_run_with_an_earlier_failed_attempt() -> (RunEvidence, String) {
    let mut evidence = honest(&env(), Options::e1_production());
    let mut failed = evidence
        .contracts
        .gate_reports
        .iter()
        .find(|record| {
            record.report["metadata"]["gate_id"].as_str() == Some("build-and-unit-tests")
        })
        .cloned()
        .expect("the build gate report");
    let run_id = failed.stage_run_id.clone();
    let run = evidence
        .stage_runs
        .iter_mut()
        .find(|run| run.id == run_id)
        .expect("the run of the build gate");
    let mut earlier = run.attempts.first().cloned().expect("an attempt");
    earlier.id = "earlier-attempt".to_owned();
    run.attempts.insert(0, earlier);
    failed.report["metadata"]["attempt_id"] = serde_json::json!("earlier-attempt");
    failed.report["outcome"] = serde_json::json!("FAILED");
    evidence.contracts.gate_reports.insert(0, failed);
    (evidence, run_id)
}

#[test]
fn a_failed_report_of_an_earlier_attempt_of_a_passed_run_does_not_block_delivery() {
    let env = env();
    let (evidence, _) = specification_run_with_an_earlier_failed_attempt();
    let verdict = by_id("A13").expect("A13").apply(&evidence, &env);
    assert!(verdict.pass, "{verdict}");
}

#[test]
fn a_failed_report_of_the_deciding_attempt_still_blocks_delivery() {
    let env = env();
    let (mut evidence, run_id) = specification_run_with_an_earlier_failed_attempt();
    let newest = evidence
        .stage_runs
        .iter()
        .find(|run| run.id == run_id)
        .and_then(|run| run.attempts.last())
        .map(|attempt| attempt.id.clone())
        .expect("the newest attempt");
    let record = evidence
        .contracts
        .gate_reports
        .iter_mut()
        .find(|record| {
            record.stage_run_id == run_id
                && record.report["metadata"]["attempt_id"].as_str() == Some(newest.as_str())
        })
        .expect("a report of the newest attempt");
    record.report["outcome"] = serde_json::json!("FAILED");
    let verdict = by_id("A13").expect("A13").apply(&evidence, &env);
    assert!(
        !verdict.pass
            && verdict
                .reason
                .contains("deciding attempt with outcome FAILED"),
        "{verdict}"
    );
}

#[test]
fn a_failed_report_that_names_no_attempt_is_judged_with_the_deciding_attempt() {
    let env = env();
    let (mut evidence, run_id) = specification_run_with_an_earlier_failed_attempt();
    let mut unplaced = evidence
        .contracts
        .gate_reports
        .iter()
        .find(|record| record.stage_run_id == run_id)
        .cloned()
        .expect("a report");
    if let Some(metadata) = unplaced.report["metadata"].as_object_mut() {
        metadata.remove("attempt_id");
    }
    unplaced.report["outcome"] = serde_json::json!("FAILED");
    evidence.contracts.gate_reports.push(unplaced);
    let verdict = by_id("A13").expect("A13").apply(&evidence, &env);
    assert!(!verdict.pass, "{verdict}");
}
