use factory_domain::contracts::review_verdict::DefectClass;
use factory_domain::contracts::{Contract, GateReport, ReviewVerdict, StageContract};
use factory_domain::vocabulary::{ExecutionMode, RecorderFidelity};
use serde_json::{Value, json};

use super::*;

const CONTRACT: &str =
    include_str!("../../../../../schemas/examples/stage-contract/valid/specification-stage.json");
const PASSED: &str =
    include_str!("../../../../../schemas/examples/gate-report/valid/build-and-test-passed.json");
const BLOCKED: &str = include_str!(
    "../../../../../schemas/examples/gate-report/valid/security-scan-blocked-tool-missing.json"
);
const VERDICT: &str = include_str!(
    "../../../../../schemas/examples/review-verdict/valid/changes-required-missing-test.json"
);

/// The gate that the example contract names.
const GATE: &str = "specification-quality-gate";

fn contract() -> StageContract {
    StageContract::from_json_str(CONTRACT).expect("the example is a valid contract")
}

fn report(example: &str, gate: &str) -> GateReport {
    let mut doc: Value = serde_json::from_str(example).expect("JSON");
    doc["metadata"]["gate_id"] = json!(gate);
    GateReport::from_json_value(doc).expect("a valid report")
}

fn failed_report(gate: &str, check: &str) -> GateReport {
    let mut doc: Value = serde_json::from_str(PASSED).expect("JSON");
    doc["metadata"]["gate_id"] = json!(gate);
    doc["outcome"] = json!("FAILED");
    doc["reason"] = json!("One check of the gate failed on the job commit.");
    doc["commands"][0]["exit_code"] = json!(1);
    doc["failures"] =
        json!([{ "check_id": check, "message": "The check found a problem in the change." }]);
    GateReport::from_json_value(doc).expect("a valid report")
}

fn verdict(kind: &str, defect: &str) -> ReviewVerdict {
    let mut doc: Value = serde_json::from_str(VERDICT).expect("JSON");
    doc["verdict"] = json!(kind);
    doc["findings"][0]["defect_class"] = json!(defect);
    match kind {
        "PASS" => {
            doc["findings"] = json!([]);
        }
        "BLOCK" => {
            doc["findings"][0]["severity"] = json!("blocker");
        }
        "NEEDS_HUMAN" => {
            doc["findings"] = json!([]);
            doc["human_question"] = json!("Is the unreadable file case in scope for this change?");
        }
        _ => {}
    }
    ReviewVerdict::from_json_value(doc).expect("a valid verdict")
}

fn decision(reports: Vec<GateReport>, review: Option<ReviewVerdict>) -> GateDecision {
    GateDecision {
        reports,
        review,
        human_gate: false,
        policy_violation: false,
        assurance: Vec::new(),
    }
}

#[test]
fn a_passing_report_and_a_passing_review_pass() {
    let d = decision(
        vec![report(PASSED, GATE)],
        Some(verdict("PASS", "code_behavior")),
    );
    assert_eq!(resolve(&contract(), &d), Resolution::Pass);
}

#[test]
fn a_gate_that_has_no_report_did_not_run_and_blocks() {
    // INV-06: missing execution is never converted to a pass.
    let d = decision(Vec::new(), Some(verdict("PASS", "code_behavior")));
    assert_eq!(
        resolve(&contract(), &d),
        Resolution::Blocked(BlockCause::MissingGate(
            factory_domain::values::Slug::parse(GATE).expect("a slug")
        ))
    );
}

#[test]
fn a_report_of_another_gate_does_not_stand_in_for_the_named_one() {
    let d = decision(
        vec![report(PASSED, "some-other-gate")],
        Some(verdict("PASS", "code_behavior")),
    );
    assert!(matches!(
        resolve(&contract(), &d),
        Resolution::Blocked(BlockCause::MissingGate(_))
    ));
}

#[test]
fn a_gate_that_could_not_run_blocks() {
    let d = decision(
        vec![report(BLOCKED, GATE)],
        Some(verdict("PASS", "code_behavior")),
    );
    assert!(matches!(
        resolve(&contract(), &d),
        Resolution::Blocked(BlockCause::GateBlocked(_))
    ));
}

#[test]
fn a_contract_that_needs_a_reviewer_blocks_without_a_verdict() {
    let d = decision(vec![report(PASSED, GATE)], None);
    assert_eq!(
        resolve(&contract(), &d),
        Resolution::Blocked(BlockCause::MissingReview)
    );
}

#[test]
fn a_reviewer_pass_cannot_outweigh_a_failed_gate() {
    // NT-INJ-06: the reviewer says PASS and the deterministic gate is FAILED.
    let d = decision(
        vec![failed_report(GATE, "tests-pass")],
        Some(verdict("PASS", "code_behavior")),
    );
    assert!(matches!(
        resolve(&contract(), &d),
        Resolution::Failed { .. }
    ));
}

#[test]
fn a_reviewer_pass_cannot_outweigh_a_blocked_gate() {
    let d = decision(
        vec![report(BLOCKED, GATE)],
        Some(verdict("PASS", "code_behavior")),
    );
    assert!(matches!(resolve(&contract(), &d), Resolution::Blocked(_)));
}

#[test]
fn changes_required_carries_the_defect_class_of_the_findings() {
    let d = decision(
        vec![report(PASSED, GATE)],
        Some(verdict("CHANGES_REQUIRED", "documentation")),
    );
    match resolve(&contract(), &d) {
        Resolution::ChangesRequired { defect, .. } => {
            assert_eq!(defect, Some(DefectClass::Documentation));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_block_verdict_blocks_and_a_needs_human_verdict_asks() {
    let blocked = decision(vec![report(PASSED, GATE)], Some(verdict("BLOCK", "policy")));
    assert_eq!(
        resolve(&contract(), &blocked),
        Resolution::Blocked(BlockCause::ReviewerBlocked)
    );
    let asks = decision(
        vec![report(PASSED, GATE)],
        Some(verdict("NEEDS_HUMAN", "specification")),
    );
    assert_eq!(resolve(&contract(), &asks), Resolution::ReviewerNeedsHuman);
}

#[test]
fn a_decision_with_no_evidence_never_passes() {
    // The nearest thing to "the agent says it passed" is a decision with nothing in it.
    let mut empty = contract();
    empty.evaluator.kind =
        factory_domain::contracts::stage_contract::EvaluatorKind::DeterministicGate;
    empty.evaluator.gate_ids = None;
    let d = GateDecision::default();
    assert_eq!(
        resolve(&empty, &d),
        Resolution::Blocked(BlockCause::MissingEvidence)
    );
}

#[test]
fn a_policy_violation_blocks_before_anything_else_is_read() {
    let mut d = decision(
        vec![report(PASSED, GATE)],
        Some(verdict("PASS", "code_behavior")),
    );
    d.policy_violation = true;
    assert_eq!(
        resolve(&contract(), &d),
        Resolution::Blocked(BlockCause::PolicyViolation)
    );
}

#[test]
fn a_human_gate_asks_a_person_after_the_evidence_is_in() {
    let mut d = decision(
        vec![report(PASSED, GATE)],
        Some(verdict("PASS", "code_behavior")),
    );
    d.human_gate = true;
    assert_eq!(resolve(&contract(), &d), Resolution::HumanGate);
}

/// A failed report whose failures are the given `(check, message, line)` triples.
fn failed_with(gate: &str, failures: &[(&str, &str, Option<u32>)]) -> GateReport {
    let mut doc: Value = serde_json::from_str(PASSED).expect("JSON");
    doc["metadata"]["gate_id"] = json!(gate);
    doc["outcome"] = json!("FAILED");
    doc["reason"] = json!("One check of the gate failed on the job commit.");
    doc["commands"][0]["exit_code"] = json!(1);
    doc["failures"] = failures
        .iter()
        .map(|(check, message, line)| {
            let mut failure = json!({ "check_id": check, "message": message });
            if let Some(line) = line {
                failure["location"] = json!({ "path": "specs/feature/spec.md", "line": line });
            }
            failure
        })
        .collect();
    GateReport::from_json_value(doc).expect("a valid report")
}

#[test]
fn the_same_failures_give_the_same_digest_in_any_order() {
    let a = decision(vec![failed_report("gate-one", "check-b")], None);
    let b = decision(vec![failed_report("gate-one", "check-b")], None);
    assert_eq!(failing_set(&a), failing_set(&b));
    let c = decision(vec![failed_report("gate-one", "check-c")], None);
    assert_ne!(failing_set(&a), failing_set(&c));

    let first = "The JSON layout is only an assumption.";
    let second = "Standard error is not covered.";
    let one_way = decision(
        vec![failed_with(
            "gate-one",
            &[
                ("review-finding", first, None),
                ("review-finding", second, None),
            ],
        )],
        None,
    );
    let other_way = decision(
        vec![failed_with(
            "gate-one",
            &[
                ("review-finding", second, None),
                ("review-finding", first, None),
            ],
        )],
        None,
    );
    assert_eq!(failing_set(&one_way), failing_set(&other_way));
}

#[test]
fn one_rule_that_fails_on_another_thing_is_another_failure() {
    // Every finding of the specification reviewer has the rule `review-finding`. A round that
    // resolved one finding and met a new one made progress, so its failing set must differ.
    let round_one = decision(
        vec![failed_with(
            "specification-review",
            &[(
                "review-finding",
                "The JSON layout is only an assumption.",
                None,
            )],
        )],
        None,
    );
    let round_two = decision(
        vec![failed_with(
            "specification-review",
            &[("review-finding", "Standard error is not covered.", None)],
        )],
        None,
    );
    assert_ne!(failing_set(&round_one), failing_set(&round_two));

    // Fewer failures of the same rule is progress too.
    let two = decision(
        vec![failed_with(
            "specification-checklist",
            &[
                (
                    "checklist-item-unresolved",
                    "The question Q-001 is open.",
                    None,
                ),
                (
                    "checklist-item-unresolved",
                    "The question Q-002 is open.",
                    None,
                ),
            ],
        )],
        None,
    );
    let one = decision(
        vec![failed_with(
            "specification-checklist",
            &[(
                "checklist-item-unresolved",
                "The question Q-001 is open.",
                None,
            )],
        )],
        None,
    );
    assert_ne!(failing_set(&two), failing_set(&one));
}

#[test]
fn the_place_of_a_failure_is_part_of_what_failed() {
    let message = "The line is longer than the limit.";
    let at_three = decision(
        vec![failed_with(
            "gate-one",
            &[("line-too-long", message, Some(3))],
        )],
        None,
    );
    let at_nine = decision(
        vec![failed_with(
            "gate-one",
            &[("line-too-long", message, Some(9))],
        )],
        None,
    );
    let nowhere = decision(
        vec![failed_with("gate-one", &[("line-too-long", message, None)])],
        None,
    );
    assert_ne!(failing_set(&at_three), failing_set(&at_nine));
    assert_ne!(failing_set(&at_three), failing_set(&nowhere));
    assert_eq!(
        failing_set(&at_three),
        failing_set(&decision(
            vec![failed_with(
                "gate-one",
                &[("line-too-long", message, Some(3))]
            )],
            None,
        ))
    );
}

#[test]
fn a_line_break_in_a_message_cannot_merge_or_split_failures() {
    // The items of the set are joined by line breaks. A message is hashed before it is joined, so
    // one failure whose message holds a line break is never read as two failures.
    let joined = decision(
        vec![failed_with(
            "gate-one",
            &[(
                "check-a",
                "The first check failed.\ngate-one:check-a:The second check failed.",
                None,
            )],
        )],
        None,
    );
    let apart = decision(
        vec![failed_with(
            "gate-one",
            &[
                ("check-a", "The first check failed.", None),
                ("check-a", "The second check failed.", None),
            ],
        )],
        None,
    );
    assert_ne!(failing_set(&joined), failing_set(&apart));
}

#[test]
fn a_criterion_is_covered_only_by_evidence_of_its_own_verifier() {
    let contract = contract();
    // Three criteria: a schema check, the named gate, and the independent review.
    let full = decision(
        vec![report(PASSED, GATE)],
        Some(verdict("PASS", "code_behavior")),
    );
    assert_eq!(uncovered_criteria(&contract, &full), 0);
    let no_review = decision(vec![report(PASSED, GATE)], None);
    assert_eq!(uncovered_criteria(&contract, &no_review), 1);
    let nothing = GateDecision::default();
    assert_eq!(uncovered_criteria(&contract, &nothing), 2);
}

// ---- the evidence check -----------------------------------------------------------------------

fn expectation(report: &GateReport) -> Expectation {
    Expectation {
        job: report.metadata.job_id,
        stage_run: report.metadata.stage_run_id,
        attempt: report
            .metadata
            .attempt_id
            .expect("the example names the attempt"),
        mode: ExecutionMode::Production,
    }
}

#[test]
fn evidence_about_this_stage_run_is_accepted() {
    let r = report(PASSED, GATE);
    let expect = expectation(&r);
    assert_eq!(check_evidence(&decision(vec![r], None), &expect), Ok(()));
}

#[test]
fn evidence_about_another_stage_run_is_refused() {
    let r = report(PASSED, GATE);
    let mut expect = expectation(&r);
    expect.stage_run = factory_domain::ids::StageRunId::from_uuid(uuid::Uuid::from_u128(7));
    assert_eq!(
        check_evidence(&decision(vec![r], None), &expect),
        Err(EvidenceProblem::WrongSubject)
    );
}

#[test]
fn evidence_from_another_attempt_is_refused() {
    let r = report(PASSED, GATE);
    let mut expect = expectation(&r);
    expect.attempt = factory_domain::ids::AttemptId::from_uuid(uuid::Uuid::from_u128(9));
    assert_eq!(
        check_evidence(&decision(vec![r], None), &expect),
        Err(EvidenceProblem::WrongAttempt)
    );
}

#[test]
fn evidence_made_in_test_mode_is_refused_for_a_production_job() {
    let mut r = report(PASSED, GATE);
    // The example is a production report. The job is a test job, so the modes differ.
    let mut expect = expectation(&r);
    expect.mode = ExecutionMode::Test;
    assert_eq!(
        check_evidence(&decision(vec![r.clone()], None), &expect),
        Err(EvidenceProblem::WrongMode)
    );
    // And a report that says fake, built by hand for a production job, breaks its own schema.
    r.environment.fidelity = factory_domain::vocabulary::Fidelity::Fake;
    let expect = expectation(&r);
    assert!(check_evidence(&decision(vec![r], None), &expect).is_err());
}

#[test]
fn two_reports_for_one_gate_are_refused() {
    let r = report(PASSED, GATE);
    let expect = expectation(&r);
    assert_eq!(
        check_evidence(&decision(vec![r.clone(), r], None), &expect),
        Err(EvidenceProblem::DuplicateGate)
    );
}

// ---- assurance claims -----------------------------------------------------------------------

fn claiming(report: GateReport, level: &str) -> GateDecision {
    let gate = report.metadata.gate_id.clone();
    GateDecision {
        reports: vec![report],
        assurance: vec![AssuranceClaim {
            level: factory_domain::vocabulary::AssuranceLevel::parse(level)
                .expect("an assurance level"),
            gate,
        }],
        ..GateDecision::default()
    }
}

#[test]
fn a_claim_on_a_real_current_passing_report_is_written_by_a_real_recorder() {
    let r = report(PASSED, GATE);
    let expect = expectation(&r);
    let d = claiming(r, "VERIFIED_IN_SANDBOX");
    let entries = assurance_entries(&d, &expect, RecorderFidelity::Real);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].report_index, 0);
}

#[test]
fn no_claim_is_written_by_a_recorder_that_is_not_real() {
    // INV-08: a fake or simulated recorder never supports an assurance level.
    let r = report(PASSED, GATE);
    let expect = expectation(&r);
    let d = claiming(r, "VERIFIED_IN_SANDBOX");
    for recorder in [RecorderFidelity::Fake, RecorderFidelity::Simulated] {
        assert!(assurance_entries(&d, &expect, recorder).is_empty());
    }
}

#[test]
fn a_claim_on_a_report_of_a_fake_environment_is_dropped() {
    let mut doc: Value = serde_json::from_str(PASSED).expect("JSON");
    doc["metadata"]["gate_id"] = json!(GATE);
    // A fake environment is allowed in a test job and refused in a production one.
    doc["metadata"]["execution_mode"] = json!("test");
    doc["environment"]["fidelity"] = json!("fake");
    let r = GateReport::from_json_value(doc).expect("a valid report");
    let mut expect = expectation(&r);
    expect.mode = ExecutionMode::Test;
    let d = claiming(r, "VERIFIED_IN_SANDBOX");
    assert!(assurance_entries(&d, &expect, RecorderFidelity::Real).is_empty());
}

#[test]
fn a_claim_on_a_failed_or_blocked_report_is_dropped() {
    let failed = failed_report(GATE, "check-1");
    let expect = expectation(&failed);
    assert!(
        assurance_entries(
            &claiming(failed, "VERIFIED_IN_SANDBOX"),
            &expect,
            RecorderFidelity::Real
        )
        .is_empty()
    );
    // The blocked example names no attempt, so give it the failed report's, so that only its
    // outcome is what makes the claim fail.
    let mut doc: Value = serde_json::from_str(BLOCKED).expect("JSON");
    doc["metadata"]["gate_id"] = json!(GATE);
    doc["metadata"]["attempt_id"] = json!(expect.attempt.to_string());
    let blocked = GateReport::from_json_value(doc).expect("a valid report");
    assert!(
        assurance_entries(
            &claiming(blocked, "VERIFIED_IN_SANDBOX"),
            &expect,
            RecorderFidelity::Real
        )
        .is_empty()
    );
}

#[test]
fn a_claim_on_a_report_of_another_attempt_is_not_current() {
    let r = report(PASSED, GATE);
    let mut expect = expectation(&r);
    expect.attempt = factory_domain::ids::AttemptId::from_uuid(uuid::Uuid::from_u128(9));
    assert!(
        assurance_entries(
            &claiming(r, "VERIFIED_IN_SANDBOX"),
            &expect,
            RecorderFidelity::Real
        )
        .is_empty()
    );
}

#[test]
fn a_claim_on_a_report_with_no_attempt_is_not_current() {
    let mut doc: Value = serde_json::from_str(PASSED).expect("JSON");
    doc["metadata"]["gate_id"] = json!(GATE);
    doc["metadata"]
        .as_object_mut()
        .expect("metadata")
        .remove("attempt_id");
    let r = GateReport::from_json_value(doc).expect("a valid report");
    let expect = Expectation {
        job: r.metadata.job_id,
        stage_run: r.metadata.stage_run_id,
        attempt: factory_domain::ids::AttemptId::from_uuid(uuid::Uuid::from_u128(9)),
        mode: ExecutionMode::Production,
    };
    assert!(
        assurance_entries(
            &claiming(r, "VERIFIED_IN_SANDBOX"),
            &expect,
            RecorderFidelity::Real
        )
        .is_empty()
    );
}

#[test]
fn a_claim_that_names_a_gate_without_a_report_is_dropped() {
    let r = report(PASSED, GATE);
    let expect = expectation(&r);
    let mut d = claiming(r, "VERIFIED_IN_SANDBOX");
    d.assurance[0].gate = factory_domain::values::Slug::parse("some-other-gate").expect("a slug");
    assert!(assurance_entries(&d, &expect, RecorderFidelity::Real).is_empty());
}

#[test]
fn a_report_edited_into_a_pass_without_proof_is_refused() {
    let mut r = report(PASSED, GATE);
    // A handler flips a failing command into a pass after the fact.
    r.commands[0].exit_code = Some(2);
    let expect = expectation(&r);
    assert_eq!(
        check_evidence(&decision(vec![r], None), &expect),
        Err(EvidenceProblem::InvalidDocument)
    );
}
