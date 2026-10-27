use factory_domain::contracts::review_verdict::DefectClass;
use factory_domain::contracts::{Contract, GateReport, ReviewVerdict, StageContract};
use factory_domain::vocabulary::ExecutionMode;
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

#[test]
fn the_same_failures_give_the_same_digest_in_any_order() {
    let a = decision(vec![failed_report("gate-one", "check-b")], None);
    let b = decision(vec![failed_report("gate-one", "check-b")], None);
    assert_eq!(failing_set(&a), failing_set(&b));
    let c = decision(vec![failed_report("gate-one", "check-c")], None);
    assert_ne!(failing_set(&a), failing_set(&c));
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
