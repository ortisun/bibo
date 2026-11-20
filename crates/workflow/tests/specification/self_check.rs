//! The self-check pass: the faults the factory's own deterministic checks name are fixed inside
//! the attempt that wrote the draft, once, before the independent review.
//!
//! The defect this guards against, seen in the twenty-sixth real run: a draft whose requirements
//! FR-010 to FR-014 no scenario cited, and then a requirement without MUST, each used a rework
//! round, and the job died at the rework limit after one reviewer finding.

use factory_domain::contracts::{Contract, SpecificationContract};
use factory_domain::state::StageRunStatus;
use factory_domain::values::Slug;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_ports::spec::{PostCondition, SpecError, SpecOperation};
use factory_workflow::engine::AttemptOutcome;
use serde_json::{Value, json};

use crate::rig::{
    NO_KEYWORD, QUALITY_MD, REQUIREMENTS_MD, Rig, SPEC_TEXT, lock, pass, person_record, write,
};
use crate::stage::{answer, status};

const FEEDBACK: &str = "inputs/review-feedback.md";

fn written_to(rig: &Rig, file: &str) -> Vec<String> {
    lock(&rig.written)
        .iter()
        .filter(|(path, _)| path == file)
        .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
        .collect()
}

fn unlinked(requirement: &str) -> SpecError {
    SpecError::PostConditionFailed(vec![PostCondition {
        name: Slug::parse("requirement-without-scenario").expect("a slug"),
        detail: format!("{requirement} has no acceptance scenario that cites it."),
    }])
}

fn operations(rig: &Rig) -> Vec<SpecOperation> {
    lock(&rig.provider.requests).iter().map(|r| r.op).collect()
}

async fn kept_evidence(rig: &Rig) -> Value {
    let run = rig.run_of(StageKind::Specification).await;
    let kept = rig
        .drafts
        .kept(run)
        .expect("the draft is kept for the person");
    serde_json::from_slice(&kept.evidence).expect("the evidence")
}

/// A person approves the draft that waits, and the next attempt freezes it.
async fn approve(rig: &Rig) -> SpecificationContract {
    let person = rig.world.person("approver-s", &[HumanRole::Approver]).await;
    rig.approvals.grant(person_record(person));
    answer(rig, "I approve this specification.").await;
    assert_eq!(rig.run_next().await.1, AttemptOutcome::Succeeded);
    assert_eq!(status(rig).await, StageRunStatus::Passed);
    let frozen = rig
        .deliverable(StageKind::Specification, "specification-contract")
        .await
        .expect("the frozen contract");
    SpecificationContract::from_json_value(frozen).expect("it validates")
}

#[tokio::test]
async fn a_requirement_no_scenario_cites_is_fixed_in_the_same_attempt_without_a_rework() {
    let rig = Rig::new().await;
    rig.run_until_specification().await;
    let dir = rig.feature();
    // The specify skill leaves a draft whose FR-010 no scenario cites: the assembly fails.
    rig.writer_writes(vec![
        write(&format!("{dir}/spec.md"), "# Draft with FR-010 unlinked\n"),
        write(
            &format!("{dir}/checklists/requirements.md"),
            REQUIREMENTS_MD,
        ),
    ]);
    lock(&rig.provider.assembly_errors).push_back(unlinked("FR-010"));
    // The self-check pass fixes it, the checklist runs on the fixed draft, the reviewer passes.
    rig.writer_writes(vec![write(&format!("{dir}/spec.md"), SPEC_TEXT)]);
    rig.writer_writes(vec![write(
        &format!("{dir}/checklists/requirements-quality.md"),
        QUALITY_MD,
    )]);
    rig.reviewer_answers(pass());

    // One attempt reaches the person who approves.
    assert_eq!(rig.run_next().await.1, AttemptOutcome::NeedsHuman);
    assert_eq!(status(&rig).await, StageRunStatus::WaitingForHuman);
    assert_eq!(
        operations(&rig),
        [
            SpecOperation::Specify,
            SpecOperation::Clarify,
            SpecOperation::Checklist
        ]
    );
    let clarify = rig.provider.requests_of(SpecOperation::Clarify);
    let check = clarify[0]
        .self_check
        .as_ref()
        .expect("a self-check request");
    assert_eq!(check.findings_file.as_str(), FEEDBACK);
    assert!(clarify[0].rework.is_none() && clarify[0].resume.is_none());
    // Only that pass reads the list, and the list names the fault and says what it is.
    let lists = written_to(&rig, FEEDBACK);
    assert_eq!(lists.len(), 1);
    assert!(
        lists[0].starts_with("Self-check before review."),
        "{}",
        lists[0]
    );
    assert!(
        lists[0].contains(
            "- requirement-without-scenario: FR-010 has no acceptance scenario that cites it."
        ),
        "{}",
        lists[0]
    );
    assert!(
        lists[0].contains("this is not a rework round"),
        "{}",
        lists[0]
    );
    assert!(lists[0].contains("previous release"), "{}", lists[0]);
    assert_eq!(rig.runtime.runs("specification-reviewer"), 1);

    // The evidence records the pass, and the failure of the first assembly is gone.
    let evidence = kept_evidence(&rig).await;
    assert_eq!(
        evidence["operations"],
        json!(["specify", "self-check", "checklist"])
    );
    assert_eq!(
        evidence["self_check"],
        json!([[
            "requirement-without-scenario",
            "FR-010 has no acceptance scenario that cites it."
        ]])
    );
    assert_eq!(evidence["post_conditions"], json!([]));
    assert_eq!(evidence["parse_failure"], Value::Null);

    // The person approves, and no rework round was ever used.
    approve(&rig).await;
    let runs = rig
        .world
        .view(rig.job)
        .await
        .runs_of(StageKind::Specification)
        .count();
    assert_eq!(runs, 1, "no rework run was made");
    assert_eq!(rig.provider.requests_of(SpecOperation::Clarify).len(), 1);
}

#[tokio::test]
async fn a_requirement_without_must_is_fixed_in_the_same_attempt_without_a_rework() {
    let rig = Rig::new().await;
    rig.run_until_specification().await;
    let dir = rig.feature();
    rig.writer_writes(vec![
        write(
            &format!("{dir}/spec.md"),
            &format!("{SPEC_TEXT}{NO_KEYWORD}\n"),
        ),
        write(
            &format!("{dir}/checklists/requirements.md"),
            REQUIREMENTS_MD,
        ),
    ]);
    rig.writer_writes(vec![write(
        &format!("{dir}/checklists/requirements-quality.md"),
        QUALITY_MD,
    )]);
    // The pass writes the keyword back.
    rig.writer_writes(vec![write(&format!("{dir}/spec.md"), SPEC_TEXT)]);
    rig.reviewer_answers(pass());

    assert_eq!(rig.run_next().await.1, AttemptOutcome::NeedsHuman);
    // The contract is checked after the last skill, so the pass comes after the checklist.
    assert_eq!(
        operations(&rig),
        [
            SpecOperation::Specify,
            SpecOperation::Checklist,
            SpecOperation::Clarify
        ]
    );
    let lists = written_to(&rig, FEEDBACK);
    assert_eq!(lists.len(), 1);
    assert!(
        lists[0].contains("- requirement-keyword-missing: FR-001 does not say MUST"),
        "{}",
        lists[0]
    );
    let evidence = kept_evidence(&rig).await;
    assert_eq!(
        evidence["operations"],
        json!(["specify", "checklist", "self-check"])
    );
    assert_eq!(
        evidence["self_check"][0][0],
        json!("requirement-keyword-missing")
    );

    let frozen = approve(&rig).await;
    assert!(
        frozen.requirements.as_slice()[0]
            .statement
            .as_str()
            .contains("MUST"),
        "the frozen draft is the fixed one"
    );
}

#[tokio::test]
async fn faults_left_after_the_one_pass_end_the_attempt_as_before() {
    let rig = Rig::new().await;
    rig.run_until_specification().await;
    let dir = rig.feature();
    rig.writer_writes(vec![
        write(&format!("{dir}/spec.md"), "# Draft with FR-010 unlinked\n"),
        write(
            &format!("{dir}/checklists/requirements.md"),
            REQUIREMENTS_MD,
        ),
    ]);
    // The pass does not fix it.
    rig.writer_writes(vec![write(
        &format!("{dir}/spec.md"),
        "# Draft with FR-011 unlinked\n",
    )]);
    {
        let mut errors = lock(&rig.provider.assembly_errors);
        errors.push_back(unlinked("FR-010"));
        errors.push_back(unlinked("FR-011"));
    }

    let (_, outcome) = rig.run_next().await;
    assert_ne!(outcome, AttemptOutcome::NeedsHuman);
    // One pass, and nothing after it: no second pass, no checklist, no reviewer.
    assert_eq!(
        operations(&rig),
        [SpecOperation::Specify, SpecOperation::Clarify]
    );
    assert_eq!(written_to(&rig, FEEDBACK).len(), 1);
    assert_eq!(rig.runtime.runs("specification-reviewer"), 0);
    assert!(lock(&rig.provider.assembly_errors).is_empty());

    // The gate reports what the draft after the pass still holds.
    let traceability = rig.reports_of("specification-traceability").await;
    let last = traceability.last().expect("a traceability report");
    assert_eq!(last["outcome"], json!("FAILED"), "{last}");
    assert!(last.to_string().contains("FR-011"), "{last}");
    assert!(!last.to_string().contains("FR-010"), "{last}");
    let evidence = rig
        .deliverable(StageKind::Specification, "specification-evidence")
        .await
        .expect("the evidence");
    assert_eq!(evidence["operations"], json!(["specify", "self-check"]));
    assert_eq!(
        evidence["self_check"][0][1]
            .as_str()
            .map(|m| m.contains("FR-010")),
        Some(true)
    );
    assert_eq!(
        evidence["post_conditions"][0]["name"],
        json!("requirement-without-scenario")
    );
}

#[tokio::test]
async fn a_clean_draft_runs_no_self_check() {
    let rig = Rig::new().await;
    rig.run_until_specification().await;
    rig.a_sound_specification();
    assert_eq!(rig.run_next().await.1, AttemptOutcome::NeedsHuman);
    assert_eq!(
        operations(&rig),
        [SpecOperation::Specify, SpecOperation::Checklist]
    );
    assert!(
        lock(&rig.provider.requests)
            .iter()
            .all(|request| request.self_check.is_none())
    );
    assert!(written_to(&rig, FEEDBACK).is_empty());
    let evidence = kept_evidence(&rig).await;
    assert_eq!(evidence["self_check"], json!([]));
    assert_eq!(evidence["operations"], json!(["specify", "checklist"]));
}
