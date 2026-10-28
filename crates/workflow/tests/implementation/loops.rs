//! Whole loops through the engine: build, validate, review, send back, build again.
//!
//! The engine decides where the work goes, how many rounds it may take and when the same findings
//! have come back. What these tests prove is that the two stages give the engine what it needs to
//! decide that way: the failing checks and the finding identifiers it compares, the defect class it
//! routes by, and a feedback that holds the reports and the deduplicated findings and nothing else.

use factory_domain::contracts::{Contract, GateReport};
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::paths::CommitSha;
use factory_workflow::engine::AttemptOutcome;
use factory_workflow::stages::implementation::ReworkContext;
use serde_json::Value;

use crate::review::{changes, finding, pass};
use crate::rig::{OUTPUT, Rig, done, lock, write};
use crate::standin::ValidationMode;

impl Rig {
    /// What the composition root reads from the store for the rework run that is about to start:
    /// the head commit of the run that was replaced, the failed reports of the stage that sent
    /// the work back, and the findings of the reviewer when the reviewer did.
    pub async fn queue_feedback(&self, failed: StageKind, round: u8) {
        let implementation = self.runs_of(StageKind::Implementation).await;
        let previous = implementation[implementation.len() - 2].0;
        let evidence = self
            .deliverable_in(previous, "implementation-evidence")
            .await
            .expect("the replaced run left its evidence");
        let previous_head = CommitSha::parse(evidence["head_commit"].as_str().expect("a commit"))
            .expect("a commit");
        let sent_back = self.runs_of(failed).await;
        let (run, _) = sent_back[sent_back.len() - 2];
        let failed_reports: Vec<GateReport> = self
            .gate_reports()
            .await
            .into_iter()
            .filter(|report| {
                report["outcome"] == "FAILED"
                    && report["metadata"]["stage_run_id"] == run.to_string()
            })
            .map(|report| GateReport::from_json_value(report).expect("a report"))
            .collect();
        let findings = if failed == StageKind::Review {
            self.verdict().await.map(|v| v.findings).unwrap_or_default()
        } else {
            Vec::new()
        };
        self.rework.queue(Some(ReworkContext {
            previous_head,
            failed_reports,
            findings,
            round,
        }));
    }

    /// The rework run: one builder task on top of the previous head.
    pub async fn rework_round(&self, failed: StageKind, round: u8) {
        self.queue_feedback(failed, round).await;
        self.builder_will(
            vec![write(
                "src/output.rs",
                &format!("{OUTPUT}// fixed in round {round}\n"),
            )],
            done(&format!("rework-round-{round}"), &["src/output.rs"]),
        );
        let (claimed, outcome) = self.run_next().await;
        assert_eq!(claimed.kind, StageKind::Implementation);
        assert_eq!(outcome, AttemptOutcome::Succeeded, "round {round}");
    }
}

fn block<'a>(prompt: &'a str, name: &str) -> &'a str {
    let start = prompt
        .find(&format!("<<<DATA name={name} "))
        .unwrap_or_else(|| panic!("no block {name}"));
    let end = prompt[start..]
        .find(&format!("<<<END name={name}>>>"))
        .expect("the block ends");
    &prompt[start..start + end]
}

/// A failed deterministic gate sends the work back to implementation with the reports, up to the
/// cap of two rounds, then to a human.
#[tokio::test]
async fn rework_is_capped_at_two() {
    let rig = Rig::build(crate::rig::Options {
        validation: ValidationMode::UnitTestsFail,
        ..crate::rig::Options::through_review()
    })
    .await;
    rig.run_until_implementation().await;
    rig.builder_does_the_plan();
    assert_eq!(rig.run_next().await.1, AttemptOutcome::Succeeded);
    // The first validation fails its test gate, and the work goes back.
    let (claimed, _) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Validation);
    assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 2);

    // Round one. The builder gets the failing report and nothing else.
    rig.rework_round(StageKind::Validation, 1).await;
    let prompts = rig.runtime.prompts("builder");
    let feedback = block(
        &prompts.last().expect("a prompt").instructions,
        "gate_reports",
    );
    assert!(feedback.contains("Rework round 1."), "{feedback}");
    assert!(feedback.contains("unit-tests"), "{feedback}");
    assert!(feedback.contains("unit-test-failed-1"), "{feedback}");
    assert!(feedback.contains("counts_a_line_1 failed"), "{feedback}");
    assert!(
        !feedback.contains("Everything the task asked for is done"),
        "the previous builder's summary is not feedback"
    );
    let (claimed, _) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Validation);
    assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 3);

    // Round two.
    rig.rework_round(StageKind::Validation, 2).await;
    let (claimed, _) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Validation);

    // The third failure meets the cap: a person decides, and no third round starts.
    let view = rig.world.view(rig.job).await;
    assert_eq!(view.code_rework_rounds, 2);
    assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 3);
    assert_eq!(
        view.newest(StageKind::Validation).expect("a run").status,
        StageRunStatus::WaitingForHuman
    );
    assert_eq!(rig.runs_of(StageKind::Validation).await.len(), 3);
    // Each rework run is one task, on top of the commit the round before it ended with.
    let second = rig.runs_of(StageKind::Implementation).await[1].0;
    let third = rig.runs_of(StageKind::Implementation).await[2].0;
    let first_evidence = rig
        .deliverable_in(
            rig.runs_of(StageKind::Implementation).await[0].0,
            "implementation-evidence",
        )
        .await
        .expect("evidence");
    let second_evidence = rig
        .deliverable_in(second, "implementation-evidence")
        .await
        .expect("evidence");
    let third_evidence = rig
        .deliverable_in(third, "implementation-evidence")
        .await
        .expect("evidence");
    assert_eq!(second_evidence["tasks"][0]["key"], "rework-round-1");
    assert_eq!(
        second_evidence["tasks"][0]["built_on"], first_evidence["head_commit"],
        "the rework builds on the commit the replaced run ended with"
    );
    assert_eq!(
        third_evidence["tasks"][0]["built_on"],
        second_evidence["head_commit"]
    );
    // The base of the job does not move: the result always names the protected branch tip.
    assert_eq!(third_evidence["base_commit"], rig.base.as_str());
}

/// The whole loop: build, validate, review asks for changes, rework with the deduplicated findings
/// as the only feedback, validate, review passes.
#[tokio::test]
async fn a_review_that_asks_for_changes_loops_once_and_then_passes() {
    let rig = Rig::through_review().await;
    rig.run_to_review().await;
    rig.reviewer_returns(changes(vec![
        finding(
            "Empty file is not handled",
            "high",
            "src/output.rs",
            5,
            "code_behavior",
        ),
        finding(
            "Empty file is not handled",
            "medium",
            "src/output.rs",
            9,
            "code_behavior",
        ),
        finding(
            "A magic number in the formatter",
            "low",
            "src/output.rs",
            6,
            "code_behavior",
        ),
    ]));
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Review);
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(
        rig.runs_of(StageKind::Implementation).await.len(),
        2,
        "sent back once"
    );

    rig.rework_round(StageKind::Review, 1).await;
    // The feedback is the findings, once each, and no words of the reviewer's own summary.
    let prompts = rig.runtime.prompts("builder");
    let feedback = block(
        &prompts.last().expect("a prompt").instructions,
        "gate_reports",
    );
    assert_eq!(
        feedback.matches("Empty file is not handled").count(),
        1,
        "{feedback}"
    );
    assert!(
        feedback.contains("A magic number in the formatter"),
        "{feedback}"
    );
    assert!(
        feedback.contains("src/output.rs:5"),
        "the most serious report is kept: {feedback}"
    );
    assert!(
        !feedback.contains("One problem must be fixed before the work can move on"),
        "the reviewer's summary is not feedback: {feedback}"
    );

    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Validation);
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    rig.reviewer_returns(pass());
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Review);
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let view = rig.world.view(rig.job).await;
    assert_eq!(
        view.newest(StageKind::Review).expect("a run").status,
        StageRunStatus::Passed
    );
    assert_eq!(view.code_rework_rounds, 1);
    // The second review judged the second diff: it holds the rework's line.
    let prompts = rig.runtime.prompts("code-reviewer");
    assert_eq!(prompts.len(), 2);
    assert!(prompts[1].instructions.contains("fixed in round 1"));
    assert!(!prompts[0].instructions.contains("fixed in round 1"));
    let _ = (lock(&rig.specs.seen).len(), Value::Null);
}

/// NT-BUD-04: a code reviewer that always returns CHANGES_REQUIRED, with a different finding each
/// time, gets two rounds of rework and then a person decides. There is no third round.
#[tokio::test]
async fn negative_nt_bud_04_a_reviewer_that_always_asks_for_changes_is_capped_at_two() {
    let rig = Rig::through_review().await;
    rig.run_to_review().await;
    for round in 1..=2_u8 {
        rig.reviewer_returns(changes(vec![finding(
            &format!(
                "Problem number {} in the formatter",
                ["one", "two", "three"][usize::from(round) - 1]
            ),
            "high",
            "src/output.rs",
            5,
            "code_behavior",
        )]));
        let (claimed, _) = rig.run_next().await;
        assert_eq!(claimed.kind, StageKind::Review);
        rig.rework_round(StageKind::Review, round).await;
        let (claimed, _) = rig.run_next().await;
        assert_eq!(claimed.kind, StageKind::Validation);
    }
    rig.reviewer_returns(changes(vec![finding(
        "Problem number three in the formatter",
        "high",
        "src/output.rs",
        5,
        "code_behavior",
    )]));
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Review);
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let view = rig.world.view(rig.job).await;
    assert_eq!(view.code_rework_rounds, 2);
    assert_eq!(
        rig.runs_of(StageKind::Implementation).await.len(),
        3,
        "no third round"
    );
    assert_eq!(
        view.newest(StageKind::Review).expect("a run").status,
        StageRunStatus::WaitingForHuman
    );
}

/// The same findings twice in a row are stagnation: a person is asked after the first round, not
/// after the cap. The reviewer names the finding differently and cites another line each time, and
/// the stage still sees one problem, because the identifier comes from the file, the category and
/// the title.
#[tokio::test]
async fn the_same_findings_twice_escalate_before_the_cap() {
    let rig = Rig::through_review().await;
    rig.run_to_review().await;
    rig.reviewer_returns(changes(vec![finding(
        "Empty file is not handled",
        "high",
        "src/output.rs",
        5,
        "code_behavior",
    )]));
    assert_eq!(rig.run_next().await.0.kind, StageKind::Review);
    rig.rework_round(StageKind::Review, 1).await;
    assert_eq!(rig.run_next().await.0.kind, StageKind::Validation);
    let mut again = finding(
        "Empty file is not handled.",
        "high",
        "src/output.rs",
        8,
        "code_behavior",
    );
    again["finding_id"] = serde_json::json!("another-name-for-it");
    rig.reviewer_returns(changes(vec![again]));
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Review);
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let view = rig.world.view(rig.job).await;
    assert_eq!(view.code_rework_rounds, 1, "the cap was not the reason");
    assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 2);
    assert_eq!(
        view.newest(StageKind::Review).expect("a run").status,
        StageRunStatus::WaitingForHuman
    );
}

/// A finding that only a person can decide (the specification or a policy) is never sent back to
/// the builder, whatever the round.
#[tokio::test]
async fn a_finding_about_the_specification_asks_a_person_and_uses_no_round() {
    let rig = Rig::through_review().await;
    rig.run_to_review().await;
    rig.reviewer_returns(changes(vec![finding(
        "Two requirements contradict each other",
        "high",
        "src/output.rs",
        5,
        "specification",
    )]));
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let view = rig.world.view(rig.job).await;
    assert_eq!(view.code_rework_rounds, 0);
    assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 1);
    assert_eq!(
        view.newest(StageKind::Review).expect("a run").status,
        StageRunStatus::WaitingForHuman
    );
}
