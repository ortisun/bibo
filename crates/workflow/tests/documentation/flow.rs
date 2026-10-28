//! The documentation stages through the real engine: the happy path of a command line feature,
//! the independence of the reviewer, and where each kind of defect goes.

use std::collections::BTreeMap;

use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_testkit::agent::AdversarialScript;
use factory_testkit::contracts::workspace::TreeEdit;
use factory_workflow::engine::AttemptOutcome;
use serde_json::{Value, json};

use crate::rig::{Options, Rig, documented_scope, write};

pub const README: &str = "# Word count\n\nWord count prints the number of lines, words and characters of a text file.\n\n## Usage\n\nRun the tool with a file name. Add `--json` to print the counts as JSON.\n\n```console\n$ word-count --json notes.txt\n{\"lines\":1,\"words\":2,\"characters\":9}\n```\n\nThe [changelog](CHANGELOG.md#unreleased) lists what changed.\n";
pub const CHANGELOG: &str =
    "# Changelog\n\n## Unreleased\n\n- Added the `--json` flag, which prints the counts as JSON.\n";

/// What the documentation writer reports when it did its work. The summary is the writer's own
/// account of it, so a test can look for it where it must not be.
pub const WRITER_SUMMARY: &str =
    "The README and the changelog now describe the new flag, with a runnable example.";

pub fn writer_done(files: &[&str], evidence: &str) -> Value {
    json!({
        "schema_version": 1,
        "status": "DONE",
        "summary": WRITER_SUMMARY,
        "files_written": files,
        "plan_coverage": [
            { "plan_item": "usage", "status": "covered", "files": ["README.md"] },
            { "plan_item": "changelog-entry", "status": "covered", "files": ["CHANGELOG.md"] }
        ],
        "claims": [{ "claim": "The flag prints the counts as JSON.", "evidence_path": evidence }],
        "ignored_instructions": []
    })
}

/// What the documentation reviewer returns when it finds nothing.
pub fn reviewer_passes() -> Value {
    json!({
        "schema_version": 1,
        "verdict": "PASS",
        "title": "Documentation review",
        "summary": "The documents match the change and the gate reports show no failure.",
        "findings": [],
        "confidence_overall": 0.9,
        "residual_risks": [],
        "ignored_instructions": []
    })
}

/// A finding of the documentation reviewer at a line one of the patches shows.
pub fn reviewer_asks(class: &str, path: &str, line: u32) -> Value {
    let action = if class == "specification" || class == "policy" {
        "escalate_to_human"
    } else {
        "fix"
    };
    json!({
        "schema_version": 1,
        "verdict": "CHANGES_REQUIRED",
        "title": "Documentation review",
        "summary": "One statement of the documents does not match what the change does.",
        "findings": [{
            "finding_id": "reviewer-chosen-id",
            "severity": "high",
            "category": "documentation",
            "title": "A statement does not match the code",
            "description": "The page says the flag prints text, and the change makes it print JSON.",
            "location": { "path": path, "line_start": line },
            "confidence": 0.8,
            "proposed_next_action": action,
            "defect_class": class
        }],
        "confidence_overall": 0.8,
        "residual_risks": [],
        "ignored_instructions": []
    })
}

/// The job, up to the stage that documents: the real implementation stage built the feature.
pub async fn up_to_documenting() -> Rig {
    let rig = Rig::build(Options {
        scope: documented_scope(),
        ..Options::default()
    })
    .await;
    rig.run_until_implementation().await;
    rig.builder_does_the_plan();
    through_review(&rig).await;
    rig
}

/// Runs the implementation, validation and review stages.
pub async fn through_review(rig: &Rig) {
    for kind in [
        StageKind::Implementation,
        StageKind::Validation,
        StageKind::Review,
    ] {
        let (claimed, outcome) = rig.run_next().await;
        assert_eq!(claimed.kind, kind);
        assert_eq!(outcome, AttemptOutcome::Succeeded, "{kind:?}");
    }
}

/// The writer will make these edits and report this.
pub fn writer_will(rig: &Rig, edits: Vec<TreeEdit>, report: Value) {
    rig.runtime.edits("documentation-writer", edits);
    rig.runtime
        .inner
        .queue(AdversarialScript::returning(report));
}

/// The writer will write the README and the changelog.
pub fn writer_will_document(rig: &Rig) {
    writer_will(
        rig,
        vec![write("README.md", README), write("CHANGELOG.md", CHANGELOG)],
        writer_done(&["README.md", "CHANGELOG.md"], "src/main.rs"),
    );
}

/// The reviewer will return this.
pub fn reviewer_will(rig: &Rig, report: Value) {
    rig.runtime
        .inner
        .queue(AdversarialScript::returning(report));
}

/// Claims the next stage run, checks which stage it is, and runs it.
pub async fn run(rig: &Rig, kind: StageKind) -> AttemptOutcome {
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, kind);
    outcome
}

/// The outcome of each gate of the newest documentation review that stored a gate report.
pub async fn gate_outcomes(rig: &Rig) -> BTreeMap<String, String> {
    let document = rig
        .deliverable(StageKind::DocumentationReview, "documentation-gate-report")
        .await
        .expect("the gate report is stored");
    document["reports"]
        .as_array()
        .expect("reports")
        .iter()
        .filter_map(|r| {
            Some((
                r["metadata"]["gate_id"].as_str()?.to_owned(),
                r["outcome"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// The failure messages of one gate of the newest documentation review.
pub async fn failures_of(rig: &Rig, gate: &str) -> Vec<String> {
    let document = rig
        .deliverable(StageKind::DocumentationReview, "documentation-gate-report")
        .await
        .expect("the gate report is stored");
    document["reports"]
        .as_array()
        .expect("reports")
        .iter()
        .filter(|r| r["metadata"]["gate_id"] == gate)
        .flat_map(|r| r["failures"].as_array().cloned().unwrap_or_default())
        .filter_map(|f| f["message"].as_str().map(str::to_owned))
        .collect()
}

/// The documentation reviewer's verdict of the newest documentation review run, read back from
/// the artifact store. The verdict has no `kind` field, so it is found by its shape.
pub async fn verdict_of(rig: &Rig) -> Option<Value> {
    use factory_domain::contracts::ArtifactRef;
    use factory_domain::scope::TenantScope;
    use factory_domain::values::MediaType;
    use factory_ports::artifact::ArtifactStore;
    let tenant = TenantScope::new(rig.world.tenant);
    for (run, _) in rig
        .runs_of(StageKind::DocumentationReview)
        .await
        .into_iter()
        .rev()
    {
        for link in rig.world.links(run).await {
            let reference = ArtifactRef {
                sha256: link.sha256.clone(),
                media_type: MediaType::parse("application/json").expect("a media type"),
                size_bytes: None,
            };
            if let Ok(bytes) = ArtifactStore::get(&*rig.artifacts, &tenant, &reference).await
                && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                && value.get("inputs_reviewed").is_some()
            {
                return Some(value);
            }
        }
    }
    None
}

/// The text of one data block of a prompt.
pub fn block<'a>(prompt: &'a str, name: &str) -> &'a str {
    let start = prompt
        .find(&format!("<<<DATA name={name} "))
        .unwrap_or_else(|| panic!("no block {name}"));
    let end = prompt[start..]
        .find(&format!("<<<END name={name}>>>"))
        .expect("the block ends");
    &prompt[start..start + end]
}

/// Runs both documentation stages over a clean write and a passing reviewer.
pub async fn documented_and_reviewed() -> Rig {
    let rig = up_to_documenting().await;
    writer_will_document(&rig);
    reviewer_will(&rig, reviewer_passes());
    assert_eq!(
        run(&rig, StageKind::Documenting).await,
        AttemptOutcome::Succeeded
    );
    assert_eq!(
        run(&rig, StageKind::DocumentationReview).await,
        AttemptOutcome::Succeeded
    );
    rig
}

#[tokio::test]
async fn a_command_line_feature_is_documented_checked_and_reviewed() {
    let rig = documented_and_reviewed().await;

    // The plan the impact policy derived: usage text and a changelog entry for the new flag.
    let plan = rig
        .deliverable(StageKind::Documenting, "documentation-plan")
        .await
        .expect("the plan is stored");
    let kinds: Vec<&str> = plan["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["usage", "changelog"]);
    assert_eq!(plan["interface"]["new_flags"], json!(["--json"]));
    assert_eq!(plan["program"], "word-count");

    // The documentation commit sits on top of the code head, on the same branch, and the host
    // made it.
    let result = rig
        .deliverable(StageKind::Documenting, "documentation-result")
        .await
        .expect("the result is stored");
    assert_ne!(result["head_commit"], result["code_head"]);
    assert_eq!(result["refusal"], Value::Null);
    assert_eq!(result["unresolved_claims"], json!([]));
    assert!(
        rig.events_of("workspace.commit:")
            .iter()
            .any(|event| event == "workspace.commit:Factory")
    );

    // Every check ran or does not apply, and none is recorded as passed without having run.
    let outcomes = gate_outcomes(&rig).await;
    assert_eq!(outcomes.len(), 10, "{outcomes:?}");
    for (gate, outcome) in &outcomes {
        assert!(
            matches!(outcome.as_str(), "PASSED" | "NOT_APPLICABLE"),
            "{gate}: {outcome}"
        );
    }
    assert_eq!(outcomes["docs-examples"], "PASSED");
    assert_eq!(outcomes["docs-commands"], "PASSED");
    assert_eq!(outcomes["docs-links"], "PASSED");
    assert_eq!(outcomes["docs-diagrams"], "NOT_APPLICABLE");
    assert_eq!(outcomes["docs-secrets"], "PASSED");
    assert_eq!(outcomes["readability-gate"], "PASSED");
    let verdict = verdict_of(&rig).await.expect("the verdict is stored");
    assert_eq!(verdict["verdict"], "PASS");
    assert_eq!(
        verdict["metadata"]["reviewer"]["role"],
        "documentation_reviewer"
    );
    for kind in [StageKind::Documenting, StageKind::DocumentationReview] {
        assert_eq!(rig.runs_of(kind).await.len(), 1);
    }
}

/// The deliverables are stored under the exact names the delivery stage reads.
#[tokio::test]
async fn the_deliverables_have_the_names_the_delivery_stage_reads() {
    use factory_workflow::stages::delivery::input::{
        DOCUMENTATION_GATE, DOCUMENTATION_PLAN, DOCUMENTATION_REVIEW,
    };
    use factory_workflow::stages::documenting as names;
    assert_eq!(names::DOCUMENTATION_PLAN, DOCUMENTATION_PLAN);
    assert_eq!(names::DOCUMENTATION_GATE_REPORT, DOCUMENTATION_GATE);
    assert_eq!(names::DOCUMENTATION_REVIEW, DOCUMENTATION_REVIEW);
    let rig = documented_and_reviewed().await;
    assert!(
        rig.deliverable(StageKind::Documenting, DOCUMENTATION_PLAN)
            .await
            .is_some()
    );
    assert!(
        rig.deliverable(StageKind::DocumentationReview, DOCUMENTATION_GATE)
            .await
            .is_some()
    );
    assert!(verdict_of(&rig).await.is_some());
}

mod reviewer_independence {
    use super::*;

    /// The reviewer's prompt holds the specification, the plan, both patches and the gate
    /// reports, and nothing of what the writer said about its own work.
    #[tokio::test]
    async fn the_prompt_has_no_writer_account() {
        let rig = documented_and_reviewed().await;
        let prompts = rig.runtime.prompts("documentation-reviewer");
        assert_eq!(prompts.len(), 1);
        let prompt = &prompts[0].instructions;
        for name in [
            "frozen_specification",
            "documentation_plan",
            "code_diff",
            "documentation_diff",
            "gate_reports",
        ] {
            let _ = block(prompt, name);
        }
        assert!(
            !prompt.contains(WRITER_SUMMARY),
            "the writer's summary reached the reviewer"
        );
        assert!(
            !prompt.contains("The flag prints the counts as JSON."),
            "a claim of the writer reached the reviewer"
        );
        assert!(!prompt.contains("documentation_report"));
        // The gate reports the reviewer got are the factory's own measurements.
        let reports = block(prompt, "gate_reports");
        assert!(
            reports.contains("docs-links: PASSED") || reports.contains("Gate docs-links: PASSED"),
            "{reports}"
        );
        // The record says it, and the verdict carries the factory's own flag.
        let record = rig
            .deliverable(
                StageKind::DocumentationReview,
                "documentation-review-record",
            )
            .await
            .expect("the record is stored");
        assert_eq!(record["inputs"]["writer_summary_given"], false);
        let verdict = verdict_of(&rig).await.expect("the verdict");
        assert_eq!(
            verdict["inputs_reviewed"]["saw_builder_self_assessment"],
            false
        );
    }

    /// By type: an input that is an agent's account of its own work cannot be made into an input
    /// of a reviewer prompt, so no stage can pass the writer's summary to the reviewer.
    #[test]
    fn a_writer_summary_cannot_be_made_independent() {
        use factory_domain::ids::TenantId;
        use factory_workflow::prompts::{AssemblyError, ContentClass, Input, Source};
        let summary = Input::untrusted(
            "writer_summary",
            ContentClass::ModelOutput,
            Source::SelfAssessment {
                agent: "documentation-writer".to_owned(),
            },
            TenantId::from_uuid(uuid::Uuid::nil()),
            WRITER_SUMMARY.as_bytes().to_vec(),
        );
        assert_eq!(
            summary.into_independent().err(),
            Some(AssemblyError::SelfAssessmentRefused)
        );
    }
}

mod defects_route_by_class {
    use super::*;

    async fn after_a_finding(class: &str, path: &str, line: u32) -> Rig {
        let rig = up_to_documenting().await;
        writer_will_document(&rig);
        reviewer_will(&rig, reviewer_asks(class, path, line));
        run(&rig, StageKind::Documenting).await;
        run(&rig, StageKind::DocumentationReview).await;
        rig
    }

    #[tokio::test]
    async fn a_documentation_defect_goes_back_to_documenting() {
        let rig = after_a_finding("documentation", "README.md", 5).await;
        let view = rig.world.view(rig.job).await;
        assert_eq!(view.documentation_rework_rounds, 1);
        assert_eq!(view.code_rework_rounds, 0);
        assert_eq!(rig.runs_of(StageKind::Documenting).await.len(), 2);
        assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 1);
        let newest = view.newest(StageKind::Documenting).expect("a run");
        assert_eq!(newest.status, StageRunStatus::Ready);
    }

    #[tokio::test]
    async fn a_code_behavior_defect_goes_back_to_implementation() {
        let rig = after_a_finding("code_behavior", "src/main.rs", 2).await;
        let view = rig.world.view(rig.job).await;
        assert_eq!(view.code_rework_rounds, 1);
        assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 2);
        // The documents were written for the code that is being replaced, so the engine
        // supersedes both documentation runs and makes new ones (ADR 0010).
        for kind in [StageKind::Documenting, StageKind::DocumentationReview] {
            let runs = rig.runs_of(kind).await;
            assert_eq!(runs.len(), 2, "{kind:?}");
            let first = if kind == StageKind::Documenting {
                StageRunStatus::Superseded
            } else {
                StageRunStatus::ReworkRequested
            };
            assert_eq!(runs[0].1, first, "{kind:?}");
            assert_ne!(runs[1].1, StageRunStatus::Passed, "{kind:?}");
        }
    }

    #[tokio::test]
    async fn a_specification_defect_goes_to_a_person() {
        let rig = after_a_finding("specification", "README.md", 5).await;
        let view = rig.world.view(rig.job).await;
        assert_eq!(
            view.newest(StageKind::DocumentationReview)
                .expect("a run")
                .status,
            StageRunStatus::WaitingForHuman
        );
        assert_eq!(view.documentation_rework_rounds, 0);
        assert_eq!(rig.runs_of(StageKind::Documenting).await.len(), 1);
        assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 1);
    }

    #[tokio::test]
    async fn a_policy_defect_goes_to_a_person() {
        let rig = after_a_finding("policy", "README.md", 5).await;
        let view = rig.world.view(rig.job).await;
        assert_eq!(
            view.newest(StageKind::DocumentationReview)
                .expect("a run")
                .status,
            StageRunStatus::WaitingForHuman
        );
    }

    /// A failed deterministic check has no class and counts as a documentation defect (ADR 0010),
    /// whatever the reviewer says.
    #[tokio::test]
    async fn a_failed_gate_counts_as_a_documentation_defect() {
        let rig = up_to_documenting().await;
        let dead = README.replace(
            "The [changelog](CHANGELOG.md#unreleased)",
            "The [guide](docs/missing.md) and the [changelog](CHANGELOG.md#unreleased)",
        );
        writer_will(
            &rig,
            vec![write("README.md", &dead), write("CHANGELOG.md", CHANGELOG)],
            writer_done(&["README.md", "CHANGELOG.md"], "src/main.rs"),
        );
        reviewer_will(&rig, reviewer_passes());
        run(&rig, StageKind::Documenting).await;
        run(&rig, StageKind::DocumentationReview).await;
        let outcomes = gate_outcomes(&rig).await;
        assert_eq!(outcomes["docs-links"], "FAILED");
        let view = rig.world.view(rig.job).await;
        assert_eq!(view.documentation_rework_rounds, 1);
        assert_eq!(rig.runs_of(StageKind::Documenting).await.len(), 2);
        assert_eq!(rig.runs_of(StageKind::Implementation).await.len(), 1);
    }
}

/// The tools the contracts grant are those of the manifests, and the writer's write scope in the
/// contract is the one in its manifest. A reviewer whose manifest granted a tool that writes would
/// be refused before anything is made.
#[test]
fn the_granted_tools_are_those_of_the_manifests() {
    use factory_domain::contracts::AgentManifest;
    use factory_workflow::stages::implementation::seams::verify_read_only_tools;
    let names = |manifest: &AgentManifest| -> Vec<String> {
        manifest
            .allowed_tools
            .as_slice()
            .iter()
            .map(|tool| tool.name.as_str().to_owned())
            .collect()
    };
    let writer: AgentManifest =
        serde_json::from_str(crate::rig::WRITER_MANIFEST).expect("the real manifest");
    let reviewer: AgentManifest =
        serde_json::from_str(crate::rig::DOC_REVIEWER_MANIFEST).expect("the real manifest");
    assert_eq!(
        names(&writer),
        factory_workflow::stages::documenting::GRANTED_TOOLS
    );
    assert_eq!(
        names(&reviewer),
        factory_workflow::stages::documentation_review::GRANTED_TOOLS
    );
    assert!(verify_read_only_tools(&reviewer).is_ok());
    assert!(verify_read_only_tools(&writer).is_err());
}
