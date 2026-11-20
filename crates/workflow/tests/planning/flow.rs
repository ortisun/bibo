//! The happy path through the real engine: the stages before the two under test are stand-ins, the
//! architecture and planning stages are real, and a stand-in for the implementation stage takes
//! what planning produced by the names the real implementation stage uses.

use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_workflow::engine::AttemptOutcome;
use factory_workflow::stages::implementation::input::{ARCHITECTURE, TASK_PLAN};
use serde_json::Value;

use crate::rig::{Options, PROBE_RESULT, Rig, design, gate_outcome};

#[tokio::test]
async fn a_job_goes_from_intake_through_planning_to_the_implementation_reader() {
    let rig = Rig::build(Options::through_implementation()).await;
    rig.run_until_architecture().await;
    rig.architecture_passes(design()).await;
    rig.planner_plans(|_| {});
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::TaskPlanning);
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(
        rig.status(StageKind::TaskPlanning).await,
        StageRunStatus::Passed
    );

    // The implementation reader finds both deliverables by the names it declares, and orders the
    // tasks with its own reader of the plan.
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Implementation);
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let probe = rig
        .deliverable(StageKind::Implementation, PROBE_RESULT)
        .await
        .expect("the implementation reader ran");
    assert_eq!(
        probe["order"],
        serde_json::json!([
            "add-json-output-formatter",
            "cover-unreadable-file-error",
            "document-json-flag"
        ])
    );

    // The deliverables of the architecture stage.
    let design_doc = rig
        .deliverable(StageKind::Architecture, ARCHITECTURE)
        .await
        .expect("the design");
    assert_eq!(design_doc["status"], "DONE");
    let record = rig
        .deliverable(StageKind::Architecture, "architecture-record")
        .await
        .expect("the record");
    assert_eq!(record["risk"]["tier"], "low");
    assert_eq!(record["complexity"]["kind"], "non_trivial");
    assert_eq!(record["alternatives"], 2);
    assert_eq!(record["critic"]["outcome"], "not_required");
    let adrs = rig
        .deliverable(StageKind::Architecture, "adr-drafts")
        .await
        .expect("the draft decision records");
    assert_eq!(adrs["drafts"][0]["draft_id"], "draft-hand-written-json");

    // The deliverables of the planning stage.
    let plan = rig
        .deliverable(StageKind::TaskPlanning, TASK_PLAN)
        .await
        .expect("the plan");
    assert_eq!(plan["tasks"].as_array().map(Vec::len), Some(3));
    let matrix = rig
        .deliverable(StageKind::TaskPlanning, "plan-traceability")
        .await
        .expect("the matrix");
    assert_eq!(matrix["requirements"].as_array().map(Vec::len), Some(4));
    assert_eq!(matrix["requirements"][0]["requirement"], "FR-001");
    assert!(
        matrix["requirements"][0]["tasks"]
            .as_array()
            .is_some_and(|tasks| tasks.len() == 2)
    );
    let plan_record = rig
        .deliverable(StageKind::TaskPlanning, "plan-record")
        .await
        .expect("the plan record");
    assert_eq!(plan_record["expected_metadata"]["plan_version"], 1);
    assert_eq!(
        plan_record["analysis"]["critical_path"]["tasks"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(plan_record["status"], "done");

    // Every gate passed, and the critic gate says it did not apply.
    let reports = rig.gate_reports().await;
    for gate in [
        "architecture-traceability",
        "architecture-completeness",
        "plan-metadata-matches",
        "task-plan-validator",
        "plan-traceability-complete",
        factory_workflow::gates::readability::GATE_ID,
    ] {
        assert_eq!(
            gate_outcome(&reports, gate).as_deref(),
            Some("PASSED"),
            "{gate}"
        );
    }
    assert_eq!(
        gate_outcome(&reports, "architecture-critic").as_deref(),
        Some("NOT_APPLICABLE")
    );
}

#[tokio::test]
async fn the_agents_run_in_a_sandbox_over_a_checkout_that_is_never_ingested() {
    let rig = Rig::new().await;
    rig.run_until_architecture().await;
    rig.architecture_passes(design()).await;
    rig.planner_plans(|_| {});
    rig.run_next().await;
    let created = rig.events_of("workspace.create");
    assert_eq!(
        created.len(),
        2,
        "one checkout for the architect, one for the planner"
    );
    assert!(
        created
            .iter()
            .all(|event| event.ends_with(rig.base.as_str())),
        "{created:?}"
    );
    assert_eq!(rig.events_of("workspace.dispose").len(), 2);
    assert_eq!(rig.events_of("sandbox.create:agent").len(), 2);
    assert_eq!(rig.events_of("sandbox.removed").len(), 2);
    for nothing in ["workspace.ingest", "workspace.commit", "sandbox.exec"] {
        assert!(rig.events_of(nothing).is_empty(), "{nothing}");
    }
    let seen = rig.specs.seen.lock().expect("lock").clone();
    assert!(seen.iter().all(|(profile, access)| {
        profile.as_str() == "agent"
            && *access == factory_workflow::stages::implementation::seams::WorkspaceAccess::Inspect
    }));
    // The tools the agents ran with are the read-only tools of their manifests.
    for agent in ["architect", "planner"] {
        let prompts = rig.runtime.prompts(agent);
        assert_eq!(prompts.len(), 1);
        let tools: Vec<&str> = prompts[0]
            .granted_tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        assert_eq!(tools, factory_workflow::stages::architecture::GRANTED_TOOLS);
    }
}

#[tokio::test]
async fn the_deliverable_names_are_the_ones_the_implementation_stage_declares() {
    assert_eq!(factory_workflow::stages::architecture::DESIGN, ARCHITECTURE);
    assert_eq!(factory_workflow::stages::planning::TASK_PLAN, TASK_PLAN);
    assert_eq!(TASK_PLAN, "task-plan");
    assert_eq!(ARCHITECTURE, "architecture-design");
    let _unused: Option<Value> = None;
}
