//! The documentation commit reaches the pull request.
//!
//! The documenting stage commits the documents on top of the code head and stores
//! `documentation-result`. The delivery stage pushes that commit, opens the pull request from it
//! and shows it to the person. The gates ran on the code head, so the evidence binding stays
//! there; everything a person sees and approves is the pushed head.

use factory_domain::contracts::Contract;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::vocabulary::{GateOutcome, StageKind};
use factory_ports::githost::{ChangeHost, GitScope, PullRequestRef, PullRequestState};
use factory_ports::paths::{BranchName, CommitSha};
use factory_ports::workspace::WorkspaceProvider;
use factory_workflow::gates::framework::Resolution;
use factory_workflow::handlers::StageError;
use serde_json::{Value, json};

use crate::world::{Documentation, Scenario, World};

fn branch() -> BranchName {
    BranchName::new("factory/job-1").expect("a branch")
}

/// What the host holds at the end of the factory branch.
fn tip(world: &World) -> Option<CommitSha> {
    world.remote.branch_tip(&world.repo, &branch())
}

fn documented(world: &World) -> CommitSha {
    world
        .documented
        .lock()
        .expect("lock")
        .clone()
        .expect("the documenting stage made a commit")
}

async fn state_of(world: &World, number: u64) -> PullRequestState {
    ChangeHost::pull_request_state(
        &*world.host,
        &GitScope {
            tenant: world.tenant,
            job: world.job,
            stage: StageKind::Delivery,
            repo: world.repo.clone(),
        },
        &PullRequestRef {
            repo: world.repo.clone(),
            number,
        },
    )
    .await
    .expect("a state")
}

/// Everything up to `execute`, so that a test sees its result and not a panic. The edits change
/// the documents of the stages before delivery.
async fn execute_after(
    world: &World,
    edit: impl AsyncFnOnce(&World, &mut Vec<factory_workflow::handlers::UpstreamRun>),
) -> Result<(), StageError> {
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let mut upstream = world.upstream(&base, &head).await;
    edit(world, &mut upstream).await;
    let contract = world.resolve_contract(&handler, &upstream)?;
    world
        .execute(&handler, &contract, &upstream)
        .await
        .map(|_| ())
}

#[tokio::test]
async fn the_pull_request_is_opened_from_the_documentation_commit() {
    let world = World::new();
    let (base, code_head) = world.commits().await;
    let docs_head = documented(&world);
    assert_ne!(docs_head, code_head, "the documents sit on top of the code");

    let ran = world.run_on(&base, &code_head).await;

    // The branch ends at the documentation commit, and the code commit came with it.
    assert_eq!(tip(&world), Some(docs_head.clone()));
    assert!(world.remote.has_commit(&code_head));
    // The documentation commit changes documents and nothing else: it is the commit after the
    // code, not a rewrite of it.
    let repo = world
        .workspaces
        .repo(world.job)
        .await
        .expect("the job repo");
    let after_code = repo
        .export_patch(&code_head, &docs_head, 1_000_000, &world.cancel)
        .await
        .expect("a patch");
    let paths: Vec<&str> = after_code
        .changes
        .iter()
        .map(|change| change.path.as_str())
        .collect();
    assert_eq!(paths, ["docs/guide.md"]);

    // The pull request points at the commit that was pushed, and the stored result says so.
    let state = state_of(
        &world,
        ran.result["pull_request"].as_u64().expect("a number"),
    )
    .await;
    assert_eq!(state.head_sha, docs_head);
    assert_eq!(ran.result["head_commit"], docs_head.as_str());
    assert_eq!(ran.result["code_head"], code_head.as_str());
    assert_eq!(ran.resolution, Resolution::Pass);
    for report in &ran.decision.reports {
        assert_eq!(report.outcome, GateOutcome::Passed);
    }
}

#[tokio::test]
async fn without_a_documentation_commit_the_code_head_is_pushed() {
    let world = World::with(Scenario {
        documentation: Documentation::NotApplicable,
        ..Scenario::default()
    });
    let (base, code_head) = world.commits().await;
    assert!(world.documented.lock().expect("lock").is_none());

    let ran = world.run_on(&base, &code_head).await;

    assert_eq!(tip(&world), Some(code_head.clone()));
    assert_eq!(ran.result["head_commit"], code_head.as_str());
    assert_eq!(ran.result["code_head"], code_head.as_str());
    assert_eq!(
        ran.manifest["metadata"]["repository"]["head_commit"],
        code_head.as_str()
    );
    assert_eq!(ran.resolution, Resolution::Pass);
}

#[tokio::test]
async fn the_evidence_binding_stays_on_the_code_head() {
    // The gates ran on the code head. If the validation evidence were bound to the documentation
    // head instead, it would be evidence about a commit the gates never saw.
    let world = World::new();
    let (base, code_head) = world.commits().await;
    let docs_head = documented(&world);
    let mut upstream = world.upstream(&base, &code_head).await;
    world
        .edit_upstream(
            &mut upstream,
            StageKind::Validation,
            "validation-evidence",
            |evidence| evidence["binding"]["head_commit"] = json!(docs_head.as_str()),
        )
        .await;
    let handler = world.handler();
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("a contract");
    let result = world.execute(&handler, &contract, &upstream).await;
    assert_eq!(result.err(), Some(StageError::PolicyDenied));
    assert!(world.drift.told.lock().expect("lock").is_empty());
    assert!(tip(&world).is_none(), "nothing was pushed");
}

#[tokio::test]
async fn everything_a_person_sees_is_about_the_pushed_head() {
    let world = World::new();
    let (base, code_head) = world.commits().await;
    let docs_head = documented(&world);
    let ran = world.run_on(&base, &code_head).await;

    // The manifest cites the pushed head and the base the change is relative to.
    assert_eq!(
        ran.manifest["metadata"]["repository"]["head_commit"],
        docs_head.as_str()
    );
    assert_eq!(
        ran.manifest["metadata"]["repository"]["base_commit"],
        base.as_str()
    );
    // The links in the body resolve at the pushed head, where the documents are.
    let body = &world.host.opened()[0].body;
    assert!(
        body.contains(&format!(
            "/blob/{}/docs/adr/0001-json-output.md",
            docs_head.as_str()
        )),
        "{body}"
    );
    assert!(!body.contains(code_head.as_str()), "{body}");
    // The change is measured from the base to the pushed head, so the new page is counted.
    let measured = ran.manifest["change"]["files_changed"]
        .as_u64()
        .expect("a count");
    assert_eq!(measured, 2, "src/lib.rs and docs/guide.md");
    // The tree comes from the pushed head, and so do the check runs the host can show.
    let asked = world.sources.trees_asked.lock().expect("lock").clone();
    assert_eq!(asked, vec![docs_head.clone()]);
    for check in world.host.checks() {
        assert_eq!(check.commit, docs_head);
        assert!(
            check.summary.contains(code_head.as_str()),
            "the check says which commit the gates ran on: {}",
            check.summary
        );
    }
    // The ledger head the manifest cites is the one that was verified before the stage.
    let ledger = world.sources.ledger.lock().expect("lock").clone();
    assert_eq!(
        ran.manifest["ledger"]["head_hash"],
        ledger.head_hash.as_str()
    );
    assert!(body.contains(ledger.head_hash.hex()), "{body}");
}

#[tokio::test]
async fn a_manifest_that_cites_another_head_than_the_pushed_one_fails_the_gate() {
    let world = World::new();
    let (base, code_head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &code_head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("a contract");
    let mut outputs = world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("execute works");
    // The manifest on record cites the code head, which the pull request does not point at.
    let mut manifest = world.read_output(&outputs, "evidence-manifest").await;
    manifest["metadata"]["repository"]["head_commit"] = json!(code_head.as_str());
    let stored = world.store_json(&manifest).await;
    outputs
        .iter_mut()
        .find(|output| output.name.as_str() == "evidence-manifest")
        .expect("the manifest")
        .artifact = stored;
    let ran = world
        .evaluate(&handler, &contract, &outputs, &upstream)
        .await
        .expect("evaluate works");
    let report = ran.report("delivery-manifest");
    assert_eq!(report.outcome, GateOutcome::Failed);
    assert!(
        report
            .failures
            .iter()
            .flatten()
            .any(|failure| failure.check_id.as_str() == "manifest-head-differs"),
        "{report:#?}"
    );
}

#[tokio::test]
async fn documentation_written_for_another_code_head_is_stale_and_is_not_pushed() {
    let other = "c".repeat(40);
    type Edit = fn(&mut Value, &str);
    let cases: [(&str, StageKind, &str, Edit); 3] = [
        (
            "result, code head",
            StageKind::Documenting,
            "documentation-result",
            |value, other| value["code_head"] = json!(other),
        ),
        (
            "result, base",
            StageKind::Documenting,
            "documentation-result",
            |value, other| value["base_commit"] = json!(other),
        ),
        (
            "plan, code head",
            StageKind::Documenting,
            "documentation-plan",
            |value, other| value["code_head"] = json!(other),
        ),
    ];
    for (name, kind, document, edit) in cases {
        let world = World::new();
        let result = execute_after(&world, async |world, upstream| {
            world
                .edit_upstream(upstream, kind, document, |value| edit(value, &other))
                .await;
        })
        .await;
        assert_eq!(result, Err(StageError::PolicyDenied), "{name}");
        assert!(
            world.host.calls().is_empty(),
            "{name}: the host was not touched"
        );
        assert!(tip(&world).is_none(), "{name}: nothing was pushed");
        assert!(world.drift.told.lock().expect("lock").is_empty(), "{name}");
    }
}

#[tokio::test]
async fn a_documentation_result_that_contradicts_itself_or_its_plan_is_refused() {
    type Edit = fn(&mut Value);
    let cases: [(&str, &str, Edit, StageError); 5] = [
        (
            "the writer never ran but a commit is named",
            "documentation-result",
            |value| value["writer_ran"] = json!(false),
            StageError::InvalidOutput,
        ),
        (
            "the commit changed nothing",
            "documentation-result",
            |value| value["changes"] = json!([]),
            StageError::InvalidOutput,
        ),
        (
            "the audit refused the writer",
            "documentation-result",
            |value| value["refusal"] = json!({ "code": "secret-found", "paths": [] }),
            StageError::PolicyDenied,
        ),
        (
            "a claim cites a file that does not exist",
            "documentation-result",
            |value| value["unresolved_claims"] = json!(["src/missing.rs"]),
            StageError::PolicyDenied,
        ),
        (
            "the commit is not a commit",
            "documentation-result",
            |value| value["head_commit"] = json!("not-a-commit"),
            StageError::InvalidOutput,
        ),
    ];
    for (name, document, edit, expected) in cases {
        let world = World::new();
        let result = execute_after(&world, async |world, upstream| {
            world
                .edit_upstream(upstream, StageKind::Documenting, document, edit)
                .await;
        })
        .await;
        assert_eq!(result, Err(expected), "{name}");
        assert!(
            world.host.calls().is_empty(),
            "{name}: the host was not touched"
        );
        assert!(tip(&world).is_none(), "{name}");
    }

    // A plan that says nothing needs documenting cannot sit beside a documentation commit.
    let world = World::new();
    let result = execute_after(&world, async |world, upstream| {
        world
            .edit_upstream(
                upstream,
                StageKind::Documenting,
                "documentation-plan",
                |plan| {
                    plan["applicable"] = json!(false);
                    plan["items"] = json!([]);
                    plan["not_applicable"] =
                        json!({ "rule": "test-only", "reason": "Only tests changed." });
                },
            )
            .await;
    })
    .await;
    assert_eq!(result, Err(StageError::InvalidOutput));
    assert!(tip(&world).is_none());

    // A plan that breaks its schema is not read.
    let world = World::new();
    let result = execute_after(&world, async |world, upstream| {
        world
            .edit_upstream(
                upstream,
                StageKind::Documenting,
                "documentation-plan",
                |plan| {
                    plan["items"] = json!("none");
                },
            )
            .await;
    })
    .await;
    assert_eq!(result, Err(StageError::InvalidOutput));
    assert!(tip(&world).is_none());
}

#[tokio::test]
async fn a_missing_documentation_result_blocks_the_stage() {
    let world = World::with(Scenario {
        missing: Some("documentation-result"),
        ..Scenario::default()
    });
    let result = execute_after(&world, async |_, _| {}).await;
    assert_eq!(
        result,
        Err(StageError::Blocked(BlockedCode::DependencyUnavailable))
    );
    assert!(world.host.calls().is_empty());
}

#[tokio::test]
async fn the_names_match_what_the_documenting_stage_stores() {
    use factory_workflow::stages::delivery::input as delivery;
    use factory_workflow::stages::documenting::input as documenting;
    assert_eq!(
        delivery::DOCUMENTATION_RESULT,
        documenting::DOCUMENTATION_RESULT
    );
    assert_eq!(
        delivery::DOCUMENTATION_PLAN,
        documenting::DOCUMENTATION_PLAN
    );
    assert_eq!(
        delivery::DOCUMENTATION_GATE,
        documenting::DOCUMENTATION_GATE_REPORT
    );
    assert_eq!(
        delivery::DOCUMENTATION_REVIEW,
        documenting::DOCUMENTATION_REVIEW
    );
}

#[tokio::test]
async fn a_restart_pushes_the_same_commit_and_opens_no_second_pull_request() {
    let world = World::new();
    let (base, code_head) = world.commits().await;
    let docs_head = documented(&world);
    let first = world.run_on(&base, &code_head).await;
    let second = world.run_on(&base, &code_head).await;

    assert_eq!(first.result["pull_request"], second.result["pull_request"]);
    assert_eq!(tip(&world), Some(docs_head.clone()));
    assert_eq!(second.result["head_commit"], docs_head.as_str());
    for name in ["factory-validation", "factory-review"] {
        assert_eq!(
            world.host.inner().check_run_count(&docs_head, name),
            1,
            "{name}"
        );
        assert_eq!(
            world.host.inner().check_run_count(&code_head, name),
            0,
            "{name}"
        );
    }
    assert_eq!(second.resolution, Resolution::Pass);
}

#[tokio::test]
async fn reports_made_for_other_commits_or_another_plan_are_stale_and_are_not_pushed() {
    let other = "9".repeat(40);
    let other_plan = factory_domain::values::Sha256Digest::of(b"a plan nobody delivered");
    for field in [
        "base_commit",
        "code_head",
        "documentation_head",
        "plan_sha256",
    ] {
        let world = World::new();
        let result = execute_after(&world, async |world, upstream| {
            world
                .edit_upstream(
                    upstream,
                    StageKind::DocumentationReview,
                    "documentation-gate-report",
                    |document| {
                        document["binding"][field] = if field == "plan_sha256" {
                            json!(other_plan)
                        } else {
                            json!(other)
                        };
                    },
                )
                .await;
        })
        .await;
        assert_eq!(result, Err(StageError::PolicyDenied), "{field}");
        assert!(
            world.host.calls().is_empty(),
            "{field}: the host was not touched"
        );
        assert!(tip(&world).is_none(), "{field}: nothing was pushed");
        assert!(world.drift.told.lock().expect("lock").is_empty(), "{field}");
    }
}

#[tokio::test]
async fn a_documentation_gate_report_that_is_not_the_stored_document_is_not_delivered() {
    let world = World::new();
    let single = world
        .report("documentation-gate", "PASSED")
        .to_json_value()
        .expect("JSON");
    let result = execute_after(&world, async |world, upstream| {
        world
            .edit_upstream(
                upstream,
                StageKind::DocumentationReview,
                "documentation-gate-report",
                |document| *document = single,
            )
            .await;
    })
    .await;
    assert_eq!(result, Err(StageError::InvalidOutput));
    assert!(world.host.calls().is_empty());
    assert!(tip(&world).is_none());
}
