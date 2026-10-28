//! The seams that answer from stored evidence, over PostgreSQL and a whole engine.
//!
//! The engine runs with the engine suite's scripted handlers, which produce real gate reports and
//! real review verdicts and so real ledger entries. The documents that the real stages name
//! (`implementation-result`, `normalized-request`, `task-plan`) are linked by the tests, under the
//! role the engine would give them, because the scripted handlers produce one deliverable of
//! their own.

mod support;

use factory_composition::feedback::StoreFeedback;
use factory_composition::risk::StoreRisk;
use factory_composition::specs::{StoreSpecApprovals, StoreSpecDrafts, StoreSpecHistory};
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::JobId;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_domain::vocabulary::StageKind;
use factory_ports::paths::CommitSha;
use factory_ports::store::{ArtifactDirection, NewArtifactIndexEntry, Store};
use factory_workflow::engine::links::output_role;
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::architecture::seams::{RiskSource, RoundSource};
use factory_workflow::stages::implementation::seams::ReworkSource;
use factory_workflow::stages::specification::seams::{
    DraftRecord, SeamError, SpecApprovals, SpecDrafts, SpecHistory,
};
use support::engine::{Eval, PgWorld};
use support::pg_world;

fn commit(letter: char) -> CommitSha {
    CommitSha::parse(&letter.to_string().repeat(40)).expect("a commit")
}

/// Claims and runs stages until the one of `kind` has run.
async fn run_through(world: &PgWorld, kind: StageKind) {
    loop {
        let claimed = world.claim_one("worker-a").await;
        world
            .engine
            .run_attempt(&claimed)
            .await
            .expect("the attempt runs");
        if claimed.kind == kind {
            return;
        }
    }
}

async fn identity_of(world: &PgWorld, job: JobId, kind: StageKind, index: usize) -> RunIdentity {
    let view = world.view(job).await;
    let run = view.runs_of(kind).nth(index).expect("the run exists");
    let mut tx = world
        .store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a transaction");
    let stored = tx.get_job(job).await.expect("the job").value;
    let _ = tx.rollback().await;
    RunIdentity {
        tenant: world.tenant,
        job,
        correlation: stored.correlation_id,
        stage_run: run.id,
        kind,
    }
}

/// Stores a document, indexes it for the tenant and links it to the stage run as the engine would
/// link the deliverable `name` of attempt number 1.
async fn deliver(world: &PgWorld, run: &RunIdentity, name: &str, json: &serde_json::Value) {
    let reference: ArtifactRef = world
        .deps
        .artifacts
        .put(
            serde_json::to_vec(json).expect("json"),
            MediaType::parse("application/json").expect("a media type"),
        )
        .await
        .expect("stored");
    let mut tx = world
        .store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a transaction");
    tx.index_artifact(
        NewArtifactIndexEntry::from_reference(&reference, Some((run.job, run.stage_run)))
            .expect("sized"),
    )
    .await
    .expect("indexed");
    tx.link_stage_run_artifact(
        run.stage_run,
        ArtifactDirection::Output,
        output_role(
            &factory_domain::values::Slug::parse(name).expect("a slug"),
            1,
        )
        .expect("a role"),
        reference.sha256,
    )
    .await
    .expect("linked");
    tx.commit().await.expect("commit");
}

fn feedback(world: &PgWorld) -> StoreFeedback {
    StoreFeedback::new(world.store.clone(), world.deps.artifacts.clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_run_has_no_feedback() {
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    run_through(&world, StageKind::Intake).await;
    let intake = identity_of(&world, job, StageKind::Intake, 0).await;
    assert_eq!(feedback(&world).of(&intake).await, Ok(None));
    assert!(matches!(feedback(&world).previous(&intake).await, Ok(None)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rework_run_reads_the_failed_report_and_builds_on_the_previous_head() {
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Validation)
        .queue_evals([Eval::Fail("tests-pass")]);
    run_through(&world, StageKind::Implementation).await;
    // The implementation result the stage would have stored: the commit the next run builds on.
    let first = identity_of(&world, job, StageKind::Implementation, 0).await;
    deliver(
        &world,
        &first,
        "implementation-result",
        &serde_json::json!({"base_commit": commit('a').as_str(), "head_commit": commit('b').as_str()}),
    )
    .await;
    run_through(&world, StageKind::Validation).await;

    let second = identity_of(&world, job, StageKind::Implementation, 1).await;
    let context = feedback(&world)
        .of(&second)
        .await
        .expect("readable")
        .expect("a rework run has feedback");
    assert_eq!(context.round, 1);
    assert_eq!(context.previous_head, commit('b'));
    assert_eq!(context.failed_reports.len(), 1, "{context:?}");
    assert_eq!(
        context.failed_reports[0].outcome,
        factory_domain::vocabulary::GateOutcome::Failed
    );
    assert!(context.findings.is_empty());

    // The round source reads the same failure for the same run.
    let round = feedback(&world)
        .previous(&second)
        .await
        .expect("readable")
        .expect("a previous round");
    assert_eq!(round.round, 1);
    assert_eq!(round.failed_reports.len(), 1);
    assert_eq!(round.plan_version, 0);
    assert!(round.previous_plan.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rework_run_after_a_review_reads_the_findings() {
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Review)
        .queue_evals([Eval::ChangesRequired("code_behavior")]);
    run_through(&world, StageKind::Implementation).await;
    let first = identity_of(&world, job, StageKind::Implementation, 0).await;
    deliver(
        &world,
        &first,
        "implementation-result",
        &serde_json::json!({"base_commit": commit('a').as_str(), "head_commit": commit('c').as_str()}),
    )
    .await;
    run_through(&world, StageKind::Review).await;
    let second = identity_of(&world, job, StageKind::Implementation, 1).await;
    let context = feedback(&world)
        .of(&second)
        .await
        .expect("readable")
        .expect("feedback");
    assert_eq!(context.previous_head, commit('c'));
    assert!(
        !context.findings.is_empty(),
        "the reviewer's findings are handed to the builder: {context:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_planning_rework_gets_the_previous_plan_and_its_version() {
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::TaskPlanning)
        .queue_evals([Eval::Fail("plan-traceability-complete")]);
    run_through(&world, StageKind::TaskPlanning).await;
    let view = world.view(job).await;
    assert!(
        view.runs_of(StageKind::TaskPlanning).count() >= 2,
        "a failed planning gate creates a second planning run"
    );
    let first = identity_of(&world, job, StageKind::TaskPlanning, 0).await;
    deliver(
        &world,
        &first,
        "task-plan",
        &serde_json::json!({"metadata": {"plan_version": 3}}),
    )
    .await;
    let second = identity_of(&world, job, StageKind::TaskPlanning, 1).await;
    let round = feedback(&world)
        .previous(&second)
        .await
        .expect("readable")
        .expect("a previous round");
    assert_eq!(round.plan_version, 3);
    assert!(round.previous_plan.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_risk_claim_is_the_hint_of_the_stored_intake_and_a_missing_hint_fails_closed() {
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    run_through(&world, StageKind::Intake).await;
    let intake = identity_of(&world, job, StageKind::Intake, 0).await;
    let risk = StoreRisk::new(world.store.clone(), world.deps.artifacts.clone());
    assert_eq!(
        risk.of(&intake)
            .await
            .expect_err("no normalized request yet"),
        SeamError::Unavailable
    );
    deliver(
        &world,
        &intake,
        "normalized-request",
        &serde_json::json!({"risk_hint": "high", "title": "t"}),
    )
    .await;
    let found = risk.of(&intake).await.expect("readable");
    assert_eq!(
        found.agent_claim,
        Some(factory_domain::vocabulary::RiskTier::High)
    );
    assert_eq!(
        found.facts,
        factory_domain::policy::risk::RiskFacts::default()
    );
}

fn draft(letter: char, contract: &str) -> DraftRecord {
    DraftRecord {
        commit: commit(letter),
        feature_directory: "specs/001-word-count".to_owned(),
        contract: contract.as_bytes().to_vec(),
        evidence: br#"{"operations":["specify"]}"#.to_vec(),
    }
}

/// A specification run that waits for a person, so that its ledger can hold the person's decision.
async fn waiting_specification(world: &PgWorld, job: JobId) -> RunIdentity {
    world
        .script(StageKind::Specification)
        .evals_otherwise(Eval::HumanGate);
    run_through(world, StageKind::Specification).await;
    identity_of(world, job, StageKind::Specification, 0).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_draft_is_kept_loaded_and_replaced_by_a_newer_one() {
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    let run = waiting_specification(&world, job).await;
    let drafts = StoreSpecDrafts::new(world.store.clone(), world.deps.artifacts.clone());
    assert_eq!(drafts.load(&run).await, Ok(None));
    drafts
        .save(&run, draft('a', r#"{"v":1}"#))
        .await
        .expect("saved");
    drafts
        .save(&run, draft('a', r#"{"v":1}"#))
        .await
        .expect("saved again");
    let first = drafts.load(&run).await.expect("loads").expect("a draft");
    assert_eq!(first.contract, br#"{"v":1}"#);
    assert_eq!(first.commit, commit('a'));
    drafts
        .save(&run, draft('b', r#"{"v":2}"#))
        .await
        .expect("saved");
    let newest = drafts.load(&run).await.expect("loads").expect("a draft");
    assert_eq!(newest.contract, br#"{"v":2}"#);
    assert_eq!(newest.commit, commit('b'));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_persons_approval_counts_for_the_draft_they_saw_and_not_for_another() {
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    let run = waiting_specification(&world, job).await;
    let drafts = StoreSpecDrafts::new(world.store.clone(), world.deps.artifacts.clone());
    let approvals = StoreSpecApprovals::new(world.store.clone(), world.deps.artifacts.clone());
    let one = Sha256Digest::of(br#"{"v":1}"#);
    let two = Sha256Digest::of(br#"{"v":2}"#);

    drafts
        .save(&run, draft('a', r#"{"v":1}"#))
        .await
        .expect("saved");
    assert_eq!(
        approvals.approval(&run, &one).await,
        Ok(None),
        "nobody decided yet"
    );
    // A person approves the first draft.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    world.approve(&world.engine, job, run.stage_run).await;
    let found = approvals
        .approval(&run, &one)
        .await
        .expect("readable")
        .expect("the approval of the first draft");
    assert_eq!(
        found.role,
        factory_domain::contracts::specification_contract::SpecApproverRole::Approver
    );
    assert_eq!(
        found.basis,
        factory_domain::contracts::specification_contract::ApprovalBasis::HumanDecision
    );
    // A draft the run never kept has no approval, and a draft kept after the decision has none.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    drafts
        .save(&run, draft('b', r#"{"v":2}"#))
        .await
        .expect("saved");
    assert_eq!(approvals.approval(&run, &two).await, Ok(None));
    assert!(
        approvals
            .approval(&run, &one)
            .await
            .expect("readable")
            .is_some(),
        "the earlier draft keeps its approval"
    );
    assert_eq!(
        approvals
            .approval(&run, &Sha256Digest::of(b"never kept"))
            .await,
        Ok(None)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_specification_has_no_history() {
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    let run = waiting_specification(&world, job).await;
    let history = StoreSpecHistory::new(world.store.clone(), world.deps.artifacts.clone());
    assert!(matches!(history.previous(&run).await, Ok(None)));
}

fn allowlist_in(
    dir: &std::path::Path,
) -> std::sync::Arc<factory_composition::seams::FileAllowlist> {
    std::fs::create_dir_all(dir.join("allowlist")).expect("a directory");
    std::fs::write(
        dir.join("allowlist/allowlist.yaml"),
        "version: 1\nentries: []\n",
    )
    .expect("the allowlist");
    std::sync::Arc::new(factory_composition::seams::FileAllowlist::in_checkout(dir))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_approval_sources_read_the_requester_the_level_and_the_allowlist() {
    use factory_composition::delivery::StoreApprovalSources;
    use factory_workflow::stages::approval::ApprovalSources;
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    run_through(&world, StageKind::Intake).await;
    let intake = identity_of(&world, job, StageKind::Intake, 0).await;
    let dir = std::env::temp_dir().join(format!("composition-allowlist-{}", std::process::id()));
    let sources = StoreApprovalSources::new(
        world.store.clone(),
        world.deps.artifacts.clone(),
        allowlist_in(&dir),
    );
    // The requester of the job is the principal the world made, with GitHub user id 1001.
    assert_eq!(sources.requester(&intake).await, Ok(1001));
    assert!(sources.level(world.tenant, job).await.is_ok());
    assert!(sources.allowlist(world.tenant).await.is_ok());
    // No approval request was stored for this run.
    assert_eq!(
        sources.request(world.tenant, intake.stage_run).await.err(),
        Some(SeamError::NotFound)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_delivery_ledger_is_verified_and_the_two_blocked_methods_fail_closed() {
    use factory_composition::delivery::StoreDeliverySources;
    use factory_composition::system::SystemClock;
    use factory_workflow::stages::delivery::DeliverySources;
    let (_db, world, _) = pg_world().await;
    let job = world.admitted_job().await;
    run_through(&world, StageKind::Intake).await;
    let intake = identity_of(&world, job, StageKind::Intake, 0).await;
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let policies =
        factory_composition::startup::load_policy(&root, &[]).expect("the repository policy loads");
    let sources = StoreDeliverySources::new(
        world.store.clone(),
        world.deps.artifacts.clone(),
        policies.engine.clone(),
        std::sync::Arc::new(SystemClock),
    );
    let state = sources.ledger(&intake).await.expect("the chain verifies");
    assert!(state.entry_count >= 1);
    assert_eq!(state.head_sequence, state.entry_count);
    // BLOCKED: no port exposes a tree id, and the gate definition hash lives in the validation
    // stage. The stage must fail closed there.
    assert_eq!(
        sources.tree_of(&intake, &commit('a')).await,
        Err(SeamError::Unavailable)
    );
    assert_eq!(
        sources.current_values(&intake, &commit('a')).await.err(),
        Some(SeamError::Unavailable)
    );
}
