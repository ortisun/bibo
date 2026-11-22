//! The task ledger over PostgreSQL: the moves of the task machine, the fence, and the refusal of a
//! write that carries none.

mod support;

use std::sync::Arc;

use factory_composition::ledger::StoreTaskLedger;
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::machines::guards::{GuardFacts, TaskDepsFacts, TaskStartFacts, evaluate};
use factory_domain::scope::TenantScope;
use factory_domain::state::{Guard, TaskNodeEvent, TaskNodeStatus};
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_ports::clock::Clock;
use factory_ports::paths::CommitSha;
use factory_ports::store::{
    AppliedTransition, Fence, LeaseEpoch, NewArtifactIndexEntry, Store, StoreError, TaskNodeEffects,
};
use factory_workflow::handlers::RunIdentity;
use factory_workflow::scheduler::ClaimedAttempt;
use factory_workflow::stages::implementation::seams::{
    Hold, LedgerError, PlannedTask, TaskLedger, TaskRunRecord,
};
use support::engine::PgWorld;
use support::pg_world;

fn slug(text: &str) -> Slug {
    Slug::parse(text).expect("a slug")
}

fn plan_hash(text: &str) -> Sha256Digest {
    Sha256Digest::of(text.as_bytes())
}

/// Stores a plan document and indexes it for the tenant, as the planning stage does: the nodes of
/// a plan refer to the plan by hash and the store checks the tenant has it.
async fn plan_artifact(world: &PgWorld, run: &RunIdentity, text: &str) -> Sha256Digest {
    let stored = world
        .deps
        .artifacts
        .put(
            text.as_bytes().to_vec(),
            MediaType::parse("application/json").expect("a media type"),
        )
        .await
        .expect("the plan is stored");
    let mut tx = world
        .store
        .begin(TenantScope::new(run.tenant))
        .await
        .expect("a transaction");
    tx.index_artifact(
        NewArtifactIndexEntry::from_reference(&stored, Some((run.job, run.stage_run)))
            .expect("a sized reference"),
    )
    .await
    .expect("indexed");
    tx.commit().await.expect("commit");
    stored.sha256
}

fn tasks() -> Vec<PlannedTask> {
    vec![
        PlannedTask {
            key: slug("t-001"),
            depends_on: vec![],
        },
        PlannedTask {
            key: slug("t-002"),
            depends_on: vec![slug("t-001")],
        },
    ]
}

fn commit(seed: &str) -> CommitSha {
    let digest = plan_hash(seed);
    let hex = digest.as_str().trim_start_matches("sha256:");
    CommitSha::parse(&hex[..40]).expect("a commit")
}

struct Held {
    _db: support::TestDb,
    world: PgWorld,
    ledger: StoreTaskLedger,
    run: RunIdentity,
    hold: Hold,
    claimed: ClaimedAttempt,
}

/// A world with one claimed attempt (the first stage), standing in for the implementation attempt
/// that holds the lease.
async fn held() -> Held {
    let (db, world, tenant) = pg_world().await;
    let job = world.admitted_job().await;
    let claimed = world.claim_one("worker-a").await;
    let run = RunIdentity {
        tenant,
        job,
        correlation: claimed.correlation,
        stage_run: claimed.stage_run,
        kind: claimed.kind,
    };
    let ids = Arc::new(RandomIds::new().expect("the random source opens"));
    let ledger = StoreTaskLedger::new(world.store.clone(), Arc::new(SystemClock), ids);
    let hold = Hold {
        attempt: claimed.attempt,
        epoch: claimed.epoch,
    };
    Held {
        _db: db,
        world,
        ledger,
        run,
        hold,
        claimed,
    }
}

async fn statuses(world: &PgWorld, run: &RunIdentity) -> Vec<(String, TaskNodeStatus)> {
    let mut tx = world
        .store
        .begin(TenantScope::new(run.tenant))
        .await
        .expect("a transaction");
    let nodes = tx.list_task_nodes(run.stage_run).await.expect("the nodes");
    let _ = tx.rollback().await;
    nodes
        .into_iter()
        .map(|node| (node.value.key.to_string(), node.value.status))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn open_creates_every_node_in_the_order_of_the_plan_and_is_idempotent() {
    let h = held().await;
    let plan_1 = plan_artifact(&h.world, &h.run, "{\"plan\": 1}").await;
    let first = h
        .ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("the graph opens");
    assert_eq!(
        first.iter().map(|t| t.key.as_str()).collect::<Vec<_>>(),
        ["t-001", "t-002"]
    );
    assert!(
        first
            .iter()
            .all(|t| t.status == TaskNodeStatus::Pending && t.commit.is_none())
    );
    let again = h
        .ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("a repeat finds the nodes");
    assert_eq!(first, again);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_plan_for_a_stage_run_that_has_nodes_is_refused() {
    let h = held().await;
    let plan_1 = plan_artifact(&h.world, &h.run, "{\"plan\": 1}").await;
    let plan_2 = plan_artifact(&h.world, &h.run, "{\"plan\": 2}").await;
    h.ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("opens");
    let refused = h
        .ledger
        .open(&h.run, &plan_2, &tasks())
        .await
        .expect_err("another plan must be refused");
    assert_eq!(refused, LedgerError::Illegal);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_task_runs_and_finishes_and_then_its_dependant_can_start() {
    let h = held().await;
    let plan_1 = plan_artifact(&h.world, &h.run, "{\"plan\": 1}").await;
    h.ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("opens");
    // The dependant cannot start while its dependency has not succeeded.
    assert_eq!(
        h.ledger.start(&h.run, &slug("t-002"), &h.hold).await,
        Err(LedgerError::Illegal)
    );
    h.ledger
        .start(&h.run, &slug("t-001"), &h.hold)
        .await
        .expect("the first task starts (T01 and T02 in one call)");
    assert_eq!(
        statuses(&h.world, &h.run).await,
        [
            ("t-001".to_owned(), TaskNodeStatus::Running),
            ("t-002".to_owned(), TaskNodeStatus::Pending)
        ]
    );
    h.ledger
        .confirm(&h.run, &h.hold)
        .await
        .expect("the hold is current");
    h.ledger
        .finish(&h.run, &slug("t-001"), &commit("one"), &h.hold)
        .await
        .expect("the first task finishes");
    h.ledger
        .start(&h.run, &slug("t-002"), &h.hold)
        .await
        .expect("the dependant starts");
    let opened = h
        .ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("a reopen reads the stored state");
    assert_eq!(opened[0].status, TaskNodeStatus::Succeeded);
    assert_eq!(opened[0].commit, Some(commit("one")));
    assert_eq!(opened[1].status, TaskNodeStatus::Running);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_left_running_is_returned_to_ready_and_taken_again() {
    let h = held().await;
    let plan_1 = plan_artifact(&h.world, &h.run, "{\"plan\": 1}").await;
    h.ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("opens");
    h.ledger
        .start(&h.run, &slug("t-001"), &h.hold)
        .await
        .expect("starts");
    // The same call again finds the node RUNNING, as after a crash: T05, then T02.
    h.ledger
        .start(&h.run, &slug("t-001"), &h.hold)
        .await
        .expect("a node left running is taken again");
    assert_eq!(
        statuses(&h.world, &h.run).await[0],
        ("t-001".to_owned(), TaskNodeStatus::Running)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_task_is_retried_until_the_limit_and_then_refused() {
    let mut h = held().await;
    let plan_1 = plan_artifact(&h.world, &h.run, "{\"plan\": 1}").await;
    h.ledger = h.ledger.with_retry_limit(1);
    h.ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("opens");
    h.ledger
        .start(&h.run, &slug("t-001"), &h.hold)
        .await
        .expect("starts");
    h.ledger
        .fail(&h.run, &slug("t-001"), &h.hold)
        .await
        .expect("fails");
    assert_eq!(
        statuses(&h.world, &h.run).await[0],
        ("t-001".to_owned(), TaskNodeStatus::Failed)
    );
    h.ledger
        .start(&h.run, &slug("t-001"), &h.hold)
        .await
        .expect("the first retry is allowed (T06 then T02)");
    h.ledger
        .fail(&h.run, &slug("t-001"), &h.hold)
        .await
        .expect("fails again");
    assert_eq!(
        h.ledger.start(&h.run, &slug("t-001"), &h.hold).await,
        Err(LedgerError::Illegal),
        "the second retry is over the limit of one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_write_with_a_stale_epoch_is_fenced_and_changes_nothing() {
    let h = held().await;
    let plan_1 = plan_artifact(&h.world, &h.run, "{\"plan\": 1}").await;
    h.ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("opens");
    let stale = Hold {
        attempt: h.hold.attempt,
        epoch: LeaseEpoch::new(h.hold.epoch.get() + 1),
    };
    assert_eq!(
        h.ledger.start(&h.run, &slug("t-001"), &stale).await,
        Err(LedgerError::Fenced)
    );
    assert_eq!(
        h.ledger.confirm(&h.run, &stale).await,
        Err(LedgerError::Fenced)
    );
    assert_eq!(
        h.ledger
            .finish(&h.run, &slug("t-001"), &commit("x"), &stale)
            .await,
        Err(LedgerError::Fenced)
    );
    assert_eq!(
        h.ledger.fail(&h.run, &slug("t-001"), &stale).await,
        Err(LedgerError::Fenced)
    );
    assert_eq!(
        statuses(&h.world, &h.run).await[0],
        ("t-001".to_owned(), TaskNodeStatus::Pending),
        "a fenced call wrote nothing"
    );
}

fn ready_move() -> AppliedTransition<TaskNodeStatus> {
    let facts = TaskDepsFacts { dependencies: &[] };
    let cleared =
        evaluate(Guard::TaskDepsSucceeded, &GuardFacts::TaskDeps(facts)).expect("cleared");
    AppliedTransition::plan(
        TaskNodeStatus::Pending,
        TaskNodeEvent::DependenciesSatisfied,
        SystemClock.now(),
        cleared,
    )
    .expect("T01")
}

fn start_move(node: factory_domain::ids::TaskNodeId) -> AppliedTransition<TaskNodeStatus> {
    let cleared = evaluate(
        Guard::TaskStartedByAttempt,
        &GuardFacts::TaskStart(TaskStartFacts {
            this_task: node,
            next_in_topological_order: Some(node),
        }),
    )
    .expect("cleared");
    AppliedTransition::plan(
        TaskNodeStatus::Ready,
        TaskNodeEvent::Start,
        SystemClock.now(),
        cleared,
    )
    .expect("T02")
}

/// The deliberate break: a ledger that forgot the fence. The store, not this crate, is the second
/// line: a move of a node that an attempt makes and that carries no fence is refused, and a fence
/// with another epoch is refused too. This is what would happen if `StoreTaskLedger` passed `None`
/// or a made-up fence.
#[tokio::test(flavor = "multi_thread")]
async fn an_unfenced_task_write_is_refused_by_the_store() {
    let h = held().await;
    let plan_1 = plan_artifact(&h.world, &h.run, "{\"plan\": 1}").await;
    h.ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("opens");
    let effects = TaskNodeEffects {
        attempt: Some(h.hold.attempt),
        commit: None,
    };
    for fence in [
        None,
        Some(Fence {
            attempt: h.hold.attempt,
            epoch: LeaseEpoch::new(h.hold.epoch.get() + 5),
            worker: h.claimed.worker.clone(),
        }),
    ] {
        let mut tx = h
            .world
            .store
            .begin(TenantScope::new(h.run.tenant))
            .await
            .expect("a transaction");
        let node = tx
            .list_task_nodes(h.run.stage_run)
            .await
            .expect("nodes")
            .into_iter()
            .find(|n| n.value.key == slug("t-001"))
            .expect("t-001");
        let version = tx
            .transition_task_node(
                node.value.id,
                node.version,
                None,
                ready_move(),
                TaskNodeEffects::default(),
            )
            .await
            .expect("T01 needs no fence");
        let refused = tx
            .transition_task_node(
                node.value.id,
                version,
                fence,
                start_move(node.value.id),
                effects.clone(),
            )
            .await
            .expect_err("a start with no fence or a stale one must be refused");
        assert!(
            matches!(refused, StoreError::LeaseFenced | StoreError::Conflict),
            "{refused:?}"
        );
        let _ = tx.rollback().await;
    }
    assert_eq!(
        statuses(&h.world, &h.run).await[0],
        ("t-001".to_owned(), TaskNodeStatus::Pending)
    );
}

fn ran(
    tier: factory_domain::contracts::agent_manifest::RecommendedTier,
    tokens: u64,
) -> TaskRunRecord {
    TaskRunRecord {
        runtime: factory_ports::agent::RuntimeId::new("claude-code-cli").expect("a runtime"),
        model: factory_domain::values::NonEmptyString::parse("claude-sonnet-5-5").expect("a model"),
        tier,
        metered: Some(
            factory_ports::store::MeteredUsage::new(tokens, 300, 4_500, 2).expect("in range"),
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_run_of_the_builder_becomes_one_row_of_the_task_and_the_attempt() {
    use factory_domain::contracts::agent_manifest::RecommendedTier::{Large, Standard};

    let h = held().await;
    let plan_1 = plan_artifact(&h.world, &h.run, "{\"plan\": 1}").await;
    h.ledger
        .open(&h.run, &plan_1, &tasks())
        .await
        .expect("the graph opens");
    let first = slug("t-001");
    h.ledger
        .start(&h.run, &first, &h.hold)
        .await
        .expect("the task starts");

    h.ledger
        .record_run(&h.run, &first, &h.hold, &ran(Standard, 1200))
        .await
        .expect("the run is recorded");
    // The same record a second time changes nothing.
    h.ledger
        .record_run(&h.run, &first, &h.hold, &ran(Standard, 1200))
        .await
        .expect("a repeat is accepted");
    // The attempt has one record for the task: another content is refused, and so is a task the
    // plan does not have.
    for other in [ran(Large, 1200), ran(Standard, 1201)] {
        assert_eq!(
            h.ledger.record_run(&h.run, &first, &h.hold, &other).await,
            Err(LedgerError::Illegal)
        );
    }
    assert_eq!(
        h.ledger
            .record_run(&h.run, &slug("t-999"), &h.hold, &ran(Standard, 1))
            .await,
        Err(LedgerError::Illegal)
    );
    // A worker that lost its lease records nothing.
    let stale = Hold {
        attempt: h.hold.attempt,
        epoch: LeaseEpoch::new(h.hold.epoch.get() + 1),
    };
    assert_eq!(
        h.ledger
            .record_run(&h.run, &first, &stale, &ran(Standard, 1200))
            .await,
        Err(LedgerError::Fenced)
    );

    let mut tx = h
        .world
        .store
        .begin(TenantScope::new(h.run.tenant))
        .await
        .expect("a transaction");
    let rows = tx.list_task_runs(h.run.stage_run).await.expect("the runs");
    let nodes = tx
        .list_task_nodes(h.run.stage_run)
        .await
        .expect("the nodes");
    let _ = tx.rollback().await;
    assert_eq!(rows.len(), 1, "one row for the task and the attempt");
    let row = &rows[0];
    assert_eq!(row.attempt_id, h.claimed.attempt);
    assert_eq!((row.job_id, row.stage_run_id), (h.run.job, h.run.stage_run));
    assert_eq!(row.task_node_id, nodes[0].value.id);
    assert_eq!(row.tier, Standard);
    assert_eq!(row.model.as_str(), "claude-sonnet-5-5");
    assert_eq!(row.metered.map(|used| used.tokens()), Some(1500));
    assert_eq!(row.metered.map(|used| used.cost_micro_usd()), Some(4_500));
}
