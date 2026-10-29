//! A person's approval of a specification draft.
//!
//! Found by the full run (`apps/api/tests/full_run.rs`): the specification stage keeps its draft
//! aside and waits for a person, and its next attempt reads the person's approval from the ledger
//! and freezes that draft. The engine passed a waiting stage run on an approval (`S14`), which for
//! this stage would pass a run that had stored nothing, so no approval of a specification could
//! lead anywhere. The approval now records the judgment and sends the run back to `READY` the way
//! an answer does (`S13`), and the stage passes by its own next attempt.

mod support;

use factory_domain::contracts::evidence_ledger_entry::{ClaimKind, Evidence};
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_workflow::commands::{Decision, Subject};
use factory_workflow::engine::{AttemptOutcome, EngineError};
use support::Step;
use support::World;

async fn run_one(world: &World) -> AttemptOutcome {
    world.advance_time(400).await;
    world.run_next("worker-1").await.1
}

/// A job whose specification stage has asked a person: the first two stages passed.
async fn asking(world: &World) -> (factory_domain::ids::JobId, factory_domain::ids::StageRunId) {
    world
        .script(StageKind::Specification)
        .queue([Step::NeedsHuman, Step::Succeed]);
    let job = world.admitted_job().await;
    assert_eq!(run_one(world).await, AttemptOutcome::Succeeded);
    assert_eq!(run_one(world).await, AttemptOutcome::Succeeded);
    assert_eq!(run_one(world).await, AttemptOutcome::NeedsHuman);
    let view = world.view(job).await;
    let run = view.newest(StageKind::Specification).expect("a run");
    assert_eq!(run.status, StageRunStatus::WaitingForHuman);
    (job, run.id)
}

async fn head(world: &World, job: factory_domain::ids::JobId) -> Sha256Digest {
    world
        .ledger(job)
        .await
        .last()
        .expect("an entry")
        .entry_hash
        .clone()
}

#[tokio::test]
async fn an_approval_records_the_judgment_and_sends_the_stage_back_to_ready() {
    let world = World::new().await;
    let (job, run) = asking(&world).await;
    let approver = world.person("approver-1", &[HumanRole::Approver]).await;
    let seen = head(&world, job).await;
    world
        .engine
        .decide(
            &world.actor(approver),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Approve {
                evidence_seen: seen,
                warnings_decided: true,
            },
        )
        .await
        .expect("the approval applies");

    // The run is not passed: it has stored no specification yet. It waits for its next attempt.
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Specification).expect("a run").status,
        StageRunStatus::Ready
    );
    assert_eq!(view.status, JobStatus::Active);

    // The person's judgment is in the ledger of the stage run, in the words the stage's own seam
    // reads (`StoreSpecApprovals` looks for " approved the " in an expert judgment).
    let approvals: Vec<_> = world
        .ledger(job)
        .await
        .into_iter()
        .filter(|entry| entry.claim.kind == ClaimKind::ExpertJudgment)
        .filter(|entry| entry.claim.statement.as_str().contains(" approved the "))
        .collect();
    assert_eq!(approvals.len(), 1);
    assert!(matches!(
        approvals[0].evidence.first(),
        Some(Evidence::ExpertJudgment(judgment)) if judgment.attestor.principal_id == approver
    ));

    // The next attempt is the stage's own, and it passes the run.
    assert_eq!(run_one(&world).await, AttemptOutcome::Succeeded);
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Specification).expect("a run").status,
        StageRunStatus::Passed
    );
    assert_eq!(
        factory_domain::ledger::verify_chain(&world.ledger(job).await),
        Ok(())
    );
}

#[tokio::test]
async fn an_approval_of_what_the_person_did_not_see_is_refused_and_moves_nothing() {
    let world = World::new().await;
    let (job, run) = asking(&world).await;
    let approver = world.person("approver-1", &[HumanRole::Approver]).await;
    let stale = Sha256Digest::of(b"something the person saw long ago");
    let refused = world
        .engine
        .decide(
            &world.actor(approver),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Approve {
                evidence_seen: stale,
                warnings_decided: true,
            },
        )
        .await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "{refused:?}"
    );
    assert_eq!(
        world
            .view(job)
            .await
            .newest(StageKind::Specification)
            .expect("a run")
            .status,
        StageRunStatus::WaitingForHuman
    );
}

#[tokio::test]
async fn nobody_approves_their_own_request() {
    let world = World::new().await;
    let (job, run) = asking(&world).await;
    // The requester of the job also holds the approver role: still not allowed.
    world
        .authority
        .grant(world.requester, &[HumanRole::Approver]);
    let seen = head(&world, job).await;
    let refused = world
        .engine
        .decide(
            &world.actor(world.requester),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Approve {
                evidence_seen: seen,
                warnings_decided: true,
            },
        )
        .await;
    assert!(
        matches!(refused, Err(EngineError::NotAuthorized(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn the_same_approval_twice_is_applied_once() {
    let world = World::new().await;
    let (job, run) = asking(&world).await;
    let approver = world.person("approver-1", &[HumanRole::Approver]).await;
    let seen = head(&world, job).await;
    let actor = world.actor(approver);
    let subject = Subject {
        job,
        stage_run: run,
    };
    let decision = Decision::Approve {
        evidence_seen: seen,
        warnings_decided: true,
    };
    world
        .engine
        .decide(&actor, subject, decision.clone())
        .await
        .expect("the first applies");
    let again = world.engine.decide(&actor, subject, decision).await;
    assert!(matches!(again, Err(EngineError::Duplicate)), "{again:?}");
}
