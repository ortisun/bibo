//! The shared store contract suite of `factory-testkit`, run against `PgStore` on a real
//! PostgreSQL server.
//!
//! The suite is the one the in-memory fake passes. Every check gets a database of its own, cloned
//! from a migrated template, and the checks run side by side. The slow ones wait for the database
//! clock (the lease time to live in the suite is 60 seconds), so running them together keeps the
//! whole suite near the length of the longest check.
//!
//! # What does not pass, and why
//!
//! Twelve of the 45 checks cannot pass against the schema as it is. None of them is a defect of
//! the adapter that a code change here could fix. Each is listed in [`EXCLUDED`] with its cause,
//! and the test is strict in both directions: an excluded check **must still fail** with the
//! stated error, so a later fix of the port or the schema cannot leave a stale exclusion behind.
//! Every excluded property is covered by a test of this crate that uses valid data: see the
//! `Covered by` note on each entry.
//!
//! There are four causes:
//!
//! * `LEASE`: the port gives a stage run a lease (worker, epoch, expiry) and leaves it `READY`.
//!   The schema keeps the lease on the attempt and lets the epoch rise only with `READY` to
//!   `RUNNING`. A claim therefore creates the attempt that carries the lease, and the caller's
//!   `insert_attempt` cannot create a second live one. See `src/pg/stage_runs.rs`.
//! * `VERSION`: the fixtures queue events that announce versions 2, 3 and 4 of a job that is at
//!   version 1. The database refuses an event whose aggregate has not reached the version
//!   (`outbox_aggregate_has_reached_version`), at commit.
//! * `TASK`: `NewTaskNode` has no stage run and no plan artifact, and the table requires both.
//!
//! One more property of the fixtures is completed by the subject below, not excluded: the ledger
//! entries of the suite name stage runs that were never created, and the table has a foreign key
//! to `stage_runs`. A trigger that the subject installs in the throwaway database creates the
//! missing run, as the real engine always has, right before the ledger insert.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use factory_ports::store::Store;
use factory_testkit::contracts::store::{StoreSubject, checks};
use factory_testkit::contracts::{Report, SKIPPED_PREFIX};
use support::Scene;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// The checks that cannot pass, with the cause, the text their failure must contain, and where
/// the property is covered instead.
const EXCLUDED: &[(&str, &str, &str, &str)] = &[
    (
        "claiming_sets_the_lease_and_raises_the_epoch",
        "LEASE",
        "expected Ready but found Running",
        "claims_and_leases.rs: a_claim_sets_the_lease_and_raises_the_epoch",
    ),
    (
        "an_attempt_needs_the_current_lease",
        "LEASE",
        "the stage run already has a live attempt",
        "claims_and_leases.rs: stale_lease_epoch_is_fenced",
    ),
    (
        "a_heartbeat_with_the_current_epoch_renews_the_lease",
        "LEASE",
        "the stage run already has a live attempt",
        "claims_and_leases.rs: a_heartbeat_renews_the_lease_by_the_database_clock",
    ),
    (
        "a_heartbeat_after_the_lease_expired_is_fenced",
        "LEASE",
        "the stage run already has a live attempt",
        "claims_and_leases.rs: lease_expiry_uses_database_time",
    ),
    (
        "a_zombie_worker_is_fenced_after_another_worker_takes_over",
        "LEASE",
        "the stage run already has a live attempt",
        "claims_and_leases.rs: stale_lease_epoch_is_fenced",
    ),
    (
        "a_zombie_cannot_change_its_attempt",
        "LEASE",
        "the stage run already has a live attempt",
        "claims_and_leases.rs: stale_lease_epoch_is_fenced",
    ),
    (
        "an_attempt_that_ended_cannot_be_heartbeated",
        "LEASE",
        "the stage run already has a live attempt",
        "claims_and_leases.rs: an_ended_attempt_cannot_be_heartbeated",
    ),
    (
        "expired_leases_lists_only_attempts_past_their_lease",
        "LEASE",
        "the stage run already has a live attempt",
        "claims_and_leases.rs: expired_leases_lists_only_attempts_past_their_lease",
    ),
    (
        "events_read_back_in_the_order_they_were_queued",
        "VERSION",
        "outbox_aggregate_has_reached_version",
        "atomicity.rs: an_event_must_announce_a_version_the_job_has_reached",
    ),
    (
        "reading_resumes_after_the_last_position_seen",
        "VERSION",
        "outbox_aggregate_has_reached_version",
        "atomicity.rs: the_outbox_reads_back_in_order_and_resumes",
    ),
    (
        "events_are_kept_per_job",
        "VERSION",
        "outbox_aggregate_has_reached_version",
        "atomicity.rs: the_outbox_reads_back_in_order_and_resumes",
    ),
    (
        "inserted_rows_read_back_at_the_first_version",
        "TASK",
        "a task node needs a stage run and a plan artifact",
        "tenant_isolation.rs: every_repository_method_refuses_another_tenants_rows",
    ),
];

struct PgSubject {
    scene: Scene,
}

/// Completes what the shared fixtures leave out and PostgreSQL requires: a ledger entry names a
/// stage run, and the table has a foreign key to it. The fixtures never create the run. This runs
/// as the superuser, in the throwaway database only, and creates the run in the same statement
/// and transaction as the ledger insert, so a rolled-back append leaves no run behind.
const COMPLETE_LEDGER_FIXTURE: &str = "
CREATE FUNCTION dbtest_complete_ledger_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status)
  SELECT NEW.tenant_id, NEW.stage_run_id, NEW.job_id, 'INTAKE',
         coalesce((SELECT max(run_number) FROM stage_runs
                    WHERE tenant_id = NEW.tenant_id AND job_id = NEW.job_id AND stage_kind = 'INTAKE'), 0) + 1,
         'PENDING'
   WHERE NOT EXISTS (SELECT 1 FROM stage_runs WHERE tenant_id = NEW.tenant_id AND id = NEW.stage_run_id);
  RETURN NEW;
END
$$;
CREATE TRIGGER dbtest_complete_ledger_fixture BEFORE INSERT ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION dbtest_complete_ledger_fixture();
";

impl PgSubject {
    async fn new() -> Self {
        let scene = Scene::new().await;
        scene.db.run(COMPLETE_LEDGER_FIXTURE).await;
        Self { scene }
    }
}

#[async_trait]
impl StoreSubject for PgSubject {
    fn store(&self) -> &dyn Store {
        &self.scene.store
    }

    /// A real store waits. The database clock is the server's, so there is nothing to shift.
    async fn advance_database_time(&self, by: Duration) {
        tokio::time::sleep(by + Duration::from_millis(100)).await;
    }
}

/// Runs every check, all together, each on a fresh database.
async fn run_all() -> Report {
    let gate = Arc::new(Semaphore::new(12));
    let mut tasks = JoinSet::new();
    for check in checks() {
        let gate = gate.clone();
        tasks.spawn(async move {
            let _slot = gate.acquire_owned().await.expect("the gate stays open");
            let subject: Box<dyn StoreSubject> = Box::new(PgSubject::new().await);
            let outcome = (check.run)(&*subject).await;
            (check.name, outcome)
        });
    }
    let mut report = Report::default();
    while let Some(done) = tasks.join_next().await {
        let (name, outcome) = done.expect("a check task does not panic");
        match outcome {
            Ok(()) => report.passed.push(name),
            Err(why) if why.starts_with(SKIPPED_PREFIX) => report.skipped.push((name, why)),
            Err(why) => report.failed.push((name, why)),
        }
    }
    report.passed.sort_unstable();
    report.failed.sort_by_key(|(name, _)| *name);
    report
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shared_store_contract_suite_against_postgres() {
    let report = run_all().await;
    let total = report.passed.len() + report.failed.len() + report.skipped.len();
    eprintln!(
        "{} checks: {} passed, {} failed, {} skipped",
        total,
        report.passed.len(),
        report.failed.len(),
        report.skipped.len()
    );
    let failed: BTreeMap<&str, &str> = report
        .failed
        .iter()
        .map(|(name, why)| (*name, why.as_str()))
        .collect();
    let mut problems = Vec::new();

    // 1. Every exclusion must name a real check, and the check must still fail the stated way.
    for (name, cause, expected, covered_by) in EXCLUDED {
        if !checks().iter().any(|check| check.name == *name) {
            problems.push(format!(
                "the excluded check {name} no longer exists in the suite"
            ));
            continue;
        }
        match failed.get(name) {
            Some(why) if why.contains(expected) => {
                eprintln!("  excluded [{cause}] {name}\n      covered by {covered_by}");
            }
            Some(why) => problems.push(format!(
                "the excluded check {name} fails for another reason than {cause}: {why}"
            )),
            None => problems.push(format!(
                "the excluded check {name} passes now: remove it from EXCLUDED ({cause})"
            )),
        }
    }
    // 2. Every other check must pass.
    for (name, why) in &failed {
        if !EXCLUDED.iter().any(|(excluded, ..)| excluded == name) {
            problems.push(format!("{name}: {why}"));
        }
    }
    assert!(
        report.skipped.is_empty(),
        "skipped checks: {:?}",
        report.skipped
    );
    assert!(
        problems.is_empty(),
        "the contract suite found problems:\n  {}",
        problems.join("\n  ")
    );
}
