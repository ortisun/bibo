//! The in-memory store against the shared store contract suite, and against each deliberate
//! defect. The defect tests prove the suite can fail: a store that breaks one rule must fail the
//! check that guards that rule.

use factory_testkit::contracts::store::{self, StoreCheck};
use factory_testkit::store::{InMemoryStoreSubject, StoreDefect};

#[tokio::test]
async fn the_in_memory_store_passes_the_store_contract() {
    let report = store::run(|| async { InMemoryStoreSubject::new() }).await;
    report.assert_ok();
    assert_eq!(
        report.passed.len(),
        store::checks().len(),
        "every check must have run"
    );
}

#[test]
fn every_store_check_has_a_unique_name() {
    let checks: Vec<StoreCheck> = store::checks();
    let mut names: Vec<&str> = checks.iter().map(|check| check.name).collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "two checks share a name");
}

/// Each defect, and the checks that must catch it.
const DEFECTS: [(StoreDefect, &[&str]); 8] = [
    (
        StoreDefect::DoubleGrantsLease,
        &["a_ready_stage_run_is_claimed_by_exactly_one_worker"],
    ),
    (
        StoreDefect::IgnoresLeaseEpoch,
        &[
            "an_attempt_needs_the_current_lease",
            "a_zombie_worker_is_fenced_after_another_worker_takes_over",
            "a_zombie_cannot_change_its_attempt",
        ],
    ),
    (
        StoreDefect::SkipsVersionCheck,
        &["a_stale_version_conflicts_and_changes_nothing"],
    ),
    (
        StoreDefect::LosesLastOutboxRow,
        &[
            "events_read_back_in_the_order_they_were_queued",
            "status_ledger_and_outbox_commit_together_or_not_at_all",
        ],
    ),
    (
        StoreDefect::ReversesOutboxOrder,
        &["events_read_back_in_the_order_they_were_queued"],
    ),
    (
        StoreDefect::ReadsAcrossTenants,
        &["a_row_of_another_tenant_looks_like_a_missing_row"],
    ),
    (
        StoreDefect::AcceptsBrokenChain,
        &[
            "a_ledger_entry_with_the_wrong_previous_hash_breaks_the_chain",
            "a_ledger_entry_with_a_wrong_own_hash_is_refused",
        ],
    ),
    (
        StoreDefect::KeepsWritesOnDrop,
        &["writes_are_invisible_until_commit_and_vanish_on_drop"],
    ),
];

#[tokio::test]
async fn the_store_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let report = store::run(|| async move { InMemoryStoreSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a store with the defect {defect:?}"
        );
        for name in must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail the check {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}

#[tokio::test]
async fn a_double_granted_lease_is_reported_in_plain_words() {
    let report =
        store::run(|| async { InMemoryStoreSubject::with_defect(StoreDefect::DoubleGrantsLease) })
            .await;
    let (_, why) = report
        .failed
        .iter()
        .find(|(name, _)| *name == "a_ready_stage_run_is_claimed_by_exactly_one_worker")
        .expect("the claim check must fail");
    assert!(
        why.contains("a claim while another open transaction holds the row"),
        "{why}"
    );
}
