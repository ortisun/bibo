//! NT-BUD-01 and NT-BUD-07 (and the counting rule of NT-BUD-03 and NT-BUD-08) against the real
//! listener and a fake provider that reports usage.
//!
//! The attacker is a client that loops model calls, or one that ignores its own budget flag. The
//! assertion is made where the factory controls the boundary: the broker's answers, its ledger and
//! audit stream, and the fake provider's own request log.

mod support;

use std::time::{Duration, Instant};

use factory_egress::broker::{AuditKind, CapPolicy, LedgerKind, Refusal, RevokeReason};
use factory_ports::agent::{CostMicroUsd, ModelBroker, TokenState};
use support::{CEILING, HttpRig};

/// NT-BUD-01. A client loops model calls against a fake provider that reports usage. At the
/// ceiling the broker revokes the job token and refuses further calls. Recorded cost is at most
/// the ceiling plus one maximum request. A later request is refused (402 here). Audit events are
/// written at 80 and 100 percent.
#[test]
fn negative_nt_bud_01_per_task_cost_ceiling_stops_a_looping_client() {
    let rig = HttpRig::new();
    // One request costs 1532 micro-dollars in the test prices: a ceiling of 10_000 is crossed by
    // the seventh request.
    let ceiling = CostMicroUsd(10_000);
    let one_request = 1532;
    let token = rig.claude_token(ceiling);
    let mut statuses = Vec::new();
    for _ in 0..12 {
        statuses.push(rig.claude(&token, true).status);
    }
    let allowed = statuses.iter().filter(|s| **s == 200).count();
    assert_eq!(allowed, 7, "statuses: {statuses:?}");
    assert!(
        statuses[7..].iter().all(|s| *s == 402),
        "every request after the ceiling is refused with 402: {statuses:?}"
    );
    // The provider saw exactly the requests that were allowed, and none after the stop.
    assert_eq!(rig.provider.hits(), 7);

    let standing = rig.rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(standing.state, TokenState::Revoked);
    assert!(
        standing.usage.cost.0 <= ceiling.0 + one_request,
        "recorded cost {} passes the ceiling {} by more than one request",
        standing.usage.cost.0,
        ceiling.0
    );
    assert_eq!(
        rig.rig.core.revoke_reason(&token.id),
        Some(RevokeReason::CostCeiling)
    );

    let percents: Vec<u8> = rig
        .rig
        .audit
        .events()
        .iter()
        .filter_map(|e| match e.kind {
            AuditKind::BudgetThreshold { percent, .. } => Some(percent),
            _ => None,
        })
        .collect();
    assert_eq!(percents, vec![80, 100]);
    let job = rig.rig.core.ledger(
        rig.rig
            .audit
            .events()
            .iter()
            .find_map(|e| match e.kind {
                AuditKind::TokenIssued { job, .. } => Some(job),
                _ => None,
            })
            .expect("the token was issued"),
    );
    assert!(job.entries.iter().any(|e| matches!(
        e.kind,
        LedgerKind::Refused(Refusal::Revoked(RevokeReason::CostCeiling))
    )));
}

/// NT-BUD-07. The tool ignores its own budget flag (Codex has none): only the broker stops it.
/// The token is revoked mid-run, and the next request is refused, within two seconds. The broker
/// counts every POST that it forwards, retries included, so its count is the provider's count.
#[tokio::test]
async fn negative_nt_bud_07_a_tool_that_ignores_its_budget_is_still_stopped_and_counted() {
    let rig = HttpRig::new();
    let token = rig.codex_token(CEILING);
    for _ in 0..5 {
        assert_eq!(rig.codex(&token, true).status, 200);
    }
    let revoked_at = Instant::now();
    rig.rig.core.revoke(&token.id).await.expect("revoke");
    let refused = rig.codex(&token, true);
    let latency = revoked_at.elapsed();
    assert_eq!(
        refused.status, 401,
        "a revoke by a person is a 401, a budget stop is a 402"
    );
    assert!(
        latency < Duration::from_secs(2),
        "the first refusal took {latency:?}, more than the two seconds NT-BUD-07 allows"
    );
    // The tool retries a refused token. Each retry is refused, and none reaches the provider.
    for _ in 0..10 {
        assert_eq!(rig.codex(&token, true).status, 401);
    }
    let usage = rig.rig.core.token_usage(&token.id).expect("usage").usage;
    assert_eq!(usage.requests, 5);
    assert_eq!(
        usage.requests as usize,
        rig.provider.hits(),
        "the broker's count of forwarded requests equals the provider's log"
    );
}

/// NT-BUD-07, the budget stop: a cap answers 402, the status on which Claude Code stops at once,
/// and the token reads as revoked for the supervisor, which then kills the container.
#[test]
fn negative_nt_bud_07_a_turn_cap_stops_a_tool_that_has_no_turn_limit_of_its_own() {
    let rig = HttpRig::with_caps(CapPolicy {
        max_requests: Some(4),
        ..CapPolicy::default()
    });
    let token = rig.codex_token(CEILING);
    let statuses: Vec<u16> = (0..8).map(|_| rig.codex(&token, true).status).collect();
    assert_eq!(statuses, vec![200, 200, 200, 200, 402, 402, 402, 402]);
    assert_eq!(rig.provider.hits(), 4, "no provider call after the stop");
    assert_eq!(
        rig.rig.core.token_usage(&token.id).expect("usage").state,
        TokenState::Revoked
    );
    assert_eq!(
        rig.rig.core.revoke_reason(&token.id),
        Some(RevokeReason::RequestCap)
    );
}

/// NT-BUD-08. A provider that fails after the broker forwarded still counts, and a client that
/// retries aggressively is counted per attempt.
#[test]
fn negative_nt_bud_07_failed_attempts_are_counted_per_attempt() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    rig.provider.set(|s| s.error_status = Some(500));
    for _ in 0..30 {
        assert_eq!(rig.claude(&token, true).status, 500);
    }
    let usage = rig.rig.core.token_usage(&token.id).expect("usage").usage;
    assert_eq!(usage.requests, 30);
    assert_eq!(usage.requests as usize, rig.provider.hits());
    assert_eq!(
        usage.cost,
        CostMicroUsd(0),
        "a refused attempt consumed nothing"
    );
}
