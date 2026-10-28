//! The rules of the broker core that the shared contract suite does not reach: audience, model
//! lists, expiry, the caps and the reason each stop is recorded with, counting of failed attempts,
//! and the audit events at 80 and 100 percent.

mod support;

use std::time::Duration;

use factory_egress::broker::{
    AuditKind, CapPolicy, LedgerKind, Outcome, Provider, Refusal, RequestFacts, RevokeReason,
    TokenCounts,
};
use factory_ports::agent::{CostMicroUsd, ModelBroker, TokenState};
use support::{CEILING, CLAUDE_MODEL, GPT_MODEL, Rig};

fn facts(model: &str) -> RequestFacts<'_> {
    RequestFacts {
        provider: Provider::Anthropic,
        model,
        expected_job: None,
    }
}

/// A usage of `input` plain input tokens, at one micro-dollar each in the test prices.
fn input_tokens(input: u64) -> Outcome {
    Outcome::Counted(TokenCounts {
        input,
        ..TokenCounts::default()
    })
}

async fn issue(
    rig: &Rig,
    ceiling: CostMicroUsd,
) -> (
    factory_ports::agent::IssuedJobToken,
    factory_domain::ids::JobId,
) {
    let request = rig.request(ceiling);
    let job = request.job;
    (rig.core.issue(request).await.expect("a token"), job)
}

#[tokio::test]
async fn a_valid_token_is_admitted_and_counted_and_a_garbage_credential_is_unknown() {
    let rig = Rig::new();
    let (token, _) = issue(&rig, CEILING).await;
    let permit = rig
        .core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("admitted");
    assert_eq!(permit.token(), token.id);
    assert_eq!(
        rig.core
            .token_usage(&token.id)
            .expect("usage")
            .usage
            .requests,
        1
    );
    permit.settle(input_tokens(10));
    for garbage in [
        "",
        "sfjt_",
        "sfjt_not-a-real-token",
        "Bearer x",
        "sk-something",
    ] {
        assert_eq!(
            rig.core
                .authorize(garbage, &facts(CLAUDE_MODEL))
                .unwrap_err(),
            Refusal::UnknownToken,
            "{garbage:?}"
        );
    }
}

#[tokio::test]
async fn a_token_for_one_job_is_useless_for_another_and_spend_stays_with_its_own_job() {
    let rig = Rig::new();
    let (a, job_a) = issue(&rig, CEILING).await;
    let (b, job_b) = issue(&rig, CEILING).await;
    let at_b = RequestFacts {
        expected_job: Some(job_b),
        ..facts(CLAUDE_MODEL)
    };
    assert_eq!(
        rig.core.authorize(a.secret.expose(), &at_b).unwrap_err(),
        Refusal::WrongAudience,
        "job A's token at job B's listener"
    );
    assert_eq!(Refusal::WrongAudience.http_status(), 403);
    let at_a = RequestFacts {
        expected_job: Some(job_a),
        ..facts(CLAUDE_MODEL)
    };
    let permit = rig
        .core
        .authorize(a.secret.expose(), &at_a)
        .expect("job A's token at job A's listener");
    permit.settle(input_tokens(500));
    assert_eq!(rig.core.ledger(job_a).total.cost, CostMicroUsd(500));
    assert_eq!(rig.core.ledger(job_b).total.cost, CostMicroUsd(0));
    assert_eq!(
        rig.core.token_usage(&b.id).expect("usage").usage.cost,
        CostMicroUsd(0)
    );
    // Ending job B revokes nothing of job A.
    rig.core.revoke_for_job(job_b).await.expect("revoke");
    assert_eq!(
        rig.core.token_usage(&a.id).expect("usage").state,
        TokenState::Active
    );
}

#[tokio::test]
async fn a_token_works_at_its_own_provider_only_and_for_its_listed_models_only() {
    let rig = Rig::new();
    let (token, _) = issue(&rig, CEILING).await;
    let openai = RequestFacts {
        provider: Provider::OpenAi,
        model: GPT_MODEL,
        expected_job: None,
    };
    assert_eq!(
        rig.core
            .authorize(token.secret.expose(), &openai)
            .unwrap_err(),
        Refusal::WrongAudience
    );
    assert_eq!(
        rig.core
            .authorize(token.secret.expose(), &facts(GPT_MODEL))
            .unwrap_err(),
        Refusal::ModelNotAllowed,
        "a model that is priced but not on the token's list"
    );
    assert_eq!(
        rig.core
            .authorize(token.secret.expose(), &facts("claude-unlisted"))
            .unwrap_err(),
        Refusal::ModelNotAllowed
    );
    // None of the refusals counted as a request.
    assert_eq!(
        rig.core
            .token_usage(&token.id)
            .expect("usage")
            .usage
            .requests,
        0
    );
}

#[tokio::test]
async fn an_expired_token_and_a_revoked_token_are_refused_with_401() {
    let rig = Rig::new();
    let (expiring, _) = issue(&rig, CEILING).await;
    let (revoked, _) = issue(&rig, CEILING).await;
    rig.core.revoke(&revoked.id).await.expect("revoke");
    assert_eq!(
        rig.core
            .authorize(revoked.secret.expose(), &facts(CLAUDE_MODEL))
            .unwrap_err(),
        Refusal::Revoked(RevokeReason::Requested)
    );
    assert_eq!(Refusal::Revoked(RevokeReason::Requested).http_status(), 401);
    rig.clock.advance(Duration::from_secs(3601));
    let refusal = rig
        .core
        .authorize(expiring.secret.expose(), &facts(CLAUDE_MODEL))
        .unwrap_err();
    assert_eq!(refusal, Refusal::Expired);
    assert_eq!(refusal.http_status(), 401);
}

/// NT-BUD-01 at the level of the core: a looping client is stopped at the ceiling, the stop has a
/// recorded reason, the recorded cost is at most the ceiling plus one maximum request, and the
/// audit stream has one event at 80 percent and one at 100 percent.
#[tokio::test]
async fn a_looping_client_is_stopped_at_the_ceiling_with_a_recorded_reason() {
    let rig = Rig::new();
    let (token, job) = issue(&rig, CEILING).await;
    // Each request costs 150_000 micro-dollars: the ceiling is crossed by the seventh.
    let one_request = 150_000;
    let mut admitted = 0;
    let refusal = loop {
        match rig
            .core
            .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        {
            Ok(permit) => {
                admitted += 1;
                permit.settle(input_tokens(one_request));
            }
            Err(refusal) => break refusal,
        }
        assert!(admitted < 20, "the loop was never stopped");
    };
    assert_eq!(refusal, Refusal::Revoked(RevokeReason::CostCeiling));
    assert_eq!(refusal.http_status(), 402, "a budget stop answers 402");
    assert_eq!(admitted, 7);
    let standing = rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(standing.state, TokenState::Revoked);
    assert!(
        standing.usage.cost.0 <= CEILING.0 + one_request,
        "recorded cost {} passes the ceiling by more than one request",
        standing.usage.cost.0
    );
    assert_eq!(
        standing.usage.requests, 7,
        "the refused request is not counted"
    );
    assert_eq!(
        rig.core.revoke_reason(&token.id),
        Some(RevokeReason::CostCeiling)
    );

    let thresholds: Vec<u8> = rig
        .audit
        .events()
        .iter()
        .filter_map(|e| match e.kind {
            AuditKind::BudgetThreshold { percent, .. } => Some(percent),
            _ => None,
        })
        .collect();
    assert_eq!(
        thresholds,
        vec![80, 100],
        "one event at each threshold, once"
    );

    let ledger = rig.core.ledger(job);
    assert!(
        ledger
            .entries
            .iter()
            .any(|e| e.kind == LedgerKind::Refused(Refusal::Revoked(RevokeReason::CostCeiling)))
    );
    assert!(
        ledger
            .entries
            .iter()
            .any(|e| e.kind == LedgerKind::Revoked(RevokeReason::CostCeiling))
    );
    assert_eq!(ledger.total, standing.usage);
}

#[tokio::test]
async fn a_request_cap_refuses_the_next_request_and_revokes_the_token() {
    let rig = Rig::with_caps(CapPolicy {
        max_requests: Some(3),
        ..CapPolicy::default()
    });
    let (token, job) = issue(&rig, CEILING).await;
    for _ in 0..3 {
        rig.core
            .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
            .expect("inside the cap")
            .settle(input_tokens(1));
    }
    assert_eq!(
        rig.core.token_usage(&token.id).expect("usage").state,
        TokenState::Active,
        "the cap is enforced at the next request, so the last allowed one is not cut short"
    );
    let refusal = rig
        .core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .unwrap_err();
    assert_eq!(refusal, Refusal::Revoked(RevokeReason::RequestCap));
    let standing = rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(standing.state, TokenState::Revoked);
    assert_eq!(standing.usage.requests, 3);
    assert!(
        rig.core
            .ledger(job)
            .entries
            .iter()
            .any(|e| e.kind == LedgerKind::Refused(Refusal::Revoked(RevokeReason::RequestCap)))
    );
}

#[tokio::test]
async fn the_token_caps_revoke_the_token_when_they_are_reached() {
    let rig = Rig::with_caps(CapPolicy {
        max_input_tokens: Some(1_000),
        ..CapPolicy::default()
    });
    let (token, _) = issue(&rig, CEILING).await;
    rig.core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("admitted")
        .settle(input_tokens(1_000));
    assert_eq!(
        rig.core.revoke_reason(&token.id),
        Some(RevokeReason::InputTokenCap)
    );
    assert!(
        rig.core
            .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
            .is_err()
    );

    let rig = Rig::with_caps(CapPolicy {
        max_output_tokens: Some(100),
        ..CapPolicy::default()
    });
    let (token, _) = issue(&rig, CEILING).await;
    rig.core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("admitted")
        .settle(Outcome::Counted(TokenCounts {
            output: 100,
            ..TokenCounts::default()
        }));
    assert_eq!(
        rig.core.revoke_reason(&token.id),
        Some(RevokeReason::OutputTokenCap)
    );
}

#[tokio::test]
async fn the_per_minute_rate_limit_refuses_with_a_delay_and_recovers_with_time() {
    let rig = Rig::with_caps(CapPolicy {
        max_requests_per_minute: Some(2),
        max_in_flight: 10,
        ..CapPolicy::default()
    });
    let (token, _) = issue(&rig, CEILING).await;
    for _ in 0..2 {
        rig.core
            .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
            .expect("inside the rate")
            .settle(input_tokens(1));
    }
    rig.clock.advance(Duration::from_secs(20));
    let refusal = rig
        .core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .unwrap_err();
    assert_eq!(
        refusal,
        Refusal::RateLimited {
            retry_after_secs: 41
        }
    );
    assert_eq!(refusal.http_status(), 429);
    assert_eq!(
        rig.core.token_usage(&token.id).expect("usage").state,
        TokenState::Active,
        "a rate limit does not revoke"
    );
    rig.clock.advance(Duration::from_secs(41));
    rig.core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("the window moved on");
}

#[tokio::test]
async fn the_in_flight_limit_bounds_how_far_the_cost_can_pass_the_ceiling() {
    let rig = Rig::with_caps(CapPolicy {
        max_in_flight: 1,
        ..CapPolicy::default()
    });
    let (token, _) = issue(&rig, CEILING).await;
    let first = rig
        .core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("admitted");
    assert_eq!(
        rig.core
            .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
            .unwrap_err(),
        Refusal::TooManyInFlight
    );
    first.settle(input_tokens(1));
    rig.core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("the slot was released");
}

/// NT-BUD-07 and NT-BUD-08: a request whose answer could not be read, or that was dropped, still
/// counts, and it is charged the worst case for one request so that abandoning is never cheaper.
#[tokio::test]
async fn failed_and_abandoned_requests_still_count_and_an_unread_answer_is_charged_in_full() {
    let rig = Rig::new();
    let (token, _) = issue(&rig, CEILING).await;
    rig.core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("admitted")
        .settle(Outcome::NoCharge);
    let after_failure = rig.core.token_usage(&token.id).expect("usage").usage;
    assert_eq!(after_failure.requests, 1, "a failed attempt is counted");
    assert_eq!(after_failure.cost, CostMicroUsd(0));

    let dropped = rig
        .core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("admitted");
    drop(dropped);
    let after_drop = rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(after_drop.usage.requests, 2);
    // 200_000 input tokens as cache writes at 1.25 and 32_000 output tokens at 5, per million.
    let worst = 250_000 + 160_000;
    assert_eq!(after_drop.usage.cost, CostMicroUsd(worst));
    assert_eq!(after_drop.state, TokenState::Active);

    rig.core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("admitted")
        .settle(Outcome::Unreadable);
    let after_unread = rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(after_unread.usage.cost, CostMicroUsd(2 * worst));
    let settled: Vec<bool> = rig
        .audit
        .events()
        .iter()
        .filter_map(|e| match e.kind {
            AuditKind::RequestSettled { usage_read, .. } => Some(usage_read),
            _ => None,
        })
        .collect();
    assert_eq!(settled, vec![true, false, false]);
}

#[tokio::test]
async fn spend_that_finishes_after_a_revoke_is_still_recorded_and_the_token_stays_revoked() {
    let rig = Rig::new();
    let (token, job) = issue(&rig, CEILING).await;
    let permit = rig
        .core
        .authorize(token.secret.expose(), &facts(CLAUDE_MODEL))
        .expect("admitted");
    rig.core.revoke_for_job(job).await.expect("revoke");
    permit.settle(input_tokens(700));
    let standing = rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(
        standing.usage.cost,
        CostMicroUsd(700),
        "the money was spent"
    );
    assert_eq!(standing.state, TokenState::Revoked);
    assert_eq!(
        rig.core.revoke_reason(&token.id),
        Some(RevokeReason::JobEnded)
    );
    assert_eq!(rig.core.ledger(job).total.cost, CostMicroUsd(700));
}

#[tokio::test]
async fn a_model_with_no_price_is_refused_and_not_guessed() {
    // The made-up price table has no entry for this model, but the token lists it.
    let rig = Rig::new();
    let mut request = rig.request(CEILING);
    request.allowed_models[0].model =
        factory_domain::values::NonEmptyString::parse("model-with-no-price").expect("a name");
    let token = rig.core.issue(request).await.expect("a token");
    assert_eq!(
        rig.core
            .authorize(token.secret.expose(), &facts("model-with-no-price"))
            .unwrap_err(),
        Refusal::PriceUnknown
    );
}
