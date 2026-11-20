//! The contract suite for the `ModelBroker` port: issuing a bound token, metering, revocation at
//! the ceiling and on request, and expiry.
//!
//! Spending is not a method of the port: the real broker meters requests that arrive from the
//! per-job sidecar. The subject therefore supplies [`BrokerSubject::spend`], which sends one
//! metered request through the broker the way the sidecar would (for a real broker, a request to
//! its listener answered by a scripted fake provider).

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use factory_ports::agent::{
    BrokerError, CostMicroUsd, JobTokenId, JobTokenRequest, ModelBroker, TokenState, Usage,
};

use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks,
};

/// Whether the broker let a metered request through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spend {
    /// The request was forwarded and its usage was recorded.
    Allowed,
    /// The request was refused. Nothing was recorded.
    Refused,
}

/// What the suite needs beyond the `ModelBroker` port itself.
#[async_trait]
pub trait BrokerSubject: Send + Sync {
    /// The broker under test.
    fn broker(&self) -> &dyn ModelBroker;

    /// A valid token request. Its cost ceiling is `ceiling()` and its lifetime is `lifetime()`.
    fn request(&self) -> JobTokenRequest;

    /// Sends one metered request that uses `usage` through the broker with this token.
    async fn spend(&self, token: &JobTokenId, usage: Usage) -> Spend;

    /// Lets `by` of time pass. A fake moves its clock. A real broker sleeps.
    async fn advance_time(&self, by: Duration);
}

/// A check of the broker contract.
pub type BrokerCheck = Check<dyn BrokerSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: BrokerSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn BrokerSubject>
    })
    .await
}

/// Every check of the broker contract.
#[must_use]
pub fn checks() -> Vec<BrokerCheck> {
    check_list![dyn BrokerSubject;
        an_issued_token_starts_active_with_no_usage,
        a_secret_never_appears_in_debug_output,
        an_invalid_request_is_refused,
        spending_is_metered_against_the_token,
        a_token_that_reaches_its_ceiling_is_revoked_and_refuses_more,
        revoking_stops_spending_and_keeps_the_usage_readable,
        revoking_twice_or_revoking_an_unknown_token_succeeds,
        an_unknown_token_has_no_usage,
        a_token_expires_with_time,
        tokens_are_independent,
        revoke_for_job_revokes_every_token_of_the_job,
        metering_to_the_ceiling_revokes_the_token,
        spend_under_a_revoked_token_is_refused,
    ]
}

/// The secret check cannot fail through the fake: the type decides what `Debug` shows.
pub const WAIVERS: &[Waiver] = &[Waiver {
    check: "a_secret_never_appears_in_debug_output",
    reason: "JobTokenSecret implements Debug in the ports crate, so no fake can make it show the secret.",
    trigger: "None: the unit test of JobTokenSecret in factory-ports is the proof. This check guards the real broker's own types.",
}];

fn cost(micro: u64) -> Usage {
    Usage {
        input_tokens: 100,
        output_tokens: 10,
        cost: CostMicroUsd(micro),
        requests: 1,
    }
}

async fn an_issued_token_starts_active_with_no_usage(
    subject: &dyn BrokerSubject,
) -> Result<(), String> {
    let request = subject.request();
    let first = subject
        .broker()
        .issue(request.clone())
        .await
        .ctx("first issue")?;
    let second = subject
        .broker()
        .issue(request.clone())
        .await
        .ctx("second issue")?;
    ensure!(first.id != second.id, "two tokens must have different ids");
    ensure!(!first.secret.expose().is_empty(), "a token needs a secret");
    ensure!(
        first.secret != second.secret,
        "two tokens must have different secrets"
    );
    let standing = subject.broker().usage(&first.id).await.ctx("usage")?;
    ensure_eq!(standing.state, TokenState::Active, "a new token's state");
    ensure_eq!(standing.usage, Usage::default(), "a new token's usage");
    ensure_eq!(
        standing.ceiling,
        request.cost_ceiling,
        "the ceiling the token was issued with"
    );
    Ok(())
}

async fn a_secret_never_appears_in_debug_output(subject: &dyn BrokerSubject) -> Result<(), String> {
    let issued = subject
        .broker()
        .issue(subject.request())
        .await
        .ctx("issue")?;
    let shown = format!("{issued:?}");
    ensure!(
        !shown.contains(issued.secret.expose()),
        "the debug output of an issued token must not show the secret"
    );
    Ok(())
}

async fn an_invalid_request_is_refused(subject: &dyn BrokerSubject) -> Result<(), String> {
    let good = subject.request();
    let mut no_ceiling = good.clone();
    no_ceiling.cost_ceiling = CostMicroUsd(0);
    ensure_err!(
        subject.broker().issue(no_ceiling).await,
        BrokerError::InvalidRequest(_),
        "a token with a zero ceiling"
    );
    let mut no_models = good.clone();
    no_models.allowed_models.clear();
    ensure_err!(
        subject.broker().issue(no_models).await,
        BrokerError::InvalidRequest(_),
        "a token that allows no model"
    );
    let mut no_lifetime = good;
    no_lifetime.ttl = Duration::ZERO;
    ensure_err!(
        subject.broker().issue(no_lifetime).await,
        BrokerError::InvalidRequest(_),
        "a token with no lifetime"
    );
    Ok(())
}

async fn spending_is_metered_against_the_token(subject: &dyn BrokerSubject) -> Result<(), String> {
    let issued = subject
        .broker()
        .issue(subject.request())
        .await
        .ctx("issue")?;
    ensure_eq!(
        subject.spend(&issued.id, cost(1_000)).await,
        Spend::Allowed,
        "the first request"
    );
    ensure_eq!(
        subject.spend(&issued.id, cost(2_500)).await,
        Spend::Allowed,
        "the second request"
    );
    let standing = subject.broker().usage(&issued.id).await.ctx("usage")?;
    ensure_eq!(
        standing.usage,
        cost(1_000).saturating_add(cost(2_500)),
        "the usage after two requests"
    );
    ensure_eq!(
        standing.state,
        TokenState::Active,
        "a token under its ceiling"
    );
    Ok(())
}

async fn a_token_that_reaches_its_ceiling_is_revoked_and_refuses_more(
    subject: &dyn BrokerSubject,
) -> Result<(), String> {
    let request = subject.request();
    let ceiling = request.cost_ceiling.0;
    let issued = subject.broker().issue(request).await.ctx("issue")?;
    ensure_eq!(
        subject.spend(&issued.id, cost(ceiling / 2)).await,
        Spend::Allowed,
        "a request that takes half the ceiling"
    );
    // The request that crosses the ceiling is allowed (the broker cannot know its cost in
    // advance). Everything after it is refused.
    let crossing = subject.spend(&issued.id, cost(ceiling)).await;
    ensure_eq!(
        crossing,
        Spend::Allowed,
        "the request that crosses the ceiling"
    );
    let standing = subject.broker().usage(&issued.id).await.ctx("usage")?;
    ensure_eq!(
        standing.state,
        TokenState::Revoked,
        "a token that reached its ceiling"
    );
    ensure_eq!(
        subject.spend(&issued.id, cost(1)).await,
        Spend::Refused,
        "a request after the ceiling was reached"
    );
    let after = subject.broker().usage(&issued.id).await.ctx("usage")?;
    ensure_eq!(
        after.usage,
        standing.usage,
        "a refused request must record nothing"
    );
    Ok(())
}

async fn revoking_stops_spending_and_keeps_the_usage_readable(
    subject: &dyn BrokerSubject,
) -> Result<(), String> {
    let issued = subject
        .broker()
        .issue(subject.request())
        .await
        .ctx("issue")?;
    subject.spend(&issued.id, cost(500)).await;
    subject.broker().revoke(&issued.id).await.ctx("revoke")?;
    let standing = subject.broker().usage(&issued.id).await.ctx("usage")?;
    ensure_eq!(standing.state, TokenState::Revoked, "a revoked token");
    ensure_eq!(
        standing.usage,
        cost(500),
        "the usage recorded before the revoke"
    );
    ensure_eq!(
        subject.spend(&issued.id, cost(1)).await,
        Spend::Refused,
        "a request after the revoke"
    );
    Ok(())
}

async fn revoking_twice_or_revoking_an_unknown_token_succeeds(
    subject: &dyn BrokerSubject,
) -> Result<(), String> {
    let issued = subject
        .broker()
        .issue(subject.request())
        .await
        .ctx("issue")?;
    subject
        .broker()
        .revoke(&issued.id)
        .await
        .ctx("first revoke")?;
    subject
        .broker()
        .revoke(&issued.id)
        .await
        .ctx("second revoke")?;
    let unknown = JobTokenId::from_uuid(factory_ports::clock::Uuid::from_u128(0xdead_beef));
    subject
        .broker()
        .revoke(&unknown)
        .await
        .ctx("revoke of a token that was never issued")?;
    Ok(())
}

async fn an_unknown_token_has_no_usage(subject: &dyn BrokerSubject) -> Result<(), String> {
    let unknown = JobTokenId::from_uuid(factory_ports::clock::Uuid::from_u128(0xdead_beef));
    ensure_err!(
        subject.broker().usage(&unknown).await,
        BrokerError::UnknownToken,
        "usage of a token that was never issued"
    );
    Ok(())
}

async fn a_token_expires_with_time(subject: &dyn BrokerSubject) -> Result<(), String> {
    let request = subject.request();
    let ttl = request.ttl;
    let issued = subject.broker().issue(request).await.ctx("issue")?;
    ensure_eq!(
        subject.spend(&issued.id, cost(1)).await,
        Spend::Allowed,
        "a request inside the lifetime"
    );
    subject.advance_time(ttl + Duration::from_secs(1)).await;
    let standing = subject.broker().usage(&issued.id).await.ctx("usage")?;
    ensure_eq!(
        standing.state,
        TokenState::Expired,
        "a token past its lifetime"
    );
    ensure_eq!(
        subject.spend(&issued.id, cost(1)).await,
        Spend::Refused,
        "a request after the lifetime"
    );
    Ok(())
}

async fn tokens_are_independent(subject: &dyn BrokerSubject) -> Result<(), String> {
    let one = subject
        .broker()
        .issue(subject.request())
        .await
        .ctx("first issue")?;
    let two = subject
        .broker()
        .issue(subject.request())
        .await
        .ctx("second issue")?;
    subject.spend(&one.id, cost(700)).await;
    ensure_eq!(
        subject
            .broker()
            .usage(&two.id)
            .await
            .ctx("usage of two")?
            .usage,
        Usage::default(),
        "the second token's usage after the first one spent"
    );
    subject.broker().revoke(&one.id).await.ctx("revoke one")?;
    ensure_eq!(
        subject
            .broker()
            .usage(&two.id)
            .await
            .ctx("state of two")?
            .state,
        TokenState::Active,
        "the second token after the first was revoked"
    );
    ensure_eq!(
        subject.spend(&two.id, cost(1)).await,
        Spend::Allowed,
        "a request on the second token"
    );
    Ok(())
}

async fn revoke_for_job_revokes_every_token_of_the_job(
    subject: &dyn BrokerSubject,
) -> Result<(), String> {
    let request = subject.request();
    let first = subject.broker().issue(request.clone()).await.ctx("issue")?;
    let second = subject.broker().issue(request.clone()).await.ctx("issue")?;
    let mut other_job = subject.request();
    other_job.job = factory_domain::ids::JobId::from_uuid(factory_ports::clock::Uuid::from_u128(
        (99_u128 << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ));
    let elsewhere = subject
        .broker()
        .issue(other_job)
        .await
        .ctx("issue for another job")?;
    subject
        .broker()
        .revoke_for_job(request.job)
        .await
        .ctx("revoke for the job")?;
    for token in [&first, &second] {
        ensure_eq!(
            subject.broker().usage(&token.id).await.ctx("usage")?.state,
            TokenState::Revoked,
            "a token of the job"
        );
    }
    ensure_eq!(
        subject
            .broker()
            .usage(&elsewhere.id)
            .await
            .ctx("usage")?
            .state,
        TokenState::Active,
        "a token of another job"
    );
    subject
        .broker()
        .revoke_for_job(request.job)
        .await
        .ctx("a repeat")?;
    Ok(())
}

async fn metering_to_the_ceiling_revokes_the_token(
    subject: &dyn BrokerSubject,
) -> Result<(), String> {
    let request = subject.request();
    let ceiling = request.cost_ceiling.0;
    let issued = subject.broker().issue(request).await.ctx("issue")?;
    subject.spend(&issued.id, cost(ceiling)).await;
    let standing = subject.broker().usage(&issued.id).await.ctx("usage")?;
    ensure_eq!(
        standing.state,
        TokenState::Revoked,
        "a token at its ceiling"
    );
    ensure_eq!(
        subject.spend(&issued.id, cost(1)).await,
        Spend::Refused,
        "spend after the ceiling"
    );
    Ok(())
}

async fn spend_under_a_revoked_token_is_refused(subject: &dyn BrokerSubject) -> Result<(), String> {
    let issued = subject
        .broker()
        .issue(subject.request())
        .await
        .ctx("issue")?;
    subject.broker().revoke(&issued.id).await.ctx("revoke")?;
    ensure_eq!(
        subject.spend(&issued.id, cost(10)).await,
        Spend::Refused,
        "spend under a revoked token"
    );
    ensure_eq!(
        subject.broker().usage(&issued.id).await.ctx("usage")?.usage,
        Usage::default(),
        "a refused spend adds nothing"
    );
    Ok(())
}
