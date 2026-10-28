//! The same shared `ModelBroker` contract suite, with spending done the way the port describes for
//! a real broker: a request to the listener, answered by the fake provider, which reports usage.
//!
//! The contract's spend has an exact cost per request (`Usage` with 100 input tokens, 10 output
//! tokens and a chosen cost), and a price table cannot give an arbitrary cost for fixed token
//! counts. The subject therefore uses a price list whose answer the subject sets before each
//! request; the token counts come from the provider's report, the cost from the list.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::JobId;
use factory_domain::vocabulary::Fidelity;
use factory_egress::broker::{CapPolicy, PriceList, Provider, TokenCounts};
use factory_ports::agent::{
    BrokerError, CostMicroUsd, IssuedJobToken, JobTokenId, JobTokenRequest, ModelBroker,
    TokenUsage, Usage,
};
use factory_testkit::contracts::broker::{self, BrokerSubject, Spend};
use serde_json::json;
use support::{CEILING, CLAUDE_MODEL, HttpRig};

mod support;

/// A price list that charges whatever the subject last said, for any counts.
#[derive(Default)]
struct SetCost(AtomicU64);

impl PriceList for SetCost {
    fn cost(&self, _: Provider, model: &str, _: &TokenCounts) -> Option<CostMicroUsd> {
        (model == CLAUDE_MODEL).then(|| CostMicroUsd(self.0.load(Ordering::SeqCst)))
    }
}

/// Wraps the core and remembers the secret of each token it issues, because the port returns the
/// secret only from `issue` and the subject needs it to make a request.
struct KeepsSecrets {
    rig: Arc<HttpRig>,
    secrets: Mutex<HashMap<JobTokenId, String>>,
}

#[async_trait]
impl ModelBroker for KeepsSecrets {
    fn fidelity(&self) -> Fidelity {
        self.rig.rig.core.fidelity()
    }

    async fn issue(&self, req: JobTokenRequest) -> Result<IssuedJobToken, BrokerError> {
        let issued = self.rig.rig.core.issue(req).await?;
        self.secrets
            .lock()
            .expect("secrets")
            .insert(issued.id, issued.secret.expose().to_owned());
        Ok(issued)
    }

    async fn revoke(&self, token: &JobTokenId) -> Result<(), BrokerError> {
        self.rig.rig.core.revoke(token).await
    }

    async fn revoke_for_job(&self, job: JobId) -> Result<(), BrokerError> {
        self.rig.rig.core.revoke_for_job(job).await
    }

    async fn usage(&self, token: &JobTokenId) -> Result<TokenUsage, BrokerError> {
        self.rig.rig.core.usage(token).await
    }
}

struct HttpSubject {
    broker: KeepsSecrets,
    cost: Arc<SetCost>,
}

impl HttpSubject {
    fn new() -> Self {
        let cost = Arc::new(SetCost::default());
        let rig = Arc::new(HttpRig::with_prices(CapPolicy::default(), cost.clone()));
        // The fake provider reports the tokens of the contract's `Usage`: 100 in and 10 out.
        rig.provider.set(|s| {
            s.anthropic = (100, 0, 0, 10);
        });
        Self {
            broker: KeepsSecrets {
                rig,
                secrets: Mutex::new(HashMap::new()),
            },
            cost,
        }
    }
}

#[async_trait]
impl BrokerSubject for HttpSubject {
    fn broker(&self) -> &dyn ModelBroker {
        &self.broker
    }

    fn request(&self) -> JobTokenRequest {
        self.broker
            .rig
            .rig
            .request_for(support::fixed_job(), CEILING)
    }

    async fn spend(&self, token: &JobTokenId, usage: Usage) -> Spend {
        let Some(secret) = self
            .broker
            .secrets
            .lock()
            .expect("secrets")
            .get(token)
            .cloned()
        else {
            return Spend::Refused;
        };
        self.cost.0.store(usage.cost.0, Ordering::SeqCst);
        let response = self.broker.rig.post(
            "/v1/messages",
            ("x-api-key", &secret),
            &json!({"model": CLAUDE_MODEL, "stream": true, "max_tokens": 10}),
        );
        if response.status == 200 {
            Spend::Allowed
        } else {
            Spend::Refused
        }
    }

    async fn advance_time(&self, by: Duration) {
        self.broker.rig.rig.clock.advance(by);
    }
}

#[tokio::test]
async fn the_http_listener_passes_the_broker_contract() {
    let report = broker::run(|| async { HttpSubject::new() }).await;
    report.assert_ok();
    assert_eq!(report.passed.len(), broker::checks().len());
}

/// The done criterion of the work package, through the listener: `revoke_for_job` revokes every
/// token of the job, and spend that reaches the ceiling revokes the token in the same step.
#[tokio::test]
async fn revoke_for_job_and_metering_through_the_http_listener() {
    let report = broker::run(|| async { HttpSubject::new() }).await;
    for name in [
        "revoke_for_job_revokes_every_token_of_the_job",
        "metering_to_the_ceiling_revokes_the_token",
    ] {
        assert!(
            report.passed.contains(&name),
            "{name} did not pass: {:?}",
            report.failed_names()
        );
    }
}
