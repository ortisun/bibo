//! The routing policy applied to the job tokens the engine asks for.
//!
//! The engine builds the request for a job token itself: the models it holds are the one the
//! router chose, and the cost ceiling is the stage contract's budget (`stages.budget.max_cost_usd`,
//! ten dollars by default). The routing policy ([`crate::routing`]) says more than that: a stage
//! has a ceiling of its own, a model is allowed in a stage only through its routes, and a job has
//! a ceiling for all its stages together. [`PolicyBroker`] stands in front of the real broker and
//! applies the policy to every request, so that none of it depends on the engine remembering it.
//!
//! What it does to a request, and never the other way:
//!
//! * The models are cut to those the policy allows in the stage. A model outside the stage's routes
//!   is dropped; a request with none left is refused as `NoModels`.
//! * The ceiling is the lowest of the request's, the stage's ceiling in the policy, and what is left
//!   of the job's ceiling. A job that has spent all of its ceiling gets no token (`ZeroCeiling`).
//! * The caps on one request are those of the stage's role (`JobTokenRequest::per_request`), and a
//!   request that carries smaller caps keeps them.
//! * It never adds a model and never raises a ceiling.
//!
//! # What it cannot do
//!
//! The spend of a job is read from the broker of this process, which keeps its ledger in memory. A
//! worker that restarts starts a job's count again, and a second worker does not see the first one's
//! spend. The stage ceiling and the cost ceiling of each token still hold in both cases, so the
//! error is bounded by one stage per restart. The proposal to carry the spend in the store is
//! `docs/architecture/ports-v1.1.md`, section 16.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::JobId;
use factory_domain::policy::routing::ModelRoutingPolicy;
use factory_domain::vocabulary::Fidelity;
use factory_egress::broker::BrokerCore;
use factory_ports::agent::{
    BrokerError, CostMicroUsd, InvalidTokenRequest, IssuedJobToken, JobTokenId, JobTokenRequest,
    ModelBroker, TokenUsage,
};

/// What a job has spent so far, in millionths of a dollar, across all its tokens.
pub trait JobSpend: Send + Sync {
    /// The spend of the job in this process.
    fn spent(&self, job: JobId) -> CostMicroUsd;
}

impl JobSpend for BrokerCore {
    fn spent(&self, job: JobId) -> CostMicroUsd {
        self.ledger(job).total.cost
    }
}

/// A job that spent nothing, for a broker that cannot say.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSpendKnown;

impl JobSpend for NoSpendKnown {
    fn spent(&self, _: JobId) -> CostMicroUsd {
        CostMicroUsd(0)
    }
}

/// Applies the routing policy to the token requests that go to `inner`.
pub struct PolicyBroker {
    inner: Arc<dyn ModelBroker>,
    policy: Arc<ModelRoutingPolicy>,
    spend: Arc<dyn JobSpend>,
}

impl PolicyBroker {
    /// A broker that narrows every request to `policy` before it reaches `inner`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn ModelBroker>,
        policy: Arc<ModelRoutingPolicy>,
        spend: Arc<dyn JobSpend>,
    ) -> Self {
        Self {
            inner,
            policy,
            spend,
        }
    }

    /// The request as the policy allows it, or why nothing of it is allowed.
    fn narrowed(&self, mut req: JobTokenRequest) -> Result<JobTokenRequest, BrokerError> {
        let stage = req.stage.as_str();
        // A model is allowed as the policy pairs it with its runtime: the name alone is not enough.
        let allowed = self.policy.allowed_models(stage);
        req.allowed_models.retain(|held| {
            allowed.iter().any(|model| {
                model.id == held.model.as_str() && model.runtime == held.runtime.as_str()
            })
        });
        if req.allowed_models.is_empty() {
            return Err(BrokerError::InvalidRequest(InvalidTokenRequest::NoModels));
        }
        let Some(stage_ceiling) = self.policy.stage_ceiling(stage) else {
            // A stage with no role in the policy has no ceiling to apply, and no model either.
            return Err(BrokerError::InvalidRequest(InvalidTokenRequest::NoModels));
        };
        let left_for_the_job = self
            .policy
            .job
            .max_micro_usd
            .saturating_sub(self.spend.spent(req.job).0);
        req.cost_ceiling = CostMicroUsd(
            req.cost_ceiling
                .0
                .min(stage_ceiling.max_micro_usd)
                .min(left_for_the_job),
        );
        // The caps on one request are those of the stage's role. A request that already carries
        // smaller caps keeps them.
        if let Some(role) = crate::routing::request_caps(&self.policy, req.stage) {
            req.per_request = Some(match req.per_request {
                Some(asked) => factory_ports::agent::RequestCaps {
                    max_input_tokens: asked.max_input_tokens.min(role.max_input_tokens),
                    max_output_tokens: asked.max_output_tokens.min(role.max_output_tokens),
                },
                None => role,
            });
        }
        if req.cost_ceiling == CostMicroUsd(0) {
            return Err(BrokerError::InvalidRequest(
                InvalidTokenRequest::ZeroCeiling,
            ));
        }
        Ok(req)
    }
}

impl std::fmt::Debug for PolicyBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyBroker").finish_non_exhaustive()
    }
}

#[async_trait]
impl ModelBroker for PolicyBroker {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn issue(&self, req: JobTokenRequest) -> Result<IssuedJobToken, BrokerError> {
        self.inner.issue(self.narrowed(req)?).await
    }

    async fn revoke(&self, token: &JobTokenId) -> Result<(), BrokerError> {
        self.inner.revoke(token).await
    }

    async fn revoke_for_job(&self, job: JobId) -> Result<(), BrokerError> {
        self.inner.revoke_for_job(job).await
    }

    async fn usage(&self, token: &JobTokenId) -> Result<TokenUsage, BrokerError> {
        self.inner.usage(token).await
    }
}
