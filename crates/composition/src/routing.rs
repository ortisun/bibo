//! The routing policy (`policies/model_routing.yaml`) as the router, the engine and the broker use
//! it.
//!
//! The policy is typed in `factory-domain` and loaded by `factory-contracts`. This module turns it
//! into the three things the running system needs, and nothing here reads a file or a key:
//!
//! * [`PolicyModelRouter`] answers `ModelRouter::route` from the routes of the policy: the models
//!   of a stage and a tier, in the order of the file, skipping a runtime already excluded and one
//!   that lacks a capability the stage needs. It never returns a model that is not in a route.
//! * [`price_table`] gives the broker the price of each model of the policy. The broker refuses a
//!   model that has no price, so a model outside the policy is refused there as well.
//! * [`token_request`] builds the request for a job token: the models of the stage's routes, and
//!   the ceiling of the stage run. [`broker_caps`] gives the broker the per-request caps.
//!
//! # What the policy does not yet drive
//!
//! * The broker applies one set of per-request caps to every token, so [`broker_caps`] takes the
//!   largest cap of any role. A cap for each role needs a field on the job token request, which is
//!   a change of the port.
//! * The router does not know the model the author of the work used, so it cannot choose a
//!   reviewer of another family by itself. The reviewing stages list the model of the other family
//!   first, and `ModelRoutingPolicy::independent` answers the question for a caller that knows the
//!   author. Passing the author to the router needs a field on `RoutingNeed`, a change of the port.

use std::sync::Arc;
use std::time::Duration;

use factory_contracts::policy::routing::routing_problems;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::routing::{Model, ModelRoutingPolicy, Tier};
use factory_domain::values::NonEmptyString;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_egress::broker::{CapPolicy, ModelPrice, PerRequestCaps, PriceTable, Provider};
use factory_ports::agent::{
    CostMicroUsd, FlagSet, JobTokenRequest, ModelRouter, ModelSelection, RoutingDecision,
    RoutingError, RoutingNeed, RuntimeId,
};

/// Why the policy cannot be used to route.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoutingBuildError {
    /// The policy breaks one of its own rules.
    #[error("the routing policy breaks a rule at {path}: {message}")]
    Invalid {
        /// The key.
        path: String,
        /// What is wrong.
        message: String,
    },
    /// A model names a provider or a runtime that the broker or the engine does not know, or the
    /// two do not belong together.
    #[error(
        "the model {0} has a provider and a runtime that do not belong together, or one the broker does not know"
    )]
    ProviderMismatch(String),
    /// A stage kind the policy names does not exist.
    #[error("the stage {0} is not a stage kind")]
    UnknownStage(String),
    /// The stage has no route, so a token cannot be built for it.
    #[error("the stage {0} has no route in the routing policy")]
    NoRoute(String),
}

fn provider_of(model: &Model) -> Result<Provider, RoutingBuildError> {
    let named = match model.provider.as_str() {
        "anthropic" => Provider::Anthropic,
        "openai" => Provider::OpenAi,
        _ => return Err(RoutingBuildError::ProviderMismatch(model.id.clone())),
    };
    let runtime = RuntimeId::new(&model.runtime)
        .map_err(|_| RoutingBuildError::ProviderMismatch(model.id.clone()))?;
    if Provider::for_runtime(&runtime) == Some(named) {
        Ok(named)
    } else {
        Err(RoutingBuildError::ProviderMismatch(model.id.clone()))
    }
}

fn selection_of(model: &Model) -> Result<ModelSelection, RoutingBuildError> {
    Ok(ModelSelection {
        runtime: RuntimeId::new(&model.runtime)
            .map_err(|_| RoutingBuildError::ProviderMismatch(model.id.clone()))?,
        model: NonEmptyString::parse(&model.id)
            .map_err(|_| RoutingBuildError::ProviderMismatch(model.id.clone()))?,
    })
}

fn checked(policy: &ModelRoutingPolicy) -> Result<(), RoutingBuildError> {
    if let Some(problem) = routing_problems(policy).into_iter().next() {
        return Err(RoutingBuildError::Invalid {
            path: problem.path,
            message: problem.message,
        });
    }
    for model in &policy.models {
        provider_of(model)?;
    }
    Ok(())
}

/// The price of every model of the policy, for the broker.
///
/// # Errors
/// [`RoutingBuildError`] when the policy breaks a rule of its own, or a model's provider and
/// runtime do not agree.
pub fn price_table(policy: &ModelRoutingPolicy) -> Result<PriceTable, RoutingBuildError> {
    checked(policy)?;
    let mut table = PriceTable::new();
    for model in &policy.models {
        table = table.with_model(
            provider_of(model)?,
            &model.id,
            ModelPrice {
                input: model.prices.input,
                cache_write: model.prices.cache_write,
                cache_read: model.prices.cache_read,
                output: model.prices.output,
            },
        );
    }
    Ok(table)
}

/// The caps the broker applies to every request: the largest cap of any role. A broker holds one
/// set for all its tokens, so a smaller cap for one role cannot be enforced here.
///
/// # Errors
/// [`RoutingBuildError`] as for [`price_table`].
pub fn broker_caps(policy: &ModelRoutingPolicy) -> Result<CapPolicy, RoutingBuildError> {
    checked(policy)?;
    let input = policy
        .roles
        .iter()
        .map(|role| role.per_request.max_input_tokens)
        .max()
        .unwrap_or(0);
    let output = policy
        .roles
        .iter()
        .map(|role| role.per_request.max_output_tokens)
        .max()
        .unwrap_or(0);
    Ok(CapPolicy {
        per_request: PerRequestCaps {
            max_input_tokens: input,
            max_output_tokens: output,
            ..PerRequestCaps::default()
        },
        ..CapPolicy::default()
    })
}

/// The request for the job token of a stage: bound to the tenant, the job and the stage, holding
/// the models of the stage's routes and no other, with the ceiling of a run of the stage.
///
/// # Errors
/// [`RoutingBuildError`] when the policy is unusable or the stage has no route.
pub fn token_request(
    policy: &ModelRoutingPolicy,
    tenant: TenantId,
    job: JobId,
    stage: StageKind,
    ttl: Duration,
) -> Result<JobTokenRequest, RoutingBuildError> {
    checked(policy)?;
    let allowed = policy.allowed_models(stage.as_str());
    let ceiling = policy
        .stage_ceiling(stage.as_str())
        .ok_or_else(|| RoutingBuildError::NoRoute(stage.as_str().to_owned()))?;
    if allowed.is_empty() {
        return Err(RoutingBuildError::NoRoute(stage.as_str().to_owned()));
    }
    Ok(JobTokenRequest {
        tenant,
        job,
        stage,
        cost_ceiling: CostMicroUsd(ceiling.max_micro_usd),
        allowed_models: allowed
            .into_iter()
            .map(selection_of)
            .collect::<Result<_, _>>()?,
        ttl,
    })
}

/// A router over the routing policy. It reports fidelity `real`: it reads the policy, not a fixed
/// table of a test.
#[derive(Debug, Clone)]
pub struct PolicyModelRouter {
    policy: Arc<ModelRoutingPolicy>,
}

impl PolicyModelRouter {
    /// A router for a policy that passes its own rules.
    ///
    /// # Errors
    /// [`RoutingBuildError`] when the policy breaks a rule of its own, or a model's provider and
    /// runtime do not agree.
    pub fn new(policy: Arc<ModelRoutingPolicy>) -> Result<Self, RoutingBuildError> {
        checked(&policy)?;
        Ok(Self { policy })
    }
}

fn tier_of(need: &RoutingNeed) -> Tier {
    match need.tier {
        RecommendedTier::Small => Tier::Small,
        RecommendedTier::Standard => Tier::Standard,
        RecommendedTier::Large => Tier::Large,
    }
}

impl ModelRouter for PolicyModelRouter {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn route(&self, need: &RoutingNeed) -> Result<RoutingDecision, RoutingError> {
        let candidates = self.policy.candidates(need.stage.as_str(), tier_of(need));
        if candidates.is_empty() {
            return Err(RoutingError::NoRoute);
        }
        let mut missing = None;
        let mut any_left = false;
        for model in candidates {
            let Ok(selection) = selection_of(model) else {
                continue;
            };
            if need.exclude.contains(&selection.runtime) {
                continue;
            }
            any_left = true;
            // A runtime with no probe is not a candidate: the router never guesses a capability.
            let Some(found) = need.probed.0.get(&selection.runtime) else {
                continue;
            };
            if let Some(lacks) = need
                .required
                .iter()
                .find(|capability| !found.supports(**capability))
            {
                missing.get_or_insert(*lacks);
                continue;
            }
            return Ok(RoutingDecision {
                model: selection,
                flag_set: FlagSet::for_stage(need.stage),
            });
        }
        Err(match (any_left, missing) {
            (false, _) => RoutingError::AllExcluded,
            (true, Some(capability)) => RoutingError::CapabilityUnavailable(capability),
            (true, None) => RoutingError::NoRoute,
        })
    }
}
