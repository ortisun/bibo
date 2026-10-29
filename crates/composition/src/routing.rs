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

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{PriceConfig, UpstreamConfig};
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
    /// A provider the broker does not know.
    #[error("the provider {0} is not one the broker knows")]
    UnknownProvider(String),
    /// The configuration enables a model for a provider, and the policy does not list the model
    /// for that provider.
    #[error(
        "broker.upstreams enables the model {model} for the provider {provider}, and the routing policy does not list it for that provider"
    )]
    ModelNotInPolicy {
        /// The provider.
        provider: String,
        /// The model.
        model: String,
    },
    /// The configuration prices a model the policy does not list for that provider.
    #[error("broker.prices names the model {0}, which the routing policy does not list for that provider")]
    PriceForUnknownModel(String),
    /// The configuration lowers a price of the policy.
    #[error(
        "broker.prices lowers a price of the routing policy for the model {0}; a price in the configuration may only raise one"
    )]
    PriceLowersPolicy(String),
}

/// Why an author-aware route found nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorRoutingError {
    /// The ordinary routing failed.
    #[error(transparent)]
    Routing(#[from] RoutingError),
    /// Candidates exist, and none of them is independent of the author under the policy's rule.
    /// The policy says the reviewing stage then waits for a person (`on_no_independent_model`).
    #[error("no allowed model is independent of the author, so the stage waits for a person")]
    NoIndependentModel,
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

/// The price list of the broker: the policy's prices, each raised by the deployment's entry when
/// there is one. A deployment may price a model of the policy higher than the policy does (the
/// broker then counts more, which stops a job sooner), never lower, and may not price a model the
/// policy does not list for that provider.
///
/// # Errors
/// [`RoutingBuildError`] as for [`price_table`], and [`RoutingBuildError::PriceForUnknownModel`] or
/// [`RoutingBuildError::PriceLowersPolicy`] for an entry that breaks the rule above.
pub fn price_table_with(
    policy: &ModelRoutingPolicy,
    entries: &[PriceConfig],
) -> Result<PriceTable, RoutingBuildError> {
    checked(policy)?;
    let mut table = PriceTable::new();
    for model in &policy.models {
        let provider = provider_of(model)?;
        let mut prices = ModelPrice {
            input: model.prices.input,
            cache_write: model.prices.cache_write,
            cache_read: model.prices.cache_read,
            output: model.prices.output,
        };
        for entry in entries
            .iter()
            .filter(|entry| entry.model == model.id && entry.provider == model.provider)
        {
            let raised = ModelPrice {
                input: entry.input,
                cache_write: entry.cache_write,
                cache_read: entry.cache_read,
                output: entry.output,
            };
            if raised.input < prices.input
                || raised.cache_write < prices.cache_write
                || raised.cache_read < prices.cache_read
                || raised.output < prices.output
            {
                return Err(RoutingBuildError::PriceLowersPolicy(model.id.clone()));
            }
            prices = raised;
        }
        table = table.with_model(provider, &model.id, prices);
    }
    for entry in entries {
        let known = policy
            .models
            .iter()
            .any(|model| model.id == entry.model && model.provider == entry.provider);
        if !known {
            return Err(RoutingBuildError::PriceForUnknownModel(entry.model.clone()));
        }
    }
    Ok(table)
}

/// The models the deployment enabled: for each upstream, the models it lists, or every model of
/// the policy for that provider when it lists none. A model the policy does not list for the
/// provider stops the start.
///
/// # Errors
/// [`RoutingBuildError::UnknownProvider`] or [`RoutingBuildError::ModelNotInPolicy`].
pub fn enabled_models(
    policy: &ModelRoutingPolicy,
    upstreams: &[UpstreamConfig],
) -> Result<BTreeSet<String>, RoutingBuildError> {
    let mut enabled = BTreeSet::new();
    for upstream in upstreams {
        if !matches!(upstream.provider.as_str(), "anthropic" | "openai") {
            return Err(RoutingBuildError::UnknownProvider(upstream.provider.clone()));
        }
        for name in &upstream.models {
            let listed = policy
                .models
                .iter()
                .any(|model| &model.id == name && model.provider == upstream.provider);
            if !listed {
                return Err(RoutingBuildError::ModelNotInPolicy {
                    provider: upstream.provider.clone(),
                    model: name.clone(),
                });
            }
            enabled.insert(name.clone());
        }
        if upstream.models.is_empty() {
            enabled.extend(
                policy
                    .models
                    .iter()
                    .filter(|model| model.provider == upstream.provider)
                    .map(|model| model.id.clone()),
            );
        }
    }
    Ok(enabled)
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
    /// The models the deployment enabled. `None` means every model of the policy.
    enabled: Option<BTreeSet<String>>,
}

impl PolicyModelRouter {
    /// A router for a policy that passes its own rules.
    ///
    /// # Errors
    /// [`RoutingBuildError`] when the policy breaks a rule of its own, or a model's provider and
    /// runtime do not agree.
    pub fn new(policy: Arc<ModelRoutingPolicy>) -> Result<Self, RoutingBuildError> {
        checked(&policy)?;
        Ok(Self {
            policy,
            enabled: None,
        })
    }

    /// A router that offers only the models the deployment enabled (see [`enabled_models`]). A
    /// model of the policy that no provider of the deployment serves is never a candidate.
    #[must_use]
    pub fn with_enabled(mut self, enabled: BTreeSet<String>) -> Self {
        self.enabled = Some(enabled);
        self
    }

    /// The same answer as [`ModelRouter::route`], for a stage that reviews the work of an author
    /// whose model is known: a candidate that is not independent of the author under the policy's
    /// rule for the reviewing role is dropped. When candidates remain and none is independent the
    /// answer is [`AuthorRoutingError::NoIndependentModel`], and the policy says the stage then
    /// waits for a person. A stage that reviews nobody's work routes as `route` does.
    ///
    /// The engine does not call this yet: `RoutingNeed` carries no author (proposal in
    /// `docs/architecture/ports-v1.1.md`, section 16). The composition root that learns the
    /// author's model calls it, and the tests show what it refuses.
    ///
    /// # Errors
    /// [`AuthorRoutingError`].
    pub fn route_after_author(
        &self,
        need: &RoutingNeed,
        author: &ModelSelection,
    ) -> Result<RoutingDecision, AuthorRoutingError> {
        let rules: Vec<_> = self
            .policy
            .roles_of_stage(need.stage.as_str())
            .filter_map(|role| self.policy.rule_for_reviewer(&role.role))
            .collect();
        if rules.is_empty() {
            return Ok(self.route_filtered(need, |_| true)?);
        }
        let independent = |model: &Model| {
            rules
                .iter()
                .all(|rule| self.policy.independent(rule, author.model.as_str(), &model.id))
        };
        // Candidates the deployment serves exist, and not one is independent of the author: the
        // policy sends the stage to a person, which is not the same as a runtime being excluded.
        let served: Vec<&Model> = self
            .policy
            .candidates(need.stage.as_str(), tier_of(need))
            .into_iter()
            .filter(|model| self.serves(model))
            .collect();
        if !served.is_empty() && !served.iter().any(|model| independent(model)) {
            return Err(AuthorRoutingError::NoIndependentModel);
        }
        Ok(self.route_filtered(need, independent)?)
    }

    fn serves(&self, model: &Model) -> bool {
        self.enabled
            .as_ref()
            .is_none_or(|enabled| enabled.contains(&model.id))
    }

    fn route_filtered(
        &self,
        need: &RoutingNeed,
        accept: impl Fn(&Model) -> bool,
    ) -> Result<RoutingDecision, RoutingError> {
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
            if !self.serves(model) {
                continue;
            }
            if !accept(model) {
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
        self.route_filtered(need, |_| true)
    }
}
