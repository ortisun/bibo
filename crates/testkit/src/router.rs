//! A model router over a fixed table, standing in for the policy-driven router.
//!
//! Each rule says which runtime and model serve a stage at a tier, and which capabilities that
//! runtime has. A need is routed to the rule for its stage and tier. The risk of the job is not
//! used: the real router reads it from the routing policy, and a test that needs a risk rule
//! builds a table with one.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::values::NonEmptyString;
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{
    Capability, FlagSet, ModelRouter, ModelSelection, RoutingDecision, RoutingError, RoutingNeed,
    RuntimeId,
};

use crate::contracts::router::RouterSubject;

/// One line of the routing table.
#[derive(Debug, Clone)]
pub struct RouteRule {
    /// The stage the rule serves.
    pub stage: StageKind,
    /// The tier the rule serves.
    pub tier: RecommendedTier,
    /// The runtime and model to use.
    pub model: ModelSelection,
    /// What that runtime can do.
    pub capabilities: Vec<Capability>,
}

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterDefect {
    /// Alternates between the rules' models on successive calls.
    ChoosesAtRandom,
    /// Always reports the standard flag set.
    WrongFlagSet,
    /// Answers every need with the first rule.
    RoutesAnything,
    /// Never checks capabilities.
    IgnoresCapabilities,
}

/// A router over a fixed table. Reports fidelity `fake`.
pub struct StaticModelRouter {
    rules: Vec<RouteRule>,
    defect: Option<RouterDefect>,
    calls: AtomicU64,
}

impl StaticModelRouter {
    /// A router for the given rules.
    #[must_use]
    pub fn new(rules: Vec<RouteRule>) -> Self {
        Self {
            rules,
            defect: None,
            calls: AtomicU64::new(0),
        }
    }

    /// A router that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(rules: Vec<RouteRule>, defect: RouterDefect) -> Self {
        Self {
            defect: Some(defect),
            ..Self::new(rules)
        }
    }

    fn has(&self, defect: RouterDefect) -> bool {
        self.defect == Some(defect)
    }
}

impl ModelRouter for StaticModelRouter {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn route(&self, need: &RoutingNeed) -> Result<RoutingDecision, RoutingError> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        let matching: Vec<&RouteRule> = self
            .rules
            .iter()
            .filter(|rule| rule.stage == need.stage && rule.tier == need.tier)
            .collect();
        let rule = if self.has(RouterDefect::RoutesAnything) {
            self.rules.first()
        } else if self.has(RouterDefect::ChoosesAtRandom) {
            let pool: Vec<&RouteRule> = self.rules.iter().collect();
            pool.get(usize::try_from(call).unwrap_or(0) % pool.len().max(1))
                .copied()
        } else {
            matching.first().copied()
        }
        .ok_or(RoutingError::NoRoute)?;
        if !self.has(RouterDefect::IgnoresCapabilities)
            && let Some(missing) = need
                .required
                .iter()
                .find(|capability| !rule.capabilities.contains(capability))
        {
            return Err(RoutingError::CapabilityUnavailable(*missing));
        }
        Ok(RoutingDecision {
            model: rule.model.clone(),
            flag_set: if self.has(RouterDefect::WrongFlagSet) {
                FlagSet::Standard
            } else {
                FlagSet::for_stage(need.stage)
            },
        })
    }
}

fn rule(stage: StageKind, tier: RecommendedTier) -> RouteRule {
    RouteRule {
        stage,
        tier,
        model: ModelSelection {
            runtime: RuntimeId::new("fake").expect("a valid runtime id"),
            model: NonEmptyString::parse(&format!("fake-{}-model", stage.as_str().to_lowercase()))
                .expect("a valid model name"),
        },
        capabilities: vec![Capability::JsonSchemaOutput, Capability::HeadlessMultiTurn],
    }
}

/// The router packaged as a subject of the router contract suite.
pub struct StaticRouterSubject {
    router: StaticModelRouter,
}

impl StaticRouterSubject {
    /// A faithful router over a small table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            router: StaticModelRouter::new(Self::table()),
        }
    }

    /// A router that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: RouterDefect) -> Self {
        Self {
            router: StaticModelRouter::with_defect(Self::table(), defect),
        }
    }

    fn table() -> Vec<RouteRule> {
        vec![
            rule(StageKind::Specification, RecommendedTier::Large),
            rule(StageKind::Implementation, RecommendedTier::Standard),
            rule(StageKind::Review, RecommendedTier::Large),
        ]
    }

    fn need(stage: StageKind, tier: RecommendedTier, required: Vec<Capability>) -> RoutingNeed {
        RoutingNeed {
            stage,
            tier,
            required,
            risk: RiskTier::Medium,
        }
    }
}

impl Default for StaticRouterSubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RouterSubject for StaticRouterSubject {
    fn router(&self) -> &dyn ModelRouter {
        &self.router
    }

    fn routable_needs(&self) -> Vec<RoutingNeed> {
        vec![
            Self::need(StageKind::Specification, RecommendedTier::Large, vec![]),
            Self::need(
                StageKind::Implementation,
                RecommendedTier::Standard,
                vec![Capability::JsonSchemaOutput],
            ),
            Self::need(StageKind::Review, RecommendedTier::Large, vec![]),
        ]
    }

    fn unroutable_need(&self) -> RoutingNeed {
        Self::need(StageKind::Delivery, RecommendedTier::Small, vec![])
    }

    fn need_with_an_unavailable_capability(&self) -> Option<(RoutingNeed, Capability)> {
        Some((
            Self::need(
                StageKind::Implementation,
                RecommendedTier::Standard,
                vec![Capability::BudgetFlag],
            ),
            Capability::BudgetFlag,
        ))
    }
}
