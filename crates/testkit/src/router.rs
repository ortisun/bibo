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
    Capability, CapabilityObservation, FlagSet, ModelRouter, ModelSelection, ProbedCapabilities,
    RoutingDecision, RoutingError, RoutingNeed, RuntimeCapabilities, RuntimeId,
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
    /// Returns a runtime the need excluded.
    ReturnsExcluded,
    /// Offers a runtime that has no probe result.
    IgnoresProbe,
    /// Offers a runtime whose probe lacks a required capability.
    IgnoresProbedCapabilities,
}

/// Each defect and the checks of `contracts::router` that must fail when the fake has it.
pub const DEFECTS: &[(RouterDefect, &[&str])] = &[
    (
        RouterDefect::ChoosesAtRandom,
        &["the_same_need_always_gets_the_same_decision"],
    ),
    (
        RouterDefect::WrongFlagSet,
        &["the_flag_set_follows_the_stage"],
    ),
    (
        RouterDefect::RoutesAnything,
        &["a_need_with_no_entry_has_no_route"],
    ),
    (
        RouterDefect::IgnoresCapabilities,
        &[
            "a_missing_capability_is_reported_by_name",
            "a_probe_lacking_a_required_capability_is_skipped",
        ],
    ),
    (
        RouterDefect::ReturnsExcluded,
        &["excluding_the_answer_gives_another_runtime_or_an_error"],
    ),
    (
        RouterDefect::IgnoresProbe,
        &["a_runtime_without_a_probe_is_not_a_candidate"],
    ),
    (
        RouterDefect::IgnoresProbedCapabilities,
        &["a_probe_lacking_a_required_capability_is_skipped"],
    ),
];

/// What a probe of a runtime that supports exactly `capabilities` found.
#[must_use]
pub fn probe_of(capabilities: &[Capability]) -> RuntimeCapabilities {
    RuntimeCapabilities {
        runtime_version: "1.0.0".to_owned(),
        observations: capabilities
            .iter()
            .map(|capability| CapabilityObservation {
                capability: *capability,
                supported: true,
                source: "--help".to_owned(),
            })
            .collect(),
    }
}

/// Probe results for the listed runtimes, each supporting the standard capabilities.
///
/// # Panics
/// Panics when a runtime name is not a slug. This is test code.
#[must_use]
pub fn probed(runtimes: &[&str]) -> ProbedCapabilities {
    ProbedCapabilities(
        runtimes
            .iter()
            .map(|name| {
                (
                    RuntimeId::new(name).expect("a valid runtime id"),
                    probe_of(&[Capability::JsonSchemaOutput, Capability::HeadlessMultiTurn]),
                )
            })
            .collect(),
    )
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
        // The candidates are the rules for the stage and tier, in the order the policy lists them.
        let candidates: Vec<&RouteRule> = if self.has(RouterDefect::RoutesAnything) {
            self.rules.iter().collect()
        } else {
            self.rules
                .iter()
                .filter(|rule| rule.stage == need.stage && rule.tier == need.tier)
                .collect()
        };
        if candidates.is_empty() {
            return Err(RoutingError::NoRoute);
        }
        let not_excluded: Vec<&RouteRule> = candidates
            .iter()
            .copied()
            .filter(|rule| {
                self.has(RouterDefect::ReturnsExcluded)
                    || !need.exclude.contains(&rule.model.runtime)
            })
            .collect();
        if not_excluded.is_empty() {
            return Err(RoutingError::AllExcluded);
        }
        let mut missing = None;
        let mut chosen = None;
        for rule in &not_excluded {
            let Some(found) = need.probed.0.get(&rule.model.runtime) else {
                if self.has(RouterDefect::IgnoresProbe) {
                    chosen = Some(*rule);
                    break;
                }
                continue;
            };
            let lacks = need
                .required
                .iter()
                .find(|capability| !found.supports(**capability));
            match lacks {
                Some(capability)
                    if !self.has(RouterDefect::IgnoresCapabilities)
                        && !self.has(RouterDefect::IgnoresProbedCapabilities) =>
                {
                    missing.get_or_insert(*capability);
                }
                _ => {
                    chosen = Some(*rule);
                    break;
                }
            }
        }
        let rule = if self.has(RouterDefect::ChoosesAtRandom) {
            let pool: Vec<&RouteRule> = self.rules.iter().collect();
            pool.get(usize::try_from(call).unwrap_or(0) % pool.len().max(1))
                .copied()
        } else {
            chosen
        };
        let Some(rule) = rule else {
            return Err(match missing {
                Some(capability) => RoutingError::CapabilityUnavailable(capability),
                None => RoutingError::NoRoute,
            });
        };
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
    rule_for(stage, tier, "fake")
}

fn rule_for(stage: StageKind, tier: RecommendedTier, runtime: &str) -> RouteRule {
    RouteRule {
        stage,
        tier,
        model: ModelSelection {
            runtime: RuntimeId::new(runtime).expect("a valid runtime id"),
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
            rule_for(StageKind::Specification, RecommendedTier::Large, "fake-two"),
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
            exclude: Vec::new(),
            probed: probed(&["fake", "fake-two"]),
            author: None,
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

    fn need_with_two_candidates(&self) -> Option<RoutingNeed> {
        Some(Self::need(
            StageKind::Specification,
            RecommendedTier::Large,
            vec![Capability::JsonSchemaOutput],
        ))
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
