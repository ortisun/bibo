//! `policies/model_routing.yaml` as typed values, and the questions the router, the engine and the
//! broker ask of it.
//!
//! Same rules as `security.rs`: every struct rejects unknown keys, and a field the file may leave
//! out is an `Option`. The file holds no key and no secret. Reading the file, parsing the YAML and
//! the checks that tie the file to the agent manifests and to `policies/security.yaml` are in
//! `factory-contracts`; what is here is pure.
//!
//! # What each reader gets
//!
//! * **The router** asks [`ModelRoutingPolicy::candidates`] for the models of a stage and a tier,
//!   in the order to try them, and [`ModelRoutingPolicy::model`] for a model's provider and
//!   runtime.
//! * **The engine** asks [`ModelRoutingPolicy::stage_ceiling`] for what a run of a stage may
//!   spend, and [`ModelRoutingPolicy::allowed_models`] for what the job token may hold.
//! * **The broker** is given [`ModelRoutingPolicy::price`] for each model. A model that has no
//!   price is refused by the broker, so a model that is in no route is refused twice.
//! * **A reviewing stage** asks [`ModelRoutingPolicy::independent`] and
//!   [`ModelRoutingPolicy::independent_reviewers`] whether a model may review the work of another.
//!
//! # Tighten only
//!
//! A project may lower a ceiling or a cap, may remove a model from a role or a route, and may make
//! a rule of independence stricter. It may not add a model, raise a price, raise a ceiling or
//! weaken a rule. [`check_tighten`] lists every place where a candidate is looser.

use super::common::{
    ConfigSource, ConflictResolution, PolicyStatus, ProjectOverrides, SchemaVersionOne, ThreatId,
    closed_set, strict,
};

strict! {
    /// The whole of `policies/model_routing.yaml`.
    pub struct ModelRoutingPolicy {
        /// Always 1.
        pub schema_version: SchemaVersionOne,
        /// Identity and global rules.
        pub policy: RoutingHeader,
        /// The models, with their prices.
        pub models: Vec<Model>,
        /// What each agent role may use and spend.
        pub roles: Vec<Role>,
        /// The models to try for a stage and a tier.
        pub routes: Vec<Route>,
        /// Reviewer independence.
        pub independence: Independence,
        /// What one job may spend.
        pub job: JobSpend,
    }
}

closed_set! {
    /// What a model that no role lists gets. The only value is a refusal.
    pub enum RoutingDefault {
        /// The model is refused.
        Deny,
    }
}

strict! {
    /// Identity and global rules of the routing policy.
    pub struct RoutingHeader {
        /// Always `model_routing`.
        pub id: String,
        /// The policy version.
        pub version: u32,
        /// Designed or enforced.
        pub status: PolicyStatus,
        /// What a model that is not listed gets. Required, and only `deny` is valid.
        pub default_action: RoutingDefault,
        /// How rules combine.
        pub conflict_resolution: ConflictResolution,
        /// What a project policy may do.
        pub project_overrides: ProjectOverrides,
        /// Where the file must be read from.
        pub config_source: ConfigSource,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

closed_set! {
    /// How capable a model is. The order is the order of the variants: `Small`, `Standard`, `Large`.
    pub enum Tier {
        /// Small.
        Small,
        /// Standard.
        Standard,
        /// Large.
        Large,
    }
}

impl Tier {
    /// The order of the tiers, from the smallest.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Small => 0,
            Self::Standard => 1,
            Self::Large => 2,
        }
    }
}

strict! {
    /// What a model costs, in millionths of a US dollar for a million tokens.
    pub struct Prices {
        /// Plain input.
        pub input: u64,
        /// Input written to the provider's cache.
        pub cache_write: u64,
        /// Input read from the provider's cache.
        pub cache_read: u64,
        /// Output, including reasoning tokens.
        pub output: u64,
    }
}

strict! {
    /// One model.
    pub struct Model {
        /// The name as the provider spells it, and as the agent manifests list it.
        pub id: String,
        /// `anthropic` or `openai`.
        pub provider: String,
        /// The runtime that drives the model, such as `claude-code-cli`.
        pub runtime: String,
        /// The family: two models of one family are the same kind of reviewer.
        pub family: String,
        /// How capable it is.
        pub tier: Tier,
        /// What it costs.
        pub prices: Prices,
        /// The date a person read the prices on the provider's page (`YYYY-MM-DD`), or `unchecked`.
        pub price_checked_on: String,
        /// Where to read the real prices, or how the placeholder was chosen.
        pub price_source: String,
    }
}

strict! {
    /// What a run of a stage may spend.
    pub struct StageCeiling {
        /// Millionths of a US dollar.
        pub max_micro_usd: u64,
        /// Input and output tokens together.
        pub max_tokens: u64,
    }
}

strict! {
    /// The largest request the broker forwards for a role.
    pub struct RequestCaps {
        /// Input tokens in one request.
        pub max_input_tokens: u64,
        /// Output tokens in one request.
        pub max_output_tokens: u64,
    }
}

strict! {
    /// One agent role.
    pub struct Role {
        /// The role, as the agent manifest spells it.
        pub role: String,
        /// The stage that runs it.
        pub stage: String,
        /// Every model the role may use.
        pub allowed_models: Vec<String>,
        /// The model of the first attempt.
        pub start_with: String,
        /// The model to use after the failed repairs.
        pub escalate_to: String,
        /// How many repairs fail before the role escalates.
        pub escalate_after_failed_repairs: u32,
        /// The most one run of the stage may spend.
        pub per_stage_run: StageCeiling,
        /// The largest request the broker forwards.
        pub per_request: RequestCaps,
    }
}

strict! {
    /// The models to try for a stage and a tier.
    pub struct Route {
        /// The stage.
        pub stage: String,
        /// The tier.
        pub tier: Tier,
        /// The models, in the order to try them.
        pub candidates: Vec<String>,
    }
}

closed_set! {
    /// What happens when no allowed model is independent of the author.
    pub enum OnNoIndependentModel {
        /// The reviewing stage waits for a person.
        WaitForHuman,
    }
}

closed_set! {
    /// How two models must differ for a review to be independent. The order is the order of the
    /// variants, from the weakest to the strongest: `Model`, `Family`, `Provider`.
    pub enum DifferBy {
        /// The models are not the same model.
        Model,
        /// The models are of different families.
        Family,
        /// The models are from different providers.
        Provider,
    }
}

impl DifferBy {
    /// The order of the choices, from the weakest.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Model => 0,
            Self::Family => 1,
            Self::Provider => 2,
        }
    }
}

strict! {
    /// One rule of independence.
    pub struct IndependenceRule {
        /// The identifier.
        pub id: String,
        /// The role whose work is reviewed.
        pub author_role: String,
        /// The role that reviews it.
        pub reviewer_role: String,
        /// How the two models must differ.
        pub must_differ_by: DifferBy,
    }
}

strict! {
    /// Reviewer independence.
    pub struct Independence {
        /// What happens when no allowed model satisfies a rule.
        pub on_no_independent_model: OnNoIndependentModel,
        /// The rules.
        pub rules: Vec<IndependenceRule>,
    }
}

strict! {
    /// What all the stages of one job may spend together.
    pub struct JobSpend {
        /// Millionths of a US dollar.
        pub max_micro_usd: u64,
        /// Input and output tokens together.
        pub max_tokens: u64,
    }
}

impl ModelRoutingPolicy {
    /// The model with this name.
    #[must_use]
    pub fn model(&self, id: &str) -> Option<&Model> {
        self.models.iter().find(|model| model.id == id)
    }

    /// The role with this name.
    #[must_use]
    pub fn role(&self, role: &str) -> Option<&Role> {
        self.roles.iter().find(|entry| entry.role == role)
    }

    /// The roles that run in a stage. A stage can have more than one, such as the writer and the
    /// reviewer of a specification.
    pub fn roles_of_stage<'a>(&'a self, stage: &'a str) -> impl Iterator<Item = &'a Role> + 'a {
        self.roles.iter().filter(move |entry| entry.stage == stage)
    }

    /// The models to try for a stage and a tier, in the order the policy lists them. Empty when
    /// the policy has no route, which the router reads as "no route".
    #[must_use]
    pub fn candidates(&self, stage: &str, tier: Tier) -> Vec<&Model> {
        self.routes
            .iter()
            .filter(|route| route.stage == stage && route.tier == tier)
            .flat_map(|route| route.candidates.iter())
            .filter_map(|id| self.model(id))
            .collect()
    }

    /// The models a stage may use: those its roles may use and its routes list. A job token for
    /// the stage holds no other.
    #[must_use]
    pub fn allowed_models(&self, stage: &str) -> Vec<&Model> {
        let mut allowed: Vec<&Model> = Vec::new();
        for route in self.routes.iter().filter(|route| route.stage == stage) {
            for id in &route.candidates {
                let in_a_role = self
                    .roles_of_stage(stage)
                    .any(|role| role.allowed_models.iter().any(|m| m == id));
                if let Some(model) = self.model(id)
                    && in_a_role
                    && !allowed.iter().any(|held| held.id == model.id)
                {
                    allowed.push(model);
                }
            }
        }
        allowed
    }

    /// The most a run of the stage may spend. When more than one role runs in the stage, the
    /// larger ceiling of the two applies to the stage and each role keeps its own.
    #[must_use]
    pub fn stage_ceiling(&self, stage: &str) -> Option<StageCeiling> {
        self.roles_of_stage(stage)
            .map(|role| role.per_stage_run.clone())
            .reduce(|a, b| StageCeiling {
                max_micro_usd: a.max_micro_usd.max(b.max_micro_usd),
                max_tokens: a.max_tokens.max(b.max_tokens),
            })
    }

    /// The prices of every model, for the broker: `(provider, model, prices)`.
    #[must_use]
    pub fn prices(&self) -> Vec<(&str, &str, &Prices)> {
        self.models
            .iter()
            .map(|model| (model.provider.as_str(), model.id.as_str(), &model.prices))
            .collect()
    }

    /// The price of a model.
    #[must_use]
    pub fn price(&self, id: &str) -> Option<&Prices> {
        self.model(id).map(|model| &model.prices)
    }

    /// True when `reviewer` may review the work of `author` under the rule: they differ in the way
    /// the rule says. A model the policy does not know is never independent.
    #[must_use]
    pub fn independent(&self, rule: &IndependenceRule, author: &str, reviewer: &str) -> bool {
        let (Some(a), Some(r)) = (self.model(author), self.model(reviewer)) else {
            return false;
        };
        match rule.must_differ_by {
            DifferBy::Model => a.id != r.id,
            DifferBy::Family => a.family != r.family,
            DifferBy::Provider => a.provider != r.provider,
        }
    }

    /// The models the reviewer role may use that are independent of `author` under the rule, in
    /// the order the role lists them. Empty means the reviewing stage waits for a person.
    #[must_use]
    pub fn independent_reviewers(&self, rule: &IndependenceRule, author: &str) -> Vec<&Model> {
        let Some(role) = self.role(&rule.reviewer_role) else {
            return Vec::new();
        };
        role.allowed_models
            .iter()
            .filter(|id| self.independent(rule, author, id))
            .filter_map(|id| self.model(id))
            .collect()
    }

    /// The rule that governs a reviewer role, when there is one.
    #[must_use]
    pub fn rule_for_reviewer(&self, reviewer_role: &str) -> Option<&IndependenceRule> {
        self.independence
            .rules
            .iter()
            .find(|rule| rule.reviewer_role == reviewer_role)
    }

    /// Everything in the file that still waits for a person: the status, and each price whose date
    /// is `unchecked`. A production run starts only when this is empty.
    #[must_use]
    pub fn unconfirmed(&self) -> Vec<String> {
        let mut found = Vec::new();
        if self.policy.status == PolicyStatus::Designed {
            found.push("policy.status is designed".to_owned());
        }
        for model in &self.models {
            if model.price_checked_on == "unchecked" {
                found.push(format!("the prices of {} are unchecked", model.id));
            }
        }
        found
    }
}

/// One place where a candidate routing policy is looser than the central one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Looser {
    /// The key, such as `roles[builder].per_stage_run.max_micro_usd`.
    pub key: String,
    /// What is looser, in a few words.
    pub why: &'static str,
}

/// Every place where `candidate` is looser than `central`. Empty means the candidate only
/// tightens. Prose (`price_source`, `price_checked_on`) is free; everything else is compared.
#[must_use]
pub fn check_tighten(central: &ModelRoutingPolicy, candidate: &ModelRoutingPolicy) -> Vec<Looser> {
    let mut found = Vec::new();
    let mut loosen = |key: String, why: &'static str| found.push(Looser { key, why });

    // Models: none may be added, and a kept model keeps its price, its provider, its runtime, its
    // family and its tier. A price may go up only in the sense of being closer to the truth, which
    // the owner does by changing the central file, not a project's.
    for model in &candidate.models {
        match central.model(&model.id) {
            None => loosen(format!("models[{}]", model.id), "a model was added"),
            Some(old) => {
                if model.provider != old.provider {
                    loosen(
                        format!("models[{}].provider", model.id),
                        "the provider changed",
                    );
                }
                if model.runtime != old.runtime {
                    loosen(
                        format!("models[{}].runtime", model.id),
                        "the runtime changed",
                    );
                }
                if model.family != old.family {
                    loosen(format!("models[{}].family", model.id), "the family changed");
                }
                if model.tier != old.tier {
                    loosen(format!("models[{}].tier", model.id), "the tier changed");
                }
                if model.prices.input < old.prices.input
                    || model.prices.cache_write < old.prices.cache_write
                    || model.prices.cache_read < old.prices.cache_read
                    || model.prices.output < old.prices.output
                {
                    loosen(
                        format!("models[{}].prices", model.id),
                        "a price was lowered, so the broker would count less than the central policy does",
                    );
                }
            }
        }
    }

    // Roles: none may be added, a role may only lose models, and every ceiling may only go down.
    for role in &candidate.roles {
        let key = |field: &str| format!("roles[{}].{field}", role.role);
        let Some(old) = central.role(&role.role) else {
            loosen(format!("roles[{}]", role.role), "a role was added");
            continue;
        };
        if role.stage != old.stage {
            loosen(key("stage"), "the stage changed");
        }
        if role
            .allowed_models
            .iter()
            .any(|id| !old.allowed_models.contains(id))
        {
            loosen(key("allowed_models"), "a model was added to the role");
        }
        if !role.allowed_models.contains(&role.start_with) {
            loosen(
                key("start_with"),
                "the first model is not one the role may use",
            );
        }
        if !role.allowed_models.contains(&role.escalate_to) {
            loosen(
                key("escalate_to"),
                "the larger model is not one the role may use",
            );
        }
        if role.escalate_after_failed_repairs < old.escalate_after_failed_repairs {
            loosen(
                key("escalate_after_failed_repairs"),
                "the role escalates to the larger model sooner",
            );
        }
        if role.per_stage_run.max_micro_usd > old.per_stage_run.max_micro_usd {
            loosen(key("per_stage_run.max_micro_usd"), "a ceiling was raised");
        }
        if role.per_stage_run.max_tokens > old.per_stage_run.max_tokens {
            loosen(key("per_stage_run.max_tokens"), "a ceiling was raised");
        }
        if role.per_request.max_input_tokens > old.per_request.max_input_tokens {
            loosen(key("per_request.max_input_tokens"), "a cap was raised");
        }
        if role.per_request.max_output_tokens > old.per_request.max_output_tokens {
            loosen(key("per_request.max_output_tokens"), "a cap was raised");
        }
    }
    // A role that the central policy has must stay, or the stage has no route.
    for old in &central.roles {
        if candidate.role(&old.role).is_none() {
            loosen(format!("roles[{}]", old.role), "a role was removed");
        }
    }

    // Routes: an entry may lose candidates and may not gain one.
    for route in &candidate.routes {
        let key = format!("routes[{} {:?}]", route.stage, route.tier);
        let kept: Vec<&String> = central
            .routes
            .iter()
            .filter(|old| old.stage == route.stage && old.tier == route.tier)
            .flat_map(|old| old.candidates.iter())
            .collect();
        if kept.is_empty() {
            loosen(key, "a route was added");
        } else if route.candidates.iter().any(|id| !kept.contains(&id)) {
            loosen(key, "a model was added to the route");
        }
    }

    // Independence: no rule may be removed or weakened, and the fallback may not change.
    for old in &central.independence.rules {
        match candidate
            .independence
            .rules
            .iter()
            .find(|rule| rule.id == old.id)
        {
            None => loosen(
                format!("independence.rules[{}]", old.id),
                "a rule of independence was removed",
            ),
            Some(rule) => {
                if rule.author_role != old.author_role || rule.reviewer_role != old.reviewer_role {
                    loosen(
                        format!("independence.rules[{}]", old.id),
                        "the roles of a rule changed",
                    );
                }
                if rule.must_differ_by.rank() < old.must_differ_by.rank() {
                    loosen(
                        format!("independence.rules[{}].must_differ_by", old.id),
                        "a rule of independence was weakened",
                    );
                }
            }
        }
    }

    if candidate.job.max_micro_usd > central.job.max_micro_usd {
        loosen("job.max_micro_usd".to_owned(), "a ceiling was raised");
    }
    if candidate.job.max_tokens > central.job.max_tokens {
        loosen("job.max_tokens".to_owned(), "a ceiling was raised");
    }
    found
}
