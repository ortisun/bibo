//! `policies/model_routing.yaml`: loading it, and the rules that tie it to the rest.
//!
//! The file is read like the other two policies (through a `ProtectedPolicySource`, one document,
//! no unknown key, a hash of the canonical form), and it must pass the rules in
//! [`routing_problems`] before a value exists. Two more sets of rules need something the file does
//! not hold:
//!
//! * [`security_problems_of`] compares it with `policies/security.yaml`: the ceiling of a job is at
//!   or under the hard ceiling there, and the per-request caps are at or under the caps there.
//!   [`PolicyLoader::load_model_routing`] runs it, so a routing policy that is looser than the
//!   security policy does not load.
//! * [`manifest_problems`] compares it with the agent manifests: the models a role may use are the
//!   models its manifest recommends, and its ceilings are at or under the manifest's limits. The
//!   manifests are read elsewhere (`FileAgentRegistry`), so the caller hands in the facts.
//!
//! No key and no secret is ever read or held here.

use std::collections::BTreeSet;

use factory_domain::policy::routing::{DifferBy, ModelRoutingPolicy, Tier};
use factory_domain::policy::security::SecurityPolicy;
use factory_domain::vocabulary::StageKind;

use super::check::{Problem, ProblemKind};
use super::{
    ConfigSource, LoadedPolicy, PolicyError, PolicyLoader, ProtectedPolicySource, load_document,
    read_policy_file,
};

/// The routing policy file, relative to the checkout.
pub const MODEL_ROUTING_FILE: &str = "policies/model_routing.yaml";

/// The providers the broker can forward to.
const PROVIDERS: [&str; 2] = ["anthropic", "openai"];

impl PolicyLoader {
    /// Loads `policies/model_routing.yaml` and checks it against the security policy.
    ///
    /// # Errors
    /// A [`PolicyError`]. No policy value exists after an error.
    pub fn load_model_routing(
        source: &ProtectedPolicySource,
        security: &SecurityPolicy,
    ) -> Result<LoadedPolicy<ModelRoutingPolicy>, PolicyError> {
        let (label, text, file_sha256) = read_policy_file(source, MODEL_ROUTING_FILE)?;
        load_document(
            &label,
            &text,
            file_sha256,
            |p: &ModelRoutingPolicy| p.policy.config_source,
            |p: &ModelRoutingPolicy| {
                let mut found = routing_problems(p);
                found.extend(security_problems_of(p, security));
                found
            },
        )
    }
}

fn problem(path: impl Into<String>, kind: ProblemKind, message: impl Into<String>) -> Problem {
    Problem {
        path: path.into(),
        kind,
        message: message.into(),
    }
}

fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 10
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            _ => b.is_ascii_digit(),
        })
}

/// The rules the file must satisfy on its own.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn routing_problems(policy: &ModelRoutingPolicy) -> Vec<Problem> {
    let mut found = Vec::new();
    if policy.policy.id != "model_routing" {
        found.push(problem(
            "policy.id",
            ProblemKind::Constraint,
            "this file must be the routing policy, with `id: model_routing`",
        ));
    }
    if policy.policy.version == 0 {
        found.push(problem(
            "policy.version",
            ProblemKind::Constraint,
            "the version starts at 1",
        ));
    }
    if policy.policy.config_source != ConfigSource::ProtectedDefaultBranch {
        found.push(problem(
            "policy.config_source",
            ProblemKind::Constraint,
            "the routing policy is read from the protected default branch",
        ));
    }

    // Models.
    let mut seen = BTreeSet::new();
    for (i, model) in policy.models.iter().enumerate() {
        let at = |field: &str| format!("models[{i}].{field}");
        if !seen.insert(model.id.as_str()) {
            found.push(problem(
                at("id"),
                ProblemKind::DuplicateId,
                format!("the model `{}` is listed twice", model.id),
            ));
        }
        if model.id.trim().is_empty() || model.id.chars().any(char::is_whitespace) {
            found.push(problem(
                at("id"),
                ProblemKind::Constraint,
                "a model name is not empty and has no white space",
            ));
        }
        if !PROVIDERS.contains(&model.provider.as_str()) {
            found.push(problem(
                at("provider"),
                ProblemKind::UnknownReference,
                format!(
                    "`{}` is not a provider the broker forwards to; it must be one of: {}",
                    model.provider,
                    PROVIDERS.join(", ")
                ),
            ));
        }
        for (field, text) in [("runtime", &model.runtime), ("family", &model.family)] {
            if text.trim().is_empty() {
                found.push(problem(
                    at(field),
                    ProblemKind::Constraint,
                    format!("`{field}` is empty"),
                ));
            }
        }
        let prices = &model.prices;
        for (field, value) in [
            ("input", prices.input),
            ("cache_write", prices.cache_write),
            ("cache_read", prices.cache_read),
            ("output", prices.output),
        ] {
            if value == 0 {
                found.push(problem(
                    at(&format!("prices.{field}")),
                    ProblemKind::Constraint,
                    "a price of zero would make the model free in the broker's count; give it a price",
                ));
            }
        }
        if model.price_checked_on != "unchecked" && !is_date(&model.price_checked_on) {
            found.push(problem(
                at("price_checked_on"),
                ProblemKind::Constraint,
                "write the date a person read the price as YYYY-MM-DD, or `unchecked`",
            ));
        }
        if model.price_source.trim().is_empty() {
            found.push(problem(
                at("price_source"),
                ProblemKind::Constraint,
                "say where the price was read, or how the placeholder was chosen",
            ));
        }
    }

    // Roles.
    let mut roles = BTreeSet::new();
    for (i, role) in policy.roles.iter().enumerate() {
        let at = |field: &str| format!("roles[{i}].{field}");
        if !roles.insert(role.role.as_str()) {
            found.push(problem(
                at("role"),
                ProblemKind::DuplicateId,
                format!("the role `{}` is listed twice", role.role),
            ));
        }
        if StageKind::parse(&role.stage).is_err() {
            found.push(problem(
                at("stage"),
                ProblemKind::UnknownReference,
                format!("`{}` is not a stage kind", role.stage),
            ));
        }
        if role.allowed_models.is_empty() {
            found.push(problem(
                at("allowed_models"),
                ProblemKind::Constraint,
                "a role needs at least one model, or it can never run",
            ));
        }
        for (field, name) in [
            ("start_with", &role.start_with),
            ("escalate_to", &role.escalate_to),
        ] {
            if !role.allowed_models.contains(name) {
                found.push(problem(
                    at(field),
                    ProblemKind::UnknownReference,
                    format!("`{name}` is not one of the models the role may use"),
                ));
            }
        }
        for model in &role.allowed_models {
            if policy.model(model).is_none() {
                found.push(problem(
                    at("allowed_models"),
                    ProblemKind::UnknownReference,
                    format!("`{model}` is not in `models`"),
                ));
            }
        }
        if let (Some(start), Some(larger)) = (
            policy.model(&role.start_with),
            policy.model(&role.escalate_to),
        ) && larger.tier.rank() <= start.tier.rank()
        {
            found.push(problem(
                at("escalate_to"),
                ProblemKind::Constraint,
                "the model to escalate to must be of a larger tier than the model to start with",
            ));
        }
        if role.escalate_after_failed_repairs == 0 {
            found.push(problem(
                at("escalate_after_failed_repairs"),
                ProblemKind::Constraint,
                "a role does not escalate before it has failed a repair; use 1 or more",
            ));
        }
        let run = &role.per_stage_run;
        if run.max_micro_usd == 0 || run.max_tokens == 0 {
            found.push(problem(
                at("per_stage_run"),
                ProblemKind::Constraint,
                "a ceiling of zero stops every run; give the stage a ceiling",
            ));
        }
        let caps = &role.per_request;
        if caps.max_input_tokens == 0 || caps.max_output_tokens == 0 {
            found.push(problem(
                at("per_request"),
                ProblemKind::Constraint,
                "a cap of zero refuses every request; give the role a cap",
            ));
        }
        if caps.max_output_tokens.saturating_add(caps.max_input_tokens) > run.max_tokens {
            found.push(problem(
                at("per_request"),
                ProblemKind::Constraint,
                "one request may not be larger than the stage run's ceiling of tokens",
            ));
        }
    }

    // Routes.
    for (i, route) in policy.routes.iter().enumerate() {
        let at = |field: &str| format!("routes[{i}].{field}");
        if route.candidates.is_empty() {
            found.push(problem(
                at("candidates"),
                ProblemKind::Constraint,
                "a route lists at least one model",
            ));
        }
        let roles_here: Vec<_> = policy.roles_of_stage(&route.stage).collect();
        if roles_here.is_empty() {
            found.push(problem(
                at("stage"),
                ProblemKind::UnknownReference,
                format!("no role runs in the stage `{}`", route.stage),
            ));
        }
        let mut listed = BTreeSet::new();
        for id in &route.candidates {
            if !listed.insert(id.as_str()) {
                found.push(problem(
                    at("candidates"),
                    ProblemKind::DuplicateId,
                    format!("`{id}` is listed twice in one route"),
                ));
            }
            match policy.model(id) {
                None => found.push(problem(
                    at("candidates"),
                    ProblemKind::UnknownReference,
                    format!("`{id}` is not in `models`"),
                )),
                Some(model) => {
                    if model.tier != route.tier {
                        found.push(problem(
                            at("candidates"),
                            ProblemKind::Constraint,
                            format!(
                                "`{id}` is a {:?} model and the route is for the {:?} tier",
                                model.tier, route.tier
                            ),
                        ));
                    }
                    if !roles_here
                        .iter()
                        .any(|role| role.allowed_models.contains(id))
                    {
                        found.push(problem(
                            at("candidates"),
                            ProblemKind::UnknownReference,
                            format!("no role of the stage `{}` may use `{id}`", route.stage),
                        ));
                    }
                }
            }
        }
    }
    // Every stage that has a role has a route for the standard tier, or it can never be routed.
    let mut stages = BTreeSet::new();
    for role in &policy.roles {
        stages.insert(role.stage.as_str());
    }
    for stage in stages {
        if policy.candidates(stage, Tier::Standard).is_empty() {
            found.push(problem(
                "routes",
                ProblemKind::UnknownReference,
                format!("the stage `{stage}` has a role and no route for the standard tier"),
            ));
        }
    }

    // Independence.
    let mut rule_ids = BTreeSet::new();
    for (i, rule) in policy.independence.rules.iter().enumerate() {
        let at = |field: &str| format!("independence.rules[{i}].{field}");
        if !rule_ids.insert(rule.id.as_str()) {
            found.push(problem(
                at("id"),
                ProblemKind::DuplicateId,
                format!("the rule `{}` is listed twice", rule.id),
            ));
        }
        for (field, name) in [
            ("author_role", &rule.author_role),
            ("reviewer_role", &rule.reviewer_role),
        ] {
            if policy.role(name).is_none() {
                found.push(problem(
                    at(field),
                    ProblemKind::UnknownReference,
                    format!("`{name}` is not a role in `roles`"),
                ));
            }
        }
        // A rule that no author could satisfy would stop every job at the review.
        if let Some(author) = policy.role(&rule.author_role) {
            for model in &author.allowed_models {
                if policy.independent_reviewers(rule, model).is_empty() {
                    found.push(problem(
                        at("must_differ_by"),
                        ProblemKind::Constraint,
                        format!(
                            "when the author uses `{model}`, no model of `{}` differs from it by {}, so the review could never run",
                            rule.reviewer_role,
                            match rule.must_differ_by {
                                DifferBy::Model => "model",
                                DifferBy::Family => "family",
                                DifferBy::Provider => "provider",
                            }
                        ),
                    ));
                }
            }
        }
    }

    // The job.
    if policy.job.max_micro_usd == 0 || policy.job.max_tokens == 0 {
        found.push(problem(
            "job",
            ProblemKind::Constraint,
            "a ceiling of zero stops every job; give the job a ceiling",
        ));
    }
    found
}

/// The rules that compare the routing policy with `policies/security.yaml`: nothing here is looser
/// than the hard ceilings and the caps there.
#[must_use]
pub fn security_problems_of(
    policy: &ModelRoutingPolicy,
    security: &SecurityPolicy,
) -> Vec<Problem> {
    let mut found = Vec::new();
    let budgets = &security.budgets;
    // Millionths of a dollar, rounded down so that a ceiling is never read as higher than it is.
    let hard_job = (budgets.hard_ceilings.per_job.max_usd * 1_000_000.0).floor();
    #[allow(clippy::cast_precision_loss)]
    if (policy.job.max_micro_usd as f64) > hard_job {
        found.push(problem(
            "job.max_micro_usd",
            ProblemKind::Constraint,
            "the ceiling of a job is above `budgets.hard_ceilings.per_job.max_usd` of the security policy",
        ));
    }
    let hard_task = (budgets.hard_ceilings.per_task.max_usd * 1_000_000.0).floor();
    for (i, role) in policy.roles.iter().enumerate() {
        #[allow(clippy::cast_precision_loss)]
        if (role.per_stage_run.max_micro_usd as f64) > hard_task {
            found.push(problem(
                format!("roles[{i}].per_stage_run.max_micro_usd"),
                ProblemKind::Constraint,
                "the ceiling of a stage run is above `budgets.hard_ceilings.per_task.max_usd` of the security policy",
            ));
        }
        if role.per_request.max_input_tokens > budgets.per_request_caps.max_input_tokens {
            found.push(problem(
                format!("roles[{i}].per_request.max_input_tokens"),
                ProblemKind::Constraint,
                "the cap is above `budgets.per_request_caps.max_input_tokens` of the security policy",
            ));
        }
        if role.per_request.max_output_tokens > budgets.per_request_caps.max_output_tokens {
            found.push(problem(
                format!("roles[{i}].per_request.max_output_tokens"),
                ProblemKind::Constraint,
                "the cap is above `budgets.per_request_caps.max_output_tokens` of the security policy",
            ));
        }
    }
    found
}

/// What the routing policy is compared with in an agent manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestFacts {
    /// The role of the agent.
    pub role: String,
    /// `resource_limits.max_tokens`.
    pub max_tokens: u64,
    /// `resource_limits.max_cost_usd`.
    pub max_cost_usd: f64,
    /// `recommended_models`: the runtime and the model of each.
    pub recommended: Vec<(String, String)>,
}

/// The rules that compare the routing policy with the agent manifests: a role of the policy is a
/// role of a manifest, the models it may use are the models its manifest recommends (and on the
/// runtime the manifest names), and its ceilings are at or under the manifest's limits.
#[must_use]
pub fn manifest_problems(policy: &ModelRoutingPolicy, manifests: &[ManifestFacts]) -> Vec<Problem> {
    let mut found = Vec::new();
    for (i, role) in policy.roles.iter().enumerate() {
        let at = |field: &str| format!("roles[{i}].{field}");
        let Some(manifest) = manifests.iter().find(|m| m.role == role.role) else {
            found.push(problem(
                at("role"),
                ProblemKind::UnknownReference,
                format!("no agent manifest has the role `{}`", role.role),
            ));
            continue;
        };
        for id in &role.allowed_models {
            let runtime = policy.model(id).map(|m| m.runtime.as_str());
            if !manifest
                .recommended
                .iter()
                .any(|(r, m)| m == id && Some(r.as_str()) == runtime)
            {
                found.push(problem(
                    at("allowed_models"),
                    ProblemKind::Constraint,
                    format!(
                        "the manifest of `{}` does not recommend `{id}` on the runtime the policy gives it",
                        role.role
                    ),
                ));
            }
        }
        if role.per_stage_run.max_tokens > manifest.max_tokens {
            found.push(problem(
                at("per_stage_run.max_tokens"),
                ProblemKind::Constraint,
                format!(
                    "the ceiling is above the {} tokens in the manifest of `{}`",
                    manifest.max_tokens, role.role
                ),
            ));
        }
        #[allow(clippy::cast_precision_loss)]
        if (role.per_stage_run.max_micro_usd as f64) > (manifest.max_cost_usd * 1_000_000.0).floor()
        {
            found.push(problem(
                at("per_stage_run.max_micro_usd"),
                ProblemKind::Constraint,
                format!(
                    "the ceiling is above the {} dollars in the manifest of `{}`",
                    manifest.max_cost_usd, role.role
                ),
            ));
        }
    }
    for manifest in manifests {
        if policy.role(&manifest.role).is_none() {
            found.push(problem(
                "roles",
                ProblemKind::UnknownReference,
                format!(
                    "the agent role `{}` has no entry in the policy",
                    manifest.role
                ),
            ));
        }
    }
    found
}
