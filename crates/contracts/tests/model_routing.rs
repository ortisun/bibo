//! `policies/model_routing.yaml`: it loads, it says what the router, the engine and the broker rely
//! on, it agrees with the agent manifests and the security policy, and a file that breaks a rule
//! does not load.

mod support;

use factory_contracts::policy::routing::{
    ManifestFacts, manifest_problems, routing_problems, security_problems_of,
};
use factory_contracts::policy::routing_policy::{
    DifferBy, ModelRoutingPolicy, Tier, check_tighten,
};
use factory_contracts::policy::{
    PolicyErrorKind, PolicyHash, PolicyLoader, PolicyStatus, ProtectedPolicySource, SecurityPolicy,
};
use support::{TempDir, read_text, repo_root};

fn source() -> ProtectedPolicySource {
    ProtectedPolicySource::protected_default_branch(&repo_root(), &[])
        .expect("the repository root exists")
}

fn security() -> SecurityPolicy {
    PolicyLoader::load_security(&source())
        .expect("security")
        .document
}

fn real() -> ModelRoutingPolicy {
    PolicyLoader::load_model_routing(&source(), &security())
        .unwrap_or_else(|e| panic!("{e}"))
        .document
}

fn real_text() -> String {
    read_text(&repo_root().join("policies/model_routing.yaml"))
}

/// Loads a variation of the real file from a checkout of its own.
fn load_text(text: &str) -> Result<(), factory_contracts::policy::PolicyError> {
    let dir = TempDir::new("model-routing");
    dir.write("policies/model_routing.yaml", text);
    let source = ProtectedPolicySource::protected_default_branch(dir.path(), &[])
        .expect("the directory exists");
    PolicyLoader::load_model_routing(&source, &security()).map(|_| ())
}

fn manifests() -> Vec<ManifestFacts> {
    let mut found = Vec::new();
    let agents = repo_root().join("agents");
    for entry in std::fs::read_dir(&agents).expect("agents/") {
        let path = entry.expect("an entry").path().join("manifest.json");
        if !path.is_file() {
            continue;
        }
        let manifest: serde_json::Value =
            serde_json::from_str(&read_text(&path)).expect("a manifest is JSON");
        found.push(ManifestFacts {
            role: manifest["role"].as_str().expect("a role").to_owned(),
            max_tokens: manifest["resource_limits"]["max_tokens"]
                .as_u64()
                .expect("tokens"),
            max_cost_usd: manifest["resource_limits"]["max_cost_usd"]
                .as_f64()
                .expect("dollars"),
            recommended: manifest["recommended_models"]
                .as_array()
                .expect("models")
                .iter()
                .map(|m| {
                    (
                        m["runtime_id"].as_str().expect("runtime").to_owned(),
                        m["model"].as_str().expect("model").to_owned(),
                    )
                })
                .collect(),
        });
    }
    found
}

// ---- the real file ----------------------------------------------------------------------------

#[test]
fn the_routing_policy_in_policies_loads_and_its_hash_is_stable() {
    let a = PolicyLoader::load_model_routing(&source(), &security()).expect("loads");
    let b = PolicyLoader::load_model_routing(&source(), &security()).expect("loads again");
    assert_eq!(a.document.policy.id, "model_routing");
    assert!(a.file.ends_with("policies/model_routing.yaml"));
    assert_eq!(a.hash, b.hash);
    assert_eq!(a.hash, PolicyHash::of(&a.document).expect("hash"));
    let approval = PolicyLoader::load_approval(&source()).expect("approval");
    assert_ne!(a.hash, approval.hash);
}

#[test]
fn the_file_is_enforced_and_every_price_was_read_on_a_named_page() {
    // The owner confirmed the policy on 2026-11-13, after the prices were read from the providers'
    // price pages. Nothing in it waits any more, and each price says when and where it was read.
    let policy = real();
    assert_eq!(policy.policy.status, PolicyStatus::Enforced);
    let waiting = policy.unconfirmed();
    assert!(waiting.is_empty(), "{waiting:?}");
    let text = real_text();
    assert!(!text.contains("PENDING CONFIRMATION BY THE PROJECT OWNER"));
    for model in &policy.models {
        assert!(
            text.contains(&format!("id: {}", model.id)),
            "{} is not in the file",
            model.id
        );
    }
    let sources = text
        .lines()
        .filter(|l| l.trim_start().starts_with("price_source:"))
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), policy.models.len());
    for source in sources {
        assert!(source.contains("price page"), "{source}");
        assert!(source.contains("Read on 2026-11-13"), "{source}");
    }
}

#[test]
fn the_file_holds_no_key_no_token_and_no_address() {
    // The comments say where a key lives (a file named in the worker configuration). The document
    // itself, with its comments taken off, holds none and names no address.
    let document: String = real_text()
        .lines()
        .map(|line| line.split(" #").next().unwrap_or(line))
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    for forbidden in [
        "sk-", "ghs_", "ghp_", "bearer", "http://", "https://", "key_file", "base_url", "secret",
        "password", "token:",
    ] {
        assert!(
            !document.contains(forbidden),
            "the document contains {forbidden}"
        );
    }
}

#[test]
fn the_models_are_the_ones_in_the_manifests_and_no_other() {
    let policy = real();
    let mut from_manifests: Vec<String> = manifests()
        .iter()
        .flat_map(|m| m.recommended.iter().map(|(_, model)| model.clone()))
        .collect();
    from_manifests.sort();
    from_manifests.dedup();
    let mut in_policy: Vec<String> = policy.models.iter().map(|m| m.id.clone()).collect();
    in_policy.sort();
    assert_eq!(in_policy, from_manifests);
}

#[test]
fn every_role_agrees_with_its_manifest_and_every_ceiling_is_under_the_manifest_limit() {
    let policy = real();
    let problems = manifest_problems(&policy, &manifests());
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn every_ceiling_and_cap_is_under_the_security_policy() {
    let problems = security_problems_of(&real(), &security());
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn the_file_passes_its_own_rules() {
    let problems = routing_problems(&real());
    assert!(problems.is_empty(), "{problems:#?}");
}

// ---- the JSON Schema --------------------------------------------------------------------------

fn schema() -> factory_contracts::schema_engine::Schema {
    factory_contracts::schema_engine::Schema::compile_text(&read_text(
        &support::schemas_dir().join("policy-model-routing.schema.json"),
    ))
    .expect("the schema compiles")
}

#[test]
fn the_real_policy_validates_against_its_schema() {
    let value = serde_json::to_value(real()).expect("the policy is JSON");
    let (violations, _) = schema().validate(&value);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn every_valid_example_validates_and_every_invalid_example_is_rejected_by_the_rust_engine_too() {
    let schema = schema();
    let base = support::schemas_dir().join("examples/policy-model-routing");
    let valid = support::files_in(&base.join("valid"), &["json"]);
    let invalid = support::files_in(&base.join("invalid"), &["json"]);
    assert!(!valid.is_empty() && !invalid.is_empty());
    for path in valid {
        let (violations, _) = schema.validate(&support::read_example(&path));
        assert!(violations.is_empty(), "{}: {violations:#?}", path.display());
    }
    for path in invalid {
        let (violations, _) = schema.validate(&support::read_example(&path));
        assert!(!violations.is_empty(), "{} was accepted", path.display());
    }
}

#[test]
fn a_policy_that_the_schema_accepts_but_the_loader_refuses_is_a_rule_only_code_can_check() {
    // The example with one model and a checked price is valid for the schema. The shipped file with
    // the stage `DELIVERY` in a route is valid for the schema too (it is a stage kind), and the
    // loader refuses it: names that refer to each other are code's to check.
    let mut value = serde_json::to_value(real()).expect("json");
    value["routes"][0]["stage"] = serde_json::json!("DELIVERY");
    let (violations, _) = schema().validate(&value);
    assert!(violations.is_empty(), "{violations:#?}");
    let mut typed = real();
    typed.routes[0].stage = "DELIVERY".to_owned();
    assert!(!routing_problems(&typed).is_empty());
}

// ---- what the readers ask ---------------------------------------------------------------------

#[test]
fn the_router_gets_the_candidates_of_a_stage_and_tier_in_the_order_of_the_file() {
    let policy = real();
    let ids = |stage: &str, tier: Tier| -> Vec<String> {
        policy
            .candidates(stage, tier)
            .iter()
            .map(|m| m.id.clone())
            .collect()
    };
    assert_eq!(
        ids("IMPLEMENTATION", Tier::Standard),
        ["claude-sonnet-5-5", "gpt-6.1-sol"]
    );
    assert_eq!(ids("IMPLEMENTATION", Tier::Large), ["claude-opus-5-5"]);
    // The reviewing stage lists the model of the other family first.
    assert_eq!(ids("REVIEW", Tier::Standard)[0], "gpt-6.1-sol");
    // There is no small tier and no route for a stage that runs no agent.
    assert!(ids("IMPLEMENTATION", Tier::Small).is_empty());
    assert!(ids("DELIVERY", Tier::Standard).is_empty());
}

#[test]
fn a_job_token_for_a_stage_holds_the_models_of_its_routes_and_no_other() {
    let policy = real();
    let held: Vec<&str> = policy
        .allowed_models("REVIEW")
        .iter()
        .map(|m| m.id.as_str())
        .collect();
    assert_eq!(
        held,
        ["gpt-6.1-sol", "claude-sonnet-5-5", "claude-opus-5-5"]
    );
    assert!(policy.allowed_models("DELIVERY").is_empty());
}

#[test]
fn every_model_has_a_price_and_an_unknown_model_has_none() {
    let policy = real();
    for model in &policy.models {
        assert!(policy.price(&model.id).is_some());
    }
    assert!(policy.price("a-model-nobody-listed").is_none());
    assert_eq!(policy.prices().len(), policy.models.len());
}

#[test]
fn a_stage_with_two_roles_gets_the_larger_ceiling_of_the_two() {
    let policy = real();
    let writer = policy.role("specification_writer").expect("writer");
    let reviewer = policy.role("specification_reviewer").expect("reviewer");
    let ceiling = policy.stage_ceiling("SPECIFICATION").expect("a ceiling");
    assert_eq!(
        ceiling.max_micro_usd,
        writer
            .per_stage_run
            .max_micro_usd
            .max(reviewer.per_stage_run.max_micro_usd)
    );
    assert!(policy.stage_ceiling("DELIVERY").is_none());
}

// ---- reviewer independence --------------------------------------------------------------------

/// The owner chose `must_differ_by: model` for every reviewing rule on 2026-11-13 (ADR 0020,
/// amendment): in subscription mode only Claude runs, and another Claude model is the best
/// reviewer available. A reviewer is never the author's own model.
#[test]
fn every_reviewing_rule_asks_for_another_model_and_never_the_authors_own() {
    let policy = real();
    for reviewer in [
        "code_reviewer",
        "documentation_reviewer",
        "specification_reviewer",
        "architecture_critic",
    ] {
        let rule = policy.rule_for_reviewer(reviewer).expect("a rule");
        assert_eq!(rule.must_differ_by, DifferBy::Model, "{reviewer}");
        for author in ["claude-sonnet-5-5", "claude-opus-5-5", "gpt-6.1-sol"] {
            assert!(
                !policy.independent(rule, author, author),
                "{reviewer} {author}"
            );
            let reviewers: Vec<&str> = policy
                .independent_reviewers(rule, author)
                .iter()
                .map(|m| m.id.as_str())
                .collect();
            assert!(!reviewers.contains(&author), "{reviewer} {author}");
            assert_eq!(reviewers.len(), 2, "{reviewer} {author}");
        }
    }
    let code = policy.rule_for_reviewer("code_reviewer").expect("a rule");
    assert!(policy.independent(code, "claude-sonnet-5-5", "claude-opus-5-5"));
    assert!(policy.independent(code, "claude-opus-5-5", "claude-sonnet-5-5"));
}

/// The rule of `family` still works as before, for a deployment or a project that asks for it
/// (a project may make a rule stronger): a Claude builder is then reviewed only by the model of
/// the other family.
#[test]
fn a_reviewer_under_the_family_rule_is_never_of_the_family_of_the_builder() {
    let policy = real();
    let mut rule = policy
        .rule_for_reviewer("code_reviewer")
        .expect("a rule")
        .clone();
    rule.must_differ_by = DifferBy::Family;
    for builder in ["claude-sonnet-5-5", "claude-opus-5-5"] {
        assert!(!policy.independent(&rule, builder, "claude-sonnet-5-5"));
        assert!(!policy.independent(&rule, builder, "claude-opus-5-5"));
        assert!(policy.independent(&rule, builder, "gpt-6.1-sol"));
        let reviewers: Vec<&str> = policy
            .independent_reviewers(&rule, builder)
            .iter()
            .map(|m| m.id.as_str())
            .collect();
        assert_eq!(reviewers, ["gpt-6.1-sol"]);
    }
    let for_gpt: Vec<&str> = policy
        .independent_reviewers(&rule, "gpt-6.1-sol")
        .iter()
        .map(|m| m.id.as_str())
        .collect();
    assert_eq!(for_gpt, ["claude-sonnet-5-5", "claude-opus-5-5"]);
}

#[test]
fn a_model_the_policy_does_not_know_is_never_independent() {
    let policy = real();
    let rule = policy.rule_for_reviewer("code_reviewer").expect("a rule");
    assert!(!policy.independent(rule, "claude-sonnet-5-5", "a-model-nobody-listed"));
    assert!(!policy.independent(rule, "a-model-nobody-listed", "gpt-6.1-sol"));
}

#[test]
fn every_reviewing_role_has_a_rule_and_the_first_route_is_independent_of_the_first_author_model() {
    let policy = real();
    for (reviewer, author) in [
        ("code_reviewer", "builder"),
        ("documentation_reviewer", "technical_writer"),
        ("specification_reviewer", "specification_writer"),
        ("architecture_critic", "architect"),
    ] {
        let rule = policy
            .rule_for_reviewer(reviewer)
            .unwrap_or_else(|| panic!("no rule for {reviewer}"));
        assert_eq!(rule.author_role, author);
        let author_role = policy.role(author).expect("author role");
        let reviewer_role = policy.role(reviewer).expect("reviewer role");
        assert!(
            policy.independent(rule, &author_role.start_with, &reviewer_role.start_with),
            "{reviewer} starts with a model of the family of the starting model of {author}"
        );
    }
}

// ---- a file that breaks a rule does not load --------------------------------------------------

fn broken(from: &str, to: &str) -> String {
    let text = real_text();
    assert!(text.contains(from), "the real file has no `{from}`");
    text.replacen(from, to, 1)
}

fn refused(text: &str, kind: PolicyErrorKind) -> factory_contracts::policy::PolicyError {
    let error = load_text(text).expect_err("the file must not load");
    assert_eq!(error.kind, kind, "{error}");
    error
}

#[test]
fn the_real_file_loads_from_its_own_checkout() {
    load_text(&real_text()).expect("loads");
}

#[test]
fn an_unknown_key_is_refused() {
    refused(
        &broken(
            "  default_action: deny ",
            "  surprise: 1\n  default_action: deny ",
        ),
        PolicyErrorKind::Type,
    );
}

#[test]
fn a_default_other_than_deny_is_refused() {
    refused(
        &broken("default_action: deny ", "default_action: allow "),
        PolicyErrorKind::Type,
    );
}

#[test]
fn another_schema_version_is_refused() {
    refused(
        &broken("schema_version: 1", "schema_version: 2"),
        PolicyErrorKind::SchemaVersion,
    );
}

#[test]
fn a_provider_the_broker_does_not_know_is_refused() {
    let error = refused(
        &broken("provider: openai", "provider: elsewhere"),
        PolicyErrorKind::UnknownReference,
    );
    assert!(error.message.contains("provider"), "{error}");
}

#[test]
fn a_model_listed_twice_is_refused() {
    refused(
        &broken("  - id: claude-opus-5-5", "  - id: claude-sonnet-5-5"),
        PolicyErrorKind::DuplicateId,
    );
}

#[test]
fn a_price_of_zero_is_refused() {
    let error = refused(
        &broken(
            "prices: { input: 2000000, cache_write: 2000000, cache_read: 100000, output: 10000000 }",
            "prices: { input: 0, cache_write: 10000000, cache_read: 1000000, output: 40000000 }",
        ),
        PolicyErrorKind::Constraint,
    );
    assert!(error.message.contains("price of zero"), "{error}");
}

#[test]
fn a_price_date_that_is_neither_a_date_nor_unchecked_is_refused() {
    refused(
        &broken(
            "price_checked_on: \"2026-11-13\"",
            "price_checked_on: yesterday",
        ),
        PolicyErrorKind::Constraint,
    );
}

#[test]
fn a_role_that_starts_with_a_model_it_may_not_use_is_refused() {
    let text = real_text();
    // The intake role loses gpt-6.1-sol, and its start is set to it.
    let changed = text.replacen(
        "    stage: INTAKE\n    allowed_models: [claude-sonnet-5-5, claude-opus-5-5, gpt-6.1-sol]\n    start_with: claude-sonnet-5-5",
        "    stage: INTAKE\n    allowed_models: [claude-sonnet-5-5, claude-opus-5-5]\n    start_with: gpt-6.1-sol",
        1,
    );
    assert_ne!(changed, text);
    let error = refused(&changed, PolicyErrorKind::UnknownReference);
    assert!(error.message.contains("not one of the models"), "{error}");
}

#[test]
fn a_role_that_escalates_to_a_model_that_is_not_larger_is_refused() {
    let error = refused(
        &broken(
            "    start_with: claude-sonnet-5-5\n    escalate_to: claude-opus-5-5",
            "    start_with: claude-opus-5-5\n    escalate_to: claude-sonnet-5-5",
        ),
        PolicyErrorKind::Constraint,
    );
    assert!(error.message.contains("larger tier"), "{error}");
}

#[test]
fn a_route_with_a_model_no_role_of_the_stage_may_use_is_refused() {
    let text = real_text();
    let changed = text.replacen(
        "    allowed_models: [claude-sonnet-5-5, claude-opus-5-5, gpt-6.1-sol]\n    start_with: claude-sonnet-5-5\n    escalate_to: claude-opus-5-5\n    escalate_after_failed_repairs: 2\n    per_stage_run: { max_micro_usd: 2500000",
        "    allowed_models: [claude-sonnet-5-5, claude-opus-5-5]\n    start_with: claude-sonnet-5-5\n    escalate_to: claude-opus-5-5\n    escalate_after_failed_repairs: 2\n    per_stage_run: { max_micro_usd: 2500000",
        1,
    );
    assert_ne!(
        changed, text,
        "the builder entry is where the test expects it"
    );
    let error = refused(&changed, PolicyErrorKind::UnknownReference);
    assert!(error.message.contains("no role of the stage"), "{error}");
}

#[test]
fn a_route_for_a_stage_that_no_role_runs_is_refused() {
    refused(
        &broken(
            "  - { stage: INTAKE,               tier: standard,",
            "  - { stage: DELIVERY,             tier: standard,",
        ),
        PolicyErrorKind::UnknownReference,
    );
}

#[test]
fn a_ceiling_above_the_limit_of_the_security_policy_is_refused() {
    let error = refused(
        &broken(
            "max_micro_usd: 10000000             # PENDING",
            "max_micro_usd: 26000000             # PENDING",
        ),
        PolicyErrorKind::Constraint,
    );
    assert!(error.message.contains("hard_ceilings"), "{error}");
}

#[test]
fn a_request_cap_above_the_security_policy_is_refused() {
    let error = refused(
        &broken(
            "max_output_tokens: 16000 }          # PENDING CONFIRMATION\n  - role: specification_reviewer",
            "max_output_tokens: 90000 }          # PENDING CONFIRMATION\n  - role: specification_reviewer",
        ),
        PolicyErrorKind::Constraint,
    );
    assert!(
        error.message.contains("per_request_caps") || error.message.contains("larger than"),
        "{error}"
    );
}

#[test]
fn a_rule_of_independence_that_no_author_could_satisfy_is_refused() {
    // Under the rule of family, with both reviewers limited to the claude family: a builder on
    // claude can never be reviewed independently, so the review could never run.
    let mut policy = real();
    for rule in &mut policy.independence.rules {
        rule.must_differ_by = DifferBy::Family;
    }
    let reviewer = policy
        .roles
        .iter_mut()
        .find(|r| r.role == "code_reviewer")
        .expect("code reviewer");
    reviewer.allowed_models = vec!["claude-sonnet-5-5".to_owned(), "claude-opus-5-5".to_owned()];
    reviewer.start_with = "claude-sonnet-5-5".to_owned();
    for route in policy.routes.iter_mut().filter(|r| r.stage == "REVIEW") {
        route.candidates.retain(|m| m != "gpt-6.1-sol");
    }
    let found = routing_problems(&policy);
    assert!(
        found.iter().any(|p| p.message.contains("could never run")),
        "{found:#?}"
    );
}

#[test]
fn the_policy_is_read_only_from_the_protected_checkout() {
    let dir = TempDir::new("model-routing-missing");
    let source =
        ProtectedPolicySource::protected_default_branch(dir.path(), &[]).expect("the directory");
    let error = PolicyLoader::load_model_routing(&source, &security()).expect_err("no file");
    assert_eq!(error.kind, PolicyErrorKind::Unavailable);
}

// ---- tighten only -----------------------------------------------------------------------------

#[test]
fn a_project_policy_equal_to_the_central_one_tightens_nothing_and_loosens_nothing() {
    let central = real();
    assert!(check_tighten(&central, &central).is_empty());
}

#[test]
fn lowering_a_ceiling_and_dropping_a_model_only_tighten() {
    let central = real();
    let mut project = central.clone();
    let builder = project
        .roles
        .iter_mut()
        .find(|r| r.role == "builder")
        .expect("builder");
    builder.per_stage_run.max_micro_usd /= 2;
    builder.per_request.max_output_tokens = 4000;
    builder.allowed_models.retain(|m| m != "gpt-6.1-sol");
    project.job.max_micro_usd /= 2;
    for route in &mut project.routes {
        route
            .candidates
            .retain(|m| m != "gpt-6.1-sol" || route.stage != "IMPLEMENTATION");
    }
    let looser = check_tighten(&central, &project);
    assert!(looser.is_empty(), "{looser:#?}");
}

#[test]
fn every_way_to_widen_the_policy_is_reported_by_its_key() {
    let central = real();
    let builder = central
        .roles
        .iter()
        .position(|r| r.role == "builder")
        .expect("builder");
    let widen = |change: &dyn Fn(&mut ModelRoutingPolicy)| -> Vec<String> {
        let mut project = central.clone();
        change(&mut project);
        check_tighten(&central, &project)
            .into_iter()
            .map(|looser| looser.key)
            .collect()
    };
    assert_eq!(
        widen(&|p| p.roles[builder].per_stage_run.max_micro_usd += 1),
        ["roles[builder].per_stage_run.max_micro_usd"]
    );
    assert_eq!(
        widen(&|p| p.roles[builder].per_request.max_output_tokens += 1),
        ["roles[builder].per_request.max_output_tokens"]
    );
    assert_eq!(widen(&|p| p.job.max_micro_usd += 1), ["job.max_micro_usd"]);
    assert_eq!(widen(&|p| p.job.max_tokens += 1), ["job.max_tokens"]);
    assert!(
        widen(&|p| {
            let mut extra = p.models[0].clone();
            extra.id = "a-new-model".to_owned();
            p.models.push(extra);
        })
        .contains(&"models[a-new-model]".to_owned())
    );
    assert_eq!(
        widen(&|p| p.models[0].prices.output -= 1),
        ["models[claude-sonnet-5-5].prices"],
        "a lower price makes the broker count less"
    );
    // The shipped rule is the weakest (`model`), so a project can only make it stronger.
    assert!(widen(&|p| p.independence.rules[0].must_differ_by = DifferBy::Family).is_empty());
    let mut by_family = central.clone();
    by_family.independence.rules[0].must_differ_by = DifferBy::Family;
    let mut weakened = by_family.clone();
    weakened.independence.rules[0].must_differ_by = DifferBy::Model;
    assert_eq!(
        check_tighten(&by_family, &weakened)
            .into_iter()
            .map(|looser| looser.key)
            .collect::<Vec<_>>(),
        ["independence.rules[code_review_not_by_the_builders_model].must_differ_by"]
    );
    assert_eq!(
        widen(&|p| {
            p.independence.rules.remove(0);
        }),
        ["independence.rules[code_review_not_by_the_builders_model]"]
    );
    assert!(
        widen(&|p| p.roles[builder].escalate_after_failed_repairs = 1)
            .contains(&"roles[builder].escalate_after_failed_repairs".to_owned())
    );
    assert!(
        widen(&|p| {
            p.roles.remove(builder);
        })
        .contains(&"roles[builder]".to_owned())
    );
}

/// SF-18. The module comment of the crate said that the routing policy did not exist and that no
/// schema described it, after both existed. A type cannot check a comment, so this test reads it:
/// it must not say the file is missing, and it must point at the module that reads the policy and
/// at the crate that applies it.
#[test]
fn sf_18_the_module_comment_of_the_crate_does_not_say_the_routing_policy_is_missing() {
    let lib = read_text(&repo_root().join("crates/contracts/src/lib.rs"));
    let comment: String = lib
        .lines()
        .take_while(|line| line.starts_with("//!") || line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    for stale in ["does not exist", "no schema describes"] {
        assert!(!comment.contains(stale), "the comment still says {stale:?}");
    }
    for wanted in [
        "policies/model_routing.yaml",
        "policy::routing",
        "factory_composition::routing",
    ] {
        assert!(
            comment.contains(wanted),
            "the comment does not name {wanted}"
        );
    }
    // The policy and its schema are in the repository, as the comment now says.
    assert!(repo_root().join("policies/model_routing.yaml").is_file());
    assert!(
        repo_root()
            .join("schemas/policy-model-routing.schema.json")
            .is_file()
    );
}
