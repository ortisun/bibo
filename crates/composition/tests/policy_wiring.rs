//! The routing policy as the running worker applies it: loaded at start-up, narrowing every job
//! token, enabling only the models a provider serves, and keeping a reviewer independent of the
//! author when the author is known. Real: the policy file, its loader, the broker core. No network.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use factory_composition::config::{PriceConfig, SecretFile, UpstreamConfig};
use factory_composition::policy_broker::{JobSpend, NoSpendKnown, PolicyBroker};
use factory_composition::profile::Profile;
use factory_composition::routing::{
    AuthorRoutingError, PolicyModelRouter, RoutingBuildError, broker_caps, enabled_models,
    price_table, price_table_with,
};
use factory_composition::startup::{
    LoadedRouting, StartupFailure, confirm_routing, load_policy, load_routing,
};
use factory_composition::system::{RandomIds, SystemClock};
use factory_contracts::policy::routing::routing_problems;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::routing::{DifferBy, ModelRoutingPolicy, Tier};
use factory_domain::values::NonEmptyString;
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_egress::broker::{BrokerCore, BrokerParts, MemoryAudit, SystemEntropy};
use factory_ports::agent::{
    BrokerError, Capability, CapabilityObservation, CostMicroUsd, IndependenceKind,
    InvalidTokenRequest, JobTokenRequest, ModelBroker, ModelSelection, ProbedCapabilities,
    RoutingError, RoutingNeed, RuntimeCapabilities, RuntimeId, Usage,
};
use factory_ports::clock::IdGenerator;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn loaded() -> LoadedRouting {
    let policies = load_policy(&root(), &[]).expect("policies");
    load_routing(&root(), &[], &policies.security).expect("the routing policy loads")
}

fn core(policy: &ModelRoutingPolicy) -> Arc<BrokerCore> {
    BrokerCore::new(BrokerParts {
        clock: Arc::new(SystemClock),
        ids: Arc::new(RandomIds::new().expect("random")),
        entropy: Arc::new(SystemEntropy),
        prices: Arc::new(price_table(policy).expect("prices")),
        caps: broker_caps(policy).expect("caps"),
        audit: Arc::new(MemoryAudit::new()),
    })
}

fn policy_broker(routing: &LoadedRouting, core: &Arc<BrokerCore>) -> PolicyBroker {
    PolicyBroker::new(
        core.clone(),
        Arc::clone(&routing.policy),
        core.clone() as Arc<dyn JobSpend>,
    )
}

fn ids() -> (TenantId, JobId) {
    let ids = RandomIds::new().expect("random");
    (
        TenantId::from_uuid(ids.new_uuid()),
        JobId::from_uuid(ids.new_uuid()),
    )
}

fn selection(runtime: &str, model: &str) -> ModelSelection {
    ModelSelection {
        runtime: RuntimeId::new(runtime).expect("a runtime"),
        model: NonEmptyString::parse(model).expect("a model"),
    }
}

/// What the engine asks for: one model, and the ten dollars of the stage contract.
fn engine_request(stage: StageKind, model: ModelSelection, ceiling: u64) -> JobTokenRequest {
    let (tenant, job) = ids();
    JobTokenRequest {
        tenant,
        job,
        stage,
        cost_ceiling: CostMicroUsd(ceiling),
        allowed_models: vec![model],
        ttl: Duration::from_secs(900),
        per_request: None,
    }
}

// ---- the policy is loaded at start-up --------------------------------------------------------

#[test]
fn a_missing_routing_policy_stops_the_start() {
    // Break: the protected checkout has no policies/model_routing.yaml.
    let scratch = root()
        .join("target/policy-wiring")
        .join(format!("missing-{}", std::process::id()));
    let policies_dir = scratch.join("policies");
    std::fs::create_dir_all(&policies_dir).expect("scratch");
    for name in ["security.yaml", "approval.yaml"] {
        std::fs::copy(root().join("policies").join(name), policies_dir.join(name)).expect("copy");
    }
    let policies = load_policy(&scratch, &[]).expect("the two older policies load");
    let refusal = load_routing(&scratch, &[], &policies.security).unwrap_err();
    assert!(matches!(refusal, StartupFailure::Policy(_)), "{refusal}");
    let _ = std::fs::remove_dir_all(scratch);
}

#[test]
fn the_production_profile_refuses_a_routing_policy_that_still_waits_for_the_owner() {
    let routing = loaded();
    assert!(!routing.policy.unconfirmed().is_empty());
    let refusal = confirm_routing(Profile::Production, &routing).unwrap_err();
    assert!(
        refusal.to_string().contains("waits for the project owner"),
        "{refusal}"
    );
    // The other profiles start and say so in the log.
    for profile in [Profile::Local, Profile::Test] {
        assert!(confirm_routing(profile, &routing).is_ok());
    }
}

// ---- the broker applies the policy to every request ------------------------------------------

#[tokio::test]
async fn the_stage_ceiling_of_the_policy_caps_the_ceiling_the_engine_asks_for() {
    let routing = loaded();
    let core = core(&routing.policy);
    let broker = policy_broker(&routing, &core);
    // The engine asks for ten dollars (the stage contract's default).
    let request = engine_request(
        StageKind::Intake,
        selection("claude-code-cli", "claude-sonnet-5-5"),
        10_000_000,
    );
    let issued = broker.issue(request).await.expect("a token");
    let ceiling = routing.policy.stage_ceiling("INTAKE").expect("a ceiling");
    let usage = broker.usage(&issued.id).await.expect("usage");
    assert_eq!(usage.ceiling, CostMicroUsd(ceiling.max_micro_usd));
    assert!(usage.ceiling.0 < 10_000_000);
}

#[tokio::test]
async fn the_policy_never_raises_a_ceiling_the_engine_asked_for() {
    let routing = loaded();
    let core = core(&routing.policy);
    let broker = policy_broker(&routing, &core);
    let issued = broker
        .issue(engine_request(
            StageKind::Intake,
            selection("claude-code-cli", "claude-sonnet-5-5"),
            1_000,
        ))
        .await
        .expect("a token");
    assert_eq!(
        broker.usage(&issued.id).await.expect("usage").ceiling,
        CostMicroUsd(1_000)
    );
}

#[tokio::test]
async fn a_model_outside_the_routes_of_the_stage_gets_no_token() {
    // Break: the engine (or a bug) asks for a model the stage's routes do not list.
    let routing = loaded();
    let core = core(&routing.policy);
    let broker = policy_broker(&routing, &core);
    for outside in [
        selection("claude-code-cli", "claude-haiku-9"),
        selection("codex-cli", "claude-sonnet-5-5 "),
        // A model of the policy, in a stage whose routes do not list it for this runtime pair.
        selection("codex-cli", "claude-sonnet-5-5"),
    ] {
        let refusal = broker
            .issue(engine_request(StageKind::Intake, outside, 100_000))
            .await
            .unwrap_err();
        assert_eq!(
            refusal,
            BrokerError::InvalidRequest(InvalidTokenRequest::NoModels)
        );
    }
    // A stage that has no role in the policy gets no token at all.
    let refusal = broker
        .issue(engine_request(
            StageKind::Delivery,
            selection("claude-code-cli", "claude-sonnet-5-5"),
            100_000,
        ))
        .await
        .unwrap_err();
    assert_eq!(
        refusal,
        BrokerError::InvalidRequest(InvalidTokenRequest::NoModels)
    );
}

struct Spent(u64);

impl JobSpend for Spent {
    fn spent(&self, _: JobId) -> CostMicroUsd {
        CostMicroUsd(self.0)
    }
}

#[tokio::test]
async fn the_ceiling_of_the_job_leaves_each_new_token_only_what_remains() {
    let routing = loaded();
    let core = core(&routing.policy);
    let job_max = routing.policy.job.max_micro_usd;
    let stage_max = routing
        .policy
        .stage_ceiling("IMPLEMENTATION")
        .expect("ceiling")
        .max_micro_usd;
    let near = |spent: u64| {
        PolicyBroker::new(
            core.clone(),
            Arc::clone(&routing.policy),
            Arc::new(Spent(spent)),
        )
    };
    let request = || {
        engine_request(
            StageKind::Implementation,
            selection("claude-code-cli", "claude-sonnet-5-5"),
            10_000_000,
        )
    };
    // Plenty left: the stage ceiling applies.
    let first = near(0).issue(request()).await.expect("a token");
    assert_eq!(
        core.token_usage(&first.id).expect("usage").ceiling.0,
        stage_max
    );
    // Less left than the stage may spend: the remainder applies.
    let second = near(job_max - 40_000)
        .issue(request())
        .await
        .expect("a token");
    assert_eq!(
        core.token_usage(&second.id).expect("usage").ceiling.0,
        40_000
    );
    // Nothing left: no token.
    let refusal = near(job_max).issue(request()).await.unwrap_err();
    assert_eq!(
        refusal,
        BrokerError::InvalidRequest(InvalidTokenRequest::ZeroCeiling)
    );
    let _ = NoSpendKnown;
}

// ---- the author in the need (SF-17 a) ---------------------------------------------------------

#[test]
fn a_need_that_names_the_author_is_routed_to_an_independent_reviewer() {
    use factory_ports::agent::ModelRouter as _;
    let policy = loaded().policy;
    let router = PolicyModelRouter::new(Arc::clone(&policy)).expect("router");
    let builder_used = selection("claude-code-cli", "claude-sonnet-5-5");

    // The same answer as `route_after_author`, through the port the engine calls.
    let mut review = need(StageKind::Review);
    review.author = Some(builder_used.clone());
    assert_eq!(
        router
            .route(&review)
            .expect("a reviewer")
            .model
            .model
            .as_str(),
        "gpt-6.1-sol"
    );

    // Break: the other family's runtime failed. The plain route would fall back to the builder's
    // own model; with the author in the need, the router takes another model instead (the rule
    // is `must_differ_by: model`), at the large tier, and never the builder's own.
    let mut fallen_back = review.clone();
    fallen_back.exclude = vec![RuntimeId::new("codex-cli").expect("runtime")];
    assert_eq!(
        router
            .route(&fallen_back)
            .expect("another model reviews")
            .model
            .model
            .as_str(),
        "claude-opus-5-5"
    );
    let mut forgotten = fallen_back.clone();
    forgotten.author = None;
    assert_eq!(
        router
            .route(&forgotten)
            .expect("without the author the router falls back")
            .model
            .model
            .as_str(),
        "claude-sonnet-5-5",
        "this is the hole the author closes"
    );

    // Break: only the builder's provider is served. Candidates exist and none is independent.
    let only_claude = PolicyModelRouter::new(Arc::clone(&policy))
        .expect("router")
        .with_enabled(BTreeSet::from(["claude-sonnet-5-5".to_owned()]));
    assert_eq!(
        only_claude.route(&review).unwrap_err(),
        RoutingError::NoRoute
    );

    // A stage that reviews nobody's work is routed as before even when an author is named.
    let mut intake = need(StageKind::Intake);
    intake.author = Some(builder_used);
    assert_eq!(
        router.route(&intake).expect("routes").model.model.as_str(),
        "claude-sonnet-5-5"
    );
}

#[tokio::test]
async fn a_reviewer_of_the_builders_family_gets_no_request_through_the_real_broker() {
    // The router refuses the builder's family for the reviewer, and the token it leads to cannot be
    // used for the builder's family either: the real broker refuses the model.
    use factory_egress::broker::{Provider, RequestFacts};
    let routing = loaded();
    let core = core(&routing.policy);
    let broker = policy_broker(&routing, &core);
    let router = PolicyModelRouter::new(Arc::clone(&routing.policy)).expect("router");
    use factory_ports::agent::ModelRouter as _;
    let mut review = need(StageKind::Review);
    review.author = Some(selection("claude-code-cli", "claude-sonnet-5-5"));
    let decision = router.route(&review).expect("an independent reviewer");
    let token = broker
        .issue(engine_request(StageKind::Review, decision.model, 100_000))
        .await
        .expect("a token");
    let refusal = core
        .authorize(
            token.secret.expose(),
            &RequestFacts {
                provider: Provider::Anthropic,
                model: "claude-sonnet-5-5",
                expected_job: None,
            },
        )
        .expect_err("the builder's family is refused");
    assert_eq!(refusal.as_str(), "wrong_audience");
}

// ---- the caps of the role (SF-17 b) -----------------------------------------------------------

/// The most output tokens a request may ask for under a token, read from the real broker's
/// permission for a request of that token.
fn output_cap_of(core: &Arc<BrokerCore>, secret: &str, model: &str) -> u64 {
    use factory_egress::broker::{Provider, RequestFacts};
    core.authorize(
        secret,
        &RequestFacts {
            provider: Provider::Anthropic,
            model,
            expected_job: None,
        },
    )
    .expect("the broker lets the request in")
    .max_output_tokens()
}

fn largest_output_cap(policy: &ModelRoutingPolicy, stage: &str) -> u64 {
    policy
        .roles_of_stage(stage)
        .map(|role| role.per_request.max_output_tokens)
        .max()
        .expect("the stage has a role")
}

#[tokio::test]
async fn a_token_is_held_to_the_cap_of_its_role_and_not_to_the_largest_cap_of_any_role() {
    let routing = loaded();
    let core = core(&routing.policy);
    let broker = policy_broker(&routing, &core);
    let model = selection("claude-code-cli", "claude-sonnet-5-5");
    let intake_cap = largest_output_cap(&routing.policy, "INTAKE");
    let builder_cap = largest_output_cap(&routing.policy, "IMPLEMENTATION");
    assert!(
        intake_cap < builder_cap,
        "the policy gives the intake role the smaller cap"
    );
    // The broker's own cap is the largest of any role.
    assert!(core.caps().per_request.max_output_tokens >= builder_cap);

    let intake = broker
        .issue(engine_request(StageKind::Intake, model.clone(), 100_000))
        .await
        .expect("a token");
    let builder = broker
        .issue(engine_request(StageKind::Implementation, model, 100_000))
        .await
        .expect("a token");
    assert_eq!(
        output_cap_of(&core, intake.secret.expose(), "claude-sonnet-5-5"),
        intake_cap
    );
    assert_eq!(
        output_cap_of(&core, builder.secret.expose(), "claude-sonnet-5-5"),
        builder_cap
    );
}

#[tokio::test]
async fn a_stage_with_two_roles_gets_the_larger_of_their_caps() {
    let routing = loaded();
    let core = core(&routing.policy);
    let broker = policy_broker(&routing, &core);
    assert_eq!(routing.policy.roles_of_stage("SPECIFICATION").count(), 2);
    let token = broker
        .issue(engine_request(
            StageKind::Specification,
            selection("claude-code-cli", "claude-sonnet-5-5"),
            100_000,
        ))
        .await
        .expect("a token");
    assert_eq!(
        output_cap_of(&core, token.secret.expose(), "claude-sonnet-5-5"),
        largest_output_cap(&routing.policy, "SPECIFICATION")
    );
}

#[tokio::test]
async fn the_engine_cannot_ask_for_more_room_than_the_role_has() {
    // Break: the request already carries caps, larger than the role's. The policy keeps the smaller.
    let routing = loaded();
    let core = core(&routing.policy);
    let broker = policy_broker(&routing, &core);
    let mut request = engine_request(
        StageKind::Intake,
        selection("claude-code-cli", "claude-sonnet-5-5"),
        100_000,
    );
    request.per_request = Some(factory_ports::agent::RequestCaps {
        max_input_tokens: u64::MAX,
        max_output_tokens: u64::MAX,
    });
    let token = broker.issue(request).await.expect("a token");
    assert_eq!(
        output_cap_of(&core, token.secret.expose(), "claude-sonnet-5-5"),
        largest_output_cap(&routing.policy, "INTAKE")
    );
}

#[tokio::test]
async fn the_spend_of_a_job_is_read_from_the_brokers_own_ledger() {
    let routing = loaded();
    let core = core(&routing.policy);
    let broker = policy_broker(&routing, &core);
    let first = engine_request(
        StageKind::Implementation,
        selection("claude-code-cli", "claude-sonnet-5-5"),
        10_000_000,
    );
    let job = first.job;
    let tenant = first.tenant;
    let issued = broker.issue(first).await.expect("a token");
    // The broker's relay records spend; here the core is told directly.
    core.add_usage(
        &issued.id,
        Usage {
            cost: CostMicroUsd(2_000_000),
            ..Usage::default()
        },
    )
    .expect("spend");
    assert_eq!(core.spent(job), CostMicroUsd(2_000_000));
    // The next stage of the same job gets the stage ceiling or the remainder, whichever is lower.
    let next = JobTokenRequest {
        tenant,
        job,
        stage: StageKind::Review,
        cost_ceiling: CostMicroUsd(10_000_000),
        allowed_models: vec![selection("codex-cli", "gpt-6.1-sol")],
        ttl: Duration::from_secs(900),
        per_request: None,
    };
    let issued = broker.issue(next).await.expect("a token");
    let review = routing
        .policy
        .stage_ceiling("REVIEW")
        .expect("ceiling")
        .max_micro_usd;
    let left = routing.policy.job.max_micro_usd - 2_000_000;
    assert_eq!(
        core.token_usage(&issued.id).expect("usage").ceiling.0,
        review.min(left)
    );
}

// ---- prices and enabled models from the configuration ----------------------------------------

fn price(provider: &str, model: &str, bump: i64) -> PriceConfig {
    let policy = loaded().policy;
    let base = policy.price(model).expect("a model of the policy").clone();
    let shift =
        |value: u64| u64::try_from(i64::try_from(value).expect("fits") + bump).expect("positive");
    PriceConfig {
        provider: provider.to_owned(),
        model: model.to_owned(),
        input: shift(base.input),
        cache_write: shift(base.cache_write),
        cache_read: shift(base.cache_read),
        output: shift(base.output),
    }
}

#[test]
fn a_price_in_the_configuration_may_raise_the_policys_price_and_never_lower_it() {
    let policy = loaded().policy;
    assert!(price_table_with(&policy, &[price("anthropic", "claude-sonnet-5-5", 1)]).is_ok());
    assert_eq!(
        price_table_with(&policy, &[price("anthropic", "claude-sonnet-5-5", -1)]).unwrap_err(),
        RoutingBuildError::PriceLowersPolicy("claude-sonnet-5-5".to_owned())
    );
    // A model the policy lists for another provider, or not at all, has no price to set.
    let wrong_provider = PriceConfig {
        provider: "openai".to_owned(),
        ..price("anthropic", "claude-sonnet-5-5", 1)
    };
    assert_eq!(
        price_table_with(&policy, &[wrong_provider]).unwrap_err(),
        RoutingBuildError::PriceForUnknownModel("claude-sonnet-5-5".to_owned())
    );
    let unknown = PriceConfig {
        model: "claude-haiku-9".to_owned(),
        ..price("anthropic", "claude-sonnet-5-5", 1)
    };
    assert_eq!(
        price_table_with(&policy, &[unknown]).unwrap_err(),
        RoutingBuildError::PriceForUnknownModel("claude-haiku-9".to_owned())
    );
}

fn upstream(provider: &str, models: &[&str]) -> UpstreamConfig {
    UpstreamConfig {
        provider: provider.to_owned(),
        base_url: "http://127.0.0.1:9".to_owned(),
        key_file: SecretFile::at("/nonexistent"),
        models: models.iter().map(|m| (*m).to_owned()).collect(),
    }
}

#[test]
fn a_provider_enables_its_own_models_or_the_ones_it_lists_and_nothing_else() {
    let policy = loaded().policy;
    let all = enabled_models(
        &policy,
        &[upstream("anthropic", &[]), upstream("openai", &[])],
    )
    .expect("both");
    assert_eq!(
        all,
        BTreeSet::from(["claude-sonnet-5-5", "claude-opus-5-5", "gpt-6.1-sol"].map(String::from))
    );
    let one =
        enabled_models(&policy, &[upstream("anthropic", &["claude-sonnet-5-5"])]).expect("one");
    assert_eq!(one, BTreeSet::from(["claude-sonnet-5-5".to_owned()]));
    // A model the policy lists for the other provider.
    assert!(matches!(
        enabled_models(&policy, &[upstream("anthropic", &["gpt-6.1-sol"])]),
        Err(RoutingBuildError::ModelNotInPolicy { .. })
    ));
    assert!(matches!(
        enabled_models(&policy, &[upstream("azure", &[])]),
        Err(RoutingBuildError::UnknownProvider(_))
    ));
}

// ---- the router: enabled models and the independence of the reviewer -------------------------

fn probed_both() -> ProbedCapabilities {
    ProbedCapabilities(
        ["claude-code-cli", "codex-cli"]
            .iter()
            .map(|name| {
                (
                    RuntimeId::new(name).expect("a runtime"),
                    RuntimeCapabilities {
                        runtime_version: "test".to_owned(),
                        observations: vec![CapabilityObservation {
                            capability: Capability::JsonSchemaOutput,
                            supported: true,
                            source: "the test".to_owned(),
                        }],
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
}

fn need(stage: StageKind) -> RoutingNeed {
    RoutingNeed {
        stage,
        tier: RecommendedTier::Standard,
        required: vec![Capability::JsonSchemaOutput],
        risk: RiskTier::Low,
        exclude: Vec::new(),
        probed: probed_both(),
        author: None,
    }
}

#[test]
fn a_model_no_provider_of_the_deployment_serves_is_never_offered() {
    let policy = loaded().policy;
    let router = PolicyModelRouter::new(Arc::clone(&policy))
        .expect("router")
        .with_enabled(BTreeSet::from(["claude-sonnet-5-5".to_owned()]));
    use factory_ports::agent::ModelRouter as _;
    // Review starts with gpt-6.1-sol, which nobody serves here, so the next candidate is taken.
    let review = router.route(&need(StageKind::Review)).expect("a route");
    assert_eq!(review.model.model.as_str(), "claude-sonnet-5-5");
    // The large tier lists only claude-opus-5-5, which is not enabled either.
    let mut large = need(StageKind::Review);
    large.tier = RecommendedTier::Large;
    assert_eq!(router.route(&large).unwrap_err(), RoutingError::AllExcluded);
}

/// The repository policy with every reviewing rule set to `must_differ_by: family`, as a project
/// may ask (a project may make a rule stronger, never weaker).
fn reviewers_differ_by_family() -> ModelRoutingPolicy {
    let mut policy = (*loaded().policy).clone();
    for rule in &mut policy.independence.rules {
        rule.must_differ_by = DifferBy::Family;
    }
    policy
}

fn only_claude(policy: ModelRoutingPolicy) -> PolicyModelRouter {
    PolicyModelRouter::new(Arc::new(policy))
        .expect("the policy passes its own rules")
        .with_enabled(BTreeSet::from([
            "claude-sonnet-5-5".to_owned(),
            "claude-opus-5-5".to_owned(),
        ]))
}

/// The reviewing stages, each with the need it routes its reviewer with. The specification
/// reviewer shares its stage with the writer and asks for no capability of its own.
fn reviewing_needs() -> Vec<RoutingNeed> {
    let mut specification = need(StageKind::Specification);
    specification.required = Vec::new();
    vec![
        need(StageKind::Review),
        need(StageKind::DocumentationReview),
        specification,
    ]
}

/// Under `must_differ_by: family` (api_key mode), the review goes to the other family, and the
/// router never falls back to the builder's family.
#[test]
fn the_reviewer_of_the_family_of_the_builder_is_refused_by_the_router() {
    let policy = Arc::new(reviewers_differ_by_family());
    let both = PolicyModelRouter::new(Arc::clone(&policy)).expect("router");
    let builder_used = selection("claude-code-cli", "claude-sonnet-5-5");

    // With both providers served, the review goes to the other family.
    let decision = both
        .route_after_author(&need(StageKind::Review), &builder_used)
        .expect("an independent reviewer");
    assert_eq!(decision.model.model.as_str(), "gpt-6.1-sol");
    let independence = decision.independence.expect("the router says how far");
    assert_eq!(independence.kind, IndependenceKind::OtherProvider);
    assert_eq!(independence.author, builder_used);

    // If that runtime fails and is excluded, the router does not fall back to the builder's
    // family, at any tier: it says every candidate is gone.
    let mut excluded = need(StageKind::Review);
    excluded.exclude = vec![RuntimeId::new("codex-cli").expect("runtime")];
    assert_eq!(
        both.route_after_author(&excluded, &builder_used)
            .unwrap_err(),
        AuthorRoutingError::Routing(RoutingError::AllExcluded)
    );
    // The plain route, which does not know the author, would have taken the builder's family:
    use factory_ports::agent::ModelRouter as _;
    let plain = both.route(&excluded).expect("the plain route falls back");
    assert_eq!(plain.model.model.as_str(), "claude-sonnet-5-5");
    assert_eq!(plain.independence, None);

    // With only the builder's provider served, no model of any tier is independent, and the
    // policy sends the stage to a person.
    let claude = only_claude(reviewers_differ_by_family());
    for reviewing in reviewing_needs() {
        assert_eq!(
            claude
                .route_after_author(&reviewing, &builder_used)
                .unwrap_err(),
            AuthorRoutingError::NoIndependentModel,
            "{:?}",
            reviewing.stage
        );
    }
    // A stage that reviews nobody's work routes as usual.
    let intake = claude
        .route_after_author(&need(StageKind::Intake), &builder_used)
        .expect("routes");
    assert_eq!(intake.model.model.as_str(), "claude-sonnet-5-5");
    assert_eq!(intake.independence, None);
    let _ = Path::new("");
}

// ---- the owner's decision of 2026-11-13: a reviewer that differs by model --------------------
//
// In subscription mode only Claude runs, so no reviewer is of another family than a Claude
// author. The owner set every reviewing rule to `must_differ_by: model` (ADR 0020, amendment):
// another Claude model reviews. Claude Opus is listed only at the large tier, so the router looks
// at the other tiers of the stage when the asked tier has no independent model.

/// Listing `claude-opus-5-5` among the `standard` candidates of the review stages is refused by
/// the policy's own check: the policy lists it as a `large` model, and a route lists only models
/// of its own tier. That is why the router looks at the large tier instead.
#[test]
fn claude_opus_on_the_standard_route_of_a_review_is_refused_by_the_policy_check() {
    let mut policy = (*loaded().policy).clone();
    for route in &mut policy.routes {
        if ["REVIEW", "DOCUMENTATION_REVIEW"].contains(&route.stage.as_str())
            && route.tier == Tier::Standard
        {
            route.candidates = ["gpt-6.1-sol", "claude-opus-5-5", "claude-sonnet-5-5"]
                .map(String::from)
                .to_vec();
        }
    }
    let problems = routing_problems(&policy);
    assert_eq!(problems.len(), 2, "{problems:?}");
    for problem in &problems {
        assert!(
            problem.path.ends_with(".candidates")
                && problem.message.contains("`claude-opus-5-5`")
                && problem
                    .message
                    .contains("the route is for the Standard tier"),
            "{problem:?}"
        );
    }
    assert!(PolicyModelRouter::new(Arc::new(policy)).is_err());
}

/// Subscription mode with the shipped policy: the work of Claude Sonnet is reviewed by Claude
/// Opus, found at the large tier although the stage asked for the standard one, and the decision
/// says it is a review by the same family. This holds for the code review, the documentation
/// review and the specification review.
#[test]
fn in_subscription_mode_claude_opus_reviews_the_work_of_claude_sonnet() {
    let policy = (*loaded().policy).clone();
    assert_eq!(routing_problems(&policy), Vec::new());
    for rule in &policy.independence.rules {
        assert_eq!(rule.must_differ_by, DifferBy::Model, "{}", rule.id);
    }
    let router = only_claude(policy);
    let author = selection("claude-code-cli", "claude-sonnet-5-5");
    for reviewing in reviewing_needs() {
        assert_eq!(reviewing.tier, RecommendedTier::Standard);
        let decision = router
            .route_after_author(&reviewing, &author)
            .expect("another Claude model reviews");
        assert_eq!(
            decision.model.model.as_str(),
            "claude-opus-5-5",
            "{:?}",
            reviewing.stage
        );
        let independence = decision
            .independence
            .as_ref()
            .expect("the router says how far");
        assert_eq!(independence.kind, IndependenceKind::SameFamilyOtherModel);
        assert_eq!(independence.author, author);
        // The port's answer is the same.
        use factory_ports::agent::ModelRouter as _;
        let mut named = reviewing.clone();
        named.author = Some(author.clone());
        assert_eq!(router.route(&named).expect("routes"), decision);
    }
}

/// When Claude Opus wrote the work (a builder that escalated), Claude Sonnet reviews it at the
/// standard tier the stage asked for.
#[test]
fn in_subscription_mode_claude_sonnet_reviews_the_work_of_claude_opus() {
    let router = only_claude((*loaded().policy).clone());
    let author = selection("claude-code-cli", "claude-opus-5-5");
    for reviewing in reviewing_needs() {
        let decision = router
            .route_after_author(&reviewing, &author)
            .expect("another Claude model reviews");
        assert_eq!(
            decision.model.model.as_str(),
            "claude-sonnet-5-5",
            "{:?}",
            reviewing.stage
        );
        assert_eq!(
            decision.independence.map(|found| found.kind),
            Some(IndependenceKind::SameFamilyOtherModel)
        );
    }
}

/// With both providers served (api_key mode) and the shipped rule of `model`, the reviewing
/// routes still give the model of the other family first: a review by the same family happens
/// only when no other family is served.
#[test]
fn with_both_providers_served_the_reviewer_is_still_of_the_other_family() {
    let router = PolicyModelRouter::new(loaded().policy).expect("router");
    let author = selection("claude-code-cli", "claude-sonnet-5-5");
    for reviewing in reviewing_needs() {
        let decision = router
            .route_after_author(&reviewing, &author)
            .expect("an independent reviewer");
        assert_eq!(
            decision.model.model.as_str(),
            "gpt-6.1-sol",
            "{:?}",
            reviewing.stage
        );
        assert_eq!(
            decision.independence.map(|found| found.kind),
            Some(IndependenceKind::OtherProvider)
        );
    }
}

/// A deployment that serves only the author's own model has no reviewer at all, at any tier, and
/// the stage waits for a person.
#[test]
fn with_only_the_authors_model_served_the_review_waits_for_a_person() {
    let router = PolicyModelRouter::new(loaded().policy)
        .expect("router")
        .with_enabled(BTreeSet::from(["claude-sonnet-5-5".to_owned()]));
    let author = selection("claude-code-cli", "claude-sonnet-5-5");
    for reviewing in reviewing_needs() {
        assert_eq!(
            router.route_after_author(&reviewing, &author).unwrap_err(),
            AuthorRoutingError::NoIndependentModel,
            "{:?}",
            reviewing.stage
        );
    }
}
