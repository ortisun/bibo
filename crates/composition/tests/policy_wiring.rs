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
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::routing::ModelRoutingPolicy;
use factory_domain::values::NonEmptyString;
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_egress::broker::{BrokerCore, BrokerParts, MemoryAudit, SystemEntropy};
use factory_ports::agent::{
    BrokerError, Capability, CapabilityObservation, CostMicroUsd, InvalidTokenRequest,
    JobTokenRequest, ModelBroker, ModelSelection, ProbedCapabilities, RoutingError, RoutingNeed,
    RuntimeCapabilities, RuntimeId, Usage,
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

#[test]
fn the_reviewer_of_the_family_of_the_builder_is_refused_by_the_router() {
    let policy = loaded().policy;
    let both = PolicyModelRouter::new(Arc::clone(&policy)).expect("router");
    let builder_used = selection("claude-code-cli", "claude-sonnet-5-5");

    // With both providers served, the review goes to the other family.
    let decision = both
        .route_after_author(&need(StageKind::Review), &builder_used)
        .expect("an independent reviewer");
    assert_eq!(decision.model.model.as_str(), "gpt-6.1-sol");

    // If that runtime fails and is excluded, the router does not fall back to the builder's
    // family: it says every candidate is gone.
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

    // With only the builder's provider served, no model is independent, and the policy sends the
    // stage to a person.
    let only_claude = PolicyModelRouter::new(Arc::clone(&policy))
        .expect("router")
        .with_enabled(BTreeSet::from([
            "claude-sonnet-5-5".to_owned(),
            "claude-opus-5-5".to_owned(),
        ]));
    assert_eq!(
        only_claude
            .route_after_author(&need(StageKind::Review), &builder_used)
            .unwrap_err(),
        AuthorRoutingError::NoIndependentModel
    );
    // A stage that reviews nobody's work routes as usual.
    let intake = only_claude
        .route_after_author(&need(StageKind::Intake), &builder_used)
        .expect("routes");
    assert_eq!(intake.model.model.as_str(), "claude-sonnet-5-5");
    let _ = Path::new("");
}
