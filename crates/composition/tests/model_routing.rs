//! The routing policy as the running system uses it: the router chooses only from the routes, a job
//! token holds only the models of the stage's routes and the stage's ceiling, the broker prices
//! every answer with the policy's prices, refuses a model that is not in the route, and ends the
//! job at the ceiling. Real: the policy file, its loader, the broker core. No network and no key.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use factory_composition::routing::{
    PolicyModelRouter, RoutingBuildError, broker_caps, price_table, token_request,
};
use factory_composition::system::{RandomIds, SystemClock};
use factory_contracts::policy::{PolicyLoader, ProtectedPolicySource};
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::routing::ModelRoutingPolicy;
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_egress::broker::{
    BrokerCore, BrokerParts, MemoryAudit, Outcome, Provider, Refusal, RequestFacts, RevokeReason,
    SystemEntropy, TokenCounts,
};
use factory_ports::agent::{
    Capability, CapabilityObservation, ModelBroker, ModelRouter, ProbedCapabilities, RoutingError,
    RoutingNeed, RuntimeCapabilities, RuntimeId, TokenState,
};
use factory_ports::clock::IdGenerator;

fn policy() -> ModelRoutingPolicy {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root");
    let source = ProtectedPolicySource::protected_default_branch(&root, &[]).expect("the checkout");
    let security = PolicyLoader::load_security(&source).expect("security");
    PolicyLoader::load_model_routing(&source, &security.document)
        .unwrap_or_else(|e| panic!("{e}"))
        .document
}

fn broker(policy: &ModelRoutingPolicy) -> Arc<BrokerCore> {
    BrokerCore::new(BrokerParts {
        clock: Arc::new(SystemClock),
        ids: Arc::new(RandomIds::new().expect("random")),
        entropy: Arc::new(SystemEntropy),
        prices: Arc::new(price_table(policy).expect("prices")),
        caps: broker_caps(policy).expect("caps"),
        audit: Arc::new(MemoryAudit::new()),
    })
}

fn ids() -> (TenantId, JobId) {
    let ids = RandomIds::new().expect("random");
    (
        TenantId::from_uuid(ids.new_uuid()),
        JobId::from_uuid(ids.new_uuid()),
    )
}

fn facts<'a>(provider: Provider, model: &'a str) -> RequestFacts<'a> {
    RequestFacts {
        provider,
        model,
        expected_job: None,
    }
}

fn output_tokens(output: u64) -> Outcome {
    Outcome::Counted(TokenCounts {
        output,
        ..TokenCounts::default()
    })
}

// ---- the broker, driven by the policy ---------------------------------------------------------

#[tokio::test]
async fn the_broker_refuses_a_model_that_is_not_in_the_route_of_the_token() {
    let policy = policy();
    let core = broker(&policy);
    let (tenant, job) = ids();
    let request = token_request(
        &policy,
        tenant,
        job,
        StageKind::Review,
        Duration::from_secs(900),
    )
    .expect("a request");
    let held: Vec<&str> = request
        .allowed_models
        .iter()
        .map(|m| m.model.as_str())
        .collect();
    assert_eq!(
        held,
        ["gpt-6.1-sol", "claude-sonnet-5-5", "claude-opus-5-5"]
    );
    let token = core.issue(request).await.expect("a token");

    // A model of the route is admitted at its own provider.
    core.authorize(
        token.secret.expose(),
        &facts(Provider::OpenAi, "gpt-6.1-sol"),
    )
    .expect("in the route")
    .settle(output_tokens(10));
    // A model that no route lists is refused, whatever its name looks like.
    for outside in [
        "claude-haiku-9",
        "gpt-6.1-sol-mini",
        "claude-sonnet-5-5 ",
        "",
    ] {
        assert_eq!(
            core.authorize(token.secret.expose(), &facts(Provider::Anthropic, outside))
                .unwrap_err(),
            Refusal::ModelNotAllowed,
            "{outside:?}"
        );
    }
    // A model of the route at the wrong provider is refused too: the policy ties a model to one.
    assert!(
        core.authorize(
            token.secret.expose(),
            &facts(Provider::OpenAi, "claude-opus-5-5")
        )
        .is_err()
    );
}

#[tokio::test]
async fn the_cost_ceiling_of_the_policy_ends_the_job() {
    let policy = policy();
    let core = broker(&policy);
    let (tenant, job) = ids();
    let ceiling = policy
        .stage_ceiling("INTAKE")
        .expect("a ceiling")
        .max_micro_usd;
    let request = token_request(
        &policy,
        tenant,
        job,
        StageKind::Intake,
        Duration::from_secs(900),
    )
    .expect("a request");
    assert_eq!(request.cost_ceiling.0, ceiling);
    let token = core.issue(request).await.expect("a token");

    // The price of one output token of this model is in the policy: that many micro-dollars.
    let per_token = policy
        .price("claude-sonnet-5-5")
        .expect("a price")
        .output
        .div_ceil(1_000_000);
    let tokens_to_cross = ceiling / per_token + 1;

    // Below the ceiling, a request is admitted.
    core.authorize(
        token.secret.expose(),
        &facts(Provider::Anthropic, "claude-sonnet-5-5"),
    )
    .expect("admitted")
    .settle(output_tokens(100));
    assert_eq!(
        core.token_usage(&token.id).expect("usage").state,
        TokenState::Active
    );
    // The request that crosses it is let through (its cost is known only when it is read), and the
    // token is revoked in the same step.
    core.authorize(
        token.secret.expose(),
        &facts(Provider::Anthropic, "claude-sonnet-5-5"),
    )
    .expect("admitted")
    .settle(output_tokens(tokens_to_cross));
    let standing = core.token_usage(&token.id).expect("usage");
    assert_eq!(standing.state, TokenState::Revoked);
    assert!(standing.usage.cost.0 >= ceiling, "{standing:?}");
    assert_eq!(
        core.revoke_reason(&token.id),
        Some(RevokeReason::CostCeiling)
    );
    // Every request after that is refused with the answer on which the tool stops at once.
    let refused = core
        .authorize(
            token.secret.expose(),
            &facts(Provider::Anthropic, "claude-sonnet-5-5"),
        )
        .unwrap_err();
    assert_eq!(refused, Refusal::Revoked(RevokeReason::CostCeiling));
    assert_eq!(refused.http_status(), 402);
}

#[tokio::test]
async fn the_ceiling_of_a_dearer_model_is_reached_sooner_because_the_price_is_the_policys() {
    let policy = policy();
    let core = broker(&policy);
    let (tenant, job) = ids();
    let token = core
        .issue(
            token_request(
                &policy,
                tenant,
                job,
                StageKind::Intake,
                Duration::from_secs(900),
            )
            .expect("a request"),
        )
        .await
        .expect("a token");
    // The same number of output tokens costs five times as much on the large model in the file.
    let sonnet = policy.price("claude-sonnet-5-5").expect("p").output;
    let opus = policy.price("claude-opus-5-5").expect("p").output;
    assert_eq!(opus, sonnet * 5);
    let permit = core
        .authorize(
            token.secret.expose(),
            &facts(Provider::Anthropic, "claude-opus-5-5"),
        )
        .expect("admitted");
    permit.settle(output_tokens(1_000));
    assert_eq!(
        core.token_usage(&token.id).expect("usage").usage.cost.0,
        opus * 1_000 / 1_000_000
    );
}

#[tokio::test]
async fn a_request_may_ask_for_no_more_output_than_the_largest_cap_of_the_policy() {
    let policy = policy();
    let core = broker(&policy);
    let (tenant, job) = ids();
    let token = core
        .issue(
            token_request(
                &policy,
                tenant,
                job,
                StageKind::Implementation,
                Duration::from_secs(900),
            )
            .expect("a request"),
        )
        .await
        .expect("a token");
    let permit = core
        .authorize(
            token.secret.expose(),
            &facts(Provider::Anthropic, "claude-sonnet-5-5"),
        )
        .expect("admitted");
    let largest = policy
        .roles
        .iter()
        .map(|r| r.per_request.max_output_tokens)
        .max()
        .expect("a role");
    assert_eq!(permit.max_output_tokens(), largest);
    assert!(largest < 32_000, "tighter than the security policy's cap");
}

#[test]
fn a_stage_that_runs_no_agent_gets_no_token_request() {
    let policy = policy();
    let (tenant, job) = ids();
    let error = token_request(
        &policy,
        tenant,
        job,
        StageKind::Delivery,
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert_eq!(error, RoutingBuildError::NoRoute("DELIVERY".to_owned()));
}

// ---- the prices -------------------------------------------------------------------------------

#[test]
fn a_model_outside_the_policy_has_no_price_and_so_the_broker_could_not_meter_it() {
    use factory_egress::broker::PriceList as _;
    let policy = policy();
    let table = price_table(&policy).expect("prices");
    let counts = TokenCounts {
        input: 1,
        ..TokenCounts::default()
    };
    assert!(
        table
            .cost(Provider::Anthropic, "claude-sonnet-5-5", &counts)
            .is_some()
    );
    assert!(
        table
            .cost(Provider::Anthropic, "claude-haiku-9", &counts)
            .is_none()
    );
    assert!(
        table
            .cost(Provider::OpenAi, "claude-sonnet-5-5", &counts)
            .is_none(),
        "a model is priced at its own provider only"
    );
}

#[test]
fn a_policy_whose_model_names_a_runtime_of_another_provider_is_refused_when_it_is_used() {
    let mut policy = policy();
    // The provider says openai and the runtime says the tool that talks to anthropic.
    policy.models[0].provider = "openai".to_owned();
    assert!(matches!(
        price_table(&policy),
        Err(RoutingBuildError::ProviderMismatch(_))
    ));
    assert!(PolicyModelRouter::new(Arc::new(policy)).is_err());
}

// ---- the router -------------------------------------------------------------------------------

fn runtime(name: &str) -> RuntimeId {
    RuntimeId::new(name).expect("a runtime")
}

fn probed(names: &[&str], supported: &[Capability]) -> ProbedCapabilities {
    ProbedCapabilities(
        names
            .iter()
            .map(|name| {
                (
                    runtime(name),
                    RuntimeCapabilities {
                        runtime_version: "test".to_owned(),
                        observations: supported
                            .iter()
                            .map(|capability| CapabilityObservation {
                                capability: *capability,
                                supported: true,
                                source: "the test".to_owned(),
                            })
                            .collect(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
}

fn need(stage: StageKind, tier: RecommendedTier) -> RoutingNeed {
    RoutingNeed {
        stage,
        tier,
        required: vec![Capability::JsonSchemaOutput],
        risk: RiskTier::Low,
        exclude: Vec::new(),
        probed: probed(
            &["claude-code-cli", "codex-cli"],
            &[Capability::JsonSchemaOutput],
        ),
    }
}

fn router() -> PolicyModelRouter {
    PolicyModelRouter::new(Arc::new(policy())).expect("a router")
}

#[test]
fn the_router_reads_the_policy_and_says_so() {
    assert_eq!(
        router().fidelity(),
        factory_domain::vocabulary::Fidelity::Real
    );
}

#[test]
fn the_router_chooses_the_first_candidate_of_the_route_and_only_a_model_of_a_route() {
    let router = router();
    let build = router
        .route(&need(StageKind::Implementation, RecommendedTier::Standard))
        .expect("a route");
    assert_eq!(build.model.model.as_str(), "claude-sonnet-5-5");
    assert_eq!(build.model.runtime.as_str(), "claude-code-cli");
    // The reviewing stage starts with the model of the other family.
    let review = router
        .route(&need(StageKind::Review, RecommendedTier::Standard))
        .expect("a route");
    assert_eq!(review.model.model.as_str(), "gpt-6.1-sol");
    assert_eq!(review.model.runtime.as_str(), "codex-cli");
    let large = router
        .route(&need(StageKind::Implementation, RecommendedTier::Large))
        .expect("a route");
    assert_eq!(large.model.model.as_str(), "claude-opus-5-5");
}

#[test]
fn the_router_never_returns_an_excluded_runtime_and_says_when_none_is_left() {
    let router = router();
    let mut need = need(StageKind::Implementation, RecommendedTier::Standard);
    need.exclude = vec![runtime("claude-code-cli")];
    let second = router.route(&need).expect("the next candidate");
    assert_eq!(second.model.model.as_str(), "gpt-6.1-sol");
    need.exclude = vec![runtime("claude-code-cli"), runtime("codex-cli")];
    assert_eq!(router.route(&need).unwrap_err(), RoutingError::AllExcluded);
}

#[test]
fn the_router_skips_a_runtime_that_lacks_a_capability_and_a_runtime_nobody_probed() {
    let router = router();
    let mut need = need(StageKind::Implementation, RecommendedTier::Standard);
    // Only the second runtime was probed.
    need.probed = probed(&["codex-cli"], &[Capability::JsonSchemaOutput]);
    assert_eq!(
        router.route(&need).expect("a route").model.model.as_str(),
        "gpt-6.1-sol"
    );
    // The only probed runtime lacks the capability the stage needs.
    need.probed = probed(&["codex-cli"], &[]);
    assert_eq!(
        router.route(&need).unwrap_err(),
        RoutingError::CapabilityUnavailable(Capability::JsonSchemaOutput)
    );
    // Nothing was probed: no candidate, no guess.
    need.probed = ProbedCapabilities::default();
    assert_eq!(router.route(&need).unwrap_err(), RoutingError::NoRoute);
}

#[test]
fn a_stage_with_no_route_or_a_tier_with_none_is_no_route() {
    let router = router();
    assert_eq!(
        router
            .route(&need(StageKind::Delivery, RecommendedTier::Standard))
            .unwrap_err(),
        RoutingError::NoRoute
    );
    assert_eq!(
        router
            .route(&need(StageKind::Implementation, RecommendedTier::Small))
            .unwrap_err(),
        RoutingError::NoRoute
    );
}

#[test]
fn the_same_need_gets_the_same_answer() {
    let router = router();
    let question = need(StageKind::Review, RecommendedTier::Standard);
    let first = router.route(&question).expect("a route");
    for _ in 0..5 {
        assert_eq!(router.route(&question).expect("a route"), first);
    }
}
