//! The live smoke test of the API-key mode: one minimal request to each real provider through the
//! broker, with a real key held by the broker, recording that usage was read from the provider's
//! own report. The default mode, the owner's Claude subscription, has its own check:
//! `crates/egress/tests/live_subscription.rs` (ADR 0020).
//!
//! **UNVERIFIED and BLOCKED.** No real key exists in this project and no spend is approved, so the
//! live path of this file has never run. It is written so that it can, and so that it refuses to
//! pass without everything it needs. Run it with `FACTORY_LIVE=1`.
//!
//! What a person must provide, none of it in the repository or in a chat:
//!
//! 1. an Anthropic key and an OpenAI key, each made for the factory with a hard provider-side
//!    spend limit, each in a file; the files are named by `FACTORY_LIVE_ANTHROPIC_KEY_FILE` and
//!    `FACTORY_LIVE_OPENAI_KEY_FILE`. The test reads the files itself and never looks in a home
//!    directory, a keychain or the environment for a key;
//! 2. the model to call at each provider (`FACTORY_LIVE_ANTHROPIC_MODEL`,
//!    `FACTORY_LIVE_OPENAI_MODEL`), and its current price, because this crate holds no price:
//!    `FACTORY_LIVE_PRICES` is `{"input":N,"cache_write":N,"cache_read":N,"output":N}` in
//!    micro-dollars per million tokens, used for both models;
//! 3. a written approval of a small live budget.
//!
//! Without `FACTORY_LIVE=1` the test only says that no live run was requested. With it, anything
//! missing is a failing test whose message starts `BLOCKED:` and lists what to supply.

mod support;

use std::sync::Arc;

use factory_egress::broker::{CapPolicy, ModelPrice, PriceTable, Provider};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, ServerLimits, UpstreamConfig,
};
use factory_testkit::fx::docker::blocked;
use factory_testkit::fx::http::send_request;
use support::Rig;

fn read_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[test]
fn live_smoke_reports_blocked_and_never_passed_without_keys_and_an_approved_budget() {
    if read_env("FACTORY_LIVE").as_deref() != Some("1") {
        println!(
            "NOT REQUESTED: no live run was made and this line is not evidence of a working provider; set FACTORY_LIVE=1 to ask for one"
        );
        return;
    }
    let mut missing = Vec::new();
    for (name, why) in [
        (
            "FACTORY_LIVE_ANTHROPIC_KEY_FILE",
            "a file holding an Anthropic key made for the factory, with a provider-side spend limit",
        ),
        (
            "FACTORY_LIVE_OPENAI_KEY_FILE",
            "a file holding an OpenAI key made for the factory, with a provider-side spend limit",
        ),
        (
            "FACTORY_LIVE_ANTHROPIC_MODEL",
            "the Anthropic model name to call",
        ),
        ("FACTORY_LIVE_OPENAI_MODEL", "the OpenAI model name to call"),
        (
            "FACTORY_LIVE_PRICES",
            "the current price of those models in micro-dollars per million tokens, as JSON",
        ),
    ] {
        if read_env(name).is_none() {
            missing.push(format!("{name}: {why}"));
        }
    }
    if !missing.is_empty() {
        blocked(&format!(
            "a live run was requested and cannot run. A person must provide, outside the repository: {}. A subscription token belongs to the other check, tests/live_subscription.rs.",
            missing.join("; ")
        ));
    }

    let keys = |name: &str| -> ProviderKey {
        let path = read_env(name).expect("checked above");
        ProviderKey::from_file(std::path::Path::new(&path))
            .unwrap_or_else(|e| blocked(&format!("{name} does not hold a usable key: {e}")))
    };
    let prices: serde_json::Value =
        serde_json::from_str(&read_env("FACTORY_LIVE_PRICES").expect("checked"))
            .unwrap_or_else(|_| blocked("FACTORY_LIVE_PRICES is not JSON"));
    let field = |name: &str| {
        prices[name]
            .as_u64()
            .unwrap_or_else(|| blocked(&format!("FACTORY_LIVE_PRICES has no {name}")))
    };
    let price = ModelPrice {
        input: field("input"),
        cache_write: field("cache_write"),
        cache_read: field("cache_read"),
        output: field("output"),
    };
    let claude = read_env("FACTORY_LIVE_ANTHROPIC_MODEL").expect("checked");
    let gpt = read_env("FACTORY_LIVE_OPENAI_MODEL").expect("checked");

    let table = PriceTable::new()
        .with_model(Provider::Anthropic, &claude, price)
        .with_model(Provider::OpenAi, &gpt, price);
    let rig = Rig::with_prices(CapPolicy::default(), Arc::new(table));
    let server = BrokerServer::start(
        BrokerServerConfig {
            listen: "127.0.0.1:0".parse().expect("address"),
            upstreams: vec![
                UpstreamConfig::new(
                    Provider::Anthropic,
                    "https://api.anthropic.com",
                    keys("FACTORY_LIVE_ANTHROPIC_KEY_FILE"),
                )
                .expect("an upstream"),
                UpstreamConfig::new(
                    Provider::OpenAi,
                    "https://api.openai.com",
                    keys("FACTORY_LIVE_OPENAI_KEY_FILE"),
                )
                .expect("an upstream"),
            ],
            expected_job: None,
            limits: ServerLimits::default(),
        },
        rig.core.clone(),
    )
    .expect("the broker starts");

    // One tiny request to each provider, with a small token ceiling set by the person who ran this.
    let mut request = rig.request(factory_ports::agent::CostMicroUsd(50_000));
    request.allowed_models = vec![
        factory_ports::agent::ModelSelection {
            runtime: factory_ports::agent::RuntimeId::new("claude-code-cli").expect("slug"),
            model: factory_domain::values::NonEmptyString::parse(&claude).expect("name"),
        },
        factory_ports::agent::ModelSelection {
            runtime: factory_ports::agent::RuntimeId::new("codex-cli").expect("slug"),
            model: factory_domain::values::NonEmptyString::parse(&gpt).expect("name"),
        },
    ];
    let token = rig.core.issue_token(request).expect("a token");
    let secret = token.secret.expose();
    let anthropic = send_request(
        server.local_addr(),
        "POST",
        "/v1/messages",
        &[("Content-Type", "application/json"), ("x-api-key", secret), ("anthropic-version", "2023-06-01")],
        serde_json::json!({"model": claude, "max_tokens": 16, "messages": [{"role": "user", "content": "Reply with the word ok."}]})
            .to_string()
            .as_bytes(),
    )
    .expect("an answer");
    assert_eq!(anthropic.status, 200, "{}", anthropic.text());
    let after_anthropic = rig.core.token_usage(&token.id).expect("usage").usage;
    assert!(
        after_anthropic.output_tokens > 0,
        "usage was not read: {after_anthropic:?}"
    );

    let openai = send_request(
        server.local_addr(),
        "POST",
        "/v1/responses",
        &[("Content-Type", "application/json"), ("Authorization", &format!("Bearer {secret}"))],
        serde_json::json!({"model": gpt, "max_output_tokens": 16, "input": "Reply with the word ok."})
            .to_string()
            .as_bytes(),
    )
    .expect("an answer");
    assert_eq!(openai.status, 200, "{}", openai.text());
    let after_both = rig.core.token_usage(&token.id).expect("usage").usage;
    assert!(
        after_both.output_tokens > after_anthropic.output_tokens,
        "{after_both:?}"
    );
    println!("LIVE: fidelity real, usage {after_both:?}");
}
