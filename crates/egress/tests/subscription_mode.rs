//! The broker in subscription mode (ADR 0020): the owner's Claude subscription token is the real
//! credential, and the sandbox still holds only the per-job token.
//!
//! The provider is the fake one on the loopback address. What a real provider does with these
//! requests was checked by the owner on 2026-11-12 (ADR 0020, "What was verified"); this file
//! checks that the broker sends what that check found necessary, and nothing it should not.

mod support;

use factory_egress::broker::{AuditKind, Provider};
use factory_egress::http::{ProviderKey, StartError, UpstreamConfig};
use factory_ports::agent::TokenState;
use serde_json::json;
use support::{CEILING, CLAUDE_MODEL, HttpRig};

/// The system prompt Claude Code 2.1.323 sends in print mode on `CLAUDE_CODE_OAUTH_TOKEN`
/// (captured against a local listener on 2026-11-12).
fn cli_system() -> serde_json::Value {
    json!([
        {"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.323.f6b; cc_entrypoint=sdk-cli;"},
        {"type": "text", "text": "You are a Claude agent, built on Anthropic's Claude Agent SDK.", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "\nYou are an agent working with the user toward their goals.\n", "cache_control": {"type": "ephemeral"}},
    ])
}

/// A Messages request as Claude Code sends it on an OAuth token: the job token as a bearer
/// credential, the OAuth beta in the list, the CLI's user agent.
fn post(
    rig: &HttpRig,
    secret: &str,
    body: &serde_json::Value,
) -> factory_testkit::fx::http::ClientResponse {
    factory_testkit::fx::http::send_request(
        rig.addr(),
        "POST",
        "/v1/messages?beta=true",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &format!("Bearer {secret}")),
            ("anthropic-version", "2023-06-01"),
            (
                "anthropic-beta",
                "oauth-2025-04-20,claude-code-20250219,effort-2025-11-24",
            ),
            ("User-Agent", "claude-cli/2.1.323 (external, sdk-cli)"),
        ],
        body.to_string().as_bytes(),
    )
    .expect("the broker answers")
}

fn body(system: &serde_json::Value) -> serde_json::Value {
    json!({
        "model": CLAUDE_MODEL, "max_tokens": 1000, "stream": false, "system": system,
        "messages": [{"role": "user", "content": "say ok"}],
    })
}

#[test]
fn the_subscription_token_goes_upstream_as_a_bearer_with_the_oauth_beta_and_the_request_is_metered()
{
    let rig = HttpRig::subscription();
    let token = rig.claude_token(CEILING);
    let answer = post(&rig, token.secret.expose(), &body(&cli_system()));
    assert_eq!(answer.status, 200, "{}", answer.text());

    let sent = rig.provider.requests();
    assert_eq!(sent.len(), 1);
    let sent = &sent[0];
    assert_eq!(
        sent.header("authorization"),
        Some(format!("Bearer {}", rig.anthropic_key).as_str()),
        "the subscription token, as a bearer credential"
    );
    assert_eq!(sent.header("x-api-key"), None, "no API key header");
    let betas = sent.header("anthropic-beta").expect("a beta list");
    assert!(betas.split(',').any(|b| b == "oauth-2025-04-20"), "{betas}");
    assert!(
        betas.split(',').any(|b| b == "claude-code-20250219"),
        "{betas}"
    );
    assert_eq!(sent.query, "beta=true");
    assert_eq!(
        sent.header("user-agent"),
        Some("factory-model-broker"),
        "the broker's own user agent, which the provider accepts"
    );
    assert_eq!(
        sent.json()["system"],
        cli_system(),
        "the system prompt is forwarded unchanged"
    );
    assert!(
        !String::from_utf8_lossy(&sent.body).contains(token.secret.expose()),
        "the job token does not cross"
    );

    // Every request is metered: tokens in and out, and the list-price cost of the answer.
    let usage = rig.rig.core.token_usage(&token.id).expect("usage");
    assert!(
        usage.usage.input_tokens > 0 && usage.usage.output_tokens > 0,
        "{usage:?}"
    );
    assert!(usage.usage.cost.0 > 0, "{usage:?}");
}

#[test]
fn a_request_without_a_claude_code_identity_is_refused_by_name_and_never_sent() {
    let rig = HttpRig::subscription();
    let token = rig.claude_token(CEILING);
    for system in [
        json!("You are a helpful assistant."),
        json!([{"type": "text", "text": "Hello. You are Claude Code, Anthropic's official CLI for Claude."}]),
    ] {
        let answer = post(&rig, token.secret.expose(), &body(&system));
        assert_eq!(answer.status, 400, "{}", answer.text());
    }
    let mut missing = body(&json!(null));
    missing.as_object_mut().expect("an object").remove("system");
    assert_eq!(post(&rig, token.secret.expose(), &missing).status, 400);
    assert_eq!(rig.provider.hits(), 0, "nothing reached the provider");
    let named = rig
        .rig
        .audit
        .events()
        .into_iter()
        .filter(|e| {
            e.to_json()["detail"] == "subscription_identity_missing"
                && matches!(e.kind, AuditKind::RequestRefused { .. })
        })
        .count();
    assert_eq!(named, 3);
    // The direct form the owner checked live passes as well.
    let direct = json!([{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}]);
    assert_eq!(
        post(&rig, token.secret.expose(), &body(&direct)).status,
        200
    );
}

#[test]
fn a_plan_rate_limit_is_named_charges_nothing_and_leaves_the_token_valid() {
    let rig = HttpRig::subscription();
    let token = rig.claude_token(CEILING);
    rig.provider.set(|script| {
        script.error_status = Some(429);
        script.more_headers = vec![
            ("retry-after".to_owned(), "120".to_owned()),
            (
                "anthropic-ratelimit-unified-status".to_owned(),
                "rejected".to_owned(),
            ),
        ];
    });
    let answer = post(&rig, token.secret.expose(), &body(&cli_system()));
    assert_eq!(answer.status, 429);
    assert_eq!(answer.header("retry-after"), Some("120"));
    assert_eq!(answer.header("anthropic-ratelimit-unified-status"), None);
    let error = answer.json().expect("a JSON body");
    assert_eq!(error["error"]["type"], "provider_rate_limited");

    let usage = rig.rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(usage.state, TokenState::Active, "the job is not burned");
    assert_eq!(usage.usage.cost.0, 0, "nothing is charged");
    let limited: Vec<_> = rig
        .rig
        .audit
        .events()
        .into_iter()
        .filter(|e| matches!(e.kind, AuditKind::ProviderRateLimited { .. }))
        .collect();
    assert_eq!(limited.len(), 1);
    let line = limited[0].to_json();
    assert_eq!(line["event"], "provider_rate_limited");
    assert_eq!(line["provider"], "anthropic");
    assert_eq!(line["retry_after_secs"], 120);

    // The limit lifts, and the same token works.
    rig.provider.set(|script| {
        script.error_status = None;
        script.more_headers = Vec::new();
    });
    assert_eq!(
        post(&rig, token.secret.expose(), &body(&cli_system())).status,
        200
    );
}

#[test]
fn the_api_key_mode_is_unchanged_and_never_sends_the_oauth_beta() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let answer = post(
        &rig,
        token.secret.expose(),
        &body(&json!("Any system prompt.")),
    );
    assert_eq!(answer.status, 200, "{}", answer.text());
    let sent = &rig.provider.requests()[0];
    assert_eq!(sent.header("x-api-key"), Some(rig.anthropic_key.as_str()));
    assert_eq!(sent.header("authorization"), None);
    let betas = sent.header("anthropic-beta").unwrap_or("");
    assert!(!betas.contains("oauth"), "{betas}");
}

#[test]
fn only_the_anthropic_subscription_can_be_relayed() {
    let token = ProviderKey::subscription_token(&support::made_up_key(
        factory_egress::http::SUBSCRIPTION_TOKEN_PREFIX,
    ))
    .expect("a token");
    assert_eq!(
        UpstreamConfig::subscription(Provider::OpenAi, "https://api.openai.com", token)
            .unwrap_err(),
        StartError::SubscriptionNotRelayed
    );
}
