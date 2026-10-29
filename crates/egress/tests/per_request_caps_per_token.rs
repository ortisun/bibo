//! SF-17 (b): the limits on one request belong to the token, for the role of the stage.
//!
//! The broker holds one set of per-request caps for every token. A token may now carry smaller
//! caps of its own (`JobTokenRequest::per_request`), and the broker applies the smaller of the two
//! to the output tokens a request may ask for. Real: the broker core and its listener. Fake and
//! labelled: the provider, which records the body it receives.

mod support;

use factory_ports::agent::RequestCaps;
use factory_testkit::fx::http::send_request;
use serde_json::{Value, json};
use support::{CEILING, CLAUDE_MODEL, HttpRig};

/// The output tokens the provider was asked for in its latest request.
fn asked_for(rig: &HttpRig) -> Value {
    rig.provider
        .requests()
        .last()
        .expect("the provider was called")
        .json()["max_tokens"]
        .clone()
}

fn ask(rig: &HttpRig, secret: &str, max_tokens: u64) -> u16 {
    let body = json!({
        "model": CLAUDE_MODEL, "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": "hello"}],
    });
    send_request(
        rig.addr(),
        "POST",
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", secret),
            ("anthropic-version", "2023-06-01"),
        ],
        body.to_string().as_bytes(),
    )
    .expect("the broker answers")
    .status
}

fn token_with(rig: &HttpRig, caps: Option<RequestCaps>) -> factory_ports::agent::IssuedJobToken {
    let mut request = rig.rig.request(CEILING);
    request.per_request = caps;
    rig.rig.core.issue_token(request).expect("a token")
}

#[test]
fn a_request_over_the_cap_of_the_role_is_clamped_to_it() {
    let rig = HttpRig::new();
    let broker_cap = rig.rig.core.caps().per_request.max_output_tokens;
    let role_cap = 1_000;
    assert!(role_cap < broker_cap, "the role's cap is the smaller one");
    let token = token_with(
        &rig,
        Some(RequestCaps {
            max_input_tokens: 50_000,
            max_output_tokens: role_cap,
        }),
    );
    // Asking for more than the role may is clamped to the role's cap, not to the broker's.
    assert_eq!(ask(&rig, token.secret.expose(), 20_000), 200);
    assert_eq!(asked_for(&rig), json!(role_cap));
    // Asking for less leaves the number alone.
    assert_eq!(ask(&rig, token.secret.expose(), 100), 200);
    assert_eq!(asked_for(&rig), json!(100));
}

#[test]
fn a_token_without_caps_of_its_own_keeps_the_caps_of_the_broker() {
    let rig = HttpRig::new();
    let broker_cap = rig.rig.core.caps().per_request.max_output_tokens;
    let token = token_with(&rig, None);
    assert_eq!(ask(&rig, token.secret.expose(), broker_cap + 5_000), 200);
    assert_eq!(asked_for(&rig), json!(broker_cap));
}

#[test]
fn a_role_cap_larger_than_the_brokers_never_raises_it() {
    // Break: a token that asks for more room than the broker allows is still held to the broker.
    let rig = HttpRig::new();
    let broker_cap = rig.rig.core.caps().per_request.max_output_tokens;
    let token = token_with(
        &rig,
        Some(RequestCaps {
            max_input_tokens: u64::MAX,
            max_output_tokens: broker_cap * 10,
        }),
    );
    assert_eq!(ask(&rig, token.secret.expose(), broker_cap * 5), 200);
    assert_eq!(asked_for(&rig), json!(broker_cap));
}
