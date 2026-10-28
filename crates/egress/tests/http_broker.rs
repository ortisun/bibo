//! The HTTP listener against a labelled fake provider: routes, credentials, what crosses to the
//! provider and what does not, streamed usage, refusals and errors.

mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use factory_egress::broker::{AuditKind, CapPolicy, Refusal};
use factory_ports::agent::{CostMicroUsd, TokenState};
use factory_testkit::fx::http::send_request;
use serde_json::json;
use support::{CEILING, CLAUDE_MODEL, GPT_MODEL, HttpRig};

#[test]
fn a_claude_request_reaches_the_provider_with_the_real_key_and_with_nothing_else_of_the_sandbox() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let response = rig.claude(&token, false);
    assert_eq!(response.status, 200);
    assert!(response.text().contains("hello from the fake provider"));

    let seen = rig.provider.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.path, "/v1/messages");
    assert_eq!(request.query, "beta=true");
    assert_eq!(
        request.header("x-api-key"),
        Some(rig.anthropic_key.as_str())
    );
    assert_eq!(request.header("authorization"), None);
    assert_eq!(request.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(
        request.header("anthropic-beta"),
        Some("test-beta-1,test-beta-2"),
        "the beta list is forwarded unchanged"
    );
    for dropped in ["cookie", "x-claude-code-session-id"] {
        assert_eq!(request.header(dropped), None, "{dropped} must not cross");
    }
    // The job token is nowhere in what the provider received.
    let everything = format!(
        "{:?}{}",
        request.headers,
        String::from_utf8_lossy(&request.body)
    );
    assert!(!everything.contains(token.secret.expose()));
    // The output limit was brought down to the per-request cap.
    assert_eq!(request.json()["max_tokens"], 32_000);
}

#[test]
fn a_codex_request_uses_the_bearer_form_and_the_openai_key() {
    let rig = HttpRig::new();
    let token = rig.codex_token(CEILING);
    let response = rig.codex(&token, false);
    assert_eq!(response.status, 200);
    let seen = rig.provider.requests();
    let request = &seen[0];
    assert_eq!(request.path, "/v1/responses");
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {}", rig.openai_key).as_str())
    );
    assert_eq!(request.header("x-api-key"), None);
    assert!(!format!("{:?}", request.headers).contains(token.secret.expose()));
}

#[test]
fn streamed_usage_of_both_providers_is_metered_and_the_events_are_passed_on() {
    let rig = HttpRig::new();
    let claude = rig.claude_token(CEILING);
    let response = rig.claude(&claude, true);
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("text/event-stream"));
    let text = response.text();
    assert!(text.contains("event: message_start") && text.contains("event: message_stop"));
    let standing = rig.rig.core.token_usage(&claude.id).expect("usage");
    assert_eq!(standing.usage.requests, 1);
    assert_eq!(standing.usage.input_tokens, 1234 + 7 + 89);
    assert_eq!(standing.usage.output_tokens, 56);
    // 1234 + 7*1.25 + 89*0.1 + 56*5 micro-dollars, rounded up.
    assert_eq!(standing.usage.cost, CostMicroUsd(1532));

    let codex = rig.codex_token(CEILING);
    let response = rig.codex(&codex, true);
    assert_eq!(response.status, 200);
    assert!(response.text().contains("response.completed"));
    let standing = rig.rig.core.token_usage(&codex.id).expect("usage");
    assert_eq!(standing.usage.input_tokens, 1234);
    assert_eq!(standing.usage.output_tokens, 56);
    // (1234 - 89) + 89*0.1 + 56*5 micro-dollars, rounded up.
    assert_eq!(standing.usage.cost, CostMicroUsd(1434));
}

#[test]
fn non_streamed_answers_and_the_token_count_route_are_metered_too() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    assert_eq!(rig.claude(&token, false).status, 200);
    assert_eq!(
        rig.rig
            .core
            .token_usage(&token.id)
            .expect("usage")
            .usage
            .cost,
        CostMicroUsd(1532)
    );
    let counted = rig.post(
        "/v1/messages/count_tokens",
        ("x-api-key", token.secret.expose()),
        &json!({"model": CLAUDE_MODEL, "messages": []}),
    );
    assert_eq!(counted.status, 200);
    let usage = rig.rig.core.token_usage(&token.id).expect("usage").usage;
    assert_eq!(usage.requests, 2);
    assert_eq!(usage.cost, CostMicroUsd(1532 + 1234));
}

#[test]
fn a_refused_request_never_reaches_the_provider() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let revoked = rig.claude_token(CEILING);
    rig.rig.core.revoke_token(&revoked.id);

    let answer = |credential: (&str, &str)| {
        rig.post(
            "/v1/messages",
            credential,
            &json!({"model": CLAUDE_MODEL, "max_tokens": 5}),
        )
        .status
    };
    assert_eq!(answer(("x-api-key", "sfjt_not-issued-by-this-broker")), 401);
    assert_eq!(answer(("x-api-key", "")), 401);
    assert_eq!(answer(("x-api-key", revoked.secret.expose())), 401);
    // A job token is not a way into the OpenAI route, and its model is not on the list.
    let at_openai = rig.post(
        "/v1/responses",
        (
            "Authorization",
            &format!("Bearer {}", token.secret.expose()),
        ),
        &json!({"model": GPT_MODEL}),
    );
    assert_eq!(at_openai.status, 403);
    let wrong_model = rig.post(
        "/v1/messages",
        ("x-api-key", token.secret.expose()),
        &json!({"model": "claude-unlisted", "max_tokens": 5}),
    );
    assert_eq!(wrong_model.status, 403);
    assert_eq!(rig.provider.hits(), 0, "nothing was forwarded");
    assert_eq!(
        rig.rig
            .core
            .token_usage(&token.id)
            .expect("usage")
            .usage
            .requests,
        0
    );
}

#[test]
fn routes_methods_and_shapes_the_broker_does_not_serve_are_refused_without_a_provider_call() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let auth = [("x-api-key", token.secret.expose())];
    let status = |method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]| {
        send_request(rig.addr(), method, target, headers, body)
            .expect("an answer")
            .status
    };
    let json_headers = [
        ("Content-Type", "application/json"),
        ("x-api-key", token.secret.expose()),
    ];
    assert_eq!(status("POST", "/v1/other", &json_headers, b"{}"), 404);
    assert_eq!(
        status("POST", "/v1/messages/../models", &json_headers, b"{}"),
        404
    );
    assert_eq!(status("POST", "//v1/messages", &json_headers, b"{}"), 404);
    assert_eq!(status("GET", "/v1/messages", &auth, b""), 405);
    assert_eq!(status("DELETE", "/v1/messages", &auth, b""), 405);
    assert_eq!(
        status(
            "GET",
            "/v1/responses",
            &[("Upgrade", "websocket"), auth[0]],
            b""
        ),
        426
    );
    // A wrong content type, a body that is not JSON, one with no model, one with a model that
    // has odd characters.
    assert_eq!(
        status(
            "POST",
            "/v1/messages",
            &[("Content-Type", "text/plain"), auth[0]],
            b"{}"
        ),
        415
    );
    assert_eq!(
        status("POST", "/v1/messages", &json_headers, b"not json"),
        400
    );
    assert_eq!(status("POST", "/v1/messages", &json_headers, b"[1]"), 400);
    assert_eq!(
        status(
            "POST",
            "/v1/messages",
            &json_headers,
            br#"{"max_tokens":1}"#
        ),
        400
    );
    assert_eq!(
        status("POST", "/v1/messages", &json_headers, br#"{"model":"a b"}"#),
        400
    );
    assert_eq!(rig.provider.hits(), 0);
    assert_eq!(
        rig.rig
            .core
            .token_usage(&token.id)
            .expect("usage")
            .usage
            .requests,
        0
    );
}

#[test]
fn two_different_credentials_in_one_request_are_refused() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let response = send_request(
        rig.addr(),
        "POST",
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", token.secret.expose()),
            ("Authorization", "Bearer sfjt_something-else"),
        ],
        br#"{"model":"claude-test-model","max_tokens":1}"#,
    )
    .expect("an answer");
    assert_eq!(response.status, 400);
    assert_eq!(rig.provider.hits(), 0);
}

#[test]
fn a_body_over_the_limit_is_refused_before_it_is_read() {
    let mut caps = CapPolicy::default();
    caps.per_request.max_body_bytes = 1024;
    let rig = HttpRig::with_caps(caps);
    let token = rig.claude_token(CEILING);
    let big = json!({"model": CLAUDE_MODEL, "max_tokens": 5, "pad": "x".repeat(4096)});
    let response = rig.post("/v1/messages", ("x-api-key", token.secret.expose()), &big);
    assert_eq!(response.status, 413);
    assert_eq!(rig.provider.hits(), 0);
}

#[test]
fn a_request_with_no_length_or_a_chunked_body_is_refused() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let raw = |text: String| -> String {
        let mut stream = TcpStream::connect(rig.addr()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        stream.write_all(text.as_bytes()).expect("write");
        let mut out = String::new();
        let _ = stream.read_to_string(&mut out);
        out
    };
    let no_length = raw(format!(
        "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nx-api-key: {}\r\n\r\n",
        token.secret.expose()
    ));
    assert!(no_length.starts_with("HTTP/1.1 411"), "{no_length}");
    let chunked = raw(format!(
        "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nx-api-key: {}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        token.secret.expose()
    ));
    assert!(chunked.starts_with("HTTP/1.1 400"), "{chunked}");
    assert_eq!(rig.provider.hits(), 0);
}

#[test]
fn the_model_list_answers_a_valid_token_and_nobody_else() {
    let rig = HttpRig::new();
    let token = rig.codex_token(CEILING);
    let ok = send_request(
        rig.addr(),
        "GET",
        "/v1/models?client_version=0.0.0",
        &[(
            "Authorization",
            &format!("Bearer {}", token.secret.expose()),
        )],
        b"",
    )
    .expect("an answer");
    assert_eq!(ok.status, 200);
    assert_eq!(ok.json().expect("json")["models"], json!([]));
    let bad = send_request(
        rig.addr(),
        "GET",
        "/v1/models",
        &[("Authorization", "Bearer sfjt_unknown")],
        b"",
    )
    .expect("an answer");
    assert_eq!(bad.status, 401);
    assert_eq!(
        rig.provider.hits(),
        0,
        "the list is never asked of the provider"
    );
    assert_eq!(
        rig.rig
            .core
            .token_usage(&token.id)
            .expect("usage")
            .usage
            .requests,
        0
    );
}

#[test]
fn a_provider_error_is_passed_on_and_counted_as_a_request_with_no_cost() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    rig.provider.set(|s| s.error_status = Some(529));
    let response = rig.claude(&token, true);
    assert_eq!(response.status, 529);
    assert!(response.text().contains("fake_error"));
    let usage = rig.rig.core.token_usage(&token.id).expect("usage").usage;
    assert_eq!(usage.requests, 1, "a failed attempt is counted");
    assert_eq!(usage.cost, CostMicroUsd(0));
}

#[test]
fn a_provider_that_rejects_the_brokers_key_or_redirects_is_not_passed_on_as_such() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    for status in [401, 403, 302] {
        rig.provider.set(|s| s.error_status = Some(status));
        let response = rig.claude(&token, false);
        assert_eq!(response.status, 502, "upstream {status}");
        let body = response.text();
        assert!(body.contains("upstream_rejected_request"), "{body}");
    }
    assert_eq!(
        rig.rig
            .core
            .token_usage(&token.id)
            .expect("usage")
            .usage
            .requests,
        3
    );
}

#[test]
fn a_stream_cut_before_its_usage_report_is_charged_the_worst_case_for_one_request() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CostMicroUsd(10_000_000));
    rig.provider.set(|s| s.cut_after_events = Some(2));
    let response = send_request(
        rig.addr(),
        "POST",
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", token.secret.expose()),
        ],
        json!({"model": CLAUDE_MODEL, "stream": true, "max_tokens": 5})
            .to_string()
            .as_bytes(),
    );
    // The client sees a stream that ends early. What matters is the ledger.
    let _ = response;
    let usage = rig.rig.core.token_usage(&token.id).expect("usage").usage;
    assert_eq!(usage.requests, 1);
    // 200_000 input tokens at the cache-write price plus 32_000 output tokens.
    assert_eq!(usage.cost, CostMicroUsd(250_000 + 160_000));
    let unread = rig
        .rig
        .audit
        .events()
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                AuditKind::RequestSettled {
                    usage_read: false,
                    ..
                }
            )
        })
        .count();
    assert_eq!(unread, 1);
}

#[test]
fn a_listener_bound_to_one_job_refuses_the_token_of_another() {
    let job_a = support::fixed_job();
    let rig = HttpRig::for_job(job_a);
    let mine = rig
        .rig
        .core
        .issue_token(rig.rig.request_for(job_a, CEILING))
        .expect("a token");
    let theirs = rig.claude_token(CEILING);
    assert_eq!(rig.claude(&mine, false).status, 200);
    let refused = rig.claude(&theirs, false);
    assert_eq!(refused.status, 403);
    assert_eq!(Refusal::WrongAudience.http_status(), 403);
    assert_eq!(
        rig.provider.hits(),
        1,
        "only the right job's request was forwarded"
    );
}

#[test]
fn the_rate_limit_answers_429_with_a_delay_and_does_not_forward() {
    let rig = HttpRig::with_caps(CapPolicy {
        max_requests_per_minute: Some(1),
        ..CapPolicy::default()
    });
    let token = rig.claude_token(CEILING);
    assert_eq!(rig.claude(&token, false).status, 200);
    let second = rig.claude(&token, false);
    assert_eq!(second.status, 429);
    assert!(second.header("retry-after").is_some());
    assert_eq!(rig.provider.hits(), 1);
    assert_eq!(
        rig.rig.core.token_usage(&token.id).expect("usage").state,
        TokenState::Active
    );
}
