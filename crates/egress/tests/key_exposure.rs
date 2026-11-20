//! The real provider key never leaves the broker, shown by the canary sweep.
//!
//! The two keys of the rig are made up at run time and registered as canaries. A full set of
//! requests runs through the broker, including a provider that misbehaves and echoes the
//! credential it was given in a header and in the text of its answer. The sweeper then looks for
//! the keys, in every spelling a leak can take, in every place a sandbox, a person or a log could
//! see them: each response (head and body), the audit stream, and the text the types print.
//!
//! The control: the same sweep finds the key in the one place it must be, the request that the
//! fake provider received. A sweep that cannot find the key there proves nothing elsewhere.

mod support;

use factory_egress::broker::CapPolicy;
use factory_testkit::fx::canary::{Canary, CanarySet, Sweeper};
use support::{CEILING, HttpRig, Script};

fn sweeper_for(rig: &HttpRig) -> Sweeper {
    let set = CanarySet::generate()
        .with(Canary::custom("anthropic_key", &rig.anthropic_key))
        .with(Canary::custom("openai_key", &rig.openai_key));
    Sweeper::new(&set)
}

fn everything_a_response_shows(response: &factory_testkit::fx::http::ClientResponse) -> Vec<u8> {
    let mut out = format!("{:?}", response.headers).into_bytes();
    out.extend_from_slice(&response.body);
    out
}

#[test]
fn real_key_never_leaves_the_broker() {
    let rig = HttpRig::new();
    let sweeper = sweeper_for(&rig);
    let claude = rig.claude_token(CEILING);
    let codex = rig.codex_token(CEILING);

    // A provider that echoes the credential it was called with, in a header and in its text.
    // `request-id` is a header the broker once passed on. It no longer is (the answer's headers
    // are a closed set of a media type and a delay), and this sweep shows the key does not
    // reach the sandbox through it or through the text.
    let leaked_key = rig.anthropic_key.clone();
    rig.provider.set(move |s: &mut Script| {
        s.echo_credential_in_body = true;
        s.extra_header = Some(("request-id".to_owned(), leaked_key));
    });
    let mut sinks: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, response) in [
        ("claude stream", rig.claude(&claude, true)),
        ("claude body", rig.claude(&claude, false)),
        ("codex stream", rig.codex(&codex, true)),
        ("codex body", rig.codex(&codex, false)),
    ] {
        assert_eq!(response.status, 200, "{name}");
        sinks.push((name.to_owned(), everything_a_response_shows(&response)));
    }
    // The text the provider echoed must have been scrubbed, not just never produced.
    let echoed = sinks
        .iter()
        .filter(|(_, bytes)| String::from_utf8_lossy(bytes).contains("your credential was"))
        .count();
    assert_eq!(
        echoed, 4,
        "the fake provider did echo the credential in every answer"
    );
    assert!(
        sinks.iter().all(
            |(_, b)| String::from_utf8_lossy(b).contains("[REDACTED:provider_key]")
                || String::from_utf8_lossy(b).contains("REDACTED")
        ),
        "every echoed key was replaced by the marker"
    );

    // Errors, refusals and the model list.
    rig.provider.set(|s| *s = Script::default());
    rig.provider.set(|s| s.error_status = Some(500));
    sinks.push((
        "provider error".into(),
        everything_a_response_shows(&rig.claude(&claude, true)),
    ));
    rig.provider.set(|s| s.error_status = Some(401));
    sinks.push((
        "provider 401".into(),
        everything_a_response_shows(&rig.claude(&claude, false)),
    ));
    let unknown = rig.post(
        "/v1/messages",
        ("x-api-key", "sfjt_not-a-token"),
        &serde_json::json!({"model": "claude-test-model"}),
    );
    sinks.push(("refusal".into(), everything_a_response_shows(&unknown)));

    // The audit stream, as lines.
    let audit: String = rig
        .rig
        .audit
        .events()
        .iter()
        .map(|e| e.to_json().to_string() + "\n")
        .collect();
    sinks.push(("audit".into(), audit.into_bytes()));
    // What the types print.
    sinks.push((
        "debug of the server address".into(),
        format!("{:?}", rig.addr()).into_bytes(),
    ));
    sinks.push((
        "debug of a token".into(),
        format!("{claude:?}{codex:?}").into_bytes(),
    ));

    for (name, bytes) in &sinks {
        let hits = sweeper.scan(name, bytes);
        assert!(hits.is_empty(), "the real key leaked into {name}: {hits:?}");
    }

    // The job tokens did not go upstream either.
    for request in rig.provider.requests() {
        let seen = format!(
            "{:?}{}",
            request.headers,
            String::from_utf8_lossy(&request.body)
        );
        assert!(!seen.contains(claude.secret.expose()));
        assert!(!seen.contains(codex.secret.expose()));
    }

    // Control: the sweep does find each key where it belongs, in the request the provider got.
    let received: Vec<u8> = rig
        .provider
        .requests()
        .iter()
        .flat_map(|r| format!("{:?}", r.headers).into_bytes())
        .collect();
    let hits = sweeper.scan("what the provider received", &received);
    assert!(
        hits.len() >= 2,
        "the sweep must find both keys in the provider's request log, found {hits:?}"
    );
}

#[test]
fn the_key_is_not_in_a_response_even_when_a_cap_stops_the_job() {
    let rig = HttpRig::with_caps(CapPolicy {
        max_requests: Some(1),
        ..CapPolicy::default()
    });
    let sweeper = sweeper_for(&rig);
    let token = rig.claude_token(CEILING);
    let first = rig.claude(&token, true);
    let second = rig.claude(&token, true);
    assert_eq!(second.status, 402);
    for (name, response) in [("first", first), ("second", second)] {
        let hits = sweeper.scan(name, &everything_a_response_shows(&response));
        assert!(hits.is_empty(), "{name}: {hits:?}");
    }
}
