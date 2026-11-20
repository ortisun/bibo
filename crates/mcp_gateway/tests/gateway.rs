//! The gateway end to end, offline: fake upstreams in process and over loopback HTTP, the agent
//! as an MCP client over the gateway's Streamable HTTP with its run token.

mod support;

use std::sync::Arc;
use std::time::Duration;

use factory_mcp_gateway::{
    CallOrigin, ConfigError, Gateway, GatewayError, HttpUpstream, HttpUpstreamError,
    InProcessUpstream, MissingReason, Outcome, RefusalReason, Upstream, UpstreamId,
    VictoriaMetricsConfig,
};
use support::{
    Behavior, FAKE_VM_TOKEN, FakeServer, PLANTED_SECRET, agent, args, fixture, limits, policy,
    raw_status, redactor, secret_file, texts,
};

fn sorted(mut names: Vec<String>) -> Vec<String> {
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_sees_exactly_the_allowlist_offered_by_the_upstreams() {
    let fx = fixture().await;
    let token = fx
        .gateway
        .open_run("run-list", fx.gateway.policy_limits())
        .expect("run");
    let agent = agent(&fx.server, token.expose()).await;
    let tools = agent.list_tools().await.expect("tools");
    let names = sorted(tools.iter().map(|tool| tool.name.to_string()).collect());
    assert_eq!(
        names,
        ["pg_factory_health", "pg_query", "vm_labels", "vm_query"]
    );
    let query = tools
        .iter()
        .find(|tool| tool.name == "vm_query")
        .expect("vm_query");
    assert_eq!(
        query.description.as_deref(),
        Some("The upstream tool query.")
    );
    assert_eq!(query.input_schema["properties"]["query"]["type"], "string");
    assert!(
        query.output_schema.is_none(),
        "only name, description and input schema pass"
    );

    let report = fx.gateway.catalog_report();
    let missing: Vec<_> = report
        .missing
        .iter()
        .map(|m| (m.tool.gateway_name.as_str(), m.reason))
        .collect();
    assert!(missing.contains(&("vm_alerts", MissingReason::NotOfferedByUpstream)));
    assert!(missing.contains(&("datadog_search_logs", MissingReason::UpstreamNotConfigured)));
    assert_eq!(report.not_allowed.len(), 1);
    assert_eq!(report.not_allowed[0].upstream, UpstreamId::Victoriametrics);
    assert_eq!(report.not_allowed[0].upstream_tool, "export");
    fx.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_off_the_allowlist_is_refused_even_when_called_by_name() {
    let fx = fixture().await;
    let token = fx
        .gateway
        .open_run("run-refuse", fx.gateway.policy_limits())
        .expect("run");
    let agent = agent(&fx.server, token.expose()).await;
    for name in ["export", "query", "vm_export", "vm_alerts"] {
        let result = agent
            .call_tool(name.to_owned(), None)
            .await
            .expect("a refusal is a tool result, not a transport failure");
        assert_eq!(result.is_error, Some(true), "{name}");
        let text = texts(&result).join("\n");
        assert!(text.contains("refused:"), "{name}: {text}");
    }
    assert!(
        fx.vm.server.calls().is_empty(),
        "nothing reached the upstream"
    );
    let record = fx.gateway.run_record("run-refuse").expect("record");
    let outcomes: Vec<String> = record.calls.iter().map(|c| c.outcome.to_string()).collect();
    assert_eq!(
        outcomes,
        [
            "refused:tool_not_allowed",
            "refused:tool_not_allowed",
            "refused:tool_not_allowed",
            "refused:tool_unavailable"
        ]
    );
    fx.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_adds_a_write_tool_does_not_expose_it_and_it_is_reported() {
    let fx = fixture().await;
    fx.postgres.add_tool("pg_drop_everything", Behavior::Echo);
    let report = fx.gateway.refresh().await;
    assert!(
        report
            .not_allowed
            .iter()
            .any(|t| t.upstream == UpstreamId::Postgres && t.upstream_tool == "pg_drop_everything")
    );
    assert_eq!(
        factory_mcp_gateway::UPSTREAM_TOOL_NOT_ALLOWED,
        "upstream_tool_not_allowed"
    );
    let token = fx
        .gateway
        .open_run("run-write", fx.gateway.policy_limits())
        .expect("run");
    let agent = agent(&fx.server, token.expose()).await;
    let names: Vec<String> = agent
        .list_tools()
        .await
        .expect("tools")
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(!names.iter().any(|n| n.contains("drop")), "{names:?}");
    let result = agent
        .call_tool("pg_drop_everything".to_owned(), None)
        .await
        .expect("a tool result");
    assert_eq!(result.is_error, Some(true));
    assert!(
        !fx.postgres
            .calls()
            .contains(&"pg_drop_everything".to_owned())
    );
    fx.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_wrong_closed_and_expired_tokens_get_401() {
    let fx = fixture().await;
    let addr = fx.server.local_addr();
    let token = fx
        .gateway
        .open_run("run-token", fx.gateway.policy_limits())
        .expect("run");
    assert_eq!(raw_status(addr, None).await, 401);
    assert_eq!(raw_status(addr, Some("Bearer not-the-token")).await, 401);
    assert_eq!(
        raw_status(addr, Some(token.expose())).await,
        401,
        "no Bearer prefix"
    );
    let wrong_last = format!("{}A", &token.expose()[..42]);
    let wrong_last = if wrong_last == token.expose() {
        format!("{}B", &token.expose()[..42])
    } else {
        wrong_last
    };
    assert_eq!(
        raw_status(addr, Some(&format!("Bearer {wrong_last}"))).await,
        401
    );
    assert_eq!(
        raw_status(addr, Some(&format!("Bearer {}", token.expose()))).await,
        200
    );

    // A closed run's token stops working at once.
    let record = fx.gateway.close_run("run-token").await.expect("closed");
    assert!(record.closed);
    assert_eq!(
        raw_status(addr, Some(&format!("Bearer {}", token.expose()))).await,
        401
    );
    assert!(matches!(
        fx.gateway.call_for_run("run-token", "vm_query", None).await,
        Err(GatewayError::UnknownRun(_))
    ));
    assert!(matches!(
        fx.gateway.close_run("run-token").await,
        Err(GatewayError::UnknownRun(_))
    ));

    // An expired run's token stops working at its wall clock.
    let mut short = limits(10, 10, 1024, 1000);
    short.run_wall_clock = Duration::from_millis(300);
    let expiring = fx.gateway.open_run("run-expiring", short).expect("run");
    assert_eq!(
        raw_status(addr, Some(&format!("Bearer {}", expiring.expose()))).await,
        200
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        raw_status(addr, Some(&format!("Bearer {}", expiring.expose()))).await,
        401
    );
    let late = fx
        .gateway
        .call_for_run("run-expiring", "vm_query", None)
        .await
        .expect("recorded");
    assert_eq!(late.outcome, Outcome::Refused(RefusalReason::RunWallClock));

    // An agent with a wrong token cannot even open a session.
    let wrong = HttpUpstream::custom(
        UpstreamId::Postgres,
        fx.server.url().parse().expect("url"),
        Default::default(),
        Some(factory_mcp_gateway::SecretValue::new(
            "not-a-run-token".to_owned(),
        )),
        Vec::new(),
    )
    .expect("client");
    assert!(wrong.connect().await.is_err());
    fx.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn calls_per_run_stop_at_the_limit_and_probes_do_not_count() {
    let fx = fixture().await;
    let token = fx
        .gateway
        .open_run("run-cap", limits(3, 10, 1024, 5000))
        .expect("run");
    let agent = agent(&fx.server, token.expose()).await;
    for _ in 0..5 {
        let probe = fx
            .gateway
            .call_for_run("run-cap", "pg_factory_health", None)
            .await
            .expect("probe");
        assert_eq!(probe.outcome, Outcome::Ok);
    }
    for n in 1..=3 {
        let result = agent
            .call_tool("vm_query".to_owned(), args(serde_json::json!({"query": n})))
            .await
            .expect("result");
        assert_eq!(
            result.is_error,
            Some(false),
            "call {n}: {:?}",
            texts(&result)
        );
    }
    let fourth = agent
        .call_tool("vm_query".to_owned(), None)
        .await
        .expect("result");
    assert_eq!(fourth.is_error, Some(true));
    assert!(texts(&fourth)[1].starts_with("refused:"));
    let record = fx.gateway.run_record("run-cap").expect("record");
    assert_eq!(
        record.calls.last().map(|c| c.outcome),
        Some(Outcome::Refused(RefusalReason::MaxCallsPerRun))
    );
    assert_eq!(fx.vm.server.calls().len(), 3);
    // The control plane still works after the agent's budget is spent.
    let probe = fx
        .gateway
        .call_for_run("run-cap", "vm_query", None)
        .await
        .expect("probe");
    assert_eq!(probe.outcome, Outcome::Ok);
    fx.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_upstream_hits_the_call_deadline() {
    let fx = fixture().await;
    fx.postgres
        .add_tool("pg_query", Behavior::Sleep(Duration::from_secs(3)));
    fx.gateway
        .open_run("run-slow", limits(10, 10, 1024, 200))
        .expect("run");
    let started = std::time::Instant::now();
    let result = fx
        .gateway
        .call_for_run("run-slow", "pg_query", None)
        .await
        .expect("recorded");
    assert_eq!(result.outcome, Outcome::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
    let record = fx.gateway.run_record("run-slow").expect("record");
    assert_eq!(record.calls[0].outcome, Outcome::Timeout);
    assert!(
        record.calls[0].duration_ms >= 200,
        "{}",
        record.calls[0].duration_ms
    );
    fx.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_result_is_cut_on_a_character_boundary_with_a_marker() {
    let fx = fixture().await;
    let big = "ü".repeat(5000); // 10 000 bytes, two per character
    fx.postgres
        .add_tool("pg_query", Behavior::Text(big.clone()));
    let token = fx
        .gateway
        .open_run("run-big", limits(10, 10, 300, 5000))
        .expect("run");
    let agent = agent(&fx.server, token.expose()).await;
    let result = agent
        .call_tool("pg_query".to_owned(), None)
        .await
        .expect("result");
    let body = &texts(&result)[1];
    assert!(body.len() <= 300, "{}", body.len());
    let marker = body.find("\n[truncated by the gateway: ").expect("marker");
    let kept = &body[..marker];
    assert!(kept.chars().all(|c| c == 'ü'));
    assert!(
        body.ends_with(&format!("{} bytes cut]", big.len() - kept.len())),
        "{body}"
    );
    let record = fx.gateway.run_record("run-big").expect("record");
    assert_eq!(record.calls[0].result_bytes, 10_000);
    assert_eq!(record.calls[0].returned_bytes, body.len() as u64);
    fx.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_registered_secrets_and_run_tokens_are_redacted_from_results() {
    let fx = fixture().await;
    fx.vm.server.add_tool("labels", Behavior::EchoAuthorization);
    let token = fx
        .gateway
        .open_run("run-redact", fx.gateway.policy_limits())
        .expect("run");
    fx.postgres.add_tool(
        "pg_query",
        Behavior::ToolError(format!(
            "error near {PLANTED_SECRET} and the caller's token {}",
            token.expose()
        )),
    );
    let agent = agent(&fx.server, token.expose()).await;

    let labels = agent
        .call_tool("vm_labels".to_owned(), None)
        .await
        .expect("result");
    let text = texts(&labels).join("\n");
    assert!(
        fx.vm.server.calls().contains(&"labels".to_owned()),
        "the upstream was called with its bearer"
    );
    assert!(!text.contains(FAKE_VM_TOKEN), "{text}");
    assert!(
        text.contains("[REDACTED:victoriametrics_mcp_token]"),
        "{text}"
    );

    let failing = agent
        .call_tool("pg_query".to_owned(), None)
        .await
        .expect("result");
    assert_eq!(failing.is_error, Some(true));
    let text = texts(&failing).join("\n");
    assert!(!text.contains(PLANTED_SECRET), "{text}");
    assert!(!text.contains(token.expose()), "{text}");
    assert!(text.contains("[REDACTED:planted]"), "{text}");
    assert!(text.contains("[REDACTED:gateway_run_token]"), "{text}");

    let record = fx.gateway.close_run("run-redact").await.expect("closed");
    assert_eq!(record.calls[1].outcome, Outcome::ToolError);
    let json = String::from_utf8(record.canonical_json().expect("json")).expect("utf8");
    let debug = format!("{:?} {:?} {record:?}", fx.gateway, token);
    for shown in [json.as_str(), debug.as_str()] {
        assert!(!shown.contains(FAKE_VM_TOKEN));
        assert!(!shown.contains(token.expose()));
        assert!(!shown.contains(PLANTED_SECRET));
    }
    // After the run closed, its token is no longer a registered secret.
    let after = factory_mcp_gateway::Redact::redact(fx.redactor.as_ref(), token.expose())
        .expect("redacted");
    assert_eq!(after, token.expose());
    fx.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn call_ids_are_sequential_per_run_and_shared_with_the_control_plane() {
    let fx = fixture().await;
    let token = fx
        .gateway
        .open_run("run-ids", fx.gateway.policy_limits())
        .expect("run");
    let other = fx
        .gateway
        .open_run("run-other", fx.gateway.policy_limits())
        .expect("run");
    let agent = agent(&fx.server, token.expose()).await;
    let other_agent = agent_for(&fx, other.expose()).await;

    let first = fx
        .gateway
        .call_for_run("run-ids", "pg_factory_health", None)
        .await
        .expect("probe");
    assert_eq!(first.call_id.to_string(), "call-1");
    let second = agent
        .call_tool(
            "vm_query".to_owned(),
            args(serde_json::json!({"query": "up"})),
        )
        .await
        .expect("result");
    assert_eq!(texts(&second)[0], "call_id: call-2");
    let elsewhere = other_agent
        .call_tool("vm_query".to_owned(), None)
        .await
        .expect("result");
    assert_eq!(texts(&elsewhere)[0], "call_id: call-1", "ids are per run");
    let refused = agent
        .call_tool("nope".to_owned(), None)
        .await
        .expect("result");
    assert_eq!(texts(&refused)[0], "call_id: call-3");
    let fourth = fx
        .gateway
        .call_for_run(
            "run-ids",
            "vm_query",
            args(serde_json::json!({"query": "up"})),
        )
        .await
        .expect("probe");
    assert_eq!(fourth.call_id.to_string(), "call-4");

    let record = fx.gateway.close_run("run-ids").await.expect("closed");
    let ids: Vec<String> = record.calls.iter().map(|c| c.call_id.to_string()).collect();
    assert_eq!(ids, ["call-1", "call-2", "call-3", "call-4"]);
    let origins: Vec<CallOrigin> = record.calls.iter().map(|c| c.origin).collect();
    assert_eq!(
        origins,
        [
            CallOrigin::ControlPlane,
            CallOrigin::Agent,
            CallOrigin::Agent,
            CallOrigin::ControlPlane
        ]
    );
    assert_eq!(record.calls[1].upstream, Some(UpstreamId::Victoriametrics));
    assert_eq!(record.calls[1].upstream_tool.as_deref(), Some("query"));
    assert_eq!(
        record.calls[1].arguments_sha256, record.calls[3].arguments_sha256,
        "the same arguments have the same digest"
    );
    assert!(record.call("call-2").is_some());
    assert!(record.call("call-9").is_none());

    let json: serde_json::Value =
        serde_json::from_slice(&record.canonical_json().expect("json")).expect("parses");
    assert_eq!(json["run_id"], "run-ids");
    assert_eq!(json["calls"][1]["call_id"], "call-2");
    assert_eq!(json["calls"][1]["origin"], "agent");
    assert_eq!(json["calls"][1]["upstream"], "victoriametrics");
    assert_eq!(json["calls"][2]["outcome"], "refused:tool_not_allowed");
    assert!(
        json["calls"][1]["arguments_sha256"]
            .as_str()
            .is_some_and(|d| d.starts_with("sha256:"))
    );
    assert_eq!(json["limits"]["call_deadline_ms"], 20_000);
    assert_eq!(
        record.digest().expect("digest"),
        record.digest().expect("digest")
    );
    fx.server.shutdown().await;
}

async fn agent_for(fx: &support::Fixture, token: &str) -> HttpUpstream {
    agent(&fx.server, token).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_loopback_listen_address_is_refused() {
    let gateway = Gateway::builder(&policy(), redactor())
        .build()
        .expect("gateway");
    for address in ["0.0.0.0:0", "192.0.2.1:7811"] {
        assert!(matches!(
            gateway.serve(address.parse().expect("addr"), &[]).await,
            Err(GatewayError::Config(ConfigError::NotLoopback(_)))
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_file_readable_by_others_is_refused() {
    let token_file = secret_file("open-token", 0o644, "fake-credential-in-an-open-file\n");
    let error = HttpUpstream::victoriametrics(&VictoriaMetricsConfig {
        url: "http://127.0.0.1:1/mcp".to_owned(),
        token_file: token_file.clone(),
    })
    .expect_err("refused");
    assert!(matches!(error, HttpUpstreamError::Credential(_)));
    let text = format!("{error} {error:?}");
    assert!(text.contains(&token_file.display().to_string()), "{text}");
    assert!(text.contains("644"), "{text}");
    assert!(!text.contains("fake-credential"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn datadog_credentials_stay_out_of_debug_and_are_registered() {
    let api = secret_file("dd-api", 0o600, "fake-datadog-api-key-for-tests\n");
    let app = secret_file("dd-app", 0o400, "fake-datadog-app-key-for-tests\n");
    let upstream = HttpUpstream::datadog(
        &factory_mcp_gateway::DatadogConfig {
            site: "datadoghq.com".to_owned(),
            api_key_file: api,
            application_key_file: app,
        },
        &policy().upstreams.datadog,
    )
    .expect("the Datadog upstream");
    assert_eq!(
        upstream.url().as_str(),
        "https://mcp.datadoghq.com/v1/mcp?toolsets=core&omit_tools=create_datadog_notebook"
    );
    let debug = format!("{upstream:?}");
    assert!(!debug.contains("fake-datadog"), "{debug}");
    let labels: Vec<&str> = upstream.credentials().iter().map(|(l, _)| *l).collect();
    assert_eq!(labels, ["datadog_api_key", "datadog_application_key"]);

    let redactor = redactor();
    let _gateway = Gateway::builder(&policy(), redactor.clone())
        .upstream(Arc::new(upstream))
        .build()
        .expect("gateway");
    let out = factory_mcp_gateway::Redact::redact(
        redactor.as_ref(),
        "keys fake-datadog-api-key-for-tests fake-datadog-app-key-for-tests",
    )
    .expect("redacted");
    assert!(!out.contains("fake-datadog"), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_upstream_reports_its_tools_missing() {
    let token_file = secret_file("vm-token", 0o600, &format!("{FAKE_VM_TOKEN}\n"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let closed = listener.local_addr().expect("addr");
    drop(listener);
    let vm = HttpUpstream::victoriametrics(&VictoriaMetricsConfig {
        url: format!("http://{closed}/mcp"),
        token_file,
    })
    .expect("upstream");
    let gateway = Gateway::builder(&policy(), redactor())
        .upstream(Arc::new(vm))
        .upstream(Arc::new(InProcessUpstream::new(
            UpstreamId::Postgres,
            FakeServer::with_tools(&["pg_query"]),
        )))
        .build()
        .expect("gateway");
    let report = gateway.connect().await;
    let vm_missing: Vec<_> = report
        .missing
        .iter()
        .filter(|m| m.tool.upstream == UpstreamId::Victoriametrics)
        .map(|m| m.reason)
        .collect();
    assert_eq!(vm_missing, [MissingReason::UpstreamUnavailable; 3]);
    let offered: Vec<&str> = report
        .offered
        .iter()
        .map(|t| t.gateway_name.as_str())
        .collect();
    assert_eq!(offered, ["pg_query"]);
    gateway
        .open_run("run-down", gateway.policy_limits())
        .expect("run");
    let result = gateway
        .call_for_run("run-down", "vm_query", None)
        .await
        .expect("recorded");
    assert_eq!(
        result.outcome,
        Outcome::Refused(RefusalReason::ToolUnavailable)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_cannot_be_opened_looser_than_the_policy() {
    let gateway = Gateway::builder(&policy(), redactor())
        .build()
        .expect("gateway");
    let mut looser = gateway.policy_limits();
    looser.max_calls_per_10s = 41;
    assert!(matches!(
        gateway.open_run("run-loose", looser),
        Err(GatewayError::LooserLimits(_))
    ));
    gateway
        .open_run("run-a", gateway.policy_limits())
        .expect("run");
    assert!(matches!(
        gateway.open_run("run-a", gateway.policy_limits()),
        Err(GatewayError::RunExists(_))
    ));
    assert!(matches!(
        gateway.open_run("bad id", gateway.policy_limits()),
        Err(GatewayError::BadRunId)
    ));
}
