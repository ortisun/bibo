//! Telemetry: the work the API does on a job runs inside a `factory.job` span that carries the
//! correlation id, the job id and the tenant (ADR 0013), and the span never carries something the
//! caller made up.

mod support;

use std::sync::PoisonError;

use serde_json::json;
use support::{Env, Req, captured};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_work_runs_in_a_job_span() {
    let _ = captured();
    let env = Env::start().await;
    let sent = "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b";
    let created = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&env.a.requester.token)
                .header("Idempotency-Key", "span")
                .header("X-Correlation-Id", sent)
                .json(&json!({"repository_id": env.a.repository.as_text(), "source_ref": format!("{}#1", env.a.full_name), "text": "x"})),
        )
        .await;
    let job = created.json()["job_id"]
        .as_str()
        .expect("job id")
        .to_owned();
    for path in [
        format!("/v1/jobs/{job}"),
        format!("/v1/jobs/{job}/timeline"),
    ] {
        let reply = env
            .send(
                Req::get(&path)
                    .bearer(&env.a.requester.token)
                    .header("X-Correlation-Id", sent),
            )
            .await;
        assert_eq!(reply.status, 200);
    }
    let seen = captured()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let spans: Vec<&String> = seen
        .iter()
        .filter(|line| line.starts_with("span factory.job "))
        .collect();
    assert_eq!(spans.len(), 2, "{seen:#?}");
    for span in spans {
        assert!(
            span.contains(&format!("correlation_id=\"{sent}\"")),
            "{span}"
        );
        assert!(span.contains(&format!("job_id=\"{job}\"")), "{span}");
        assert!(
            span.contains(&format!("tenant_id=\"{}\"", env.a.id.as_text())),
            "{span}"
        );
    }
    // A path that is not a job id never becomes an attribute.
    let hostile = "x\"; drop table jobs";
    let _ = env
        .send(
            Req::get(&format!(
                "/v1/jobs/{}",
                hostile.replace(' ', "%20").replace('"', "%22")
            ))
            .bearer(&env.a.requester.token),
        )
        .await;
    let seen = captured()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .join("\n");
    assert!(
        !seen.contains("drop table"),
        "an attribute holds what the caller typed"
    );
    env.stop().await;
}

/// The redactor the telemetry set-up gets is the one built from the loaded policy, and the
/// scrubber passed to the pipeline is the real one: the function that builds the configuration is
/// the worker's, so the API cannot forget it.
#[test]
fn telemetry_gets_the_real_redactor() {
    use std::sync::Arc;

    use factory_composition::config::TelemetryConfig;
    use factory_composition::profile::Profile;
    use factory_composition::redaction::redactor_from_policy;
    use factory_composition::startup::load_policy;
    let policies = load_policy(&support::repository_root(), &[]).expect("policies");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("redactor"));
    let config = factory_composition::telemetry::config_for(
        "factory-api",
        "0.0.0",
        Profile::Test,
        &TelemetryConfig::default(),
        &redactor,
    )
    .expect("the configuration builds");
    let _ = config;
    // The boot path calls this function and no other to build the configuration.
    let boot = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/boot.rs"),
    )
    .expect("boot.rs");
    assert!(boot.contains("telemetry::config_for("));
    assert!(!boot.contains("TelemetryConfig::new("));
}
