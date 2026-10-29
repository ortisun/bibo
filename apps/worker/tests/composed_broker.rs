//! The model path of the worker over the loopback interface: the broker the worker hosts, the routing
//! policy in front of it, the real Claude Code adapter, and a fake provider.
//!
//! What is real: the broker listener and its core (`apps/worker` `broker_host::start`), the routing
//! policy and `PolicyBroker`, the token vault, the Claude Code adapter (`ClaudeCodeRuntime`: the
//! command, the stream rule and the attestation against the broker's own ledger), the redactor.
//! What is fake, and labelled: the provider (the test kit's recorded-shape server on the loopback
//! interface), and the sandbox session, which stands in for the container: it answers the probe
//! commands from the spike's recorded text, and when the adapter starts the tool it makes the HTTP
//! request the tool would make, through the broker, and prints the recorded stream with the answer
//! it got. No Docker, no model, no key.
#![allow(dead_code)]

#[path = "../../../crates/runtime/tests/support/mod.rs"]
mod rsupport;

#[path = "../../../crates/egress/tests/support/fake_provider.rs"]
mod fake_provider;

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::config::{BrokerConfig, SecretFile, UpstreamConfig};
use factory_composition::policy_broker::{JobSpend, PolicyBroker};
use factory_composition::redaction::{FactorySecrets, RegisteringBroker, redactor_from_policy};
use factory_composition::startup::{LoadedRouting, load_policy, load_routing};
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::NonEmptyString;
use factory_domain::vocabulary::StageKind;
use factory_egress::broker::{Refusal, RevokeReason};
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRuntime, CostMicroUsd, JobTokenRef, JobTokenRequest,
    ModelBroker, ModelSelection, RuntimeId, TokenState,
};
use factory_ports::clock::{CancelSignal, IdGenerator};
use factory_ports::sandbox::{
    ExecRequest, ExecResult, PostureReport, SandboxError, SandboxId, SandboxSession,
    TeardownReason, TeardownReport,
};
use factory_runtime::probe::NeverCancelled;
use factory_runtime::{ClaudeCodeConfig, ClaudeCodeRuntime};
use factory_testkit::fx::http::send_request;
use factory_worker::broker_host::{HostedBroker, start};
use rsupport::scripted::{ScriptedSession, Step, Tool};
use rsupport::{Harness, recorded, request};
use serde_json::{Value, json};

use fake_provider::{FakeProvider, Script};

const SONNET: &str = "claude-sonnet-5-5";
const OPUS: &str = "claude-opus-5-5";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The classifier's answer that the playbook of the word-count job uses, as the text the model
/// would send back.
fn model_answer() -> String {
    std::fs::read_to_string(
        root().join("agents/intake-classifier/fixtures/valid/feature-with-json-flag.json"),
    )
    .expect("the valid fixture")
}

fn selection(model: &str) -> ModelSelection {
    ModelSelection {
        runtime: RuntimeId::new("claude-code-cli").expect("a runtime"),
        model: NonEmptyString::parse(model).expect("a model"),
    }
}

/// What the worker holds for the model path, around one fake provider.
struct Lab {
    provider: FakeProvider,
    hosted: HostedBroker,
    routing: LoadedRouting,
    registering: Arc<RegisteringBroker>,
    provider_key: String,
    dir: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = root()
            .join("target/composed-broker")
            .join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        // A key made at run time, so that no key-shaped literal sits in the source.
        let provider_key = ["provider", "-key-", &"cd".repeat(14)].concat();
        let key_path = dir.join("provider.key");
        std::fs::write(&key_path, &provider_key).expect("write");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        let provider = FakeProvider::start();
        let policies = load_policy(&root(), &[]).expect("policies");
        let routing = load_routing(&root(), &[], &policies.security).expect("routing");
        let redactor = Arc::new(redactor_from_policy(&policies.security).expect("redactor"));
        let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
        let hosted = start(
            &BrokerConfig {
                listen: "127.0.0.1:0".parse().expect("an address"),
                upstreams: vec![UpstreamConfig {
                    provider: "anthropic".to_owned(),
                    base_url: provider.base_url(),
                    key_file: SecretFile::at(key_path),
                    models: Vec::new(),
                }],
                prices: Vec::new(),
            },
            &routing.policy,
            Arc::clone(&redactor),
            Arc::new(SystemClock),
            Arc::new(RandomIds::new().expect("random")),
            &mut secrets,
        )
        .expect("the broker starts");
        let policy_broker: Arc<dyn ModelBroker> = Arc::new(PolicyBroker::new(
            hosted.core.clone(),
            Arc::clone(&routing.policy),
            hosted.core.clone() as Arc<dyn JobSpend>,
        ));
        let registering = Arc::new(RegisteringBroker::new(policy_broker, redactor));
        Self {
            provider,
            hosted,
            routing,
            registering,
            provider_key,
            dir,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.hosted.local_addr()
    }

    /// What the engine asks the broker for: one model and the ten dollars of the stage contract.
    async fn token_for(
        &self,
        stage: StageKind,
        model: &str,
    ) -> (JobTokenRef, String, TenantId, JobId) {
        let ids = RandomIds::new().expect("random");
        let tenant = TenantId::from_uuid(ids.new_uuid());
        let job = JobId::from_uuid(ids.new_uuid());
        let issued = self
            .registering
            .issue(JobTokenRequest {
                tenant,
                job,
                stage,
                cost_ceiling: CostMicroUsd(10_000_000),
                allowed_models: vec![selection(model)],
                ttl: Duration::from_secs(900),
                per_request: None,
            })
            .await
            .expect("a token");
        let secret = self
            .registering
            .secret_of(&issued.id)
            .expect("the vault holds the secret")
            .expose()
            .to_owned();
        (JobTokenRef { id: issued.id }, secret, tenant, job)
    }

    /// One request as the sidecar would forward it from the tool, with the job token.
    fn post(&self, secret: &str, body: &Value) -> (u16, String) {
        let answer = send_request(
            self.addr(),
            "POST",
            "/v1/messages?beta=true",
            &[
                ("Content-Type", "application/json"),
                ("x-api-key", secret),
                ("anthropic-version", "2023-06-01"),
            ],
            body.to_string().as_bytes(),
        )
        .expect("the broker answers");
        (answer.status, answer.text())
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.hosted.shutdown();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn messages_body(model: &str) -> Value {
    json!({
        "model": model, "stream": false, "max_tokens": 1024,
        "messages": [{"role": "user", "content": "Classify the request."}],
    })
}

// ---- the stand-in for the container ---------------------------------------------------------

/// What the tool does when the adapter starts it.
#[derive(Clone)]
enum Tool_ {
    /// Sends the request an honest tool sends, and prints the recorded stream with `answer`.
    Honest { model: String },
    /// Sends a request with a provider-side tool in it, is refused, and prints a stream that
    /// claims success all the same.
    Lying { body: Value },
}

/// A labelled fake of the container: the probe commands are answered from the spike's recorded text,
/// and the tool command makes its HTTP request through the broker.
struct ToolSession {
    harness: Arc<Harness>,
    base: ScriptedSession,
    broker: SocketAddr,
    secret: String,
    behaviour: Tool_,
    answer: String,
    seen: Arc<Mutex<Vec<(u16, String)>>>,
}

impl ToolSession {
    fn stream(&self) -> String {
        // The recorded run is of the fake provider's default answer, so its usage is what the broker
        // metered for the request below. Only the text of the result is replaced.
        let recorded = recorded::stdout("claude-turn-env");
        recorded
            .lines()
            .map(|line| {
                let mut event: Value = serde_json::from_str(line).expect("a recorded event");
                if event["type"] == "result" {
                    event["result"] = Value::String(self.answer.clone());
                }
                event.to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }
}

#[async_trait]
impl SandboxSession for ToolSession {
    fn id(&self) -> &SandboxId {
        self.base.id()
    }

    fn posture(&self) -> &PostureReport {
        self.base.posture()
    }

    async fn exec(
        &mut self,
        req: ExecRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<ExecResult, SandboxError> {
        let is_tool_run = req.argv.as_slice().iter().any(|a| a == "/usr/bin/timeout");
        if !is_tool_run {
            return self.base.exec(req, cancel).await;
        }
        let body = match &self.behaviour {
            Tool_::Honest { model } => messages_body(model),
            Tool_::Lying { body } => body.clone(),
        };
        let answer = send_request(
            self.broker,
            "POST",
            "/v1/messages?beta=true",
            &[
                ("Content-Type", "application/json"),
                ("x-api-key", &self.secret),
                ("anthropic-version", "2023-06-01"),
            ],
            body.to_string().as_bytes(),
        )
        .expect("the broker answers");
        self.seen
            .lock()
            .expect("lock")
            .push((answer.status, answer.text()));
        let mut one =
            ScriptedSession::new(&self.harness, Tool::Claude, Step::exits(0, &self.stream()));
        one.exec(req, cancel).await
    }

    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        Box::new(self.base).stop_and_remove(reason).await
    }
}

/// Runs the Claude Code adapter on the stand-in container, against the broker of `lab`.
async fn run_the_tool(
    lab: &Lab,
    token: JobTokenRef,
    secret: String,
    model: &str,
    behaviour: Tool_,
) -> (AgentRunReport, Vec<(u16, String)>) {
    let harness = Arc::new(Harness::new());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut session = ToolSession {
        base: ScriptedSession::new(&harness, Tool::Claude, Step::exits(0, "")),
        harness: Arc::clone(&harness),
        broker: lab.addr(),
        secret,
        behaviour,
        answer: model_answer(),
        seen: Arc::clone(&seen),
    };
    // The adapter is the real one, and its attestation is the broker's own record of the token.
    let runtime = ClaudeCodeRuntime::new(
        ClaudeCodeConfig::default(),
        harness.io.clone(),
        lab.hosted.core.clone(),
    );
    let mut req = request(&harness, "claude-code-cli", model, "http://egress:8080");
    req.job_token = token;
    let report = runtime.run(&mut session, req, &NeverCancelled).await;
    let seen = seen.lock().expect("lock").clone();
    (report, seen)
}

// ---- the happy path --------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_real_claude_run_goes_through_the_broker_to_the_provider_and_the_broker_attests_it() {
    let lab = Lab::new("happy");
    let (token, secret, _, job) = lab.token_for(StageKind::Intake, SONNET).await;
    let (report, seen) = run_the_tool(
        &lab,
        token,
        secret.clone(),
        SONNET,
        Tool_::Honest {
            model: SONNET.to_owned(),
        },
    )
    .await;

    // The adapter accepted the run: the stream said completed, and the broker, which is outside the
    // sandbox, saw an answer end the turn.
    let output = report.outcome.unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(output.as_bytes(), model_answer().as_bytes());
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, 200, "{}", seen[0].1);

    // The provider got one request, with the factory's key, never the job token.
    let received = lab.provider.requests();
    assert_eq!(received.len(), 1);
    let sent = &received[0];
    assert_eq!(sent.path, "/v1/messages");
    assert_eq!(sent.header("x-api-key"), Some(lab.provider_key.as_str()));
    assert_eq!(sent.json()["model"], SONNET);
    assert!(
        sent.headers
            .iter()
            .all(|(_, value)| !value.contains(&secret)),
        "the job token reached the provider"
    );
    assert!(!String::from_utf8_lossy(&sent.body).contains(&secret));

    // And it was metered at the policy's price and written to the job's ledger.
    let usage = lab.registering.usage(&token.id).await.expect("usage");
    assert_eq!(usage.usage.requests, 1);
    assert!(usage.usage.cost.0 > 0, "{usage:?}");
    assert_eq!(usage.state, TokenState::Active);
    assert_eq!(lab.hosted.core.ledger(job).total.cost, usage.usage.cost);
    // The ceiling the token holds is the stage's, not the ten dollars the engine asked for.
    let stage = lab
        .routing
        .policy
        .stage_ceiling("INTAKE")
        .expect("a ceiling");
    assert_eq!(usage.ceiling, CostMicroUsd(stage.max_micro_usd));
}

// ---- refusals --------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_that_sends_a_request_outside_the_allow_schema_is_refused_and_cannot_fake_a_success()
{
    let lab = Lab::new("shape");
    for (what, body) in [
        (
            "a provider-side tool",
            json!({"model": SONNET, "max_tokens": 64, "messages": [{"role": "user", "content": "x"}],
                   "tools": [{"type": "web_search_20250305", "name": "web_search", "max_uses": 5}]}),
        ),
        (
            "a remote MCP server",
            json!({"model": SONNET, "max_tokens": 64, "messages": [{"role": "user", "content": "x"}],
                   "mcp_servers": [{"type": "url", "url": "https://tools.example.org/mcp", "name": "t"}]}),
        ),
        (
            "a field the schema does not list",
            json!({"model": SONNET, "max_tokens": 64, "messages": [{"role": "user", "content": "x"}],
                   "send_the_workspace_to": "https://drop.example.org"}),
        ),
    ] {
        let (token, secret, _, _) = lab.token_for(StageKind::Intake, SONNET).await;
        // The fake runtime sends it, and the broker answers 400.
        let (status, _) = lab.post(&secret, &body);
        assert_eq!(status, 400, "{what}");
        // The provider never saw it.
        assert_eq!(lab.provider.hits(), 0, "{what} reached the provider");
        // A tool that lies about it, printing a stream that says completed, is not believed: the
        // broker saw no answer, so the adapter reports a failure.
        let (report, seen) = run_the_tool(&lab, token, secret, SONNET, Tool_::Lying { body }).await;
        assert_eq!(seen[0].0, 400, "{what}");
        assert!(
            matches!(report.outcome, Err(AgentRunError::OutputMissing)),
            "{what}: {:?}",
            report.outcome
        );
        assert_eq!(lab.provider.hits(), 0, "{what} reached the provider");
        let _ = what;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_for_a_model_outside_the_route_of_the_token_is_refused_at_the_listener() {
    let lab = Lab::new("route");
    // The engine asked for one model of the INTAKE route.
    let (token, secret, _, _) = lab.token_for(StageKind::Intake, SONNET).await;
    // Another model of the same route, one the policy does not know, and one with a lookalike name.
    for outside in [
        OPUS,
        "claude-haiku-9",
        "claude-sonnet-5-5-latest",
        "gpt-6.1-sol",
    ] {
        let (status, text) = lab.post(&secret, &messages_body(outside));
        assert_eq!(status, 403, "{outside}: {text}");
    }
    assert_eq!(
        lab.provider.hits(),
        0,
        "a refused model reached the provider"
    );
    // The token is still good for its own model.
    let (status, _) = lab.post(&secret, &messages_body(SONNET));
    assert_eq!(status, 200);
    assert_eq!(lab.provider.hits(), 1);
    // And the routing policy cuts a request for a model the stage does not route, before the core
    // sees it: the engine asking for the large model in a stage that routes it is fine, a model of
    // no route is not.
    let refused = lab
        .registering
        .issue(JobTokenRequest {
            tenant: TenantId::from_uuid(RandomIds::new().expect("random").new_uuid()),
            job: JobId::from_uuid(RandomIds::new().expect("random").new_uuid()),
            stage: StageKind::Intake,
            cost_ceiling: CostMicroUsd(1_000),
            allowed_models: vec![selection("claude-haiku-9")],
            ttl: Duration::from_secs(60),
            per_request: None,
        })
        .await;
    assert!(refused.is_err());
    let _ = token;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cost_ceiling_of_the_stage_stops_the_token_and_the_run() {
    let lab = Lab::new("ceiling");
    // The fake provider reports usage that costs about ninety thousandths of a dollar a request at
    // the policy's price; the INTAKE ceiling is a tenth of a dollar.
    lab.provider
        .set(|script: &mut Script| script.anthropic = (10_000, 0, 0, 1_000));
    let (token, secret, _, job) = lab.token_for(StageKind::Intake, SONNET).await;
    let ceiling = lab
        .registering
        .usage(&token.id)
        .await
        .expect("usage")
        .ceiling;
    assert_eq!(
        ceiling,
        CostMicroUsd(
            lab.routing
                .policy
                .stage_ceiling("INTAKE")
                .expect("ceiling")
                .max_micro_usd
        )
    );
    let (first, _) = lab.post(&secret, &messages_body(SONNET));
    assert_eq!(first, 200);
    let spent = lab
        .registering
        .usage(&token.id)
        .await
        .expect("usage")
        .usage
        .cost;
    assert!(spent.0 > 0 && spent < ceiling, "{spent:?}");
    // The second request is admitted (the cost is known only when the answer is read), and it
    // crosses the ceiling: the token is revoked in the same step.
    let (second, _) = lab.post(&secret, &messages_body(SONNET));
    assert_eq!(second, 200);
    let after = lab.registering.usage(&token.id).await.expect("usage");
    assert_eq!(after.state, TokenState::Revoked);
    assert_eq!(
        lab.hosted.core.revoke_reason(&token.id),
        Some(RevokeReason::CostCeiling)
    );
    // The third is a budget stop, with the status that makes the tool give up at once.
    let (third, _) = lab.post(&secret, &messages_body(SONNET));
    assert_eq!(third, 402);
    assert_eq!(
        lab.provider.hits(),
        2,
        "the refused request reached the provider"
    );
    // What was recorded is at most the ceiling plus the request that crossed it.
    assert!(after.usage.cost.0 <= ceiling.0 + spent.0, "{after:?}");
    // The job's ledger says the same, and the job has no room left for another stage's worth.
    assert_eq!(lab.hosted.core.ledger(job).total.cost, after.usage.cost);
    let _ = Refusal::UnknownToken;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_token_of_a_job_gets_only_what_is_left_of_the_job_ceiling() {
    let lab = Lab::new("job-ceiling");
    let job_max = lab.routing.policy.job.max_micro_usd;
    // Spend the whole job ceiling on one job through its tokens, at a price that makes it quick.
    lab.provider
        .set(|script: &mut Script| script.anthropic = (10_000, 0, 0, 1_000));
    let ids = RandomIds::new().expect("random");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    let job = JobId::from_uuid(ids.new_uuid());
    let mut spent = 0;
    let mut rounds = 0;
    while spent < job_max && rounds < 200 {
        rounds += 1;
        let issued = lab
            .registering
            .issue(JobTokenRequest {
                tenant,
                job,
                stage: StageKind::Implementation,
                cost_ceiling: CostMicroUsd(10_000_000),
                allowed_models: vec![selection(SONNET)],
                ttl: Duration::from_secs(900),
                per_request: None,
            })
            .await;
        let Ok(issued) = issued else { break };
        let secret = lab
            .registering
            .secret_of(&issued.id)
            .expect("secret")
            .expose()
            .to_owned();
        for _ in 0..3 {
            let _ = lab.post(&secret, &messages_body(SONNET));
        }
        spent = lab.hosted.core.ledger(job).total.cost.0;
    }
    // Once the job has spent its ceiling, the next stage's token is not issued.
    assert!(spent >= job_max, "the job spent {spent} of {job_max}");
    let refused = lab
        .registering
        .issue(JobTokenRequest {
            tenant,
            job,
            stage: StageKind::Review,
            cost_ceiling: CostMicroUsd(10_000_000),
            allowed_models: vec![selection(SONNET)],
            ttl: Duration::from_secs(900),
            per_request: None,
        })
        .await;
    assert!(refused.is_err(), "a token was issued after the job ceiling");
}
