//! The owner's live check of subscription mode (ADR 0020): one tiny request through the real broker
//! to the real provider, signed with the owner's Claude subscription token.
//!
//! **Ignored by default. It spends a little of the owner's plan, and only the owner runs it.** It
//! has never been run by the engineer who wrote it, who had no token.
//!
//! ```text
//! cargo test -p factory-egress --test live_subscription -- --ignored --nocapture
//! ```
//!
//! Two checks. The first sends one request written by hand. The second runs the real `claude`
//! program on this machine against the broker, with the job token as its subscription token, the
//! way the factory's adapter starts it, so the request has the shape the program really sends (in
//! `-p` mode a billing block and then "You are a Claude agent, built on Anthropic's Claude Agent
//! SDK."). The second needs `claude` on the PATH, and is BLOCKED without it.
//!
//! What it reads, outside the repository:
//!
//! * the token file: `FACTORY_SUBSCRIPTION_TOKEN_FILE`, or `~/claud-oauth-token.txt` when that is
//!   not set. The file must be mode 0600 or stricter and hold one token made with
//!   `claude setup-token` (the same checks the worker makes at start-up);
//! * the model: `FACTORY_LIVE_MODEL`, or `claude-haiku-5-5`.
//!
//! What it prints: the HTTP status, the model the provider answered with, and the token counts
//! the broker metered. Never the token, never the answer text. A line that starts `BLOCKED:` means
//! it could not run, which is not a pass.

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use factory_egress::broker::{CapPolicy, ModelPrice, PriceTable, Provider};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, ServerLimits, UpstreamConfig,
};
use factory_ports::agent::{ModelSelection, RuntimeId};
use factory_testkit::fx::docker::blocked;
use factory_testkit::fx::http::send_request;
use support::Rig;

fn token_path() -> PathBuf {
    if let Some(path) =
        std::env::var_os("FACTORY_SUBSCRIPTION_TOKEN_FILE").filter(|p| !p.is_empty())
    {
        return PathBuf::from(path);
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| {
        blocked("HOME is not set, and FACTORY_SUBSCRIPTION_TOKEN_FILE is not either")
    });
    PathBuf::from(home).join("claud-oauth-token.txt")
}

/// The owner's token, checked as the worker checks it.
fn owner_token() -> ProviderKey {
    let path = token_path();
    let shown = path.display().to_string();
    let meta = std::fs::metadata(&path).unwrap_or_else(|_| {
        blocked(&format!(
            "{shown} does not exist; run `claude setup-token` and save the token there"
        ))
    });
    if meta.permissions().mode() & 0o177 != 0 {
        blocked(&format!(
            "{shown} has mode {:o}; run chmod 600 on it",
            meta.permissions().mode() & 0o777
        ));
    }
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| blocked(&format!("{shown} cannot be read")));
    ProviderKey::subscription_token(&text).unwrap_or_else(|e| blocked(&format!("{shown}: {e}")))
}

fn live_model() -> String {
    std::env::var("FACTORY_LIVE_MODEL")
        .ok()
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "claude-haiku-5-5".to_owned())
}

/// A broker in front of the real provider, signed with the owner's token, and a job token for
/// one model with a budget of `budget` micro-dollars.
fn live_broker(
    model: &str,
    budget: u64,
) -> (Rig, BrokerServer, factory_ports::agent::IssuedJobToken) {
    let token = owner_token();

    // A high placeholder price: the check is about the path, and the broker meters with it.
    let price = ModelPrice {
        input: 30_000_000,
        cache_write: 37_500_000,
        cache_read: 3_000_000,
        output: 150_000_000,
    };
    let table = PriceTable::new().with_model(Provider::Anthropic, model, price);
    let rig = Rig::with_prices(CapPolicy::default(), Arc::new(table));
    let server = BrokerServer::start(
        BrokerServerConfig {
            listen: "127.0.0.1:0".parse().expect("address"),
            upstreams: vec![
                UpstreamConfig::subscription(
                    Provider::Anthropic,
                    "https://api.anthropic.com",
                    token,
                )
                .expect("an upstream"),
            ],
            expected_job: None,
            limits: ServerLimits::default(),
        },
        rig.core.clone(),
    )
    .expect("the broker starts");

    let mut request = rig.request(factory_ports::agent::CostMicroUsd(budget));
    request.allowed_models = vec![ModelSelection {
        runtime: RuntimeId::new("claude-code-cli").expect("slug"),
        model: factory_domain::values::NonEmptyString::parse(model).expect("name"),
    }];
    let job_token = rig.core.issue_token(request).expect("a token");
    (rig, server, job_token)
}

#[test]
#[ignore = "spends a little of the owner's Claude plan; the owner runs it by hand (ADR 0020)"]
fn live_subscription_one_tiny_request_through_the_broker() {
    let model = live_model();
    let (rig, server, job_token) = live_broker(&model, 100_000);
    // The request as Claude Code would send it to the sidecar: the job token as a bearer
    // credential, the betas, `?beta=true` and a system prompt that opens with the identity.
    let answer = send_request(
        server.local_addr(),
        "POST",
        "/v1/messages?beta=true",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &format!("Bearer {}", job_token.secret.expose())),
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "claude-code-20250219,oauth-2025-04-20"),
        ],
        serde_json::json!({
            "model": model,
            "max_tokens": 16,
            "system": [{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}],
            "messages": [{"role": "user", "content": "Reply with the word ok."}],
        })
        .to_string()
        .as_bytes(),
    )
    .expect("an answer");
    let answered_model = answer
        .json()
        .and_then(|v| v["model"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "(none)".to_owned());
    let usage = rig.core.token_usage(&job_token.id).expect("usage").usage;
    println!(
        "LIVE subscription: status {} model {} input_tokens {} output_tokens {}",
        answer.status, answered_model, usage.input_tokens, usage.output_tokens
    );
    if answer.status != 200 {
        let kind = answer
            .json()
            .and_then(|v| v["error"]["type"].as_str().map(str::to_owned))
            .unwrap_or_default();
        println!("LIVE subscription: the broker's error type is {kind:?}");
    }
    assert_eq!(answer.status, 200, "the request did not succeed");
    assert!(usage.output_tokens > 0, "the broker read no usage");
}

#[test]
#[ignore = "spends a little of the owner's Claude plan; the owner runs it by hand (ADR 0020)"]
fn live_subscription_the_real_claude_program_through_the_broker() {
    let model = live_model();
    // Claude Code's own system prompt is several thousand tokens; the placeholder price is high.
    let (rig, server, job_token) = live_broker(&model, 20_000_000);
    let home_dir = std::env::temp_dir().join(format!("factory-live-claude-{}", std::process::id()));
    std::fs::create_dir_all(&home_dir).expect("an empty home");
    let home = HomeDir(home_dir);
    let output = std::process::Command::new("claude")
        .args([
            "-p",
            "Reply with the word ok.",
            "--model",
            &model,
            "--setting-sources",
            "user",
            "--strict-mcp-config",
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("CLAUDE_CODE_OAUTH_TOKEN", job_token.secret.expose())
        .env(
            "ANTHROPIC_BASE_URL",
            format!("http://{}", server.local_addr()),
        )
        .env("CLAUDE_CODE_PROMPT_CACHE_TTL", "5m")
        .current_dir(home.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|_| blocked("`claude` is not on the PATH"));
    let usage = rig.core.token_usage(&job_token.id).expect("usage").usage;
    let answer = String::from_utf8_lossy(&output.stdout);
    println!(
        "LIVE claude program: exit {:?} answered_ok {} input_tokens {} output_tokens {}",
        output.status.code(),
        answer.to_lowercase().contains("ok"),
        usage.input_tokens,
        usage.output_tokens
    );
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let shown: String = answer.chars().chain(err.chars()).take(400).collect();
        println!(
            "LIVE claude program said: {}",
            shown.replace(job_token.secret.expose(), "[JOB TOKEN]")
        );
    }
    assert!(output.status.success(), "claude did not finish");
    assert!(usage.output_tokens > 0, "the broker read no usage");
}

/// An empty home for the `claude` program, removed afterwards.
struct HomeDir(PathBuf);

impl HomeDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for HomeDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
