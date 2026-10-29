//! Negative tests owned by the runtime (negative test catalog, `docs/security/negative-test-catalog.md`):
//!
//! * NT-INJ-07 repository-resident agent configuration is never honored (done criterion 3),
//! * NT-TOOL-06 environment injection has no effect (done criterion 4),
//! * NT-TOOL-07 output flood, timeout and process group are bounded (done criterion 5).
//!
//! The tool is the real one, in a real hardened container, with the spike's fake provider as the
//! model. A model is assumed fully controlled by an attacker: the fake provider asks the tool to run
//! what the attacker wants, and the container's effects are what the tests judge.

mod support;

use std::time::{Duration, Instant};

use factory_ports::agent::{AgentRunError, AgentRunRequest, AgentRuntime};
use factory_runtime::probe::NeverCancelled;
use factory_runtime::{ClaudeCodeConfig, ClaudeCodeRuntime, CodexConfig, CodexRuntime};
use support::docker::{HostWorkspace, Lab};
use support::hostile::{self, MARKER_FILES, TEXT_MARKERS};
use support::{Harness, events_of, init_of, limits, request, tool_results_of};

const OK_REPLY: &str = "Summarize the project. FAKE:OUTPUT {\"ok\":true}";

fn claude(h: &Harness) -> ClaudeCodeRuntime {
    ClaudeCodeRuntime::new(ClaudeCodeConfig::default(), h.io.clone(), h.attestation())
}

fn codex(h: &Harness) -> CodexRuntime {
    CodexRuntime::new(CodexConfig::default(), h.io.clone(), h.attestation())
}

fn claude_request(h: &Harness, lab: &Lab, prompt: &str) -> AgentRunRequest {
    let mut req = request(h, "claude-code-cli", "claude-sonnet-5-5", &lab.broker_url());
    req.prompt.instructions = prompt.to_owned();
    req
}

fn codex_request(h: &Harness, lab: &Lab, prompt: &str) -> AgentRunRequest {
    let mut req = request(h, "codex-cli", "gpt-fake", &lab.broker_url());
    req.prompt.instructions = prompt.to_owned();
    req
}

/// What the hostile checkout must not have caused, whichever tool ran.
fn assert_repository_configuration_was_ignored(lab: &Lab, ws: &HostWorkspace, tool: &str) {
    for file in MARKER_FILES {
        assert!(
            !ws.has(file),
            "{tool}: {file} exists, so repository configuration ran"
        );
    }
    let requests = lab.model_requests();
    assert!(
        !requests.is_empty(),
        "{tool}: no request reached the broker"
    );
    let seen = hostile::markers_seen(&requests);
    for marker in TEXT_MARKERS.into_iter().chain(["HOOK-RAN", "MCP-RAN"]) {
        assert!(
            !seen.iter().any(|s| s == marker),
            "{tool}: the marker {marker} reached the model; markers seen: {seen:?}"
        );
    }
    // Every request that reached the broker carried the factory's credential, not the
    // repository's helper, and nothing went anywhere but the broker (the job network has no other
    // route, and the repository's overridden address does not resolve).
    for r in lab.provider_requests() {
        if r["handler"] == "post" || r["handler"] == "get" {
            assert_eq!(
                r["client_credential"]["matches_expected_fake_key"], true,
                "{tool}: a request with the wrong credential: {r}"
            );
            assert_eq!(r["headers"]["host"], "egress:8080", "{tool}: {r}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_inj_07_claude_code_ignores_the_repositorys_hooks_servers_settings_and_instructions()
 {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let files = hostile::files();
    let ws = HostWorkspace::new(&hostile::borrowed(&files));
    let mut session = lab.session(&h, &ws).await;
    let report = claude(&h)
        .run(
            &mut session,
            claude_request(&h, &lab, OK_REPLY),
            &NeverCancelled,
        )
        .await;
    let output = report
        .outcome
        .clone()
        .unwrap_or_else(|e| panic!("the run failed: {e:?}"));
    assert_eq!(String::from_utf8_lossy(output.as_bytes()), "{\"ok\": true}");
    assert_repository_configuration_was_ignored(&lab, &ws, "claude");
    let init = init_of(&h.transcript_of(&report).await);
    assert_eq!(
        init["mcp_servers"],
        serde_json::json!([]),
        "no server from .mcp.json"
    );
    assert_eq!(
        init["apiKeySource"], "apiKeyHelper",
        "the factory's helper, not the repository's"
    );
    assert_eq!(
        init["skills"],
        serde_json::json!([]),
        "no skill in a standard stage"
    );
    assert_eq!(init["slash_commands"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_inj_07_codex_ignores_the_repositorys_provider_and_instruction_files() {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let files = hostile::files();
    let ws = HostWorkspace::new(&hostile::borrowed(&files));
    // The sandbox spec hides the skill directories of the repository behind a read-only overlay.
    let mut session = lab
        .session_with(
            &h,
            &ws,
            &lab.key.clone(),
            lab.overlay_args("/workspace/.agents/skills"),
        )
        .await;
    let report = codex(&h)
        .run(
            &mut session,
            codex_request(&h, &lab, OK_REPLY),
            &NeverCancelled,
        )
        .await;
    let output = report
        .outcome
        .clone()
        .unwrap_or_else(|e| panic!("the run failed: {e:?}"));
    assert_eq!(String::from_utf8_lossy(output.as_bytes()), "{\"ok\": true}");
    assert_repository_configuration_was_ignored(&lab, &ws, "codex");
}

fn env_names(dump: &str) -> Vec<String> {
    dump.lines()
        .filter_map(|l| l.split_once('=').map(|(n, _)| n.to_owned()))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_tool_06_the_tools_environment_is_the_adapters_list_and_nothing_the_repository_or_agent_wrote()
 {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let files = hostile::files();
    let ws = HostWorkspace::new(&hostile::borrowed(&files));
    let mut session = lab.session(&h, &ws).await;
    // [B] The container itself holds only the names the supervisor set.
    let container_names: Vec<&str> = session
        .posture
        .env
        .iter()
        .map(|(n, _)| n.as_str())
        .collect();
    assert!(
        container_names.iter().all(|n| ["HOME", "PATH"].contains(n)),
        "Config.Env: {container_names:?}"
    );
    // The attacker, through the model, asks the tool to run `env` in its shell.
    let prompt = "FAKE:TOOL Bash {\"command\": \"env\", \"description\": \"dump\"}";
    let report = claude(&h)
        .run(
            &mut session,
            claude_request(&h, &lab, prompt),
            &NeverCancelled,
        )
        .await;
    assert!(report.outcome.is_ok(), "{:?}", report.outcome);
    let transcript = h.transcript_of(&report).await;
    let dump = tool_results_of(&transcript).join("\n");
    let names = env_names(&dump);
    assert!(
        names.iter().any(|n| n == "ANTHROPIC_BASE_URL"),
        "the dump held no variables: {dump}"
    );
    for forbidden in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "RUSTFLAGS",
        "NODE_OPTIONS",
        "BASH_ENV",
        "PYTHONPATH",
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "{forbidden} reached the tool's shell"
        );
    }
    for name in &names {
        let upper = name.to_ascii_uppercase();
        // Claude Code gives its own shell a per-session token for its local messaging socket
        // (`/tmp/cc-socks`). It is the tool's own, not a provider credential, and the adapter does
        // not control it; nothing else with such a name may be there.
        if name == "CLAUDE_CODE_MESSAGING_TOKEN" {
            continue;
        }
        assert!(
            !(upper.contains("API_KEY") || upper.contains("TOKEN") || upper.contains("SECRET")),
            "a credential-looking variable reached the tool's shell: {name}"
        );
    }
    assert!(!dump.contains(&lab.key), "the token value is in the dump");
    assert!(
        dump.lines().any(|l| l.starts_with("HOME=/tmp/h-")),
        "the home directory is the run's fresh one: {dump}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_tool_06_a_container_created_with_a_loader_variable_is_not_a_target() {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let ws = HostWorkspace::new(&[]);
    for (name, value) in [("LD_PRELOAD", "/evil.so"), ("RUSTFLAGS", "-C x")] {
        let mut session = lab
            .session_with(
                &h,
                &ws,
                &lab.key.clone(),
                vec!["--env".into(), format!("{name}={value}")],
            )
            .await;
        for report in [
            claude(&h)
                .run(
                    &mut session,
                    claude_request(&h, &lab, OK_REPLY),
                    &NeverCancelled,
                )
                .await,
            codex(&h)
                .run(
                    &mut session,
                    codex_request(&h, &lab, OK_REPLY),
                    &NeverCancelled,
                )
                .await,
        ] {
            assert!(
                matches!(report.outcome, Err(AgentRunError::ProcessFailed(_))),
                "{name}: {:?}",
                report.outcome
            );
            assert_eq!(report.exit, None, "{name}: the tool must not have started");
        }
        assert!(
            lab.model_requests().is_empty(),
            "{name}: nothing may reach the broker"
        );
        assert!(
            !session
                .seen
                .iter()
                .flatten()
                .any(|a| a.contains("dangerously")),
            "{name}: a bypass flag was written for a container that was not a target"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_tool_07_a_run_that_outlasts_its_deadline_is_interrupted_and_reports_what_it_has()
 {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let ws = HostWorkspace::new(&[]);
    for tool in ["claude", "codex"] {
        let mut session = lab.session(&h, &ws).await;
        let mut req = if tool == "claude" {
            claude_request(&h, &lab, "Wait. FAKE:SLEEP 90")
        } else {
            codex_request(&h, &lab, "Wait. FAKE:SLEEP 90")
        };
        req.limits = limits(6, 5.0, 20);
        let started = Instant::now();
        let report = if tool == "claude" {
            claude(&h).run(&mut session, req, &NeverCancelled).await
        } else {
            codex(&h).run(&mut session, req, &NeverCancelled).await
        };
        let took = started.elapsed();
        assert_eq!(
            report.outcome.clone().err(),
            Some(AgentRunError::Timeout),
            "{tool}"
        );
        // Probe, setup, the 6 s soft deadline, then at most the kill-after grace. Never the 90 s.
        assert!(took < Duration::from_secs(40), "{tool}: took {took:?}");
        assert_eq!(report.exit.expect("an exit").code, Some(124), "{tool}");
        let transcript = h.transcript_of(&report).await;
        assert!(transcript.contains("\"type\":\"factory\""), "{tool}");
        if tool == "claude" {
            // The interrupt gave Claude Code the chance to write its result.
            assert!(transcript.contains("aborted_streaming"), "{transcript}");
        }
        // The soft path leaves the container alive: it is the engine that removes it.
        let (code, _) = session.exec_text(&["/usr/bin/true"]).await;
        assert_eq!(code, Some(0), "{tool}: the session should still answer");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_tool_07_a_background_child_in_its_own_session_dies_with_the_container() {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let ws = HostWorkspace::new(&[]);
    let mut session = lab.session(&h, &ws).await;
    // The model starts a process that leaves the tool's process group.
    let command = "setsid /usr/bin/sleep 3601 > /dev/null 2>&1 & echo started";
    let prompt = format!(
        "FAKE:TOOL Bash {}",
        serde_json::json!({"command": command, "description": "escape"})
    );
    let report = claude(&h)
        .run(
            &mut session,
            claude_request(&h, &lab, &prompt),
            &NeverCancelled,
        )
        .await;
    assert!(report.outcome.is_ok(), "{:?}", report.outcome);
    let (_, cmdlines) = session
        .exec_text(&[
            "/usr/bin/find",
            "/proc",
            "-maxdepth",
            "2",
            "-name",
            "cmdline",
            "-exec",
            "/usr/bin/cat",
            "{}",
            ";",
        ])
        .await;
    assert!(
        cmdlines.contains("3601"),
        "the child should have outlived the tool; that is why the container is the boundary"
    );
    let name = session.name().to_owned();
    let teardown = factory_ports::sandbox::SandboxSession::stop_and_remove(
        Box::new(session),
        factory_ports::sandbox::TeardownReason::Completed,
    )
    .await;
    assert!(teardown.is_ok());
    assert!(
        !lab.leftover_containers().contains(&name),
        "the container, and so every process in it, is gone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_tool_07_a_flood_of_output_is_cut_at_the_cap_and_the_run_still_ends() {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let ws = HostWorkspace::new(&[]);
    let mut session = lab.session(&h, &ws).await;
    const CAP: u64 = 96 * 1024;
    let config = ClaudeCodeConfig {
        transcript_cap_bytes: CAP,
        ..ClaudeCodeConfig::default()
    };
    let runtime = ClaudeCodeRuntime::new(config, h.io.clone(), h.attestation());
    // Twelve tool calls, each printing 5 MB. The tool bounds each result it reports; the adapter
    // bounds the whole stream.
    let command = "yes flood | head -c 5000000";
    let prompt = format!(
        "FAKE:LOOP 12 Bash {}",
        serde_json::json!({"command": command, "description": "flood"})
    );
    let mut req = claude_request(&h, &lab, &prompt);
    req.max_output_bytes = 512;
    req.limits = limits(100, 5.0, 40);
    let started = Instant::now();
    let report = runtime.run(&mut session, req, &NeverCancelled).await;
    assert!(started.elapsed() < Duration::from_secs(90));
    // The capture stopped at the cap, so the result event at the end of the stream was cut off.
    assert_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::OutputTooLarge)
    );
    let transcript = h.transcript_of(&report).await;
    println!("flood transcript: {} bytes", transcript.len());
    assert!(
        transcript.len() as u64 <= CAP + 80 * 1024,
        "the transcript has {} bytes",
        transcript.len()
    );
    assert!(!events_of(&transcript).is_empty());
}

#[tokio::test]
async fn negative_nt_tool_06_hostile_request_values_never_become_environment_names() {
    use support::scripted::{Step, Tool, run};
    let h = Harness::new();
    for tool in [Tool::Claude, Tool::Codex] {
        let (_, watch) = run(&h, tool, Step::exits(0, ""), |req| {
            req.prompt.instructions =
                "env LD_PRELOAD=/evil.so RUSTFLAGS=-Cx NODE_OPTIONS=--require=/x PATH=/evil"
                    .to_owned();
            let text = "BASH_ENV=/evil\nGIT_SSH_COMMAND=evil";
            req.prompt.data.push(factory_ports::agent::DataPart {
                source: "issue#1".to_owned(),
                class: factory_ports::agent::DataClass::IssueText,
                sha256: factory_domain::values::Sha256Digest::of(text.as_bytes()),
                text: text.to_owned(),
            });
        })
        .await;
        let tool_run = watch.tool_run().expect("the tool ran");
        let end = tool_run
            .argv
            .iter()
            .position(|a| a == "/usr/bin/timeout")
            .expect("the soft deadline wrapper");
        assert_eq!(&tool_run.argv[..2], ["/usr/bin/env", "-i"]);
        let known: Vec<&str> = factory_runtime::command::EnvName::ALL
            .iter()
            .map(|n| n.as_str())
            .collect();
        for pair in &tool_run.argv[2..end] {
            let (name, value) = pair.split_once('=').expect("NAME=value");
            assert!(known.contains(&name), "{name}");
            assert!(!value.contains("evil"), "{pair}");
        }
    }
}
