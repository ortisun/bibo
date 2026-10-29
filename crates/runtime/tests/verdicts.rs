//! One test for each verdict of the agent runtime spike that the adapters have to honor, against the
//! real tools in a real hardened container with the spike's fake provider as the model: skills only
//! in the specification stage and only the pinned ones, provider failures reported as errors,
//! cancellation and the deadline, the turn cap, the retry limits, the explicit model, and the
//! credential staying out of every environment, argument, log and transcript.
//!
//! Repository settings, hooks, servers and instruction files are NT-INJ-07 in `negative.rs`.

mod support;

use std::time::{Duration, Instant};

use factory_domain::values::Sha256Digest;
use factory_ports::agent::{AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, FlagSet};
use factory_runtime::probe::NeverCancelled;
use factory_runtime::{
    ClaudeCodeConfig, ClaudeCodeRuntime, CodexConfig, CodexRuntime, PinnedSkill, SkillBundle,
    SkillFile,
};
use factory_testkit::clock::FakeCancel;
use serde_json::json;
use support::docker::{HostWorkspace, Lab, RealSession};
use support::hostile::{self, TEXT_MARKERS};
use support::{Harness, init_of, limits, request, tool_results_of};

const NAMES: [&str; 4] = ["alpha-one", "beta-two", "gamma-three", "delta-four"];

fn skill_text(name: &str) -> String {
    let marker = match name {
        "alpha-one" => "ALPHA-SKILL-BODY-MARKER",
        "beta-two" => "BETA-SKILL-BODY-MARKER",
        _ => "OTHER-SKILL-BODY",
    };
    format!("---\nname: {name}\ndescription: A pinned skill.\n---\n{marker}\n")
}

fn bundle() -> SkillBundle {
    let skills = NAMES
        .iter()
        .map(|name| {
            let bytes = skill_text(name).into_bytes();
            let file = SkillFile {
                path: "SKILL.md".to_owned(),
                sha256: Sha256Digest::of(&bytes),
                bytes,
            };
            PinnedSkill::new(name, vec![file]).expect("a pinned skill")
        })
        .collect();
    SkillBundle::new(skills).expect("a bundle")
}

struct World {
    lab: Lab,
    h: Harness,
}

impl World {
    fn new() -> Self {
        let lab = Lab::start();
        let h = Harness::new();
        h.register_secret("job-token", &lab.key);
        Self { lab, h }
    }

    fn claude_request(&self, prompt: &str) -> AgentRunRequest {
        let mut req = request(
            &self.h,
            "claude-code-cli",
            "claude-sonnet-5-5",
            &self.lab.broker_url(),
        );
        req.prompt.instructions = prompt.to_owned();
        req
    }

    fn codex_request(&self, prompt: &str) -> AgentRunRequest {
        let mut req = request(&self.h, "codex-cli", "gpt-fake", &self.lab.broker_url());
        req.prompt.instructions = prompt.to_owned();
        req
    }

    fn claude(&self) -> ClaudeCodeRuntime {
        ClaudeCodeRuntime::new(
            ClaudeCodeConfig::default(),
            self.h.io.clone(),
            self.h.attestation(),
        )
    }

    fn codex(&self) -> CodexRuntime {
        CodexRuntime::new(
            CodexConfig::default(),
            self.h.io.clone(),
            self.h.attestation(),
        )
    }

    async fn session(&self, ws: &HostWorkspace) -> RealSession {
        self.lab.session(&self.h, ws).await
    }
}

fn seen_markers(lab: &Lab) -> Vec<String> {
    hostile::markers_seen(&lab.model_requests())
}

// ---------------------------------------------------------------------------------------------
// Skills

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_skills_claude_code_standard_stages_see_none() {
    let w = World::new();
    let files = hostile::files();
    let ws = HostWorkspace::new(&hostile::borrowed(&files));
    let mut session = w.session(&ws).await;
    // Even a runtime configured with the pinned skills shows none outside the specification stage.
    let runtime = ClaudeCodeRuntime::new(
        ClaudeCodeConfig {
            spec_skills: Some(bundle()),
            ..ClaudeCodeConfig::default()
        },
        w.h.io.clone(),
        w.h.attestation(),
    );
    let report = runtime
        .run(
            &mut session,
            w.claude_request("/alpha-one go"),
            &NeverCancelled,
        )
        .await;
    let init = init_of(&w.h.transcript_of(&report).await);
    assert_eq!(init["skills"], json!([]));
    assert_eq!(init["slash_commands"], json!([]));
    let seen = seen_markers(&w.lab);
    assert!(
        !seen.iter().any(|m| m == "ALPHA-SKILL-BODY-MARKER"),
        "{seen:?}"
    );
    assert!(
        !seen.iter().any(|m| m == "REPO-SKILL-BODY-MARKER"),
        "{seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_skills_claude_code_specification_stage_sees_exactly_the_pinned_four() {
    let w = World::new();
    let files = hostile::files();
    let ws = HostWorkspace::new(&hostile::borrowed(&files));
    let mut session = w.session(&ws).await;
    let runtime = ClaudeCodeRuntime::new(
        ClaudeCodeConfig {
            spec_skills: Some(bundle()),
            ..ClaudeCodeConfig::default()
        },
        w.h.io.clone(),
        w.h.attestation(),
    );
    let mut req = w.claude_request("/alpha-one build the thing");
    req.flag_set = FlagSet::Specification;
    let report = runtime.run(&mut session, req, &NeverCancelled).await;
    assert!(report.outcome.is_ok(), "{:?}", report.outcome);
    let init = init_of(&w.h.transcript_of(&report).await);
    let mut skills: Vec<String> = init["skills"]
        .as_array()
        .expect("skills")
        .iter()
        .filter_map(|s| s.as_str().map(str::to_owned))
        .collect();
    skills.sort();
    println!("skills visible in the specification stage: {skills:?}");
    println!("slash commands: {}", init["slash_commands"]);
    // With the tool's bundled skills switched off, Claude Code 2.1.311 still lists two of its own
    // (`doctor` and `plugin-authoring`; spike section 4.6, `claude-skills-no-bundled`). They are
    // part of the tool, not of the repository, and no skill of the repository is among them.
    let own: [&str; 2] = ["doctor", "plugin-authoring"];
    let mut want: Vec<String> = NAMES
        .iter()
        .chain(own.iter())
        .map(|n| (*n).to_owned())
        .collect();
    want.sort();
    assert_eq!(
        skills, want,
        "exactly the pinned four plus the two the tool cannot switch off"
    );
    let seen = seen_markers(&w.lab);
    assert!(
        seen.iter().any(|m| m == "ALPHA-SKILL-BODY-MARKER"),
        "the slash command should have expanded the pinned skill: {seen:?}"
    );
    assert!(
        !seen.iter().any(|m| m == "REPO-SKILL-BODY-MARKER"),
        "{seen:?}"
    );
    for marker in TEXT_MARKERS {
        assert!(!seen.iter().any(|m| m == marker), "{marker} in {seen:?}");
    }
    // The pinned tree is read-only for the tool's user and holds the pinned bytes.
    let (_, writable) = session
        .exec_text(&[
            "/usr/bin/find",
            "/tmp",
            "-path",
            "*/.claude/skills/*",
            "-perm",
            "-u+w",
        ])
        .await;
    assert_eq!(
        writable.trim(),
        "",
        "a skill file or directory is writable: {writable}"
    );
    let (_, listed) = session
        .exec_text(&[
            "/usr/bin/find",
            "/tmp",
            "-name",
            "SKILL.md",
            "-path",
            "*alpha-one*",
        ])
        .await;
    let path = listed
        .lines()
        .next()
        .expect("the installed skill")
        .to_owned();
    let (_, body) = session.exec_text(&["/usr/bin/cat", &path]).await;
    assert_eq!(body, skill_text("alpha-one"));
    // A skill of the repository does not resolve, even by name.
    let before = w.lab.model_requests().len();
    let mut req = w.claude_request("/repo-skill go");
    req.flag_set = FlagSet::Specification;
    let _ = runtime.run(&mut session, req, &NeverCancelled).await;
    let _ = before;
    assert!(
        !seen_markers(&w.lab)
            .iter()
            .any(|m| m == "REPO-SKILL-BODY-MARKER"),
        "the repository's skill reached the model"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_skills_claude_code_specification_stage_without_pinned_skills_does_not_start() {
    let w = World::new();
    let ws = HostWorkspace::new(&[]);
    let mut session = w.session(&ws).await;
    let mut req = w.claude_request("/alpha-one go");
    req.flag_set = FlagSet::Specification;
    let report = w.claude().run(&mut session, req, &NeverCancelled).await;
    assert_eq!(
        report.outcome.err(),
        Some(AgentRunError::CapabilityMissing(
            factory_ports::agent::Capability::SkillInvocation
        ))
    );
    assert!(w.lab.model_requests().is_empty());
}

fn codex_skill_files() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = NAMES
        .iter()
        .map(|n| (format!(".agents/skills/{n}/SKILL.md"), skill_text(n)))
        .collect();
    files.extend(
        hostile::files()
            .into_iter()
            .filter(|(p, _)| p.starts_with(".agents/")),
    );
    files
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_skills_codex_is_refused_unless_the_sandbox_shows_exactly_the_stage_skills() {
    let w = World::new();
    let files = codex_skill_files();
    let ws = HostWorkspace::new(&hostile::borrowed(&files));
    // Standard stage, the repository's skills visible: the adapter refuses to start.
    let mut open = w.session(&ws).await;
    let report = w
        .codex()
        .run(&mut open, w.codex_request("go"), &NeverCancelled)
        .await;
    assert_eq!(report.exit, None, "the tool must not start");
    assert!(report.outcome.is_err());
    assert!(w.lab.model_requests().is_empty());
    // Standard stage, the skill root hidden behind a read-only overlay: it runs.
    let mut hidden = w
        .lab
        .session_with(
            &w.h,
            &ws,
            &w.lab.key.clone(),
            w.lab.overlay_args("/workspace/.agents/skills"),
        )
        .await;
    let report = w
        .codex()
        .run(&mut hidden, w.codex_request("go"), &NeverCancelled)
        .await;
    assert!(report.outcome.is_ok(), "{:?}", report.outcome);

    // Specification stage: the four are visible and the fifth is hidden by an overlay.
    let runtime = CodexRuntime::new(
        CodexConfig {
            spec_skills: Some(NAMES.iter().map(|n| (*n).to_owned()).collect()),
            ..CodexConfig::default()
        },
        w.h.io.clone(),
        w.h.attestation(),
    );
    let mut req = w.codex_request("$alpha-one build the thing");
    req.flag_set = FlagSet::Specification;
    let mut with_fifth = w.session(&ws).await;
    let refused = runtime
        .run(&mut with_fifth, req.clone(), &NeverCancelled)
        .await;
    assert_eq!(
        refused.exit, None,
        "a fifth visible skill must stop the stage"
    );
    let mut spec = w
        .lab
        .session_with(
            &w.h,
            &ws,
            &w.lab.key.clone(),
            w.lab.overlay_args("/workspace/.agents/skills/repo-skill"),
        )
        .await;
    let report = runtime.run(&mut spec, req, &NeverCancelled).await;
    assert!(report.outcome.is_ok(), "{:?}", report.outcome);
    let seen = seen_markers(&w.lab);
    assert!(
        seen.iter().any(|m| m == "ALPHA-SKILL-BODY-MARKER"),
        "{seen:?}"
    );
    assert!(
        !seen.iter().any(|m| m == "REPO-SKILL-BODY-MARKER"),
        "{seen:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Provider failures

async fn claude_with_script(w: &World, script: serde_json::Value) -> AgentRunReport {
    let ws = HostWorkspace::new(&[]);
    let mut session = w.session(&ws).await;
    w.lab.script(&script);
    let report = w
        .claude()
        .run(&mut session, w.claude_request("go"), &NeverCancelled)
        .await;
    w.lab.clear_script();
    report
}

async fn codex_with_script(w: &World, script: serde_json::Value) -> AgentRunReport {
    let ws = HostWorkspace::new(&[]);
    let mut session = w.session(&ws).await;
    w.lab.script(&script);
    let report = w
        .codex()
        .run(&mut session, w.codex_request("go"), &NeverCancelled)
        .await;
    w.lab.clear_script();
    report
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_provider_failures_claude_code_reports_each_as_its_own_error() {
    let w = World::new();
    let cases = [
        (500, AgentRunError::ProviderUnavailable),
        (529, AgentRunError::ProviderUnavailable),
        (429, AgentRunError::RateLimited { retry_after: None }),
        (402, AgentRunError::BudgetRefused),
        (403, AgentRunError::AuthenticationRequired),
    ];
    for (status, want) in cases {
        let before = w.lab.model_requests().len();
        let report = claude_with_script(&w, json!({ "http": status })).await;
        assert_eq!(report.outcome.clone().err(), Some(want), "status {status}");
        assert!(report.transcript.is_some(), "status {status}");
        // The tool reported this as `subtype: "success"`. It is read as the failure it is.
        let transcript = w.h.transcript_of(&report).await;
        assert!(transcript.contains("\"is_error\":true"), "status {status}");
        // The retry limit holds. Measured with CLAUDE_CODE_MAX_RETRIES=2: an authentication
        // failure is tried in two rounds of a first try and two retries, so at most five requests.
        // Left at its default of ten the tool makes more than twenty.
        let made = w.lab.model_requests().len() - before;
        assert!(made <= 5, "status {status}: {made} requests");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_provider_failures_a_refused_credential_ends_claude_code_in_a_few_retries() {
    let w = World::new();
    let ws = HostWorkspace::new(&[]);
    let mut session = w
        .lab
        .session_with(&w.h, &ws, "a-token-the-broker-does-not-know", Vec::new())
        .await;
    let started = Instant::now();
    let report = w
        .claude()
        .run(&mut session, w.claude_request("go"), &NeverCancelled)
        .await;
    assert_eq!(
        report.outcome.err(),
        Some(AgentRunError::AuthenticationRequired)
    );
    // Claude Code retries a refused credential ten times by default, over well more than a minute.
    assert!(
        started.elapsed() < Duration::from_secs(45),
        "{:?}",
        started.elapsed()
    );
    assert!(w.lab.model_requests().len() <= 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_provider_failures_codex_reports_each_as_its_own_error_within_the_retry_limit() {
    let w = World::new();
    let cases = [
        (500, AgentRunError::ProviderUnavailable),
        (429, AgentRunError::RateLimited { retry_after: None }),
        (402, AgentRunError::BudgetRefused),
        (403, AgentRunError::AuthenticationRequired),
    ];
    for (status, want) in cases {
        let before = w.lab.model_requests().len();
        let report = codex_with_script(&w, json!({ "http": status })).await;
        assert_eq!(report.outcome.clone().err(), Some(want), "status {status}");
        assert!(report.transcript.is_some(), "status {status}");
        // The spike saw thirty requests for one failed turn against a 500. The limit makes it four.
        let made = w.lab.model_requests().len() - before;
        assert!(made <= 4, "status {status}: {made} requests");
    }
    let ws = HostWorkspace::new(&[]);
    let mut session = w
        .lab
        .session_with(&w.h, &ws, "a-token-the-broker-does-not-know", Vec::new())
        .await;
    let report = w
        .codex()
        .run(&mut session, w.codex_request("go"), &NeverCancelled)
        .await;
    assert_eq!(
        report.outcome.err(),
        Some(AgentRunError::AuthenticationRequired)
    );
}

// ---------------------------------------------------------------------------------------------
// Cancellation, turns and the model

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_cancel_during_the_tool_run_stops_it_and_ends_the_session() {
    let w = World::new();
    let ws = HostWorkspace::new(&[]);
    for tool in ["claude", "codex"] {
        let mut session = w.session(&ws).await;
        let cancel = FakeCancel::new();
        let (runtime, req): (Box<dyn AgentRuntime>, _) = if tool == "claude" {
            (
                Box::new(w.claude()),
                w.claude_request("Wait. FAKE:SLEEP 120"),
            )
        } else {
            (Box::new(w.codex()), w.codex_request("Wait. FAKE:SLEEP 120"))
        };
        let started = Instant::now();
        let run = runtime.run(&mut session, req, &cancel);
        let trigger = async {
            tokio::time::sleep(Duration::from_secs(7)).await;
            cancel.cancel();
        };
        let (report, ()) = tokio::join!(run, trigger);
        assert_eq!(
            report.outcome.clone().err(),
            Some(AgentRunError::Cancelled),
            "{tool}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(25),
            "{tool}: {:?}",
            started.elapsed()
        );
        assert!(
            report.transcript.is_some(),
            "{tool}: a cancelled run still stores a transcript"
        );
        // As with the real sandbox, the cancelled command ended the whole session.
        let dead = session.exec_text_result(&["/usr/bin/true"]).await;
        assert!(dead.is_err(), "{tool}: the session should be over");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_turn_cap_claude_code_stops_at_its_max_turns_and_codex_is_stopped_by_the_broker() {
    let w = World::new();
    let ws = HostWorkspace::new(&[]);
    let mut session = w.session(&ws).await;
    let mut req = w.claude_request("FAKE:LOOP 100 Read {\"file_path\": \"/workspace/README.md\"}");
    req.limits = limits(60, 5.0, 2);
    let report = w.claude().run(&mut session, req, &NeverCancelled).await;
    assert_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::BudgetRefused)
    );
    let made = w.lab.model_requests().len();
    // Two tool calls allowed means three turns, and so three requests.
    assert!((3..=4).contains(&made), "{made} requests");
    assert!(w.h.transcript_of(&report).await.contains("error_max_turns"));

    // Codex has no cap of its own. The fake broker cuts the token after fifteen tool results.
    let ws = HostWorkspace::new(&[]);
    let mut session = w.session(&ws).await;
    let before = w.lab.model_requests().len();
    let prompt = "FAKE:LOOP 15 exec text(JSON.stringify(await tools.exec_command({cmd: \"cat /workspace/README.md\"})))";
    let mut req = w.codex_request(prompt);
    req.limits = limits(90, 5.0, 2);
    let report = w.codex().run(&mut session, req, &NeverCancelled).await;
    let made = w.lab.model_requests().len() - before;
    assert!(
        made >= 15,
        "codex made {made} requests; a turn cap would have stopped it earlier"
    );
    assert_eq!(
        report.outcome.err(),
        Some(AgentRunError::AuthenticationRequired)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_model_both_tools_ask_for_the_model_the_request_names() {
    let w = World::new();
    let ws = HostWorkspace::new(&[]);
    let mut session = w.session(&ws).await;
    let _ = w
        .claude()
        .run(&mut session, w.claude_request("go"), &NeverCancelled)
        .await;
    let _ = w
        .codex()
        .run(&mut session, w.codex_request("go"), &NeverCancelled)
        .await;
    let models: Vec<String> = w
        .lab
        .model_requests()
        .iter()
        .filter_map(|r| r["body_summary"]["model"].as_str().map(str::to_owned))
        .collect();
    assert!(
        models.iter().any(|m| m == "claude-sonnet-5-5"),
        "{models:?}"
    );
    assert!(models.iter().any(|m| m == "gpt-fake"), "{models:?}");
    // The defaults of the tools are the most expensive models.
    assert!(
        !models
            .iter()
            .any(|m| m == "claude-opus-5-5" || m == "gpt-6.1-sol"),
        "{models:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The credential

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verdict_credential_never_reaches_an_environment_an_argument_a_log_or_a_transcript() {
    let w = World::new();
    let ws = HostWorkspace::new(&[]);
    let mut session = w.session(&ws).await;
    // The attacker, through the model, prints the environment and reads the token file.
    let prompt = format!(
        "FAKE:TOOL Bash {}",
        json!({"command": "env; echo TOKEN-FILE:; cat /run/factory/job-token", "description": "dump"})
    );
    let report = w
        .claude()
        .run(&mut session, w.claude_request(&prompt), &NeverCancelled)
        .await;
    assert!(report.outcome.is_ok(), "{:?}", report.outcome);
    let key = w.lab.key.clone();
    let transcript = w.h.transcript_of(&report).await;
    let results = tool_results_of(&transcript).join("\n");
    assert!(
        results.contains("TOKEN-FILE:"),
        "the command did not run: {results}"
    );
    assert!(
        results.contains("[REDACTED:job-token]"),
        "the token file is readable by design; its text must come back redacted: {results}"
    );
    assert!(!transcript.contains(&key), "the transcript holds the token");
    let codex_ws = HostWorkspace::new(&[]);
    let mut codex_session = w.session(&codex_ws).await;
    let codex_report = w
        .codex()
        .run(&mut codex_session, w.codex_request("go"), &NeverCancelled)
        .await;
    for (name, argv) in [("claude", &session.seen), ("codex", &codex_session.seen)] {
        assert!(
            !argv.iter().flatten().any(|a| a.contains(&key)),
            "{name}: the token is in an argument"
        );
    }
    for (name, sess) in [("claude", &session), ("codex", &codex_session)] {
        assert!(
            !sess.posture.env.iter().any(|(_, v)| v.contains(&key)),
            "{name}: Config.Env"
        );
    }
    let provider_log = format!("{:?}", w.lab.provider_requests());
    assert!(
        !provider_log.contains(&key),
        "the provider log holds the token"
    );
    assert!(
        !format!("{report:?}{codex_report:?}").contains(&key),
        "a report holds the token"
    );
    assert!(!w.h.transcript_of(&codex_report).await.contains(&key));
}
