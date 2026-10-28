//! A scripted stand-in for the sandbox session, **labelled fake**.
//!
//! It plays the part of the processes the adapter starts: it answers `--version`, `--help`,
//! `features list`, the preparation commands and the skill listing from recorded text, and answers
//! the tool command itself with whatever the test scripted. Nothing runs. It records every command
//! it was given, so a test can read the argument vector and the standard input back.
//!
//! The session behaves as the real one does after a timeout or a cancel: the whole session ends
//! and every later call reports why.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::{MediaType, Timestamp};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{
    ExecRequest, ExecResult, Hardening, NetworkAttachment, PostureReport, SandboxError, SandboxId,
    SandboxLimits, SandboxSession, TeardownReason, TeardownReport,
};

use super::{Harness, agent_image, recorded};

/// Which tool the scripted session pretends to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Claude,
    Codex,
}

/// What the tool command does.
#[derive(Debug, Clone)]
pub enum Step {
    /// It prints this and exits.
    Output {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_code: Option<i32>,
        signal: Option<i32>,
        truncated: bool,
    },
    /// It runs past the exec timeout; the sandbox kills the container. The output is partial.
    TimedOut { stdout: Vec<u8> },
    /// The caller cancelled; the sandbox stopped the command and reports nothing else.
    Cancelled,
    /// The sandbox itself failed.
    Failed(SandboxError),
}

impl Step {
    /// A command that printed `stdout` and exited with `exit_code`.
    pub fn exits(exit_code: i32, stdout: &str) -> Self {
        Self::Output {
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_code: Some(exit_code),
            signal: None,
            truncated: false,
        }
    }
}

/// One command the session was given.
#[derive(Debug, Clone)]
pub struct Seen {
    pub argv: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    pub max_output_bytes: u64,
}

impl Seen {
    /// True for the command that is the tool run itself: it carries the soft deadline wrapper.
    pub fn is_tool_run(&self) -> bool {
        self.argv.iter().any(|a| a == "/usr/bin/timeout")
    }
}

#[derive(Default)]
struct State {
    seen: Vec<Seen>,
    main: Option<Step>,
    dead: Option<SandboxError>,
}

/// The scripted session.
pub struct ScriptedSession {
    id: SandboxId,
    posture: PostureReport,
    tool: Tool,
    store: Arc<dyn ArtifactStore>,
    state: Arc<Mutex<State>>,
    version_text: String,
    help_text: String,
    features_text: String,
    skill_listing: String,
    max_turns_known: bool,
    binary_missing: bool,
    pub preparation_exit: i32,
}

/// A handle to read what the session saw after the session moved into the adapter.
#[derive(Clone)]
pub struct Watch(Arc<Mutex<State>>);

impl Watch {
    pub fn seen(&self) -> Vec<Seen> {
        self.0.lock().expect("lock").seen.clone()
    }

    /// The command that ran the tool, when there was one.
    pub fn tool_run(&self) -> Option<Seen> {
        self.seen().into_iter().find(Seen::is_tool_run)
    }
}

/// A posture that passes the verified-target check, with the changes a test wants.
pub fn posture(edit: impl FnOnce(&mut PostureReport)) -> PostureReport {
    let mut report = PostureReport {
        observed: Hardening::strict(10_001, 10_001),
        image: agent_image(),
        limits: SandboxLimits {
            cpu_millis: std::num::NonZeroU32::new(2000).expect("non-zero"),
            memory_mb: std::num::NonZeroU32::new(2048).expect("non-zero"),
            memory_swap_mb: std::num::NonZeroU32::new(2048).expect("non-zero"),
            pids: std::num::NonZeroU32::new(256).expect("non-zero"),
            nofile: std::num::NonZeroU32::new(1024).expect("non-zero"),
            max_file_mb: std::num::NonZeroU32::new(64).expect("non-zero"),
            tmpfs_mb: std::num::NonZeroU32::new(512).expect("non-zero"),
            workspace_disk_mb: std::num::NonZeroU32::new(512).expect("non-zero"),
            wall_clock: Duration::from_secs(600),
        },
        network: NetworkAttachment::JobInternal {
            sidecar: "egress".to_owned(),
        },
        mounts: Vec::new(),
        env: vec![("HOME".to_owned(), "/tmp".to_owned())],
        self_check_passed: true,
        verified_at: Timestamp::parse("2026-10-27T10:00:00Z").expect("a time"),
    };
    edit(&mut report);
    report
}

impl ScriptedSession {
    pub fn new(h: &Harness, tool: Tool, main: Step) -> Self {
        let (version_text, help_text) = match tool {
            Tool::Claude => (recorded::CLAUDE_VERSION, recorded::CLAUDE_HELP),
            Tool::Codex => (recorded::CODEX_VERSION, recorded::CODEX_EXEC_HELP),
        };
        Self {
            id: SandboxId::new("scripted-fake".to_owned()),
            posture: posture(|_| {}),
            tool,
            store: h.store.clone(),
            state: Arc::new(Mutex::new(State {
                main: Some(main),
                ..State::default()
            })),
            version_text: version_text.to_owned(),
            help_text: help_text.to_owned(),
            features_text: recorded::CODEX_FEATURES.to_owned(),
            skill_listing: String::new(),
            max_turns_known: true,
            binary_missing: false,
            preparation_exit: 0,
        }
    }

    /// The tool does not know the hidden `--max-turns` option.
    pub fn without_max_turns(mut self) -> Self {
        self.max_turns_known = false;
        self
    }

    /// The tool is not in the image: every command that names it exits 127.
    pub fn without_binary(mut self) -> Self {
        self.binary_missing = true;
        self
    }

    pub fn watch(&self) -> Watch {
        Watch(self.state.clone())
    }

    /// The tool reports another version.
    pub fn with_version(mut self, text: &str) -> Self {
        self.version_text = text.to_owned();
        self
    }

    /// The help text no longer names `flag` (every occurrence is rewritten).
    pub fn without_flag(mut self, flag: &str) -> Self {
        self.help_text = self.help_text.replace(flag, "--removed-by-the-test");
        self
    }

    /// `features list` no longer names `feature`.
    pub fn without_feature(mut self, feature: &str) -> Self {
        self.features_text = self
            .features_text
            .lines()
            .filter(|l| l.split_whitespace().next() != Some(feature))
            .collect::<Vec<_>>()
            .join("\n");
        self
    }

    /// The skills the tool lists in `debug prompt-input`.
    pub fn with_visible_skills(mut self, names: &[&str]) -> Self {
        let items: String = names
            .iter()
            .map(|n| format!("- {n}: a skill (file: r0/{n}/SKILL.md)\\n"))
            .collect();
        self.skill_listing = format!(
            "{{\"text\":\"<skills_instructions>\\n### Available skills\\n{items}</skills_instructions>\"}}"
        );
        self
    }

    pub fn with_posture(mut self, posture: PostureReport) -> Self {
        self.posture = posture;
        self
    }

    async fn output(
        &self,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: Option<i32>,
        signal: Option<i32>,
        timed_out: bool,
        truncated: bool,
    ) -> ExecResult {
        let media = MediaType::parse("text/plain").expect("a media type");
        let stdout = self
            .store
            .put(stdout.to_vec(), media.clone())
            .await
            .expect("stored");
        let stderr = self
            .store
            .put(stderr.to_vec(), media)
            .await
            .expect("stored");
        let now = Timestamp::parse("2026-10-27T10:00:00Z").expect("a time");
        ExecResult {
            exit_code,
            signal,
            timed_out,
            oom_killed: false,
            stdout,
            stderr,
            stdout_truncated: truncated,
            stderr_truncated: false,
            started_at: now,
            finished_at: now,
        }
    }

    /// The scripted answer for a command that is not the tool run.
    fn answer_short(&self, argv: &[String]) -> (String, String, i32) {
        let has = |word: &str| argv.iter().any(|a| a == word);
        let ok = |text: &str| (text.to_owned(), String::new(), 0);
        if self.binary_missing {
            (
                String::new(),
                "exec: no such file or directory\n".to_owned(),
                127,
            )
        } else if has("--version") {
            (self.version_text.clone(), self.version_banner(), 0)
        } else if has("--help") {
            ok(&self.help_text)
        } else if has("features") && has("list") {
            ok(&self.features_text)
        } else if has("prompt-input") {
            ok(&self.skill_listing)
        } else if argv.iter().any(|a| a == "--max-turns=notanumber") {
            let said = if self.max_turns_known {
                "error: option '--max-turns <turns>' argument 'notanumber' is invalid. must be a number\n"
            } else {
                "error: unknown option '--max-turns=notanumber'\n"
            };
            (String::new(), said.to_owned(), 1)
        } else {
            (String::new(), String::new(), self.preparation_exit)
        }
    }

    fn version_banner(&self) -> String {
        match self.tool {
            Tool::Claude => String::new(),
            Tool::Codex => {
                "WARNING: proceeding, even though we could not create PATH aliases\n".to_owned()
            }
        }
    }
}

#[async_trait]
impl SandboxSession for ScriptedSession {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn posture(&self) -> &PostureReport {
        &self.posture
    }

    async fn exec(
        &mut self,
        req: ExecRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<ExecResult, SandboxError> {
        let argv = req.argv.as_slice().to_vec();
        let seen = Seen {
            argv: argv.clone(),
            stdin: req.stdin.clone(),
            timeout: req.timeout,
            max_output_bytes: req.max_output_bytes,
        };
        let is_tool_run = seen.is_tool_run();
        let main = {
            let mut state = self.state.lock().expect("lock");
            state.seen.push(seen);
            if let Some(dead) = &state.dead {
                return Err(dead.clone());
            }
            if cancel.is_cancelled() {
                return Err(SandboxError::Cancelled);
            }
            if is_tool_run {
                state.main.clone()
            } else {
                None
            }
        };
        if !is_tool_run {
            let (stdout, stderr, code) = self.answer_short(&argv);
            return Ok(self
                .output(
                    stdout.as_bytes(),
                    stderr.as_bytes(),
                    Some(code),
                    None,
                    false,
                    false,
                )
                .await);
        }
        match main.unwrap_or(Step::exits(0, "")) {
            Step::Output {
                stdout,
                stderr,
                exit_code,
                signal,
                truncated,
            } => Ok(self
                .output(&stdout, &stderr, exit_code, signal, false, truncated)
                .await),
            Step::TimedOut { stdout } => {
                self.state.lock().expect("lock").dead = Some(SandboxError::Timeout);
                Ok(self.output(&stdout, b"", None, Some(9), true, false).await)
            }
            Step::Cancelled => {
                self.state.lock().expect("lock").dead = Some(SandboxError::Cancelled);
                Err(SandboxError::Cancelled)
            }
            Step::Failed(error) => Err(error),
        }
    }

    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        Ok(TeardownReport {
            sandbox: self.id.clone(),
            reason,
            oom_killed: false,
        })
    }
}

/// Runs one request against the real adapter for `tool` on a scripted session whose tool command
/// does `main`. Returns the report and a watch on what the session saw.
pub async fn run(
    h: &Harness,
    tool: Tool,
    main: Step,
    edit: impl FnOnce(&mut factory_ports::agent::AgentRunRequest),
) -> (factory_ports::agent::AgentRunReport, Watch) {
    use factory_ports::agent::AgentRuntime;
    let mut session = ScriptedSession::new(h, tool, main);
    let watch = session.watch();
    let (runtime, name): (Box<dyn AgentRuntime>, &str) = match tool {
        Tool::Claude => (
            Box::new(factory_runtime::ClaudeCodeRuntime::new(
                factory_runtime::ClaudeCodeConfig::default(),
                h.io.clone(),
            )),
            "claude-code-cli",
        ),
        Tool::Codex => (
            Box::new(factory_runtime::CodexRuntime::new(
                factory_runtime::CodexConfig::default(),
                h.io.clone(),
            )),
            "codex-cli",
        ),
    };
    let mut req = super::request(h, name, "some-model", "http://egress:8080");
    edit(&mut req);
    let report = runtime
        .run(&mut session, req, &factory_runtime::probe::NeverCancelled)
        .await;
    (report, watch)
}
