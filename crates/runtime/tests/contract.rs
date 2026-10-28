//! The shared `AgentRuntime` contract suite (testkit `contracts::agent`) against each adapter,
//! running the REAL agent image in a real hardened container with the spike's fake provider as the
//! model behind the job network. The subject arranges what the provider does; the tool and the
//! adapter are real.
//!
//! Some checks name exact values that a real tool cannot be made to produce: an exact cost and
//! request count, the wording of a denial, a rate-limit wait of 30 seconds, an exit code of 2. The
//! subject answers `false` for those, the suite records a skip with the reason, and a test of the
//! adapter's own covers the same ground: `output_parsing` (usage, denials), `failure_mapping`
//! (every closed variant), `failure_report` (usage and transcript of a failed run). The lists of
//! passed and skipped checks are pinned below, so a new skip or a lost pass fails the test.

mod support;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, Capability, FlagSet, ProbeError,
    RuntimeCapabilities, RuntimeId, Usage,
};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::SandboxSession;
use factory_runtime::future::BoxFuture;
use factory_runtime::{ClaudeCodeConfig, ClaudeCodeRuntime, CodexConfig, CodexRuntime};
use factory_testkit::contracts::agent::{self, AgentRuntimeSubject, Behavior};
use serde_json::json;
use support::docker::{HostWorkspace, Lab};
use support::{Harness, limits, request};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Claude,
    Codex,
}

/// Delegates to the plain adapter, or to an adapter whose tool is a wrapper that hides one flag
/// from `--help`. The wrapper is how this subject removes a capability from a real tool.
struct Switch {
    plain: Box<dyn AgentRuntime>,
    filtered: Box<dyn AgentRuntime>,
    use_filtered: AtomicBool,
}

impl Switch {
    fn current(&self) -> &dyn AgentRuntime {
        if self.use_filtered.load(Ordering::SeqCst) {
            self.filtered.as_ref()
        } else {
            self.plain.as_ref()
        }
    }
}

impl AgentRuntime for Switch {
    fn id(&self) -> &RuntimeId {
        self.plain.id()
    }

    fn fidelity(&self) -> Fidelity {
        self.plain.fidelity()
    }

    fn probe<'life0, 'life1, 'async_trait>(
        &'life0 self,
        session: &'life1 mut dyn SandboxSession,
    ) -> BoxFuture<'async_trait, Result<RuntimeCapabilities, ProbeError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.current().probe(session).await })
    }

    fn run<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        session: &'life1 mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &'life2 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, AgentRunReport>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.current().run(session, req, cancel).await })
    }
}

/// The wrapper script: the real tool, with one flag renamed in its help text.
fn filter_script(real: &str, flag: &str) -> String {
    format!(
        "#!/bin/bash\nfor a in \"$@\"; do\n  if [ \"$a\" = \"--help\" ]; then\n    {real} \"$@\" | sed 's/{flag}/--hidden-by-the-subject/g'\n    exit 0\n  fi\ndone\nexec {real} \"$@\"\n"
    )
}

struct RealSubject {
    which: Which,
    lab: Lab,
    h: Harness,
    ws: HostWorkspace,
    runtime: Switch,
    cleared: Mutex<()>,
}

impl RealSubject {
    fn new(which: Which) -> Self {
        let lab = Lab::start();
        let h = Harness::new();
        h.register_secret("job-token", &lab.key);
        let (real, flag, file) = match which {
            Which::Claude => (
                "/usr/local/bin/claude",
                "--setting-sources",
                "claude-filter.sh",
            ),
            Which::Codex => ("/opt/codex/bin/codex", "--disable", "codex-filter.sh"),
        };
        let ws = HostWorkspace::new(&[(file, &filter_script(real, flag))]);
        ws.make_executable(file);
        let wrapper = format!("/workspace/{file}");
        let runtime = match which {
            Which::Claude => Switch {
                plain: Box::new(ClaudeCodeRuntime::new(
                    ClaudeCodeConfig::default(),
                    h.io.clone(),
                )),
                filtered: Box::new(ClaudeCodeRuntime::new(
                    ClaudeCodeConfig {
                        binary: wrapper,
                        ..ClaudeCodeConfig::default()
                    },
                    h.io.clone(),
                )),
                use_filtered: AtomicBool::new(false),
            },
            Which::Codex => Switch {
                plain: Box::new(CodexRuntime::new(CodexConfig::default(), h.io.clone())),
                filtered: Box::new(CodexRuntime::new(
                    CodexConfig {
                        binary: wrapper,
                        ..CodexConfig::default()
                    },
                    h.io.clone(),
                )),
                use_filtered: AtomicBool::new(false),
            },
        };
        Self {
            which,
            lab,
            h,
            ws,
            runtime,
            cleared: Mutex::new(()),
        }
    }
}

#[async_trait]
impl AgentRuntimeSubject for RealSubject {
    fn runtime(&self) -> &dyn AgentRuntime {
        &self.runtime
    }

    async fn transcript_is_stored(&self, reference: &ArtifactRef) -> Result<bool, String> {
        self.h
            .store
            .exists(&self.h.scope, reference)
            .await
            .map_err(|e| format!("look for the transcript: {e:?}"))
    }

    async fn session(&self) -> Result<Box<dyn SandboxSession>, String> {
        Ok(Box::new(self.lab.session(&self.h, &self.ws).await))
    }

    fn request(&self) -> AgentRunRequest {
        let (runtime, model) = match self.which {
            Which::Claude => ("claude-code-cli", "claude-sonnet-5-5"),
            Which::Codex => ("codex-cli", "gpt-fake"),
        };
        let mut req = request(&self.h, runtime, model, &self.lab.broker_url());
        // Short enough that a run which sleeps is interrupted soon; long enough for a normal turn.
        req.limits = limits(8, 5.0, 20);
        req.flag_set = FlagSet::Standard;
        req
    }

    async fn arrange(&self, behavior: Behavior) -> bool {
        let _guard = self.cleared.lock().expect("lock");
        let script = match behavior {
            Behavior::Finish { output, usage } if usage == Usage::default() => {
                json!({ "output": output })
            }
            // Only Claude Code reports a cost, and only from its own price list: a count of
            // tokens large enough to cost more than the limit is the one cost it can be given.
            Behavior::Finish { usage, .. }
                if self.which == Which::Claude
                    && usage.cost.0 > 0
                    && usage.input_tokens == 0
                    && usage.output_tokens == 0
                    && usage.requests == 0 =>
            {
                json!({ "output": {}, "usage": [usage.cost.0.saturating_mul(2), 10] })
            }
            Behavior::Fail { error, usage } if usage == Usage::default() => match error {
                AgentRunError::ProviderUnavailable => json!({ "http": 500 }),
                AgentRunError::RateLimited { retry_after: None } => json!({ "http": 429 }),
                AgentRunError::AuthenticationRequired => json!({ "http": 401 }),
                AgentRunError::Timeout => json!({ "sleep": 60 }),
                // The tools do not report how long a provider asked a caller to wait.
                _ => return false,
            },
            Behavior::RunUntilCancelled => json!({ "sleep": 120 }),
            _ => return false,
        };
        self.lab.script(&script);
        true
    }

    async fn remove_capability(&self, capability: Capability) -> bool {
        if capability != Capability::SkillInvocation {
            return false;
        }
        self.runtime.use_filtered.store(true, Ordering::SeqCst);
        true
    }
}

const CLAIMS: &[&str] = &[
    "a_run_reports_what_it_used",
    "denied_tool_calls_are_reported",
    "every_failure_keeps_its_own_closed_variant",
    "a_failed_run_still_reports_usage_and_transcript",
];

fn skipped_names(report: &factory_testkit::contracts::Report) -> Vec<&'static str> {
    report.skipped.iter().map(|(name, _)| *name).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn contract_claude_code_passes_the_agent_runtime_contract() {
    let report = agent::run(|| async { RealSubject::new(Which::Claude) }).await;
    println!("claude-code-cli passed: {:?}", report.passed);
    println!("claude-code-cli skipped: {:?}", report.skipped);
    report.assert_ok();
    let mut skipped = skipped_names(&report);
    skipped.sort_unstable();
    let mut expected = CLAIMS.to_vec();
    expected.sort_unstable();
    assert_eq!(skipped, expected, "the skipped checks changed");
    assert_eq!(report.passed.len(), agent::checks().len() - CLAIMS.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn contract_codex_passes_the_agent_runtime_contract() {
    let report = agent::run(|| async { RealSubject::new(Which::Codex) }).await;
    println!("codex-cli passed: {:?}", report.passed);
    println!("codex-cli skipped: {:?}", report.skipped);
    report.assert_ok();
    // Codex reports no cost, so the cost limit check cannot be arranged either.
    let mut expected = CLAIMS.to_vec();
    expected.push("a_run_over_its_cost_limit_is_refused");
    expected.sort_unstable();
    let mut skipped = skipped_names(&report);
    skipped.sort_unstable();
    assert_eq!(skipped, expected, "the skipped checks changed");
    assert_eq!(report.passed.len(), agent::checks().len() - expected.len());
}
