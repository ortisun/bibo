//! A sandbox that starts no container and runs no process.
//!
//! It keeps the parts of the contract a caller can see: the spec is checked against the policy
//! with the same pure `SandboxSpec::validate` the real adapter uses, the posture of the "created
//! container" is compared with the spec, commands take an argument vector, run a small fixed set
//! of programs, honour a timeout, an output cap, the wall clock and a cancel signal, and store
//! their output in an artifact store.
//!
//! The programs are `echo`, `true`, `false`, `cat`, `sleep`, `head -c N /dev/zero` and `env`. Any
//! other program behaves like a missing binary: exit code 127 and a message on standard error.
//! A test that needs a different program adds it with [`FakeSandbox::with_program`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::AttemptId;
use factory_domain::values::MediaType;
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{CancelSignal, Clock, duration_between};
use factory_ports::sandbox::{
    ExecRequest, ExecResult, PostureReport, SandboxError, SandboxId, SandboxPolicy, SandboxProfile,
    SandboxProvider, SandboxSession, SandboxSpec, TeardownReason, TeardownReport,
};

use crate::clock::FakeClock;
use crate::contracts::sandbox::SandboxSubject;

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxDefect {
    /// A cancel signal is never looked at.
    IgnoresCancellation,
    /// A command's timeout is never enforced.
    IgnoresTimeout,
    /// The spec is not checked against the policy.
    AcceptsWeakSpec,
    /// A container whose posture differs from its spec is still returned.
    ReturnsSessionOnPostureMismatch,
    /// `sweep_orphans` removes nothing.
    LeavesOrphans,
    /// The sandbox's wall-clock limit is never enforced.
    NoWallClock,
    /// Output is stored whole, whatever the cap.
    UncappedOutput,
    /// Every command reports exit code 0.
    ReportsFailureAsSuccess,
}

/// What a fake program produced, before the caps are applied.
#[derive(Debug, Clone, Default)]
pub struct ProgramOutput {
    /// The exit code, when the program exits by itself.
    pub exit_code: Option<i32>,
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
}

/// A fake program: a function from the argument vector and standard input to its output.
pub type Program = Arc<dyn Fn(&[String], &[u8]) -> ProgramOutput + Send + Sync>;

struct LiveSandbox {
    attempt: AttemptId,
}

struct Inner {
    clock: Arc<FakeClock>,
    artifacts: Arc<dyn ArtifactStore>,
    policy: SandboxPolicy,
    defect: Option<SandboxDefect>,
    live: Mutex<BTreeMap<SandboxId, LiveSandbox>>,
    next: Mutex<u64>,
    drift_next: Mutex<bool>,
    programs: Mutex<BTreeMap<String, Program>>,
}

/// A sandbox provider that simulates containers. Reports fidelity `fake`.
#[derive(Clone)]
pub struct FakeSandbox {
    inner: Arc<Inner>,
}

impl FakeSandbox {
    /// A provider that checks specs against `policy` and stores output in `artifacts`.
    #[must_use]
    pub fn new(
        clock: Arc<FakeClock>,
        artifacts: Arc<dyn ArtifactStore>,
        policy: SandboxPolicy,
    ) -> Self {
        Self::build(clock, artifacts, policy, None)
    }

    /// A provider that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(
        clock: Arc<FakeClock>,
        artifacts: Arc<dyn ArtifactStore>,
        policy: SandboxPolicy,
        defect: SandboxDefect,
    ) -> Self {
        Self::build(clock, artifacts, policy, Some(defect))
    }

    fn build(
        clock: Arc<FakeClock>,
        artifacts: Arc<dyn ArtifactStore>,
        policy: SandboxPolicy,
        defect: Option<SandboxDefect>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                clock,
                artifacts,
                policy,
                defect,
                live: Mutex::new(BTreeMap::new()),
                next: Mutex::new(0),
                drift_next: Mutex::new(false),
                programs: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Adds a program to the fake image, or replaces one.
    pub fn with_program(
        self,
        name: &str,
        program: impl Fn(&[String], &[u8]) -> ProgramOutput + Send + Sync + 'static,
    ) -> Self {
        self.inner
            .programs
            .lock()
            .expect("the lock is never poisoned")
            .insert(name.to_owned(), Arc::new(program));
        self
    }

    /// Makes the next container differ from its spec, as if the daemon had ignored a setting.
    pub fn inject_posture_drift(&self) {
        *self
            .inner
            .drift_next
            .lock()
            .expect("the lock is never poisoned") = true;
    }

    /// The sandboxes that have not been removed.
    #[must_use]
    pub fn live_sandboxes(&self) -> Vec<SandboxId> {
        self.inner
            .live
            .lock()
            .expect("the lock is never poisoned")
            .keys()
            .cloned()
            .collect()
    }
}

impl Inner {
    fn has(&self, defect: SandboxDefect) -> bool {
        self.defect == Some(defect)
    }
}

#[async_trait]
impl SandboxProvider for FakeSandbox {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn create_verified(
        &self,
        spec: SandboxSpec,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        let inner = &self.inner;
        if !inner.has(SandboxDefect::AcceptsWeakSpec) {
            spec.validate(&inner.policy)
                .map_err(SandboxError::PolicyViolation)?;
        }
        // "Inspect" the container the daemon made. A drift changes what it reports.
        let mut observed = spec.hardening.clone();
        let drift =
            std::mem::take(&mut *inner.drift_next.lock().expect("the lock is never poisoned"));
        if drift {
            observed.privileged = true;
        }
        let difference = spec.hardening.differences(&observed);
        if !difference.is_empty() && !inner.has(SandboxDefect::ReturnsSessionOnPostureMismatch) {
            // The container is removed before the error is returned: nothing is registered.
            return Err(SandboxError::PostureMismatch(difference));
        }
        let id = {
            let mut next = inner.next.lock().expect("the lock is never poisoned");
            *next += 1;
            SandboxId::new(format!("fake-sandbox-{}", *next))
        };
        inner
            .live
            .lock()
            .expect("the lock is never poisoned")
            .insert(
                id.clone(),
                LiveSandbox {
                    attempt: spec.attempt,
                },
            );
        let posture = PostureReport {
            observed,
            image: spec.image.clone(),
            self_check_passed: true,
            verified_at: inner.clock.now(),
        };
        Ok(Box::new(FakeSandboxSession {
            id,
            posture,
            inner: Arc::clone(inner),
            created_at: inner.clock.now(),
            wall_clock: spec.limits.wall_clock,
            env: spec.env.pairs().to_vec(),
        }))
    }

    async fn sweep_orphans(&self, live: &[AttemptId]) -> Result<Vec<SandboxId>, SandboxError> {
        if self.inner.has(SandboxDefect::LeavesOrphans) {
            return Ok(Vec::new());
        }
        let mut sandboxes = self.inner.live.lock().expect("the lock is never poisoned");
        let orphans: Vec<SandboxId> = sandboxes
            .iter()
            .filter(|(_, sandbox)| !live.contains(&sandbox.attempt))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &orphans {
            sandboxes.remove(id);
        }
        Ok(orphans)
    }
}

struct FakeSandboxSession {
    id: SandboxId,
    posture: PostureReport,
    inner: Arc<Inner>,
    created_at: factory_domain::values::Timestamp,
    wall_clock: Duration,
    env: Vec<(String, String)>,
}

fn text_plain() -> MediaType {
    MediaType::parse("text/plain").expect("text/plain is a media type")
}

impl FakeSandboxSession {
    fn past_wall_clock(&self) -> bool {
        !self.inner.has(SandboxDefect::NoWallClock)
            && duration_between(&self.created_at, &self.inner.clock.now())
                .is_some_and(|age| age > self.wall_clock)
    }

    async fn store(&self, bytes: Vec<u8>, cap: u64) -> Result<(ArtifactRef, bool), SandboxError> {
        let cap = usize::try_from(cap).unwrap_or(usize::MAX);
        let truncated = bytes.len() > cap && !self.inner.has(SandboxDefect::UncappedOutput);
        let kept = if truncated {
            bytes[..cap].to_vec()
        } else {
            bytes
        };
        let reference = self
            .inner
            .artifacts
            .put(kept, text_plain())
            .await
            .map_err(|error| SandboxError::ProvisionFailed(error.to_string()))?;
        Ok((reference, truncated))
    }

    fn run_program(&self, req: &ExecRequest) -> ProgramOutput {
        let words = req.argv.as_slice();
        let stdin = req.stdin.clone().unwrap_or_default();
        if let Some(program) = self
            .inner
            .programs
            .lock()
            .expect("the lock is never poisoned")
            .get(req.argv.program())
            .cloned()
        {
            return program(words, &stdin);
        }
        let ok = |stdout: Vec<u8>| ProgramOutput {
            exit_code: Some(0),
            stdout,
            stderr: Vec::new(),
        };
        match req.argv.program() {
            "echo" => ok(format!("{}\n", words[1..].join(" ")).into_bytes()),
            "true" => ok(Vec::new()),
            "false" => ProgramOutput {
                exit_code: Some(1),
                ..ProgramOutput::default()
            },
            "cat" => ok(stdin),
            "head" => {
                // Only `head -c N /dev/zero` is simulated.
                match (
                    words.get(1).map(String::as_str),
                    words.get(2),
                    words.get(3).map(String::as_str),
                ) {
                    (Some("-c"), Some(count), Some("/dev/zero")) => {
                        ok(vec![0_u8; count.parse::<usize>().unwrap_or(0)])
                    }
                    _ => ProgramOutput {
                        exit_code: Some(1),
                        stderr: b"head: only `head -c N /dev/zero` is simulated\n".to_vec(),
                        ..ProgramOutput::default()
                    },
                }
            }
            "env" => ok(self
                .env
                .iter()
                .map(|(name, value)| format!("{name}={value}\n"))
                .collect::<String>()
                .into_bytes()),
            other => ProgramOutput {
                exit_code: Some(127),
                stderr: format!("{other}: command not found\n").into_bytes(),
                ..ProgramOutput::default()
            },
        }
    }
}

#[async_trait]
impl SandboxSession for FakeSandboxSession {
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
        let honours_cancel = !self.inner.has(SandboxDefect::IgnoresCancellation);
        if honours_cancel && cancel.is_cancelled() {
            return Err(SandboxError::Cancelled);
        }
        if self.past_wall_clock() {
            return Err(SandboxError::Timeout);
        }
        let started_at = self.inner.clock.now();

        let (output, timed_out) = if req.argv.program() == "sleep" {
            // `sleep N` lasts N seconds of tokio time, so a paused-time test runs it instantly
            // and a cancel can arrive while it is "running".
            let seconds = req
                .argv
                .as_slice()
                .get(1)
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
            let nap = Duration::from_secs(seconds);
            let honours_timeout = !self.inner.has(SandboxDefect::IgnoresTimeout);
            let sleeping = async {
                if honours_timeout {
                    tokio::time::timeout(req.timeout, tokio::time::sleep(nap))
                        .await
                        .is_err()
                } else {
                    tokio::time::sleep(nap).await;
                    false
                }
            };
            let timed_out = if honours_cancel {
                tokio::select! {
                    () = cancel.cancelled() => return Err(SandboxError::Cancelled),
                    timed_out = sleeping => timed_out,
                }
            } else {
                sleeping.await
            };
            self.inner
                .clock
                .advance(if timed_out { req.timeout } else { nap });
            let output = if timed_out {
                ProgramOutput::default()
            } else {
                ProgramOutput {
                    exit_code: Some(0),
                    ..ProgramOutput::default()
                }
            };
            (output, timed_out)
        } else {
            (self.run_program(&req), false)
        };

        if self.past_wall_clock() {
            return Err(SandboxError::Timeout);
        }
        let (stdout, stdout_truncated) = self.store(output.stdout, req.max_output_bytes).await?;
        let (stderr, stderr_truncated) = self.store(output.stderr, req.max_output_bytes).await?;
        let exit_code = if timed_out {
            None
        } else if self.inner.has(SandboxDefect::ReportsFailureAsSuccess) {
            Some(0)
        } else {
            output.exit_code
        };
        Ok(ExecResult {
            exit_code,
            signal: timed_out.then_some(9),
            timed_out,
            oom_killed: false,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            started_at,
            finished_at: self.inner.clock.now(),
        })
    }

    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        self.inner
            .live
            .lock()
            .expect("the lock is never poisoned")
            .remove(&self.id);
        Ok(TeardownReport {
            sandbox: self.id.clone(),
            reason,
            oom_killed: false,
        })
    }
}

/// The fake sandbox packaged as a subject of the sandbox contract suite.
pub struct FakeSandboxSubject {
    clock: Arc<FakeClock>,
    artifacts: Arc<crate::artifact::InMemoryArtifactStore>,
    sandbox: FakeSandbox,
}

impl FakeSandboxSubject {
    /// A faithful fake.
    #[must_use]
    pub fn new() -> Self {
        Self::build(None)
    }

    /// A fake that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: SandboxDefect) -> Self {
        Self::build(Some(defect))
    }

    fn build(defect: Option<SandboxDefect>) -> Self {
        let clock = Arc::new(FakeClock::new());
        let artifacts = Arc::new(crate::artifact::InMemoryArtifactStore::new());
        let policy = crate::fixtures::sandbox_policy();
        let sandbox = match defect {
            Some(defect) => {
                FakeSandbox::with_defect(Arc::clone(&clock), artifacts.clone(), policy, defect)
            }
            None => FakeSandbox::new(Arc::clone(&clock), artifacts.clone(), policy),
        };
        Self {
            clock,
            artifacts,
            sandbox,
        }
    }
}

impl Default for FakeSandboxSubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SandboxSubject for FakeSandboxSubject {
    fn provider(&self) -> &dyn SandboxProvider {
        &self.sandbox
    }

    fn artifacts(&self) -> &dyn ArtifactStore {
        self.artifacts.as_ref()
    }

    fn spec(&self, profile: SandboxProfile, attempt: AttemptId) -> SandboxSpec {
        let mut spec = crate::fixtures::sandbox_spec(&crate::fixtures::Ids::new(), profile);
        spec.attempt = attempt;
        spec
    }

    async fn advance_time(&self, by: Duration) {
        self.clock.advance(by);
    }

    async fn inject_posture_drift(&self) -> bool {
        self.sandbox.inject_posture_drift();
        true
    }
}
