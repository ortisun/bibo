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
use factory_domain::ids::{AttemptId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::MediaType;
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{CancelSignal, Clock, duration_between};
use factory_ports::sandbox::{
    Confinement, ExecRequest, ExecResult, ImageDigest, NetworkAttachment, ObservedMount,
    PostureReport, SandboxError, SandboxId, SandboxPolicy, SandboxProfile, SandboxProvider,
    SandboxSession, SandboxSpec, TeardownReason, TeardownReport,
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
    /// A different image in the container is not noticed.
    IgnoresImageDrift,
    /// A changed limit is not noticed.
    IgnoresLimitDrift,
    /// A changed network is not noticed.
    IgnoresNetworkDrift,
    /// An extra mount is not noticed.
    IgnoresExtraMount,
    /// A mount that should be read-only and is writable is not noticed.
    IgnoresWritableMount,
    /// A changed environment is not noticed.
    IgnoresEnvDrift,
    /// The job token file stays after the sandbox is removed.
    KeepsTokenFile,
    /// `apparmor: NotAvailable` is accepted whatever the policy says.
    AcceptsAnyAppArmor,
    /// A cancel signal is not looked at while the sandbox is created.
    IgnoresCancelOnCreate,
    /// The session reports a failed runtime self-check although it passed the posture check.
    ReportsStalePosture,
    /// A command runs with its program name only: the arguments are dropped.
    DropsArguments,
    /// A command gets no standard input.
    DropsStdin,
    /// `stop_and_remove` reports success and leaves the sandbox registered.
    LeavesSandboxAfterTeardown,
}

pub use crate::contracts::sandbox::DriftPart;

/// Each defect and the checks of `contracts::sandbox` that must fail when the fake has it.
pub const DEFECTS: &[(SandboxDefect, &[&str])] = &[
    (
        SandboxDefect::IgnoresCancellation,
        &[
            "a_cancel_that_is_already_set_stops_the_command_before_it_starts",
            "a_cancel_during_a_long_command_ends_it_promptly",
        ],
    ),
    (
        SandboxDefect::IgnoresTimeout,
        &["a_command_past_its_timeout_is_killed_and_flagged"],
    ),
    (
        SandboxDefect::AcceptsWeakSpec,
        &[
            "a_spec_weaker_than_the_policy_is_refused_and_builds_nothing",
            "a_network_that_does_not_suit_the_profile_is_refused",
            "a_zero_wall_clock_is_refused",
            "a_writable_cache_is_refused_outside_fetch_deps",
        ],
    ),
    (
        SandboxDefect::ReturnsSessionOnPostureMismatch,
        &["a_container_that_differs_from_its_spec_is_removed_and_never_returned"],
    ),
    (
        SandboxDefect::LeavesOrphans,
        &["sweeping_removes_only_sandboxes_whose_attempt_is_not_live"],
    ),
    (
        SandboxDefect::NoWallClock,
        &["a_sandbox_past_its_wall_clock_refuses_commands"],
    ),
    (
        SandboxDefect::UncappedOutput,
        &["output_beyond_the_cap_is_cut_and_flagged"],
    ),
    (
        SandboxDefect::ReportsFailureAsSuccess,
        &[
            "exit_codes_are_reported_as_they_are",
            "a_missing_program_is_a_failed_command",
        ],
    ),
    (
        SandboxDefect::IgnoresImageDrift,
        &["a_different_image_is_a_mismatch"],
    ),
    (
        SandboxDefect::IgnoresLimitDrift,
        &["a_drifted_limit_is_a_mismatch"],
    ),
    (
        SandboxDefect::IgnoresNetworkDrift,
        &["a_drifted_network_is_a_mismatch"],
    ),
    (
        SandboxDefect::IgnoresExtraMount,
        &["an_extra_mount_is_a_mismatch"],
    ),
    (
        SandboxDefect::IgnoresWritableMount,
        &["a_writable_mount_that_should_be_read_only_is_a_mismatch"],
    ),
    (
        SandboxDefect::IgnoresEnvDrift,
        &["a_drifted_environment_is_a_mismatch"],
    ),
    (
        SandboxDefect::KeepsTokenFile,
        &["the_job_token_file_is_absent_after_stop_and_remove"],
    ),
    (
        SandboxDefect::AcceptsAnyAppArmor,
        &["apparmor_not_available_is_accepted_only_by_policy"],
    ),
    (
        SandboxDefect::IgnoresCancelOnCreate,
        &["a_cancelled_create_removes_what_it_made"],
    ),
    (
        SandboxDefect::ReportsStalePosture,
        &["every_profile_can_be_created_and_its_posture_matches_the_spec"],
    ),
    (
        SandboxDefect::DropsArguments,
        &["a_command_runs_as_an_argument_vector_and_its_output_is_stored"],
    ),
    (
        SandboxDefect::DropsStdin,
        &["standard_input_reaches_the_command"],
    ),
    (
        SandboxDefect::LeavesSandboxAfterTeardown,
        &["teardown_removes_the_sandbox"],
    ),
];

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
    token_file: bool,
}

struct Inner {
    clock: Arc<FakeClock>,
    artifacts: Arc<dyn ArtifactStore>,
    policy: Mutex<SandboxPolicy>,
    defect: Option<SandboxDefect>,
    live: Mutex<BTreeMap<SandboxId, LiveSandbox>>,
    next: Mutex<u64>,
    drift_next: Mutex<Option<DriftPart>>,
    stray_token_files: Mutex<Vec<SandboxId>>,
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
                policy: Mutex::new(policy),
                defect,
                live: Mutex::new(BTreeMap::new()),
                next: Mutex::new(0),
                drift_next: Mutex::new(None),
                stray_token_files: Mutex::new(Vec::new()),
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
        self.inject_drift(DriftPart::Hardening);
    }

    /// Makes the next container differ from its spec in one part.
    pub fn inject_drift(&self, part: DriftPart) {
        *self
            .inner
            .drift_next
            .lock()
            .expect("the lock is never poisoned") = Some(part);
    }

    /// Sets whether the policy accepts a daemon without AppArmor (a development host).
    pub fn allow_apparmor_unavailable(&self, allowed: bool) {
        self.inner
            .policy
            .lock()
            .expect("the lock is never poisoned")
            .apparmor_may_be_unavailable = allowed;
    }

    /// True when a job token file exists on the host for any sandbox, live or not.
    #[must_use]
    pub fn token_file_present(&self) -> bool {
        let live = self.inner.live.lock().expect("the lock is never poisoned");
        live.values().any(|s| s.token_file)
            || !self
                .inner
                .stray_token_files
                .lock()
                .expect("the lock is never poisoned")
                .is_empty()
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
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        let inner = &self.inner;
        if cancel.is_cancelled() && !inner.has(SandboxDefect::IgnoresCancelOnCreate) {
            return Err(SandboxError::Cancelled);
        }
        let mut policy = inner
            .policy
            .lock()
            .expect("the lock is never poisoned")
            .clone();
        if !inner.has(SandboxDefect::AcceptsWeakSpec) {
            spec.validate(&policy)
                .map_err(SandboxError::PolicyViolation)?;
        }
        // "Inspect" the container the daemon made. A drift changes what it reports.
        let drift = inner
            .drift_next
            .lock()
            .expect("the lock is never poisoned")
            .take();
        let mut report = PostureReport {
            observed: spec.hardening.clone(),
            image: spec.image.clone(),
            limits: spec.limits.clone(),
            network: spec.network.clone(),
            mounts: spec
                .expected_mounts()
                .into_iter()
                .map(|m| ObservedMount {
                    source: m.source.unwrap_or_else(|| "host-chosen".to_owned()),
                    target: m.target,
                    read_only: m.read_only,
                })
                .collect(),
            env: spec.env.pairs().to_vec(),
            self_check_passed: true,
            verified_at: inner.clock.now(),
        };
        if let Some(part) = drift {
            apply_drift(&mut report, part);
        }
        if inner.has(SandboxDefect::AcceptsAnyAppArmor) {
            policy.apparmor_may_be_unavailable = true;
        }
        let mut difference = report.differences(&spec, &policy);
        for (defect, field) in [
            (SandboxDefect::IgnoresImageDrift, "image"),
            (SandboxDefect::IgnoresLimitDrift, "limits"),
            (SandboxDefect::IgnoresNetworkDrift, "network"),
            (SandboxDefect::IgnoresExtraMount, "mounts"),
            (SandboxDefect::IgnoresWritableMount, "mounts"),
            (SandboxDefect::IgnoresEnvDrift, "env"),
        ] {
            if inner.has(defect) {
                difference.fields.retain(|name| *name != field);
            }
        }
        if !difference.is_empty() && !inner.has(SandboxDefect::ReturnsSessionOnPostureMismatch) {
            // The container is removed before the error is returned: nothing is registered.
            return Err(SandboxError::PostureMismatch(difference));
        }
        let observed = report.observed.clone();
        let _ = observed;
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
                    token_file: spec.job_token.is_some(),
                },
            );
        Ok(Box::new(FakeSandboxSession {
            id,
            posture: {
                let mut report = report;
                if inner.has(SandboxDefect::ReportsStalePosture) {
                    report.self_check_passed = false;
                }
                report
            },
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
        self.inner
            .stray_token_files
            .lock()
            .expect("the lock is never poisoned")
            .clear();
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
            .map_err(|_| SandboxError::DaemonUnavailable)?;
        Ok((reference, truncated))
    }

    fn run_program(&self, req: &ExecRequest) -> ProgramOutput {
        let all_words = req.argv.as_slice();
        let words = if self.inner.has(SandboxDefect::DropsArguments) {
            &all_words[..1]
        } else {
            all_words
        };
        let stdin = if self.inner.has(SandboxDefect::DropsStdin) {
            Vec::new()
        } else {
            req.stdin.clone().unwrap_or_default()
        };
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
        let removed = if self.inner.has(SandboxDefect::LeavesSandboxAfterTeardown) {
            None
        } else {
            self.inner
                .live
                .lock()
                .expect("the lock is never poisoned")
                .remove(&self.id)
        };
        if self.inner.has(SandboxDefect::KeepsTokenFile)
            && removed.is_some_and(|sandbox| sandbox.token_file)
        {
            self.inner
                .stray_token_files
                .lock()
                .expect("the lock is never poisoned")
                .push(self.id.clone());
        }
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

    async fn read_output(&self, reference: &ArtifactRef) -> Result<Vec<u8>, String> {
        let tenant = TenantScope::new(
            TenantId::parse("00000000-0000-7000-8000-00000000000a").expect("a tenant id"),
        );
        self.artifacts.grant(tenant.tenant_id(), &reference.sha256);
        self.artifacts
            .get(&tenant, reference)
            .await
            .map_err(|error| format!("read stored output: {error:?}"))
    }

    fn spec(&self, profile: SandboxProfile, attempt: AttemptId) -> SandboxSpec {
        let mut spec = crate::fixtures::sandbox_spec(&crate::fixtures::Ids::new(), profile);
        spec.attempt = attempt;
        spec
    }

    async fn advance_time(&self, by: Duration) {
        self.clock.advance(by);
    }

    async fn inject_posture_drift(&self, part: DriftPart) -> bool {
        self.sandbox.inject_drift(part);
        true
    }

    async fn token_file_present(&self) -> Option<bool> {
        Some(self.sandbox.token_file_present())
    }

    async fn allow_apparmor_unavailable(&self, allowed: bool) -> bool {
        self.sandbox.allow_apparmor_unavailable(allowed);
        true
    }
}

/// Changes what the "daemon" reports for one part of the container.
fn apply_drift(report: &mut PostureReport, part: DriftPart) {
    match part {
        DriftPart::Hardening => report.observed.privileged = true,
        DriftPart::Image => {
            report.image = ImageDigest::parse(&format!(
                "registry.local/factory/other@sha256:{}",
                "b".repeat(64)
            ))
            .expect("a valid digest reference");
        }
        DriftPart::Limits => {
            report.limits.pids = report.limits.pids.saturating_add(1);
        }
        DriftPart::Network => {
            report.network = match report.network {
                NetworkAttachment::None => NetworkAttachment::JobInternal {
                    sidecar: "uninvited".to_owned(),
                },
                NetworkAttachment::JobInternal { .. } => NetworkAttachment::None,
            };
        }
        DriftPart::ExtraMount => report.mounts.push(ObservedMount {
            target: "/host".to_owned(),
            read_only: false,
            source: "/".to_owned(),
        }),
        DriftPart::WritableMount => {
            if let Some(mount) = report.mounts.iter_mut().find(|m| m.read_only) {
                mount.read_only = false;
            }
        }
        DriftPart::Env => report
            .env
            .push(("LD_PRELOAD".to_owned(), "/evil.so".to_owned())),
        DriftPart::AppArmorNotAvailable => report.observed.apparmor = Confinement::NotAvailable,
    }
}
