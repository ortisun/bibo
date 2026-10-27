//! A scripted process runner (ports-v1.1, `ProcessRunner`).
//!
//! It starts nothing. A request names a tiny script in its first argument (`fake-env`,
//! `fake-exit:3`, `fake-stdin`, `fake-emit:100:50`, `fake-hang`), and the runner plays it in a
//! small model of a host: a fixed host environment that a child must not inherit, a count of
//! started processes, and a count of children still alive, so that a timeout or a cancel can be
//! shown to kill the group before the call returns. Time is the tokio clock, so a test that pauses
//! it runs a long timeout at once.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{
    EnvValue, ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest, SpawnStep,
};

use crate::contracts::process::ProcessSubject;

/// The fixed path the runner adds to every child (`ProcessRunner` postconditions).
pub const FIXED_PATH: &str = "/usr/bin:/bin";

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessDefect {
    /// The child inherits the host environment.
    InheritsHostEnvironment,
    /// A secret value is not passed to the child.
    DropsSecrets,
    /// A failing exit code is returned as an error.
    RaisesOnNonzeroExit,
    /// The child gets no standard input.
    DropsStdin,
    /// Output is not cut at the cap.
    IgnoresOutputCap,
    /// Only standard output is cut at the cap.
    CapsOnlyStandardOutput,
    /// A timed-out child is left running.
    LeavesChildAfterTimeout,
    /// A cancelled child is left running.
    LeavesChildAfterCancel,
    /// A cancel that is already set is not looked at before the process starts.
    IgnoresCancelBeforeStart,
    /// An argument with a NUL byte is passed on.
    AcceptsNulBytes,
    /// A missing program is reported as an operating system failure.
    MissesTheProgramName,
    /// A second identical request gets the first answer back without running again.
    CachesResults,
    /// A cancel is reported as a timeout.
    ReportsCancelAsTimeout,
}

/// The seeded defects and the checks that must fail for each. `contract_register` reads this
/// table, and `tests/process_contract.rs` runs it.
pub const DEFECTS: &[(ProcessDefect, &[&str])] = &[
    (
        ProcessDefect::InheritsHostEnvironment,
        &["the_child_environment_is_the_request_and_a_fixed_path"],
    ),
    (
        ProcessDefect::DropsSecrets,
        &["a_secret_reaches_the_child_and_stays_out_of_debug_output"],
    ),
    (
        ProcessDefect::RaisesOnNonzeroExit,
        &["an_exit_code_is_reported_not_raised"],
    ),
    (
        ProcessDefect::DropsStdin,
        &["standard_input_reaches_the_child"],
    ),
    (
        ProcessDefect::IgnoresOutputCap,
        &["output_is_cut_at_the_cap_and_marked_truncated"],
    ),
    (
        ProcessDefect::CapsOnlyStandardOutput,
        &["output_is_cut_at_the_cap_and_marked_truncated"],
    ),
    (
        ProcessDefect::LeavesChildAfterTimeout,
        &["a_timeout_kills_the_process_group_before_the_call_returns"],
    ),
    (
        ProcessDefect::LeavesChildAfterCancel,
        &["a_cancel_kills_the_process_group_before_the_call_returns"],
    ),
    (
        ProcessDefect::IgnoresCancelBeforeStart,
        &["a_cancel_that_is_already_set_starts_no_process"],
    ),
    (
        ProcessDefect::AcceptsNulBytes,
        &["an_argument_with_a_nul_byte_is_refused"],
    ),
    (
        ProcessDefect::MissesTheProgramName,
        &["a_missing_program_is_reported_by_name"],
    ),
    (
        ProcessDefect::CachesResults,
        &["each_call_runs_the_program_again"],
    ),
    (
        ProcessDefect::ReportsCancelAsTimeout,
        &["a_cancel_kills_the_process_group_before_the_call_returns"],
    ),
];

#[derive(Debug, Default)]
struct World {
    started: AtomicUsize,
    alive: AtomicUsize,
    missing: Mutex<BTreeSet<&'static str>>,
    last: Mutex<Option<(SpawnRequest, SpawnOutput)>>,
}

/// The scripted runner.
#[derive(Debug, Clone, Default)]
pub struct ScriptedProcessRunner {
    world: Arc<World>,
    defect: Option<ProcessDefect>,
}

impl ScriptedProcessRunner {
    /// A runner that follows the contract.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A runner with one deliberate fault.
    #[must_use]
    pub fn with_defect(defect: ProcessDefect) -> Self {
        Self {
            world: Arc::new(World::default()),
            defect: Some(defect),
        }
    }

    /// Makes a program unavailable, as if it were not installed on the host.
    pub fn uninstall(&self, program: Program) {
        self.world
            .missing
            .lock()
            .expect("the lock is never poisoned")
            .insert(program.as_str());
    }

    /// How many processes were started.
    #[must_use]
    pub fn started(&self) -> usize {
        self.world.started.load(Ordering::SeqCst)
    }

    /// How many children are still running.
    #[must_use]
    pub fn alive(&self) -> usize {
        self.world.alive.load(Ordering::SeqCst)
    }

    fn has(&self, defect: ProcessDefect) -> bool {
        self.defect == Some(defect)
    }

    fn child_environment(&self, req: &SpawnRequest) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = Vec::new();
        if self.has(ProcessDefect::InheritsHostEnvironment) {
            env.push(("HOME".to_owned(), "/home/factory".to_owned()));
            env.push(("USER".to_owned(), "factory".to_owned()));
        }
        for (name, value) in &req.env {
            match value {
                EnvValue::Plain(text) => env.push((name.clone(), text.clone())),
                EnvValue::Secret(text) if !self.has(ProcessDefect::DropsSecrets) => {
                    env.push((name.clone(), text.clone()));
                }
                EnvValue::Secret(_) => {}
            }
        }
        env.push(("PATH".to_owned(), FIXED_PATH.to_owned()));
        env.sort();
        env
    }

    fn cut(&self, bytes: Vec<u8>, cap: u64, is_stdout: bool) -> (Vec<u8>, bool) {
        let capped = !self.has(ProcessDefect::IgnoresOutputCap)
            && (is_stdout || !self.has(ProcessDefect::CapsOnlyStandardOutput));
        let limit = usize::try_from(cap).unwrap_or(usize::MAX);
        if capped && bytes.len() > limit {
            (bytes[..limit].to_vec(), true)
        } else {
            (bytes, false)
        }
    }

    fn finished(
        &self,
        req: &SpawnRequest,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        code: i32,
    ) -> SpawnOutput {
        let (stdout, out_cut) = self.cut(stdout, req.max_output_bytes, true);
        let (stderr, err_cut) = self.cut(stderr, req.max_output_bytes, false);
        SpawnOutput {
            exit_code: Some(code),
            signal: None,
            stdout,
            stderr,
            truncated: out_cut || err_cut,
        }
    }
}

#[async_trait]
impl ProcessRunner for ScriptedProcessRunner {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        if !self.has(ProcessDefect::AcceptsNulBytes)
            && req.args.iter().any(|arg| arg.contains('\0'))
        {
            return Err(SpawnError::Os(SpawnStep::Start));
        }
        if cancel.is_cancelled() && !self.has(ProcessDefect::IgnoresCancelBeforeStart) {
            return Err(SpawnError::Cancelled);
        }
        if self
            .world
            .missing
            .lock()
            .expect("the lock is never poisoned")
            .contains(req.program.as_str())
        {
            return Err(if self.has(ProcessDefect::MissesTheProgramName) {
                SpawnError::Os(SpawnStep::Start)
            } else {
                SpawnError::ProgramMissing(req.program)
            });
        }
        if self.has(ProcessDefect::CachesResults)
            && let Some((last, output)) =
                &*self.world.last.lock().expect("the lock is never poisoned")
            && *last == req
        {
            return Ok(output.clone());
        }
        self.world.started.fetch_add(1, Ordering::SeqCst);
        let script = req.args.first().cloned().unwrap_or_default();
        let output = match script.as_str() {
            "fake-env" => {
                let text: String = self
                    .child_environment(&req)
                    .iter()
                    .map(|(name, value)| format!("{name}={value}\n"))
                    .collect();
                self.finished(&req, text.into_bytes(), Vec::new(), 0)
            }
            "fake-stdin" => {
                let stdin = if self.has(ProcessDefect::DropsStdin) {
                    Vec::new()
                } else {
                    req.stdin.clone().unwrap_or_default()
                };
                self.finished(&req, stdin, Vec::new(), 0)
            }
            "fake-hang" => return self.hang(&req, cancel).await,
            other => {
                if let Some(code) = other.strip_prefix("fake-exit:") {
                    let code = code.parse::<i32>().unwrap_or(1);
                    if code != 0 && self.has(ProcessDefect::RaisesOnNonzeroExit) {
                        return Err(SpawnError::Os(SpawnStep::Wait));
                    }
                    self.finished(&req, Vec::new(), Vec::new(), code)
                } else if let Some(sizes) = other.strip_prefix("fake-emit:") {
                    let mut parts = sizes
                        .split(':')
                        .map(|part| part.parse::<usize>().unwrap_or(0));
                    let out = parts.next().unwrap_or(0);
                    let err = parts.next().unwrap_or(0);
                    self.finished(&req, vec![b'o'; out], vec![b'e'; err], 0)
                } else {
                    return Err(SpawnError::Os(SpawnStep::Start));
                }
            }
        };
        *self.world.last.lock().expect("the lock is never poisoned") = Some((req, output.clone()));
        Ok(output)
    }
}

impl ScriptedProcessRunner {
    async fn hang(
        &self,
        req: &SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        self.world.alive.fetch_add(1, Ordering::SeqCst);
        let result = tokio::select! {
            () = tokio::time::sleep(req.timeout) => {
                if !self.has(ProcessDefect::LeavesChildAfterTimeout) {
                    self.world.alive.fetch_sub(1, Ordering::SeqCst);
                }
                SpawnError::Timeout
            }
            () = cancel.cancelled() => {
                if !self.has(ProcessDefect::LeavesChildAfterCancel) {
                    self.world.alive.fetch_sub(1, Ordering::SeqCst);
                }
                if self.has(ProcessDefect::ReportsCancelAsTimeout) {
                    SpawnError::Timeout
                } else {
                    SpawnError::Cancelled
                }
            }
        };
        Err(result)
    }
}

/// The scripted runner as a subject of the contract suite.
#[derive(Debug, Default)]
pub struct ScriptedProcessSubject {
    runner: ScriptedProcessRunner,
}

impl ScriptedProcessSubject {
    /// A subject over a runner that follows the contract.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A subject over a runner with one deliberate fault.
    #[must_use]
    pub fn with_defect(defect: ProcessDefect) -> Self {
        Self {
            runner: ScriptedProcessRunner::with_defect(defect),
        }
    }

    fn request(script: String, env: Vec<(String, EnvValue)>) -> SpawnRequest {
        SpawnRequest {
            program: Program::Git,
            args: vec![script],
            cwd: None,
            env,
            stdin: None,
            timeout: Duration::from_secs(30),
            max_output_bytes: 1024,
        }
    }
}

impl ProcessSubject for ScriptedProcessSubject {
    fn runner(&self) -> &dyn ProcessRunner {
        &self.runner
    }

    fn print_environment(&self, env: Vec<(String, EnvValue)>) -> SpawnRequest {
        Self::request("fake-env".to_owned(), env)
    }

    fn exit_with(&self, code: i32) -> SpawnRequest {
        Self::request(format!("fake-exit:{code}"), Vec::new())
    }

    fn echo_stdin(&self, bytes: Vec<u8>) -> SpawnRequest {
        let mut request = Self::request("fake-stdin".to_owned(), Vec::new());
        request.stdin = Some(bytes);
        request
    }

    fn print(&self, stdout_bytes: u64, stderr_bytes: u64, cap: u64) -> SpawnRequest {
        let mut request = Self::request(
            format!("fake-emit:{stdout_bytes}:{stderr_bytes}"),
            Vec::new(),
        );
        request.max_output_bytes = cap;
        request
    }

    fn run_until_killed(&self, timeout: Duration) -> SpawnRequest {
        let mut request = Self::request("fake-hang".to_owned(), Vec::new());
        request.timeout = timeout;
        request
    }

    fn with_a_nul_byte(&self) -> SpawnRequest {
        let mut request = Self::request("fake-exit:0".to_owned(), Vec::new());
        request.args.push("bad\0argument".to_owned());
        request
    }

    fn make_unavailable(&self, program: Program) -> bool {
        self.runner.uninstall(program);
        true
    }

    fn children_alive(&self) -> Option<usize> {
        Some(self.runner.alive())
    }

    fn processes_started(&self) -> Option<usize> {
        Some(self.runner.started())
    }
}
