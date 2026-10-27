//! A specification provider that runs a scripted tool and assembles queued outcomes.
//!
//! `run` really drives the fake sandbox: it executes the commands a test queued with
//! [`FakeSpecificationProvider::script_run`] through the session it is given, so a refused or
//! failing command is seen. It reads no file. `assemble` is pure over the committed files: it
//! refuses a feature without its `spec.md` (`Missing`) and a `spec.md` that is not text
//! (`NotText`), and then returns the outcome a test queued with
//! [`FakeSpecificationProvider::queue`]. A call made after the cancel signal is set fails with a
//! cancelled runtime error, and a call with nothing queued reports that the tool is missing.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::AgentRunError;
use factory_ports::paths::RepoPath;
use factory_ports::sandbox::{ExecArgv, ExecRequest};
use factory_ports::spec::{
    ParseReason, SkillRun, SpecContext, SpecError, SpecFileSet, SpecOutcome, SpecRequest,
    SpecRunReport, SpecificationProvider,
};

/// What one scripted run does inside the sandbox.
#[derive(Debug, Clone, Default)]
pub struct ScriptedRun {
    /// Commands to execute in the sandbox, as argument vectors.
    pub commands: Vec<Vec<String>>,
    /// The files the run is expected to have left.
    pub expected_files: Vec<RepoPath>,
}

/// A specification provider with queued runs and outcomes. Reports fidelity `fake`.
#[derive(Default)]
pub struct FakeSpecificationProvider {
    runs: Mutex<VecDeque<ScriptedRun>>,
    outcomes: Mutex<VecDeque<Result<SpecOutcome, SpecError>>>,
    requests: Mutex<Vec<SpecRequest>>,
}

impl FakeSpecificationProvider {
    /// A provider with nothing queued.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues what a later call to `assemble` returns. Outcomes are played in the order queued.
    pub fn queue(&self, outcome: Result<SpecOutcome, SpecError>) {
        self.outcomes
            .lock()
            .expect("the lock is never poisoned")
            .push_back(outcome);
    }

    /// Queues what a later call to `run` does in the sandbox. A call with nothing queued runs
    /// nothing and expects no file.
    pub fn script_run(&self, run: ScriptedRun) {
        self.runs
            .lock()
            .expect("the lock is never poisoned")
            .push_back(run);
    }

    /// Every request the provider received, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<SpecRequest> {
        self.requests
            .lock()
            .expect("the lock is never poisoned")
            .clone()
    }
}

#[async_trait]
impl SpecificationProvider for FakeSpecificationProvider {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn run(
        &self,
        req: &SpecRequest,
        ctx: &mut SpecContext<'_>,
    ) -> Result<SpecRunReport, SpecError> {
        self.requests
            .lock()
            .expect("the lock is never poisoned")
            .push(req.clone());
        if ctx.cancel.is_cancelled() {
            return Err(SpecError::Runtime(AgentRunError::Cancelled));
        }
        let scripted = self
            .runs
            .lock()
            .expect("the lock is never poisoned")
            .pop_front()
            .unwrap_or_default();
        for words in &scripted.commands {
            let argv = ExecArgv::new(words.clone()).map_err(|_| SpecError::ToolMissing)?;
            let exec = ExecRequest {
                argv,
                cwd: None,
                stdin: None,
                timeout: Duration::from_secs(30),
                max_output_bytes: 64 * 1024,
            };
            let result = ctx
                .session
                .exec(exec, ctx.cancel)
                .await
                .map_err(|_| SpecError::ToolMissing)?;
            if result.exit_code != Some(0) {
                return Err(SpecError::ToolMissing);
            }
        }
        Ok(SpecRunReport {
            op: req.op,
            feature_directory: req.feature_directory.clone(),
            expected_files: scripted.expected_files,
            skill_runs: vec![SkillRun {
                transcript: None,
                usage: factory_ports::agent::Usage::default(),
                permission_denials: Vec::new(),
            }],
        })
    }

    fn assemble(&self, req: &SpecRequest, files: &SpecFileSet) -> Result<SpecOutcome, SpecError> {
        let spec_path = RepoPath::new(&format!("{}/spec.md", req.feature_directory.as_str()))
            .map_err(|_| SpecError::ToolMissing)?;
        let Some(spec) = files.files.iter().find(|file| file.path == spec_path) else {
            return Err(SpecError::ParseError {
                path: spec_path,
                reason: ParseReason::Missing,
            });
        };
        if std::str::from_utf8(&spec.bytes).is_err() {
            return Err(SpecError::ParseError {
                path: spec_path,
                reason: ParseReason::NotText,
            });
        }
        self.outcomes
            .lock()
            .expect("the lock is never poisoned")
            .pop_front()
            .unwrap_or(Err(SpecError::ToolMissing))
    }
}
