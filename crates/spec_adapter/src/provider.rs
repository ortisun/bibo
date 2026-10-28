//! `SpecKitProvider`: the `SpecificationProvider` over the installed Spec Kit.
//!
//! `run` runs one skill through the agent runtime inside the sandbox it is given. The prompt it
//! sends is the invocation and the fixed instruction and nothing else: the data envelope of the
//! template is dropped, so neither the issue text nor any other free text reaches the arguments of
//! the skill. The request is in a file that the stage wrote into the checkout before the call.
//! `run` reads no file. It notes what the runtime reported and what the question detector heard,
//! and it says which files the stage must read back.
//!
//! `assemble` is pure over the committed bytes and the notes. It is idempotent.
//!
//! The trait is written out by hand in the form `async_trait` expands to, because the crate may
//! not depend on `async-trait` (the rules file lists the external crates of this crate).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use factory_domain::values::Slug;
use factory_domain::vocabulary::{ExecutionMode, Fidelity};
use factory_ports::agent::{AgentRunReport, AgentRunRequest, AssembledPrompt};
use factory_ports::paths::RepoPath;
use factory_ports::spec::{
    PostCondition, SkillRun, SpecContext, SpecError, SpecFileSet, SpecOutcome, SpecRequest,
    SpecRunReport, SpecificationProvider,
};
use serde_json::Value;

use crate::assemble::{ANSWERS_FILE, AssembleConfig, RunNotes, assemble};
use crate::invocation::{FixedInstruction, Host, Invocation, Recognised, Separator, recognise};
use crate::postcond::known_paths;
use crate::question::{Origin, Question, detect};

/// What the provider is built with. The host and the separator come from reading
/// `.specify/integration.json` with `IntegrationConfig::parse`.
#[derive(Debug, Clone)]
pub struct SpecKitConfig {
    /// The host the skills run on.
    pub host: Host,
    /// The separator that host uses.
    pub separator: Separator,
    /// Production or test.
    pub mode: ExecutionMode,
    /// The runtime adapter name to record when `assemble` runs in another process than `run`.
    pub fallback_adapter: Slug,
    /// Its version, in the same case.
    pub fallback_adapter_version: String,
}

/// The provider.
pub struct SpecKitProvider {
    config: SpecKitConfig,
    notes: Mutex<BTreeMap<(String, String), RunNotes>>,
}

impl SpecKitProvider {
    /// A provider with no run noted yet.
    #[must_use]
    pub fn new(config: SpecKitConfig) -> Self {
        Self {
            config,
            notes: Mutex::new(BTreeMap::new()),
        }
    }

    fn key(req: &SpecRequest) -> (String, String) {
        (
            req.job.to_string(),
            req.feature_directory.as_str().to_owned(),
        )
    }

    /// The prompt for a request: the invocation and the fixed instruction, and no data.
    ///
    /// # Errors
    /// [`SpecError::ParseError`] only when a path holds a character outside the safe set, which a
    /// feature directory or a repository path made by the stage never does.
    pub fn prompt(&self, req: &SpecRequest) -> Result<AssembledPrompt, SpecError> {
        let answers = if req.answers.is_empty() {
            None
        } else {
            Some(RepoPath::new(ANSWERS_FILE).expect("a fixed path is valid"))
        };
        let instruction = FixedInstruction::build(
            req.op,
            &req.feature_directory,
            &req.request_file,
            answers.as_ref(),
        )
        .map_err(|_| SpecError::ToolMissing)?;
        let invocation = Invocation::new(
            self.config.host,
            self.config.separator,
            req.op,
            &instruction,
        );
        Ok(AssembledPrompt {
            instructions: invocation.as_str().to_owned(),
            data: Vec::new(),
        })
    }

    /// The questions the detector heard in the final output of a run. The report is read as a
    /// signal only: it is never evidence that anything was done.
    fn heard(report: &AgentRunReport) -> Vec<Question> {
        let Ok(output) = &report.outcome else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(output.as_bytes()).into_owned();
        let mut found = detect(&text);
        if let Ok(value) = serde_json::from_slice::<Value>(output.as_bytes()) {
            let mut push = |text: &str| {
                found.push(Question {
                    text: text.to_owned(),
                    recommended: None,
                    origin: Origin::FreeText,
                });
            };
            if value["status"].as_str() == Some("NEEDS_HUMAN")
                && let Some(question) = value["human_question"].as_str()
            {
                push(question);
            }
            for question in value["clarification_questions"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if let Some(question) = question.as_str() {
                    push(question);
                }
            }
        }
        found
    }

    /// A denial that names a skill outside the four, whatever the run did next.
    fn forbidden_denial(report: &AgentRunReport) -> Option<PostCondition> {
        report.permission_denials.iter().find_map(|denial| {
            let lower = format!("{} {}", denial.tool, denial.reason);
            let at = lower.find("speckit")?;
            let rest = &lower[at + "speckit".len()..];
            let name: String = rest
                .trim_start_matches(['-', '.'])
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect();
            let allowed = matches!(
                recognise(&format!("/speckit-{name}")),
                Some(Recognised::Allowed(_))
            );
            (!name.is_empty() && !allowed).then(|| PostCondition {
                name: Slug::parse("forbidden-skill-invoked").expect("a slug"),
                detail: format!("The runtime denied a call to the skill {name}."),
            })
        })
    }

    async fn run_inner(
        &self,
        req: &SpecRequest,
        ctx: &mut SpecContext<'_>,
    ) -> Result<SpecRunReport, SpecError> {
        if ctx.cancel.is_cancelled() {
            return Err(SpecError::Runtime(
                factory_ports::agent::AgentRunError::Cancelled,
            ));
        }
        let prompt = self.prompt(req)?;
        let run_request = AgentRunRequest {
            prompt,
            ..ctx.run_template.clone()
        };
        let report = ctx
            .runtime
            .run(&mut *ctx.session, run_request, ctx.cancel)
            .await;
        if let Some(violation) = Self::forbidden_denial(&report) {
            return Err(SpecError::PostConditionFailed(vec![violation]));
        }
        let heard = Self::heard(&report);
        let failed = report.outcome.as_ref().err().cloned();
        {
            let mut notes = self
                .notes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = notes.entry(Self::key(req)).or_insert_with(|| RunNotes {
                run_succeeded: true,
                ..RunNotes::default()
            });
            entry.skills.push(req.op);
            entry.run_succeeded &= failed.is_none();
            entry.questions.extend(heard);
            entry.adapter = Some(ctx.runtime.id().as_str().to_owned());
            entry.adapter_version = report.runtime_version.clone();
            entry.fidelity = Some(ctx.runtime.fidelity());
        }
        if let Some(error) = failed {
            return Err(SpecError::Runtime(error));
        }
        let mut expected: Vec<RepoPath> = known_paths(&req.feature_directory, self.config.host)
            .into_iter()
            .filter(|path| {
                path != crate::postcond::CONSTITUTION
                    || req.op == factory_ports::spec::SpecOperation::Constitution
            })
            .filter_map(|path| RepoPath::new(&path).ok())
            .collect();
        expected.sort();
        Ok(SpecRunReport {
            op: req.op,
            feature_directory: req.feature_directory.clone(),
            expected_files: expected,
            skill_runs: vec![SkillRun {
                transcript: report.transcript,
                usage: report.usage,
                permission_denials: report.permission_denials,
            }],
        })
    }
}

impl SpecificationProvider for SpecKitProvider {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn run<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        req: &'life1 SpecRequest,
        ctx: &'life2 mut SpecContext<'life3>,
    ) -> Pin<Box<dyn Future<Output = Result<SpecRunReport, SpecError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.run_inner(req, ctx).await })
    }

    fn assemble(&self, req: &SpecRequest, files: &SpecFileSet) -> Result<SpecOutcome, SpecError> {
        let noted = self
            .notes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&Self::key(req))
            .cloned();
        let notes = noted.unwrap_or_else(|| RunNotes {
            skills: vec![req.op],
            run_succeeded: true,
            ..RunNotes::default()
        });
        let config = AssembleConfig {
            host: self.config.host,
            mode: self.config.mode,
            fallback_adapter: self.config.fallback_adapter.clone(),
            fallback_adapter_version: self.config.fallback_adapter_version.clone(),
        };
        assemble(&config, &notes, req, files)
    }
}
