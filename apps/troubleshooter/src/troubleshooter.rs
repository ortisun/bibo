//! One pass of the troubleshooter: probes, maybe an agent run, issue decisions, the run record.
//!
//! A pass opens a gateway run whose id is the troubleshooting run id, so the probes' calls and
//! the agent's calls share one record and one numbering and a probe value can be cited like an
//! agent call. When nothing tripped past its cool-down, no source failed and the sweep is not
//! due, the gateway run is closed and nothing else is written but the probe states.
//!
//! Otherwise a `troubleshooting_runs` row is written, and:
//!
//! 1. when a probe tripped past its cool-down, or the sweep is due, and the day's caps allow, the
//!    agent runs once (never two at a time): its input document is built and checked against
//!    `troubleshooter-input` v1, the prompt is assembled, the run is made with the role's
//!    ceiling, the report is checked ([`crate::findings::check_report`]);
//! 2. the gateway run is closed and its record's digest kept;
//! 3. each accepted finding and each `source_unavailable` finding is redacted, rendered by the
//!    domain's closed template, and then: a seen-again comment on its open issue (once a UTC
//!    day), a new issue (under the day's cap), or deferred and named in the run record. With
//!    `--dry-run` nothing is sent to GitHub; the decisions are listed instead;
//! 4. the run's GitHub tokens are revoked and the run row is finished.

use std::sync::Arc;
use std::time::Duration;

use factory_contracts::agent_schema::AgentSchema;
use factory_domain::contracts::AgentManifest;
use factory_domain::ids::TenantId;
use factory_domain::policy::RepoKind;
use factory_domain::policy::paths::PathPolicy;
use factory_domain::policy::troubleshooting::{ProbeKind, TroubleshootingPolicy};
use factory_domain::redaction::Redactor;
use factory_domain::troubleshooting::issue::{Investigation, render_issue, render_seen_again};
use factory_domain::troubleshooting::{
    Finding, FindingFingerprint, TriageLabels, TroubleshootingRunId, one_line,
};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_mcp_gateway::{Gateway, RunLimits, RunRecord};
use factory_ports::agent::{CostMicroUsd, McpToolName};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::GitHostError;
use factory_ports::paths::RepoRef;
use factory_ports::registry::LoadedPrompt;
use factory_ports::sandbox::McpRunTokenSecret;
use factory_ports::triage_issue::{OpenedIssue, RunScope, TriageIssueWriter};
use factory_storage::pg::troubleshooting::{
    DayCounters, DayIncrement, NewIssue, NewRun, ProbeOutcome, ProbeResult, RunEnd, RunOutcome,
    RunTrigger, TroubleshootingStore,
};
use factory_workflow::prompts::{
    Assembler, AssemblyRequest, ContentClass, Input, Limits, Scope, Source,
};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::agent::{AgentJob, AgentRunner};
use crate::exact::Exact;
use crate::findings::{Refused, ReportStatus, check_report, prepared, source_unavailable};
use crate::probes::{HealthCheck, ProbeObservation, ProbeSources, run_probe};
use crate::schedule::{
    Refusal, agent_budget, cooldown_until, may_comment, may_open_issue, past_cooldown, sweep_due,
};

/// What the agent's prompt is made from, loaded and checked at start.
pub struct PromptKit {
    /// The troubleshooter's manifest.
    pub manifest: AgentManifest,
    /// Its prompt template.
    pub prompt: LoadedPrompt,
    /// The path policy the assembler asks about every input.
    pub paths: PathPolicy,
    /// `troubleshooter-input` v1.
    pub input_schema: AgentSchema,
    /// `health-findings` v1.
    pub output_schema: AgentSchema,
}

/// The settings of a troubleshooter.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The tenant whose rows and installation the troubleshooter uses.
    pub tenant: TenantId,
    /// The one repository issues go to.
    pub issue_repository: RepoRef,
    /// Nothing is written to GitHub; the decisions are listed.
    pub dry_run: bool,
    /// Datadog is configured.
    pub datadog: bool,
    /// VictoriaMetrics is configured.
    pub victoriametrics: bool,
    /// The base URL of the factory API, for the health probes.
    pub api_base_url: String,
    /// How long a health GET waits.
    pub health_timeout: Duration,
    /// The role's ceiling for one run, in millionths of a dollar.
    pub per_run_micro_usd: u64,
    /// The role's ceiling for one UTC day.
    pub per_day_micro_usd: u64,
}

/// Everything a troubleshooter is made of.
pub struct Parts {
    /// `policies/troubleshooting.yaml`.
    pub policy: Arc<TroubleshootingPolicy>,
    /// Its hash.
    pub policy_hash: Sha256Digest,
    /// The gateway (upstreams connected).
    pub gateway: Gateway,
    /// The health check.
    pub health: Arc<dyn HealthCheck>,
    /// The troubleshooter's rows.
    pub store: TroubleshootingStore,
    /// The triage issue writer.
    pub issues: Arc<dyn TriageIssueWriter>,
    /// The agent run.
    pub agent: Arc<dyn AgentRunner>,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// The source of the random part of run ids.
    pub ids: Arc<dyn IdGenerator>,
    /// The factory's redactor.
    pub redactor: Arc<Redactor>,
    /// The prompt parts.
    pub kit: PromptKit,
    /// The settings.
    pub settings: Settings,
}

/// What to do in a pass beyond the schedule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassOptions {
    /// Start a sweep now, whatever the schedule says.
    pub sweep_now: bool,
}

/// What became of one finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueAction {
    /// A new issue was opened.
    Opened(u64),
    /// A seen-again comment was posted.
    Commented(u64),
    /// The open issue already had its comment today.
    Unchanged(u64),
    /// The day's cap of new issues was reached.
    Deferred(Sha256Digest),
    /// `--dry-run`: what would have been done.
    DryRun(String),
    /// The finding could not be rendered or GitHub refused; the reason.
    Failed(String),
}

impl IssueAction {
    const fn label(&self) -> &'static str {
        match self {
            Self::Opened(_) => "opened",
            Self::Commented(_) => "commented",
            Self::Unchanged(_) => "unchanged",
            Self::Deferred(_) => "deferred",
            Self::DryRun(_) => "dry_run",
            Self::Failed(_) => "failed",
        }
    }
}

/// What one pass did.
#[derive(Debug, Clone, PartialEq)]
pub struct PassReport {
    /// The run, when the pass made one.
    pub run: Option<TroubleshootingRunId>,
    /// How the run ended.
    pub outcome: Option<RunOutcome>,
    /// Every probe and what it found.
    pub probes: Vec<(String, ProbeOutcome)>,
    /// The agent ran.
    pub agent_ran: bool,
    /// What became of each finding.
    pub issues: Vec<IssueAction>,
}

/// Why a pass stopped before it finished. The run row, when there is one, is finished as
/// `failed`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PassError {
    /// The gateway would not open the run.
    #[error("the gateway would not open the run: {0}")]
    Gateway(String),
    /// The store failed.
    #[error("the troubleshooter's store failed: {0}")]
    Store(String),
}

fn store_error(error: impl std::fmt::Display) -> PassError {
    PassError::Store(error.to_string())
}

/// The troubleshooter.
pub struct Troubleshooter {
    parts: Parts,
    labels: TriageLabels,
    started_at: Timestamp,
    agent_slot: Semaphore,
}

/// A new run id: `tr-<UTC time>-<8 random hex>`, inside the pattern of `run_id`.
fn new_run_id(now: &Timestamp, ids: &dyn IdGenerator) -> TroubleshootingRunId {
    let t = now.to_utc();
    let random = ids.new_uuid().simple().to_string();
    let text = format!(
        "tr-{:04}{:02}{:02}T{:02}{:02}{:02}Z-{}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        &random[random.len() - 8..]
    );
    TroubleshootingRunId::parse(&text).unwrap_or_else(|_| {
        TroubleshootingRunId::parse("tr-unnamed").expect("a constant run id is valid")
    })
}

fn result_word(outcome: ProbeOutcome) -> &'static str {
    outcome.as_str()
}

impl Troubleshooter {
    /// A troubleshooter over its parts.
    ///
    /// # Errors
    /// The policy's labels are not triage labels.
    pub fn new(parts: Parts) -> Result<Self, String> {
        let labels = TriageLabels::from_policy(&parts.policy.issues).map_err(|e| e.to_string())?;
        let started_at = parts.clock.now();
        let slots = usize::try_from(parts.policy.schedule.max_concurrent_agent_runs)
            .unwrap_or(1)
            .clamp(1, 1);
        Ok(Self {
            parts,
            labels,
            started_at,
            agent_slot: Semaphore::new(slots),
        })
    }

    /// The parts, for the program's own reports.
    #[must_use]
    pub fn parts(&self) -> &Parts {
        &self.parts
    }

    /// One pass. See the module notes.
    ///
    /// # Errors
    /// [`PassError`] when the gateway or the store fails.
    pub async fn pass(&self, options: PassOptions) -> Result<PassReport, PassError> {
        let p = &self.parts;
        let now = p.clock.now();
        let run_id = new_run_id(&now, p.ids.as_ref());
        self.close_abandoned_runs(&now).await;
        let token = p
            .gateway
            .open_run(run_id.as_str(), RunLimits::from_policy(&p.policy.gateway))
            .map_err(|e| PassError::Gateway(e.to_string()))?;

        let states = p.store.probe_states().await.map_err(store_error)?;
        let observations = self.run_probes(&run_id, &now).await;
        let mut report = PassReport {
            run: None,
            outcome: None,
            probes: observations
                .iter()
                .map(|o| (o.probe.id.clone(), o.outcome))
                .collect(),
            agent_ran: false,
            issues: Vec::new(),
        };
        let tripped: Vec<&ProbeObservation> = observations
            .iter()
            .filter(|o| o.outcome == ProbeOutcome::Tripped)
            .collect();
        let eligible: Vec<&ProbeObservation> = tripped
            .iter()
            .copied()
            .filter(|o| past_cooldown(states.iter().find(|s| s.probe_id == o.probe.id), &now))
            .collect();
        let unavailable = source_unavailable(&observations);
        let last_sweep = p.store.last_sweep_started().await.map_err(store_error)?;
        let sweep = options.sweep_now
            || sweep_due(
                &p.policy.schedule,
                last_sweep.as_ref(),
                &self.started_at,
                &now,
            );
        let trigger = if !eligible.is_empty() {
            Some(RunTrigger::Probe)
        } else if sweep {
            Some(RunTrigger::Sweep)
        } else {
            None
        };
        if trigger.is_none() && unavailable.is_empty() {
            let _ = p.gateway.close_run(run_id.as_str()).await;
            return Ok(report);
        }
        let run_trigger = trigger.unwrap_or(RunTrigger::Probe);
        p.store
            .begin_run(&NewRun {
                id: run_id.clone(),
                trigger: run_trigger,
                started_at: now,
                dry_run: p.settings.dry_run,
                datadog_enabled: p.settings.datadog,
            })
            .await
            .map_err(store_error)?;
        report.run = Some(run_id.clone());
        let span = tracing::info_span!(
            "factory.troubleshooting_run",
            "factory.troubleshooting_run_id" = %run_id.as_str(),
            "factory.trigger" = run_trigger.as_str(),
            "factory.result" = tracing::field::Empty,
        );

        let window = self.window(trigger, &eligible, &now);
        let mut outcome = RunOutcome::SourceUnavailable;
        let mut spend = 0_u64;
        let mut report_digest = None;
        let mut accepted: Vec<Finding> = Vec::new();
        if let Some(trigger) = trigger {
            let today = p.store.day_counters(&now).await.map_err(store_error)?;
            match agent_budget(
                &p.policy.schedule,
                &today,
                p.settings.per_run_micro_usd,
                p.settings.per_day_micro_usd,
            ) {
                Err(Refusal::RunCap) => outcome = RunOutcome::CapReached,
                Err(Refusal::SpendCeiling) => outcome = RunOutcome::SpendCeiling,
                Ok(ceiling) => {
                    let agent = self
                        .agent_run(&run_id, trigger, &eligible, &window, &now, ceiling, &token)
                        .await;
                    report.agent_ran = agent.ran;
                    spend = agent.spend;
                    report_digest = agent.digest;
                    outcome = agent.outcome;
                    accepted = agent.findings;
                }
            }
        }
        let record = p.gateway.close_run(run_id.as_str()).await.ok();
        if let Some(record) = &record {
            gateway_metrics(record);
        }

        let tripped_ids: Vec<String> = tripped.iter().map(|o| o.probe.id.clone()).collect();
        let mut filings: Vec<Finding> = Vec::new();
        for finding in &accepted {
            match prepared(finding, &tripped_ids, &p.redactor) {
                Some(ready) => filings.push(ready),
                None => report.issues.push(IssueAction::Failed(
                    "a text could not be checked for secrets".to_owned(),
                )),
            }
        }
        for finding in &unavailable {
            let own: Vec<String> = finding
                .probe_ids
                .iter()
                .map(|s| s.as_str().to_owned())
                .collect();
            if let Some(ready) = prepared(finding, &own, &p.redactor) {
                filings.push(ready);
            }
        }
        let scope = RunScope {
            tenant: p.settings.tenant,
            run: run_id.clone(),
            repo: p.settings.issue_repository.clone(),
        };
        let investigation = Investigation {
            run: &run_id,
            window_from: window.0,
            window_to: window.1,
            earlier_closed_issue: None,
            held_back: &[],
        };
        let mut today = p.store.day_counters(&now).await.map_err(store_error)?;
        for finding in &filings {
            let action = self
                .file(&scope, finding, &investigation, &mut today, &now)
                .await;
            let _issue = tracing::info_span!(
                "factory.triage_issue",
                "factory.troubleshooting_run_id" = %run_id.as_str(),
                "factory.issue_action" = action.label(),
            )
            .entered();
            tracing::info!(
                monotonic_counter.factory_triage_issues_total = 1_u64,
                action = action.label()
            );
            report.issues.push(action);
        }
        if !p.settings.dry_run
            && !filings.is_empty()
            && let Err(error) = p.issues.revoke_run_tokens(&run_id).await
        {
            tracing::warn!(
                "factory.troubleshooting_run_id" = %run_id.as_str(),
                "the run's GitHub token could not be revoked: {error}"
            );
        }

        let deferred: Vec<Sha256Digest> = report
            .issues
            .iter()
            .filter_map(|action| match action {
                IssueAction::Deferred(digest) => Some(digest.clone()),
                _ => None,
            })
            .collect();
        let count = |word: &str| {
            u32::try_from(report.issues.iter().filter(|a| a.label() == word).count())
                .unwrap_or(u32::MAX)
        };
        p.store
            .finish_run(&RunEnd {
                id: run_id.clone(),
                ended_at: p.clock.now(),
                outcome,
                spend_micro_usd: spend,
                report_sha256: report_digest,
                gateway_record_sha256: record.as_ref().and_then(|r| r.digest().ok()),
                agent_ran: report.agent_ran,
                issues_opened: count("opened"),
                comments_posted: count("commented"),
                deferred,
            })
            .await
            .map_err(store_error)?;
        span.record("factory.result", outcome.as_str());
        tracing::info!(
            monotonic_counter.factory_troubleshooting_runs_total = 1_u64,
            trigger = run_trigger.as_str(),
            result = outcome.as_str()
        );
        report.outcome = Some(outcome);
        Ok(report)
    }

    /// Finishes, as `failed`, the runs a stopped process left open.
    async fn close_abandoned_runs(&self, now: &Timestamp) {
        let Ok(open) = self.parts.store.unfinished_runs().await else {
            return;
        };
        for run in open {
            let _ = self
                .parts
                .store
                .finish_run(&RunEnd {
                    id: run.id,
                    ended_at: *now,
                    outcome: RunOutcome::Failed,
                    spend_micro_usd: run.spend_micro_usd,
                    report_sha256: None,
                    gateway_record_sha256: None,
                    agent_ran: run.agent_ran,
                    issues_opened: 0,
                    comments_posted: 0,
                    deferred: Vec::new(),
                })
                .await;
        }
    }

    async fn run_probes(
        &self,
        run_id: &TroubleshootingRunId,
        now: &Timestamp,
    ) -> Vec<ProbeObservation> {
        let p = &self.parts;
        let sources = ProbeSources {
            gateway: p.gateway.clone(),
            health: Arc::clone(&p.health),
            api_base_url: p.settings.api_base_url.clone(),
            health_timeout: p.settings.health_timeout,
            victoriametrics: p.settings.victoriametrics,
            datadog: p.settings.datadog,
        };
        let mut found = Vec::with_capacity(p.policy.probes.len());
        for probe in &p.policy.probes {
            let span = tracing::info_span!(
                "factory.probe",
                "factory.troubleshooting_run_id" = %run_id.as_str(),
                "factory.probe_id" = %probe.id,
                "factory.result" = tracing::field::Empty,
            );
            let observation = run_probe(&sources, run_id.as_str(), probe, now).await;
            span.record("factory.result", result_word(observation.outcome));
            tracing::info!(
                monotonic_counter.factory_probe_results_total = 1_u64,
                probe = probe.id.as_str(),
                result = result_word(observation.outcome)
            );
            let stored = ProbeResult {
                probe_id: probe.id.clone(),
                outcome: observation.outcome,
                value: observation.value.as_ref().map(|v| {
                    let text = v.canonical();
                    if text.len() > 64 {
                        one_line(&text, 60)
                    } else {
                        text
                    }
                }),
                call_id: observation.call_id.clone(),
                run: Some(run_id.clone()),
                checked_at: *now,
            };
            if let Err(error) = p.store.record_probe(&stored).await {
                tracing::warn!(
                    "factory.troubleshooting_run_id" = %run_id.as_str(),
                    "a probe result was not stored: {error}"
                );
            }
            found.push(observation);
        }
        found
    }

    /// The window the run looks at: the longest window of the probes that tripped, the sweep
    /// period for a sweep, the probe period for a run of unavailable sources only.
    fn window(
        &self,
        trigger: Option<RunTrigger>,
        eligible: &[&ProbeObservation],
        now: &Timestamp,
    ) -> (Timestamp, Timestamp) {
        let schedule = &self.parts.policy.schedule;
        let seconds = match trigger {
            Some(RunTrigger::Probe) => eligible
                .iter()
                .map(|o| o.probe.window_s)
                .max()
                .unwrap_or(3600),
            Some(RunTrigger::Sweep) => schedule.sweep_period_s,
            None => schedule.probe_period_s,
        };
        let from = now
            .checked_sub(Duration::from_secs(seconds))
            .unwrap_or(*now);
        (from, *now)
    }

    #[allow(clippy::too_many_arguments)]
    async fn agent_run(
        &self,
        run_id: &TroubleshootingRunId,
        trigger: RunTrigger,
        eligible: &[&ProbeObservation],
        window: &(Timestamp, Timestamp),
        now: &Timestamp,
        ceiling: u64,
        token: &factory_mcp_gateway::RunToken,
    ) -> AgentRun {
        let p = &self.parts;
        let mut run = AgentRun {
            ran: false,
            spend: 0,
            digest: None,
            outcome: RunOutcome::Failed,
            findings: Vec::new(),
        };
        // Never two agent runs at a time (`max_concurrent_agent_runs` is 1 by the policy's rule).
        let Ok(_slot) = self.agent_slot.try_acquire() else {
            tracing::warn!(
                "factory.troubleshooting_run_id" = %run_id.as_str(),
                "an agent run is already going on; this run starts none"
            );
            return run;
        };
        let prompt = match self.prompt(run_id, trigger, eligible, window, now).await {
            Ok(prompt) => prompt,
            Err(why) => {
                tracing::warn!(
                    "factory.troubleshooting_run_id" = %run_id.as_str(),
                    "the agent's prompt could not be built: {why}"
                );
                return run;
            }
        };
        if p.store
            .add_to_day(
                now,
                DayIncrement {
                    agent_runs: 1,
                    ..DayIncrement::default()
                },
            )
            .await
            .is_err()
        {
            return run;
        }
        if trigger == RunTrigger::Probe {
            let ids: Vec<String> = eligible.iter().map(|o| o.probe.id.clone()).collect();
            let _ = p
                .store
                .start_cooldown(&ids, &cooldown_until(&p.policy.schedule, now))
                .await;
        }
        let tools: Vec<McpToolName> = p
            .gateway
            .catalog_report()
            .offered
            .iter()
            .filter_map(|tool| McpToolName::new(&tool.gateway_name).ok())
            .collect();
        let result = p
            .agent
            .run(AgentJob {
                run_id: run_id.clone(),
                tenant: p.settings.tenant,
                prompt,
                gateway_token: McpRunTokenSecret::new(token.expose().to_owned()),
                tools,
                ceiling: CostMicroUsd(ceiling),
            })
            .await;
        run.ran = true;
        run.spend = result.usage.cost.0;
        let _ = p
            .store
            .add_to_day(
                now,
                DayIncrement {
                    spend_micro_usd: run.spend,
                    ..DayIncrement::default()
                },
            )
            .await;
        let bytes = match result.output {
            Ok(bytes) => bytes,
            Err(_) => {
                run.outcome = RunOutcome::AgentFailed;
                return run;
            }
        };
        run.digest = Some(Sha256Digest::of(&bytes));
        let Some(record) = p.gateway.run_record(run_id.as_str()) else {
            return run;
        };
        match check_report(&bytes, &p.kit.output_schema, &record) {
            Err(Refused::Invalid(why)) => {
                tracing::warn!(
                    "factory.troubleshooting_run_id" = %run_id.as_str(),
                    "the agent's report was refused: {why}"
                );
                run.outcome = RunOutcome::ReportInvalid;
            }
            Err(Refused::Evidence(why)) => {
                tracing::warn!(
                    "factory.troubleshooting_run_id" = %run_id.as_str(),
                    "the agent's report cites evidence it may not cite: {why}"
                );
                run.outcome = RunOutcome::EvidenceMismatch;
            }
            Ok(report) => {
                run.outcome = match report.status {
                    ReportStatus::Healthy => RunOutcome::Healthy,
                    ReportStatus::Findings => RunOutcome::Findings,
                    ReportStatus::NeedsHuman => RunOutcome::NeedsHuman,
                    ReportStatus::Blocked => RunOutcome::Blocked,
                };
                if report.status == ReportStatus::Findings {
                    run.findings = report.findings;
                }
            }
        }
        run
    }

    /// The `troubleshooter-input` document, checked against its schema.
    ///
    /// # Errors
    /// Why it could not be built.
    pub async fn input_document(
        &self,
        run_id: &TroubleshootingRunId,
        trigger: RunTrigger,
        eligible: &[&ProbeObservation],
        window: &(Timestamp, Timestamp),
        now: &Timestamp,
    ) -> Result<Value, String> {
        let p = &self.parts;
        let ends_at = now
            .checked_add(Duration::from_secs(p.policy.gateway.run_wall_clock_s))
            .unwrap_or(*now);
        let tripped: Vec<Value> = eligible
            .iter()
            .take(16)
            .map(|o| {
                let mut item = json!({
                    "probe_id": o.probe.id,
                    "kind": kind_word(o.probe.kind),
                    "description": one_line(&o.probe.description, 300),
                    "query": one_line(&o.probe.query, 2000),
                    "comparator": comparator_word(o.probe.comparator),
                    "threshold": o.probe.threshold,
                    "observed": o.value.as_ref().and_then(Exact::approximate).unwrap_or(0.0),
                    "window_s": o.probe.window_s,
                    "severity": severity_word(o.probe.severity),
                    "observed_at": o.observed_at.as_text(),
                });
                if let Some(call) = &o.call_id {
                    item["call_id"] = json!(call.as_str());
                }
                item
            })
            .collect();
        let listed = p.gateway.listed_tools();
        let tools: Vec<Value> = p
            .gateway
            .catalog_report()
            .offered
            .iter()
            .take(40)
            .map(|tool| {
                let description = listed
                    .iter()
                    .find(|t| t.name == tool.gateway_name)
                    .and_then(|t| t.description.as_deref())
                    .map(|d| one_line(d, 1000))
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| "No description.".to_owned());
                json!({
                    "name": tool.gateway_name,
                    "upstream": tool.upstream.as_str(),
                    "description": description,
                })
            })
            .collect();
        let open: Vec<Value> = p
            .store
            .issues(50)
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .map(|entry| {
                json!({
                    "fingerprint": entry.fingerprint.as_str(),
                    "category": entry.category,
                    "component": entry.component,
                    "title": one_line(&entry.title, 100),
                    "issue_number": entry.issue_number,
                    "opened_at": entry.opened_at.as_text(),
                })
            })
            .collect();
        let document = json!({
            "run_metadata": {
                "run_id": run_id.as_str(),
                "started_at": now.as_text(),
                "ends_at": ends_at.as_text(),
                "max_gateway_calls": p.policy.gateway.max_calls_per_run,
                "policy_hash": p.policy_hash.as_str(),
            },
            "trigger": { "kind": trigger.as_str() },
            "tripped_probes": if trigger == RunTrigger::Probe { tripped } else { Vec::new() },
            "gateway_tools": tools,
            "time_window": { "from": window.0.as_text(), "to": window.1.as_text() },
            "open_findings": open,
        });
        p.kit.input_schema.check(&document).map_err(|issues| {
            format!(
                "{} problem(s) against troubleshooter-input v1",
                issues.len()
            )
        })?;
        Ok(document)
    }

    async fn prompt(
        &self,
        run_id: &TroubleshootingRunId,
        trigger: RunTrigger,
        eligible: &[&ProbeObservation],
        window: &(Timestamp, Timestamp),
        now: &Timestamp,
    ) -> Result<factory_ports::agent::AssembledPrompt, String> {
        let p = &self.parts;
        let document = self
            .input_document(run_id, trigger, eligible, window, now)
            .await?;
        let tenant = p.settings.tenant;
        let inputs: Vec<Input> = [
            ("run_metadata", ContentClass::ToolOutput),
            ("trigger", ContentClass::ToolOutput),
            ("tripped_probes", ContentClass::ToolOutput),
            ("gateway_tools", ContentClass::ToolOutput),
            ("time_window", ContentClass::ToolOutput),
            ("open_findings", ContentClass::ModelOutput),
        ]
        .into_iter()
        .map(|(name, class)| {
            let text = serde_json::to_string_pretty(&document[name]).unwrap_or_default();
            Input::untrusted(
                name,
                class,
                Source::ToolOutput {
                    producer: "troubleshooter".to_owned(),
                },
                tenant,
                text.into_bytes(),
            )
            .fetched_at(*now)
        })
        .collect();
        let assembled = Assembler::new(&p.redactor, &p.kit.paths, Limits::default())
            .assemble(AssemblyRequest::new(
                &p.kit.manifest,
                &p.kit.prompt,
                Scope::new(tenant, RepoKind::Factory),
                inputs,
            ))
            .map_err(|e| e.to_string())?;
        Ok(assembled.to_port_prompt())
    }

    /// What to do about one prepared finding.
    async fn file(
        &self,
        scope: &RunScope,
        finding: &Finding,
        investigation: &Investigation<'_>,
        today: &mut DayCounters,
        now: &Timestamp,
    ) -> IssueAction {
        let p = &self.parts;
        let issue = match render_issue(finding, investigation, &self.labels) {
            Ok(issue) => issue,
            Err(error) => return IssueAction::Failed(error.to_string()),
        };
        let fingerprint: FindingFingerprint = issue.fingerprint().clone();
        let digest = fingerprint.digest().clone();
        let entry = match p.store.issue_for(&digest).await {
            Ok(entry) => entry,
            Err(error) => return IssueAction::Failed(error.to_string()),
        };
        if p.settings.dry_run {
            let target = entry.as_ref().map_or_else(
                || format!("open a new issue in {}", scope.repo),
                |e| {
                    format!(
                        "comment on #{} (or open a new issue if it was closed)",
                        e.issue_number
                    )
                },
            );
            return IssueAction::DryRun(format!(
                "would {target}: {:?} ({})",
                issue.title(),
                digest.as_str()
            ));
        }
        let open = match p.issues.find_open_issue(scope, &fingerprint).await {
            Ok(open) => open,
            Err(error) => return IssueAction::Failed(github_reason(&error)),
        };
        let max_comments = p.policy.issues.max_comments_per_issue_per_day;
        let max_new = p.policy.issues.max_new_per_day;
        let record = |number: u64| NewIssue {
            fingerprint: fingerprint.digest(),
            category: finding.category.as_str(),
            component: finding.component.as_str(),
            title: issue.title(),
            repository: "",
            issue_number: number,
            opened_at: now,
        };
        let repository = scope.repo.to_string();
        if let Some(open) = open {
            if entry.as_ref().is_none_or(|e| e.issue_number != open.number) {
                let _ = p
                    .store
                    .record_issue(&NewIssue {
                        repository: &repository,
                        ..record(open.number)
                    })
                    .await;
            }
            if !may_comment(max_comments, entry.as_ref(), now) {
                return IssueAction::Unchanged(open.number);
            }
            let comment = match render_seen_again(finding, investigation) {
                Ok(comment) => comment,
                Err(error) => return IssueAction::Failed(error.to_string()),
            };
            if let Err(error) = p.issues.post_seen_again(scope, &open, &comment).await {
                return IssueAction::Failed(github_reason(&error));
            }
            let _ = p.store.record_comment(&digest, now).await;
            if let Ok(counted) = p
                .store
                .add_to_day(
                    now,
                    DayIncrement {
                        comments: 1,
                        ..DayIncrement::default()
                    },
                )
                .await
            {
                *today = counted;
            }
            return IssueAction::Commented(open.number);
        }
        if !may_open_issue(max_new, today) {
            return IssueAction::Deferred(digest);
        }
        // A person closed the earlier issue of this fingerprint: name it, do not reopen it.
        let issue = match entry.as_ref() {
            Some(earlier) => {
                let named = Investigation {
                    earlier_closed_issue: Some(earlier.issue_number),
                    ..investigation.clone()
                };
                match render_issue(finding, &named, &self.labels) {
                    Ok(issue) => issue,
                    Err(error) => return IssueAction::Failed(error.to_string()),
                }
            }
            None => issue.clone(),
        };
        let (number, new) = match p.issues.open_issue(scope, &issue).await {
            Ok(OpenedIssue::Opened(opened)) => (opened.number, true),
            Ok(OpenedIssue::AlreadyOpen(open)) => (open.number, false),
            Err(error) => return IssueAction::Failed(github_reason(&error)),
        };
        let _ = p
            .store
            .record_issue(&NewIssue {
                repository: &repository,
                title: issue.title(),
                ..record(number)
            })
            .await;
        if new {
            if let Ok(counted) = p
                .store
                .add_to_day(
                    now,
                    DayIncrement {
                        new_issues: 1,
                        ..DayIncrement::default()
                    },
                )
                .await
            {
                *today = counted;
            }
            IssueAction::Opened(number)
        } else {
            IssueAction::Unchanged(number)
        }
    }
}

struct AgentRun {
    ran: bool,
    spend: u64,
    digest: Option<Sha256Digest>,
    outcome: RunOutcome,
    findings: Vec<Finding>,
}

fn github_reason(error: &GitHostError) -> String {
    format!("GitHub: {error}")
}

/// Counts the calls of a closed gateway run by upstream and outcome.
fn gateway_metrics(record: &RunRecord) {
    for call in &record.calls {
        let upstream = call.upstream.map_or("none", |u| u.as_str());
        let outcome = call.outcome.to_string();
        let result = outcome.split(':').next().unwrap_or("unknown");
        tracing::info!(
            monotonic_counter.factory_gateway_calls_total = 1_u64,
            upstream = upstream,
            result = result
        );
    }
}

const fn kind_word(kind: ProbeKind) -> &'static str {
    match kind {
        ProbeKind::PromqlThreshold => "promql_threshold",
        ProbeKind::SqlCheck => "sql_check",
        ProbeKind::DatadogMonitorsAlerting => "datadog_monitors_alerting",
        ProbeKind::HttpHealth => "http_health",
    }
}

fn comparator_word(
    comparator: factory_domain::policy::troubleshooting::Comparator,
) -> &'static str {
    use factory_domain::policy::troubleshooting::Comparator;
    match comparator {
        Comparator::Gt => "gt",
        Comparator::Ge => "ge",
        Comparator::Lt => "lt",
        Comparator::Le => "le",
        Comparator::Eq => "eq",
        Comparator::Ne => "ne",
    }
}

fn severity_word(severity: factory_domain::policy::troubleshooting::Severity) -> &'static str {
    use factory_domain::policy::troubleshooting::Severity;
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
