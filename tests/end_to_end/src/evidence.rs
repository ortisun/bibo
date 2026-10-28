//! The evidence of one run: everything the assertions read.
//!
//! The harness reads the database and GitHub, never log text. A wiring (the scripted one here, the
//! composed one later) collects these records from the store, the ledger, the audit stream, the
//! fake or real GitHub, and the telemetry it captured, and hands one [`RunEvidence`] to the
//! assertions. The type is plain data with `serde`, so a run can be saved as JSON and checked
//! again later, and a corrupted copy can be made for a mutation test.
//!
//! Where a contract document has a schema (the specification, the task graph, the evidence
//! manifest, a gate report, a ledger entry), the evidence holds it as a JSON value, and the
//! assertions read it back through the typed contract of `factory-domain`. A document that the
//! factory stored is therefore judged by the same code that judged it when it was stored.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Whether the job ran against real adapters or in test mode with labelled fakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Real adapters. A fake anywhere is a defect.
    Production,
    /// Test mode. Fakes are allowed when labelled, and never support an assurance level.
    Test,
}

impl Mode {
    /// The spelling in the contracts.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Test => "test",
        }
    }
}

/// Everything one run left behind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEvidence {
    /// The scenario id, such as `E1`.
    pub scenario: String,
    /// Which wiring produced this evidence: `scripted` or `composed`.
    pub wiring: String,
    /// The execution mode of the job.
    pub mode: Mode,
    /// The language of the request: `en` or `pt-BR`.
    pub source_language: String,
    /// The job.
    pub job: JobRecord,
    /// Every stage run of the job, superseded ones included.
    pub stage_runs: Vec<StageRunRecord>,
    /// The evidence ledger of the job, oldest first, as stored. Each element is an
    /// `evidence-ledger-entry` document.
    pub ledger: Vec<Value>,
    /// The audit stream of the job, oldest first.
    pub audit: Vec<AuditRecord>,
    /// The timeline of the job: each status change with its reason, oldest first.
    pub timeline: Vec<TimelineEntry>,
    /// The human-facing texts the factory wrote.
    pub documents: Vec<Document>,
    /// The contract documents.
    pub contracts: Contracts,
    /// What GitHub holds.
    pub github: GithubEvidence,
    /// Spans and the correlation id of events.
    pub telemetry: Telemetry,
    /// What the job spent.
    pub usage: Usage,
    /// What a hostile text tried, when the scenario has one.
    #[serde(default)]
    pub hostile: Option<Hostile>,
    /// Facts only one scenario needs, by name. See `scenarios.rs` for the names.
    #[serde(default)]
    pub facts: BTreeMap<String, Value>,
}

/// The job row and the identifiers every record shares.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    /// The job id.
    pub id: String,
    /// The job status, in the spelling of the state machine (`COMPLETED`, `REJECTED`, ...).
    pub status: String,
    /// The correlation id that every event and log line of the job must carry.
    pub correlation_id: String,
    /// The login of the person who filed the issue.
    pub requester: String,
    /// The issue number on the fixture repository.
    pub issue_number: u64,
}

/// One stage run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageRunRecord {
    /// The stage run id.
    pub id: String,
    /// The stage kind, such as `INTAKE` or `DELIVERY`.
    pub kind: String,
    /// The status, in the spelling of the state machine (`PASSED`, `SUPERSEDED`, ...).
    pub status: String,
    /// The attempts of this stage run.
    pub attempts: Vec<AttemptRecord>,
    /// How many rework rounds led to this run (0 for the first run of a stage).
    #[serde(default)]
    pub rework_round: u32,
}

/// One attempt of a stage run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    /// The attempt id.
    pub id: String,
    /// The attempt status (`SUCCEEDED`, `LEASE_LOST`, ...).
    pub status: String,
}

/// One audit event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// The position in the stream.
    pub seq: u64,
    /// What happened, such as `job.rejected` or `approval.recorded`.
    pub action: String,
    /// Who did it: a login, `factory`, or `system`.
    pub actor: String,
    /// The correlation id on the event.
    pub correlation_id: Option<String>,
    /// A short plain-English detail. Never a secret.
    #[serde(default)]
    pub detail: String,
}

/// One status change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineEntry {
    /// The position in the timeline. It orders everything that happened to the job.
    pub seq: u64,
    /// `job` or `stage_run`.
    pub subject: String,
    /// The id of the job or the stage run.
    pub subject_id: String,
    /// The stage kind, for a stage run.
    #[serde(default)]
    pub kind: Option<String>,
    /// The status before.
    pub from: String,
    /// The status after.
    pub to: String,
    /// Why, in a sentence.
    pub reason: String,
}

/// A human-facing text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    /// `specification`, `task`, `plan`, `pull_request`, `documentation` or `issue_reply`.
    pub kind: String,
    /// Where it lives, for a finding to point at.
    pub path: String,
    /// The title.
    pub title: String,
    /// The body.
    pub body: String,
    /// For `documentation`: `tutorial`, `how-to`, `reference`, `explanation`, `adr` or
    /// `changelog`.
    #[serde(default)]
    pub doc_type: Option<String>,
}

/// The contract documents of the run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contracts {
    /// The specification contract.
    #[serde(default)]
    pub specification: Option<Value>,
    /// The task graph.
    #[serde(default)]
    pub task_dag: Option<Value>,
    /// The evidence manifest.
    #[serde(default)]
    pub evidence_manifest: Option<Value>,
    /// Every gate report, with the stage run it judged.
    #[serde(default)]
    pub gate_reports: Vec<GateReportRecord>,
    /// The SHA-256 of the bytes the artifact store holds for each stored document, by name
    /// (`specification`, `task_dag`), computed again by the harness when it read them back. The
    /// manifest and the plan must cite these, not hashes the factory remembers.
    #[serde(default)]
    pub stored_hashes: BTreeMap<String, String>,
}

/// A gate report and the stage run it belongs to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateReportRecord {
    /// The stage run the report is about.
    pub stage_run_id: String,
    /// The `gate-report` document.
    pub report: Value,
}

/// What GitHub holds, read back from GitHub and not from the factory.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubEvidence {
    /// `owner/name`.
    pub repository: String,
    /// The default branch.
    pub base_branch: String,
    /// The commit at the tip of the base branch before the job started.
    pub base_sha_before: String,
    /// The commit at the tip of the base branch after the job ended.
    pub base_sha_after: String,
    /// The pull requests the job opened.
    pub pull_requests: Vec<PullRequest>,
    /// The commits on the head branch since the base, oldest first.
    pub head_commits: Vec<Commit>,
    /// The files of the head commit that the specification cites, with their SHA-256.
    pub head_files: BTreeMap<String, String>,
    /// Every path that differs between the base and the head.
    pub changed_paths: Vec<String>,
    /// The check runs on the head commit.
    pub check_runs: Vec<CheckRun>,
    /// The comments the factory posted on the issue and on the pull request.
    pub comments: Vec<String>,
    /// Every request the factory made to GitHub.
    pub requests: Vec<GithubRequest>,
    /// Every installation token that was minted for the job.
    pub tokens: Vec<TokenRecord>,
    /// The protection of the base branch, when the harness read it.
    #[serde(default)]
    pub protection: Option<ProtectionFacts>,
}

/// A pull request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    /// The number.
    pub number: u64,
    /// Whether it is a draft.
    pub draft: bool,
    /// Whether it was merged.
    pub merged: bool,
    /// `open` or `closed`.
    pub state: String,
    /// The head branch.
    pub head_branch: String,
    /// The commit at the tip of the head branch.
    pub head_sha: String,
    /// The title.
    pub title: String,
    /// The body.
    pub body: String,
}

/// A commit on the head branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    /// The commit id.
    pub sha: String,
    /// The message.
    pub message: String,
    /// The paths it changes.
    pub paths: Vec<String>,
}

/// A check run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRun {
    /// The check name.
    pub name: String,
    /// `success`, `failure`, `neutral`, ...
    pub conclusion: String,
    /// The commit it is on.
    pub head_sha: String,
}

/// One request the factory sent to GitHub.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubRequest {
    /// The HTTP method.
    pub method: String,
    /// The path, with ids in it.
    pub path: String,
}

/// An installation token the factory minted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    /// A label for the token. Never its value.
    pub id: String,
    /// The permissions it carried, by name.
    pub permissions: BTreeMap<String, String>,
    /// The repositories it was narrowed to.
    pub repositories: Vec<String>,
}

/// The protection of a branch, as the preflight reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionFacts {
    /// A pull request is required before a merge.
    pub require_pull_request: bool,
    /// How many approving reviews are required.
    pub required_approvals: u32,
    /// The required checks, and whether each is pinned to the factory's App.
    pub required_checks: Vec<RequiredCheckFacts>,
    /// A new commit dismisses earlier approvals.
    pub dismiss_stale_reviews: bool,
    /// The rules apply to administrators.
    pub enforce_admins: bool,
    /// Force pushes are allowed.
    pub allow_force_pushes: bool,
    /// Deleting the branch is allowed.
    pub allow_deletions: bool,
    /// A code owner must review a change to a protected path.
    pub require_code_owner_review: bool,
    /// Whether the factory's App may bypass the pull request requirement.
    pub app_may_bypass: bool,
}

/// A required check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCheckFacts {
    /// The check name.
    pub context: String,
    /// Whether it is pinned to the factory's App.
    pub pinned_to_app: bool,
}

/// Spans and correlation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    /// Every span the job produced.
    pub spans: Vec<Span>,
    /// Every event and log line the harness captured, with the correlation id it carried.
    pub correlated: Vec<Correlated>,
}

/// A span.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span {
    /// The span id.
    pub id: String,
    /// The parent span id.
    pub parent_id: Option<String>,
    /// The span name: `factory.job`, `factory.stage_run` or `factory.attempt`.
    pub name: String,
    /// The stage run it belongs to, for a stage run or an attempt span.
    #[serde(default)]
    pub stage_run_id: Option<String>,
    /// The attempt it belongs to, for an attempt span.
    #[serde(default)]
    pub attempt_id: Option<String>,
}

/// An event or a log line with the correlation id it carried.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correlated {
    /// `audit`, `outbox` or `log`.
    pub source: String,
    /// Which event or line, for a finding to point at.
    pub label: String,
    /// The correlation id, or `None` when it carried none.
    pub correlation_id: Option<String>,
}

/// What the job spent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    /// The total spent, in millionths of a US dollar.
    pub total_micro_usd: u64,
    /// The budget of the job, in the same unit.
    pub budget_micro_usd: u64,
    /// Model calls that started after the budget was spent.
    #[serde(default)]
    pub calls_after_exhaustion: u32,
}

/// What a hostile text tried and what came of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hostile {
    /// The actions the hostile text demanded, in words.
    pub demanded: Vec<String>,
    /// Each action the scripted agent attempted, and what happened to it.
    pub attempts: Vec<Attempt>,
    /// How many canary secrets were planted for the run.
    pub canaries_planted: u32,
    /// Where a canary was found, one entry per hit. Empty when none leaked.
    pub canary_leaks: Vec<String>,
}

/// An action a compromised agent attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    /// What it tried.
    pub action: String,
    /// `denied` or `performed`.
    pub outcome: String,
}
