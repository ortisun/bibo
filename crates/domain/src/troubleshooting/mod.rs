//! The troubleshooter's findings as typed values, and the pure rules that turn one into a triage
//! issue (ADR 0021, Decision 7).
//!
//! The agent returns a `health-findings` v1 report (`agents/schemas/health-findings.v1.schema.json`).
//! The engine validates it against the schema and checks that every observation cites a call the
//! gateway recorded for the run. What is here starts after that:
//!
//! * [`Finding`] is one finding of a validated report. Its identifiers are typed (a call id, a
//!   gateway tool name, a probe id), so a value that does not match the schema's pattern cannot be
//!   read. Its texts are plain strings written by the agent: untrusted.
//! * [`FindingFingerprint`] is computed by code from the category, the component and the probes or
//!   tools behind the finding. The agent never supplies it.
//! * [`TriageLabels`] can only be made from the policy, and only holds labels of the
//!   `troubleshooter` namespace. The trigger label `factory`, a `factory:` label and a `design:`
//!   label cannot be represented.
//! * [`issue`] renders the issue and the "seen again" comment from a closed template.
//!
//! Nothing here reads the clock, the network or a file.

pub mod issue;
mod neutralise;

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::macros::{patterned_string, string_enum};
use crate::policy::troubleshooting::Issues;
use crate::values::{Sha256Digest, Slug};

pub use neutralise::{code_span, one_line};

/// The `_meta` key under which the MCP gateway names the run of a call it forwards to an
/// in-process upstream, and under which the read-only PostgreSQL server looks for the scope of
/// its call budget, so that each run has a budget of its own (TR-6 of the security review). Only
/// an in-process caller the factory wrote sets it: the agent's own requests never reach an
/// upstream with their `_meta`.
pub const BUDGET_SCOPE_META_KEY: &str = "factory.troubleshooting/run_id";

/// The pattern of a run id, as `troubleshooter-input.v1.schema.json` declares it.
const RUN_ID: &str = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$";
/// The pattern of a gateway call id, as `health-findings.v1.schema.json` declares it.
const CALL_ID: &str = r"^call-[1-9][0-9]{0,3}$";
/// The pattern of a gateway tool name, as `health-findings.v1.schema.json` declares it.
const GATEWAY_TOOL: &str = r"^(datadog|vm|pg)_[a-z][a-z0-9_]{0,46}[a-z0-9]$";

patterned_string! {
    /// One troubleshooting run. A run is not a job: it has no stage, and its credential is not a
    /// job's.
    pub struct TroubleshootingRunId("troubleshooting run id") = RUN_ID,
        "use 1 to 64 letters, digits, underscores or hyphens, starting with a letter or digit"
}

patterned_string! {
    /// A call id the gateway recorded for a run, such as `call-7`.
    pub struct GatewayCallId("gateway call id") = CALL_ID,
        "use `call-` and a number from 1 to 9999"
}

patterned_string! {
    /// A gateway tool name, such as `vm_query`.
    pub struct GatewayToolName("gateway tool name") = GATEWAY_TOOL,
        "use `datadog_`, `vm_` or `pg_` and a lowercase name"
}

string_enum! {
    /// The closed list of kinds of problem.
    pub enum FindingCategory("finding category") {
        /// Stages fail.
        StageFailures = "stage_failures",
        /// Gates fail.
        GateFailures = "gate_failures",
        /// Work waits in a queue.
        QueueBacklog = "queue_backlog",
        /// Work is retried.
        Retries = "retries",
        /// Work does not move.
        StuckWork = "stuck_work",
        /// A wait for a person is overdue.
        HumanWaitOverdue = "human_wait_overdue",
        /// Spend.
        Spend = "spend",
        /// The API is not available.
        ApiAvailability = "api_availability",
        /// The database.
        Database = "database",
        /// Latency.
        Latency = "latency",
        /// Errors in the logs.
        ErrorsInLogs = "errors_in_logs",
        /// An external monitor.
        ExternalMonitor = "external_monitor",
        /// Telemetry is missing.
        TelemetryGap = "telemetry_gap",
        /// Capacity.
        Capacity = "capacity",
    }
}

string_enum! {
    /// The part of the factory a problem is in.
    pub enum FindingComponent("finding component") {
        /// The API.
        Api = "api",
        /// The worker.
        Worker = "worker",
        /// The database.
        Database = "database",
        /// The model broker.
        ModelBroker = "model_broker",
        /// The sandbox.
        Sandbox = "sandbox",
        /// Telemetry.
        Telemetry = "telemetry",
        /// The GitHub adapter.
        GithubAdapter = "github_adapter",
    }
}

string_enum! {
    /// How bad a finding is.
    pub enum FindingSeverity("finding severity") {
        /// Low.
        Low = "low",
        /// Medium.
        Medium = "medium",
        /// High.
        High = "high",
        /// Critical.
        Critical = "critical",
    }
}

/// One observation of a finding: what a gateway call showed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// The call the gateway recorded.
    pub call_id: GatewayCallId,
    /// The tool that was called.
    pub tool: GatewayToolName,
    /// What it showed, in the agent's words. Untrusted.
    pub observed: String,
}

/// One finding of a validated `health-findings` v1 report.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// The kind of problem.
    pub category: FindingCategory,
    /// How bad it is.
    pub severity: FindingSeverity,
    /// Where it is.
    pub component: FindingComponent,
    /// A short title, in the agent's words. Untrusted.
    pub title: String,
    /// The tripped probes this finding explains. Empty for a finding of a sweep.
    #[serde(default)]
    pub probe_ids: Vec<Slug>,
    /// What the gateway calls showed.
    pub observations: Vec<Observation>,
    /// What the agent thinks is wrong. Untrusted.
    pub hypothesis: String,
    /// How sure the agent is, from 0 to 1.
    pub confidence: f64,
    /// Read-only checks a person can make, in the agent's words. Untrusted.
    pub next_checks: Vec<String>,
}

/// The first line of the text the fingerprint is the hash of. A change to the encoding changes
/// this line, so an old fingerprint cannot be read as a new one.
const FINGERPRINT_ENCODING: &str = "troubleshooter-fingerprint/v1";

/// The start of the hidden marker that carries a fingerprint in an issue body.
pub const FINGERPRINT_MARKER_PREFIX: &str = "<!-- troubleshooter-fingerprint: ";

/// The end of the hidden marker.
const MARKER_SUFFIX: &str = " -->";

/// Which problem a finding is about, as code computes it: the SHA-256 of the category, the
/// component and the sorted names of the sources behind the finding. Two findings of the same
/// problem have the same fingerprint whatever order the agent listed things in, and the agent
/// never supplies it.
///
/// The sources are the tripped probes when the finding names any, and the gateway tools of its
/// observations when it names none (a finding of a sweep). A probe is a fixed, deterministic check,
/// while the agent may reach the same problem through different tools from one run to the next, so
/// a finding that a probe explains is identified by its probes alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FindingFingerprint(Sha256Digest);

impl FindingFingerprint {
    /// Computes the fingerprint of a finding.
    #[must_use]
    pub fn of(finding: &Finding) -> Self {
        let tools: Vec<&str> = finding
            .observations
            .iter()
            .map(|o| o.tool.as_str())
            .collect();
        let probes: Vec<&str> = finding.probe_ids.iter().map(Slug::as_str).collect();
        Self::compute(finding.category, finding.component, &probes, &tools)
    }

    /// The fingerprint of a category, a component, and the probes and tools behind it. The probes
    /// win when there are any. Order and repetition do not matter.
    #[must_use]
    pub fn compute(
        category: FindingCategory,
        component: FindingComponent,
        probes: &[&str],
        tools: &[&str],
    ) -> Self {
        let sources: BTreeSet<String> = if probes.is_empty() {
            tools.iter().map(|t| format!("tool:{t}")).collect()
        } else {
            probes.iter().map(|p| format!("probe:{p}")).collect()
        };
        // One field on each line. The names are patterned identifiers that hold no line break, so
        // the encoding is unambiguous.
        let mut text = format!(
            "{FINGERPRINT_ENCODING}\ncategory={}\ncomponent={}\n",
            category.as_str(),
            component.as_str()
        );
        for source in &sources {
            text.push_str("source=");
            text.push_str(source);
            text.push('\n');
        }
        Self(Sha256Digest::of(text.as_bytes()))
    }

    /// The digest, `sha256:` and 64 hex characters.
    #[must_use]
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    /// The hidden marker the issue body carries:
    /// `<!-- troubleshooter-fingerprint: sha256:<hex> -->`.
    #[must_use]
    pub fn marker(&self) -> String {
        format!(
            "{FINGERPRINT_MARKER_PREFIX}{}{MARKER_SUFFIX}",
            self.0.as_str()
        )
    }

    /// Reads the fingerprint of an issue body. Only a line that is exactly a marker counts: a
    /// marker inside other text, or with anything else on its line, is not one. `None` when there
    /// is no marker, or when the body carries two markers that differ (an edited body says nothing
    /// trustworthy about which problem it is).
    #[must_use]
    pub fn from_body(body: &str) -> Option<Self> {
        let mut found: Option<Self> = None;
        for line in body.lines() {
            let Some(inner) = line
                .strip_suffix('\r')
                .unwrap_or(line)
                .strip_prefix(FINGERPRINT_MARKER_PREFIX)
                .and_then(|rest| rest.strip_suffix(MARKER_SUFFIX))
            else {
                continue;
            };
            let digest = Sha256Digest::parse(inner).ok()?;
            match &found {
                Some(earlier) if earlier.0 != digest => return None,
                _ => found = Some(Self(digest)),
            }
        }
        found
    }
}

/// The label that every triage issue carries and that finds them.
pub const TRIAGE_LABEL: &str = "troubleshooter";

/// The start of every other triage label, such as `troubleshooter: triage`.
pub const TRIAGE_LABEL_PREFIX: &str = "troubleshooter: ";

/// The longest label name the factory writes.
const MAX_LABEL_CHARS: usize = 50;

/// Why a label cannot be a triage label.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BadTriageLabel {
    /// The name is the trigger label, or in the `factory:` or `design:` namespace.
    #[error("`{0}` belongs to the factory or to the design gate, never to the troubleshooter")]
    Reserved(String),
    /// The name is not `troubleshooter` or `troubleshooter: <name>`.
    #[error("`{0}` is not `troubleshooter` or a `troubleshooter: ` label")]
    OutsideNamespace(String),
    /// The name is longer than 50 characters, has a space at an edge or a character that is not
    /// printable ASCII.
    #[error("`{0}` is not 1 to 50 printable ASCII characters without a space at either edge")]
    Shape(String),
    /// The list does not carry `troubleshooter`, or names a label twice.
    #[error("the labels must include `troubleshooter` once and name no label twice")]
    List,
}

/// Checks one label name. Used when [`TriageLabels`] is made and again by every adapter before a
/// request.
///
/// # Errors
/// [`BadTriageLabel`].
pub fn check_triage_label_name(name: &str) -> Result<(), BadTriageLabel> {
    let lower = name.to_ascii_lowercase();
    if lower.trim() == "factory" || lower.starts_with("factory:") || lower.starts_with("design:") {
        return Err(BadTriageLabel::Reserved(name.to_owned()));
    }
    if name.is_empty()
        || name.chars().count() > MAX_LABEL_CHARS
        || name.trim() != name
        || !name.chars().all(|c| c.is_ascii_graphic() || c == ' ')
    {
        return Err(BadTriageLabel::Shape(name.to_owned()));
    }
    let in_namespace = name == TRIAGE_LABEL
        || name
            .strip_prefix(TRIAGE_LABEL_PREFIX)
            .is_some_and(|rest| !rest.trim().is_empty());
    if in_namespace {
        Ok(())
    } else {
        Err(BadTriageLabel::OutsideNamespace(name.to_owned()))
    }
}

/// The labels of a triage issue, as the policy names them. Private fields and no constructor from
/// text: the only way to get one is [`TriageLabels::from_policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageLabels(Vec<String>);

impl TriageLabels {
    /// The labels of `issues.labels` in `policies/troubleshooting.yaml`.
    ///
    /// # Errors
    /// [`BadTriageLabel`] when any label is not a triage label, when `troubleshooter` is missing or
    /// when a label is named twice.
    pub fn from_policy(issues: &Issues) -> Result<Self, BadTriageLabel> {
        let mut seen = BTreeSet::new();
        for name in &issues.labels {
            check_triage_label_name(name)?;
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err(BadTriageLabel::List);
            }
        }
        if !seen.contains(TRIAGE_LABEL) {
            return Err(BadTriageLabel::List);
        }
        Ok(Self(issues.labels.clone()))
    }

    /// The names, in the policy's order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.0.iter().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod tests;
