//! `policies/troubleshooting.yaml`: loading it, and the rules that tie it to the security policy
//! (ADR 0021).
//!
//! The file is read like the other policies: through a [`ProtectedPolicySource`], one document in
//! the restricted YAML subset, `schema_version` checked first, no unknown key at any depth, and a
//! hash of the canonical form. Then two sets of rules run, and a file that breaks one does not
//! load:
//!
//! * [`troubleshooting_problems`]: every number is positive and inside a sane cap, the gateway
//!   stays under Datadog's fair-use limit of 50 calls in 10 seconds, every probe id is unique and
//!   every probe is well formed for its kind, every gateway tool follows the naming scheme and maps
//!   to exactly one upstream tool that the upstream narrowing does not remove, the narrowing removes
//!   every Datadog notebook tool and every VictoriaMetrics tool ADR 0021 names, and no issue label
//!   is the factory's trigger label or in the `factory:` or `design:` namespaces.
//! * [`security_problems_of`]: every gateway tool is in the tool table of `policies/security.yaml`,
//!   held by the `troubleshooter` role, with no sandbox profile, and the gateway's per-call limits
//!   are at or under the limits of each tool there.
//!
//! No key, token or address is ever read or held here.

use std::collections::BTreeSet;

use factory_domain::policy::security::SecurityPolicy;
use factory_domain::policy::troubleshooting::{ProbeKind, TroubleshootingPolicy, Upstream};

use super::check::{Problem, ProblemKind};
use super::{
    ConfigSource, LoadedPolicy, PolicyError, PolicyLoader, ProtectedPolicySource, load_document,
    read_policy_file,
};

/// The troubleshooting policy file, relative to the checkout.
pub const TROUBLESHOOTING_FILE: &str = "policies/troubleshooting.yaml";

/// The role that holds the gateway tools.
pub const TROUBLESHOOTER_ROLE: &str = "troubleshooter";

/// The longest description of a gateway tool, in characters. The gateway offers it to the model
/// as the tool's description (TR-7 of the security review).
pub const MAX_TOOL_DESCRIPTION_CHARS: usize = 300;

/// Datadog's fair-use limit: tool calls in any 10 seconds (ADR 0021, "What was checked").
pub const DATADOG_FAIR_USE_CALLS_PER_10S: u32 = 50;

/// Every notebook tool of the Datadog core toolset. Each can write, so the server URL must omit
/// every one of them (ADR 0021, Decision 3).
pub const DATADOG_NOTEBOOK_TOOLS: [&str; 9] = [
    "create_datadog_notebook",
    "create_datadog_notebook_v2",
    "edit_datadog_notebook",
    "edit_datadog_notebook_v2",
    "append_datadog_notebook",
    "replace_datadog_notebook_section",
    "update_datadog_notebook_widget",
    "delete_datadog_notebook",
    "recover_datadog_notebook",
];

/// The VictoriaMetrics tools `MCP_DISABLED_TOOLS` must remove: `export`, every debug tool, and
/// `documentation`, which the gateway never offers and whose search index holds about 705 MiB in
/// the server (measured 2026-11-20; about 18 MiB without it).
pub const VICTORIAMETRICS_DISABLED_TOOLS: [&str; 8] = [
    "export",
    "flags",
    "metric_relabel_debug",
    "downsampling_filters_debug",
    "retention_filters_debug",
    "test_rules",
    "metric_statistics",
    "documentation",
];

/// The fixed checks of `pg_factory_health` a `sql_check` probe may name (ADR 0021, Decision 4).
pub const SQL_CHECKS: [&str; 5] = [
    "jobs_by_state",
    "stage_runs_past_deadline",
    "leases_past_expiry",
    "human_waits_past_expiry",
    "failures_by_reason",
];

/// The longest label name GitHub accepts, in characters.
const MAX_LABEL: usize = 50;

impl PolicyLoader {
    /// Loads `policies/troubleshooting.yaml` and checks it against the security policy.
    ///
    /// # Errors
    /// A [`PolicyError`]. No policy value exists after an error.
    pub fn load_troubleshooting(
        source: &ProtectedPolicySource,
        security: &SecurityPolicy,
    ) -> Result<LoadedPolicy<TroubleshootingPolicy>, PolicyError> {
        let (label, text, file_sha256) = read_policy_file(source, TROUBLESHOOTING_FILE)?;
        load_document(
            &label,
            &text,
            file_sha256,
            |p: &TroubleshootingPolicy| p.policy.config_source,
            |p: &TroubleshootingPolicy| {
                let mut found = troubleshooting_problems(p);
                found.extend(security_problems_of(p, security));
                found
            },
        )
    }
}

fn problem(path: impl Into<String>, kind: ProblemKind, message: impl Into<String>) -> Problem {
    Problem {
        path: path.into(),
        kind,
        message: message.into(),
    }
}

/// Records a problem when `value` is outside `low..=high`.
fn within(found: &mut Vec<Problem>, path: &str, value: u64, low: u64, high: u64) {
    if value < low || value > high {
        found.push(problem(
            path,
            ProblemKind::Constraint,
            format!("{value} is outside the allowed range {low} to {high}"),
        ));
    }
}

fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 10
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            _ => b.is_ascii_digit(),
        })
}

fn is_name(text: &str, max: usize) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && text.len() <= max
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The rules the file must satisfy on its own.
#[must_use]
pub fn troubleshooting_problems(policy: &TroubleshootingPolicy) -> Vec<Problem> {
    let mut found = Vec::new();
    header_problems(policy, &mut found);
    schedule_problems(policy, &mut found);
    label_problems(policy, &mut found);
    gateway_problems(policy, &mut found);
    narrowing_problems(policy, &mut found);
    tool_problems(policy, &mut found);
    probe_problems(policy, &mut found);
    found
}

fn header_problems(policy: &TroubleshootingPolicy, found: &mut Vec<Problem>) {
    if policy.policy.id != "troubleshooting" {
        found.push(problem(
            "policy.id",
            ProblemKind::Constraint,
            "this file must be the troubleshooting policy, with `id: troubleshooting`",
        ));
    }
    if policy.policy.version == 0 {
        found.push(problem(
            "policy.version",
            ProblemKind::Constraint,
            "the version starts at 1",
        ));
    }
    if policy.policy.config_source != ConfigSource::ProtectedDefaultBranch {
        found.push(problem(
            "policy.config_source",
            ProblemKind::Constraint,
            "the troubleshooting policy is read from the protected default branch",
        ));
    }
}

fn schedule_problems(policy: &TroubleshootingPolicy, found: &mut Vec<Problem>) {
    let s = &policy.schedule;
    within(
        found,
        "schedule.probe_period_s",
        s.probe_period_s,
        60,
        3_600,
    );
    within(
        found,
        "schedule.sweep_period_s",
        s.sweep_period_s,
        3_600,
        604_800,
    );
    within(
        found,
        "schedule.probe_cooldown_s",
        s.probe_cooldown_s,
        s.probe_period_s.max(1),
        604_800,
    );
    within(
        found,
        "schedule.max_concurrent_agent_runs",
        s.max_concurrent_agent_runs.into(),
        1,
        1,
    );
    within(
        found,
        "schedule.max_agent_runs_per_day",
        s.max_agent_runs_per_day.into(),
        1,
        24,
    );
    if s.sweep_period_s < s.probe_period_s {
        found.push(problem(
            "schedule.sweep_period_s",
            ProblemKind::Constraint,
            "the sweep is the slow run; its period may not be shorter than the probe period",
        ));
    }
    let i = &policy.issues;
    within(
        found,
        "issues.max_new_per_day",
        i.max_new_per_day.into(),
        1,
        10,
    );
    within(
        found,
        "issues.max_comments_per_issue_per_day",
        i.max_comments_per_issue_per_day.into(),
        1,
        1,
    );
}

fn label_problems(policy: &TroubleshootingPolicy, found: &mut Vec<Problem>) {
    let labels = &policy.issues.labels;
    if labels.is_empty() || labels.len() > 10 {
        found.push(problem(
            "issues.labels",
            ProblemKind::Constraint,
            "an issue gets between one and ten labels",
        ));
    }
    let mut seen = BTreeSet::new();
    for (i, label) in labels.iter().enumerate() {
        let at = format!("issues.labels[{i}]");
        let lower = label.to_lowercase();
        if !seen.insert(lower.clone()) {
            found.push(problem(
                &at,
                ProblemKind::DuplicateId,
                format!("the label `{label}` is listed twice (GitHub ignores case)"),
            ));
        }
        if label.trim() != label || label.is_empty() || label.chars().count() > MAX_LABEL {
            found.push(problem(
                &at,
                ProblemKind::Constraint,
                format!("a label has 1 to {MAX_LABEL} characters and no space at either end"),
            ));
        }
        let squeezed: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
        if squeezed == "factory"
            || squeezed.starts_with("factory:")
            || squeezed.starts_with("design:")
        {
            found.push(problem(
                &at,
                ProblemKind::Constraint,
                format!(
                    "`{label}` is the factory's trigger label or in the `factory:` or `design:` namespace; a finding must never become factory work or a design state by its label"
                ),
            ));
        }
    }
}

fn gateway_problems(policy: &TroubleshootingPolicy, found: &mut Vec<Problem>) {
    let g = &policy.gateway;
    within(
        found,
        "gateway.max_calls_per_run",
        g.max_calls_per_run.into(),
        1,
        100,
    );
    within(
        found,
        "gateway.max_calls_per_10s",
        g.max_calls_per_10s.into(),
        1,
        DATADOG_FAIR_USE_CALLS_PER_10S.into(),
    );
    within(
        found,
        "gateway.max_result_bytes",
        g.max_result_bytes,
        1_024,
        1_048_576,
    );
    within(found, "gateway.call_deadline_s", g.call_deadline_s, 1, 60);
    within(
        found,
        "gateway.run_wall_clock_s",
        g.run_wall_clock_s,
        60,
        3_600,
    );
    if g.call_deadline_s > g.run_wall_clock_s {
        found.push(problem(
            "gateway.call_deadline_s",
            ProblemKind::Constraint,
            "one call may not outlast the run",
        ));
    }
}

fn duplicates(found: &mut Vec<Problem>, path: &str, items: &[String]) {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item.as_str()) {
            found.push(problem(
                path,
                ProblemKind::DuplicateId,
                format!("`{item}` is listed twice"),
            ));
        }
    }
}

fn narrowing_problems(policy: &TroubleshootingPolicy, found: &mut Vec<Problem>) {
    let datadog = &policy.upstreams.datadog;
    if datadog.toolsets != ["core"] {
        found.push(problem(
            "upstreams.datadog.toolsets",
            ProblemKind::Constraint,
            "the Datadog server is asked for the `core` toolset and no other",
        ));
    }
    duplicates(found, "upstreams.datadog.omit_tools", &datadog.omit_tools);
    for tool in DATADOG_NOTEBOOK_TOOLS {
        if !datadog.omit_tools.iter().any(|t| t == tool) {
            found.push(problem(
                "upstreams.datadog.omit_tools",
                ProblemKind::Constraint,
                format!("the notebook tool `{tool}` can write and must be omitted"),
            ));
        }
    }
    let vm = &policy.upstreams.victoriametrics;
    duplicates(
        found,
        "upstreams.victoriametrics.disabled_tools",
        &vm.disabled_tools,
    );
    for tool in VICTORIAMETRICS_DISABLED_TOOLS {
        if !vm.disabled_tools.iter().any(|t| t == tool) {
            found.push(problem(
                "upstreams.victoriametrics.disabled_tools",
                ProblemKind::Constraint,
                format!("the tool `{tool}` must be disabled on the VictoriaMetrics server"),
            ));
        }
    }
}

fn tool_problems(policy: &TroubleshootingPolicy, found: &mut Vec<Problem>) {
    if policy.tools.is_empty() {
        found.push(problem(
            "tools",
            ProblemKind::Constraint,
            "the gateway offers at least one tool, or no run can look at anything",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for (i, tool) in policy.tools.iter().enumerate() {
        let at = |field: &str| format!("tools[{i}].{field}");
        if !ids.insert(tool.id.as_str()) {
            found.push(problem(
                at("id"),
                ProblemKind::DuplicateId,
                format!("the tool `{}` is listed twice", tool.id),
            ));
        }
        if !names.insert(tool.gateway_name.as_str()) {
            found.push(problem(
                at("gateway_name"),
                ProblemKind::DuplicateId,
                format!("the gateway name `{}` is used twice", tool.gateway_name),
            ));
        }
        if !targets.insert((tool.upstream.as_str(), tool.upstream_tool.as_str())) {
            found.push(problem(
                at("upstream_tool"),
                ProblemKind::DuplicateId,
                format!(
                    "the upstream tool `{}` of {} is mapped twice; each gateway tool maps to exactly one upstream tool and back",
                    tool.upstream_tool,
                    tool.upstream.as_str()
                ),
            ));
        }
        // The scheme: `mcp.<upstream>.<name>` in the security policy, `<prefix><name>` for the agent.
        let expected_id = tool
            .gateway_name
            .strip_prefix(tool.upstream.gateway_prefix())
            .filter(|name| is_name(name, 47))
            .map(|name| format!("mcp.{}.{name}", tool.upstream.as_str()));
        if expected_id.as_deref() != Some(tool.id.as_str()) {
            found.push(problem(
                at("gateway_name"),
                ProblemKind::Constraint,
                format!(
                    "the tool `{}` of {} must be offered as `{}<name>` with the id `mcp.{}.<name>`, and `<name>` is lower case letters, digits and underscores",
                    tool.id,
                    tool.upstream.as_str(),
                    tool.upstream.gateway_prefix(),
                    tool.upstream.as_str()
                ),
            ));
        }
        if !is_name(&tool.upstream_tool, 64) {
            found.push(problem(
                at("upstream_tool"),
                ProblemKind::Constraint,
                "an upstream tool name is lower case letters, digits and underscores",
            ));
        }
        // The description the model reads as the tool's definition (TR-7): the factory's words,
        // short, on one line, plain text.
        let description = tool.description.trim();
        if description.is_empty()
            || tool.description.chars().count() > MAX_TOOL_DESCRIPTION_CHARS
            || tool.description != description
            || tool
                .description
                .chars()
                .any(|c| c.is_control() || matches!(c, '<' | '>' | '`'))
        {
            found.push(problem(
                at("description"),
                ProblemKind::Constraint,
                format!(
                    "a tool description is one sentence of at most {MAX_TOOL_DESCRIPTION_CHARS} characters on one line, without control characters, `<`, `>` or backticks"
                ),
            ));
        }
        let removed = match tool.upstream {
            Upstream::Datadog => &policy.upstreams.datadog.omit_tools,
            Upstream::Victoriametrics => &policy.upstreams.victoriametrics.disabled_tools,
            Upstream::Postgres => &Vec::new(),
        };
        if removed.contains(&tool.upstream_tool) {
            found.push(problem(
                at("upstream_tool"),
                ProblemKind::Constraint,
                format!(
                    "`{}` is removed by the narrowing of {}, so the gateway could never call it",
                    tool.upstream_tool,
                    tool.upstream.as_str()
                ),
            ));
        }
    }
}

#[allow(clippy::too_many_lines)]
fn probe_problems(policy: &TroubleshootingPolicy, found: &mut Vec<Problem>) {
    if policy.probes.is_empty() || policy.probes.len() > 32 {
        found.push(problem(
            "probes",
            ProblemKind::Constraint,
            "the policy lists between one and 32 probes",
        ));
    }
    let mut ids = BTreeSet::new();
    for (i, probe) in policy.probes.iter().enumerate() {
        let at = |field: &str| format!("probes[{i}].{field}");
        if !ids.insert(probe.id.as_str()) {
            found.push(problem(
                at("id"),
                ProblemKind::DuplicateId,
                format!("the probe `{}` is listed twice", probe.id),
            ));
        }
        if !is_name(&probe.id, 63) {
            found.push(problem(
                at("id"),
                ProblemKind::Constraint,
                "a probe id is lower case letters, digits and underscores, starting with a letter",
            ));
        }
        let description = probe.description.trim();
        if description.is_empty() || probe.description.chars().count() > 300 {
            found.push(problem(
                at("description"),
                ProblemKind::Constraint,
                "a description is one sentence of at most 300 characters",
            ));
        }
        if probe.query.trim().is_empty() || probe.query.len() > 2_000 {
            found.push(problem(
                at("query"),
                ProblemKind::Constraint,
                "a query has 1 to 2000 characters",
            ));
        }
        within(found, &at("window_s"), probe.window_s, 60, 604_800);
        if !probe.threshold.is_finite() {
            found.push(problem(
                at("threshold"),
                ProblemKind::Constraint,
                "a threshold is a finite number",
            ));
        }
        let whole = probe.threshold.is_finite() && probe.threshold.fract() == 0.0;
        match probe.kind {
            ProbeKind::PromqlThreshold => {}
            ProbeKind::SqlCheck => {
                if !SQL_CHECKS.contains(&probe.query.as_str()) {
                    found.push(problem(
                        at("query"),
                        ProblemKind::UnknownReference,
                        format!(
                            "`{}` is not a check of pg_factory_health; it must be one of: {}",
                            probe.query,
                            SQL_CHECKS.join(", ")
                        ),
                    ));
                }
                if !whole || probe.threshold < 0.0 {
                    found.push(problem(
                        at("threshold"),
                        ProblemKind::Constraint,
                        "a database check counts rows, so its threshold is a whole number of 0 or more",
                    ));
                }
            }
            ProbeKind::DatadogMonitorsAlerting => {
                if !whole || probe.threshold < 0.0 {
                    found.push(problem(
                        at("threshold"),
                        ProblemKind::Constraint,
                        "a monitor probe counts monitors, so its threshold is a whole number of 0 or more",
                    ));
                }
            }
            ProbeKind::HttpHealth => {
                let route = probe.query.as_str();
                if !route.starts_with('/')
                    || route.contains("//")
                    || route.contains(char::is_whitespace)
                {
                    found.push(problem(
                        at("query"),
                        ProblemKind::Constraint,
                        "a health probe names a route of the factory API, such as /readyz, and never a host",
                    ));
                }
                if !whole || !(100.0..=599.0).contains(&probe.threshold) {
                    found.push(problem(
                        at("threshold"),
                        ProblemKind::Constraint,
                        "a health probe compares an HTTP status, a whole number from 100 to 599",
                    ));
                }
            }
        }
        if probe.checked_on != "unchecked" && !is_date(&probe.checked_on) {
            found.push(problem(
                at("checked_on"),
                ProblemKind::Constraint,
                "write the date a person ran the query against a real source as YYYY-MM-DD, or `unchecked`",
            ));
        }
    }
}

/// The rules that compare the troubleshooting policy with `policies/security.yaml`: every gateway
/// tool is a tool of the troubleshooter there, run by the gateway and not in a sandbox, and the
/// gateway's per-call limits are at or under that tool's limits.
#[must_use]
pub fn security_problems_of(
    policy: &TroubleshootingPolicy,
    security: &SecurityPolicy,
) -> Vec<Problem> {
    let mut found = Vec::new();
    for (i, tool) in policy.tools.iter().enumerate() {
        let at = format!("tools[{i}].id");
        let Some(entry) = security.tools.entries.iter().find(|e| e.id == tool.id) else {
            found.push(problem(
                at,
                ProblemKind::UnknownReference,
                format!(
                    "`{}` is not in the tool table of policies/security.yaml, so the policy engine would grant it to nobody",
                    tool.id
                ),
            ));
            continue;
        };
        if security.tools.never_grantable.contains(&tool.id) || entry.enabled == Some(false) {
            found.push(problem(
                &at,
                ProblemKind::Constraint,
                format!("`{}` is switched off or never grantable", tool.id),
            ));
        }
        if !entry.roles.iter().any(|r| r == TROUBLESHOOTER_ROLE)
            || entry.roles.iter().any(|r| r != TROUBLESHOOTER_ROLE)
        {
            found.push(problem(
                &at,
                ProblemKind::Constraint,
                format!(
                    "`{}` must be held by the `{TROUBLESHOOTER_ROLE}` role and no other in policies/security.yaml",
                    tool.id
                ),
            ));
        }
        if !entry.profiles.is_empty() {
            found.push(problem(
                &at,
                ProblemKind::Constraint,
                format!(
                    "`{}` runs in the gateway of the control plane, so its entry in policies/security.yaml names no sandbox profile",
                    tool.id
                ),
            ));
        }
        if let Some(limits) = &entry.limits {
            if policy.gateway.max_result_bytes > limits.max_result_bytes {
                found.push(problem(
                    "gateway.max_result_bytes",
                    ProblemKind::Constraint,
                    format!(
                        "the gateway allows more bytes per result than `{}` has in policies/security.yaml",
                        tool.id
                    ),
                ));
            }
            if policy.gateway.call_deadline_s > limits.timeout_s {
                found.push(problem(
                    "gateway.call_deadline_s",
                    ProblemKind::Constraint,
                    format!(
                        "the gateway allows a longer call than `{}` has in policies/security.yaml",
                        tool.id
                    ),
                ));
            }
        }
    }
    found
}
