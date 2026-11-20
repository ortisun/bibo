//! `policies/troubleshooting.yaml` as typed values (ADR 0021): when the troubleshooter runs its
//! probes and its agent, how many issues and comments it may write, what the MCP gateway allows a
//! run, which gateway tools exist and which upstream tool each one calls, how the upstream servers
//! are narrowed, and the probes.
//!
//! Same rules as `routing.rs`: every struct rejects unknown keys, and the file holds no key, no
//! token and no address. Reading the file, parsing the YAML and the rules that tie it to
//! `policies/security.yaml` are in `factory-contracts` (`policy::troubleshooting`); what is here is
//! pure.
//!
//! # Tighten only
//!
//! A project may lower a cap, lengthen a period or a cool-down, remove a tool, add a tool to the
//! upstream narrowing and remove a probe. It may not do the opposite. [`check_tighten`] lists every
//! place where a candidate is looser.

use super::common::{
    ConfigSource, PolicyStatus, ProjectOverrides, SchemaVersionOne, ThreatId, closed_set, strict,
};

strict! {
    /// The whole of `policies/troubleshooting.yaml`.
    pub struct TroubleshootingPolicy {
        /// Always 1.
        pub schema_version: SchemaVersionOne,
        /// Identity and global rules.
        pub policy: TroubleshootingHeader,
        /// When probes, sweeps and agent runs happen.
        pub schedule: Schedule,
        /// What the troubleshooter may write to the issue tracker.
        pub issues: Issues,
        /// What the MCP gateway allows one run.
        pub gateway: GatewayLimits,
        /// How each upstream MCP server is narrowed before the gateway allowlist applies.
        pub upstreams: Upstreams,
        /// The gateway tools: the allowlist and its mapping to upstream tools.
        pub tools: Vec<GatewayTool>,
        /// The probes.
        pub probes: Vec<Probe>,
    }
}

closed_set! {
    /// What a gateway tool that is not listed gets. The only value is a refusal.
    pub enum TroubleshootingDefault {
        /// The tool is neither listed to the agent nor callable.
        Deny,
    }
}

strict! {
    /// Identity and global rules of the troubleshooting policy.
    pub struct TroubleshootingHeader {
        /// Always `troubleshooting`.
        pub id: String,
        /// The policy version.
        pub version: u32,
        /// Designed or enforced.
        pub status: PolicyStatus,
        /// What a tool that is not listed gets. Required, and only `deny` is valid.
        pub default_action: TroubleshootingDefault,
        /// What a project policy may do.
        pub project_overrides: ProjectOverrides,
        /// Where the file must be read from.
        pub config_source: ConfigSource,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// When probes, sweeps and agent runs happen. Durations are whole seconds.
    pub struct Schedule {
        /// How often every probe runs.
        pub probe_period_s: u64,
        /// How often the agent runs a sweep with no tripped probe.
        pub sweep_period_s: u64,
        /// How long a probe that tripped and was investigated waits before it may start another
        /// agent run.
        pub probe_cooldown_s: u64,
        /// Agent runs at the same time. The only value is 1.
        pub max_concurrent_agent_runs: u32,
        /// Agent runs in one UTC day, sweeps included.
        pub max_agent_runs_per_day: u32,
    }
}

strict! {
    /// What the troubleshooter may write to the issue tracker.
    pub struct Issues {
        /// New issues in one UTC day. Findings past the cap wait in the run record.
        pub max_new_per_day: u32,
        /// Comments on one open issue in one UTC day.
        pub max_comments_per_issue_per_day: u32,
        /// The labels every issue gets. Never the trigger label of the factory and never a label of
        /// the `factory:` or `design:` namespaces.
        pub labels: Vec<String>,
    }
}

strict! {
    /// What the MCP gateway allows one agent run.
    pub struct GatewayLimits {
        /// Tool calls in one run.
        pub max_calls_per_run: u32,
        /// Tool calls in any 10 seconds, under Datadog's fair-use limit of 50.
        pub max_calls_per_10s: u32,
        /// Bytes of one tool result; the rest is replaced by a marker that says how much was cut.
        pub max_result_bytes: u64,
        /// The deadline of one call, in seconds.
        pub call_deadline_s: u64,
        /// The wall-clock end of a run, in seconds after it started.
        pub run_wall_clock_s: u64,
    }
}

closed_set! {
    /// The upstream MCP servers of the first version.
    pub enum Upstream {
        /// The Datadog MCP Server.
        Datadog,
        /// `mcp-victoriametrics`.
        Victoriametrics,
        /// The factory's read-only PostgreSQL MCP server.
        Postgres,
    }
}

impl Upstream {
    /// Every upstream.
    pub const ALL: [Self; 3] = [Self::Datadog, Self::Victoriametrics, Self::Postgres];

    /// The name in a policy tool id: `mcp.<name>.<tool>`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Datadog => "datadog",
            Self::Victoriametrics => "victoriametrics",
            Self::Postgres => "postgres",
        }
    }

    /// The prefix of the gateway tool names of this upstream (ADR 0021, Decision 3).
    #[must_use]
    pub const fn gateway_prefix(self) -> &'static str {
        match self {
            Self::Datadog => "datadog_",
            Self::Victoriametrics => "vm_",
            Self::Postgres => "pg_",
        }
    }
}

strict! {
    /// How each upstream is narrowed on its own side, a second layer under the gateway allowlist.
    pub struct Upstreams {
        /// Datadog: the `toolsets` and `omit_tools` query parameters of the server URL.
        pub datadog: DatadogNarrowing,
        /// VictoriaMetrics: the `MCP_DISABLED_TOOLS` setting of the server.
        pub victoriametrics: VictoriaMetricsNarrowing,
    }
}

strict! {
    /// The narrowing of the Datadog MCP Server.
    pub struct DatadogNarrowing {
        /// The toolsets the server URL asks for.
        pub toolsets: Vec<String>,
        /// The tools the server URL removes.
        pub omit_tools: Vec<String>,
    }
}

strict! {
    /// The narrowing of `mcp-victoriametrics`.
    pub struct VictoriaMetricsNarrowing {
        /// The tools `MCP_DISABLED_TOOLS` removes.
        pub disabled_tools: Vec<String>,
    }
}

strict! {
    /// One gateway tool: the id in the security policy's tool table, the name the agent sees, and
    /// the one upstream tool it calls.
    pub struct GatewayTool {
        /// `mcp.<upstream>.<name>`, an id of the tool table of `policies/security.yaml`.
        pub id: String,
        /// The name the gateway offers, `<prefix><name>`, such as `vm_query`.
        pub gateway_name: String,
        /// The upstream server.
        pub upstream: Upstream,
        /// The tool's name on the upstream server.
        pub upstream_tool: String,
    }
}

closed_set! {
    /// What a probe checks.
    pub enum ProbeKind {
        /// A PromQL expression against VictoriaMetrics, compared with a threshold.
        PromqlThreshold,
        /// A fixed check of `pg_factory_health`, whose count is compared with a threshold.
        SqlCheck,
        /// The number of Datadog monitors that match a query and are in Alert.
        DatadogMonitorsAlerting,
        /// The HTTP status of a health route of the factory API.
        HttpHealth,
    }
}

closed_set! {
    /// How the observed value is compared with the threshold. The probe trips when the comparison
    /// holds.
    pub enum Comparator {
        /// Greater than.
        Gt,
        /// Greater than or equal.
        Ge,
        /// Less than.
        Lt,
        /// Less than or equal.
        Le,
        /// Equal.
        Eq,
        /// Not equal.
        Ne,
    }
}

impl Comparator {
    /// True when `observed` compared with `threshold` this way holds, which trips the probe. A value
    /// that is not a number never trips it.
    #[must_use]
    pub fn trips(self, observed: f64, threshold: f64) -> bool {
        if observed.is_nan() || threshold.is_nan() {
            return false;
        }
        match self {
            Self::Gt => observed > threshold,
            Self::Ge => observed >= threshold,
            Self::Lt => observed < threshold,
            Self::Le => observed <= threshold,
            #[allow(clippy::float_cmp)]
            Self::Eq => observed == threshold,
            #[allow(clippy::float_cmp)]
            Self::Ne => observed != threshold,
        }
    }
}

closed_set! {
    /// How bad a tripped probe is.
    pub enum Severity {
        /// Low.
        Low,
        /// Medium.
        Medium,
        /// High.
        High,
        /// Critical.
        Critical,
    }
}

strict! {
    /// One probe: a typed, deterministic check with a threshold.
    pub struct Probe {
        /// The identifier, unique in the file.
        pub id: String,
        /// What it checks.
        pub kind: ProbeKind,
        /// One sentence for a person.
        pub description: String,
        /// The PromQL expression, the database check id, the monitor query, or the health route.
        pub query: String,
        /// How the observed value is compared with the threshold.
        pub comparator: Comparator,
        /// The threshold.
        pub threshold: f64,
        /// The window the query looks at, in seconds.
        pub window_s: u64,
        /// How bad a trip is.
        pub severity: Severity,
        /// The date a person ran the query against a real source (`YYYY-MM-DD`), or `unchecked`.
        pub checked_on: String,
    }
}

impl TroubleshootingPolicy {
    /// The gateway tool with this gateway name.
    #[must_use]
    pub fn tool_by_gateway_name(&self, name: &str) -> Option<&GatewayTool> {
        self.tools.iter().find(|tool| tool.gateway_name == name)
    }

    /// The probe with this id.
    #[must_use]
    pub fn probe(&self, id: &str) -> Option<&Probe> {
        self.probes.iter().find(|probe| probe.id == id)
    }

    /// Everything in the file that still waits for a person: the status, and each probe whose query
    /// nobody has run against a real source.
    #[must_use]
    pub fn unconfirmed(&self) -> Vec<String> {
        let mut found = Vec::new();
        if self.policy.status == PolicyStatus::Designed {
            found.push("policy.status is designed".to_owned());
        }
        for probe in &self.probes {
            if probe.checked_on == "unchecked" {
                found.push(format!("the query of the probe {} is unchecked", probe.id));
            }
        }
        found
    }
}

/// One place where a candidate troubleshooting policy is looser than the central one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Looser {
    /// The key, such as `schedule.max_agent_runs_per_day`.
    pub key: String,
    /// What is looser, in a few words.
    pub why: &'static str,
}

/// Every place where `candidate` is looser than `central`. Empty means the candidate only
/// tightens. Prose (descriptions, `checked_on`) is free.
#[must_use]
pub fn check_tighten(
    central: &TroubleshootingPolicy,
    candidate: &TroubleshootingPolicy,
) -> Vec<Looser> {
    let mut found = Vec::new();
    let mut loosen = |key: &str, why: &'static str| {
        found.push(Looser {
            key: key.to_owned(),
            why,
        });
    };
    let (a, b) = (&central.schedule, &candidate.schedule);
    for (key, new, old) in [
        (
            "schedule.probe_period_s",
            b.probe_period_s,
            a.probe_period_s,
        ),
        (
            "schedule.sweep_period_s",
            b.sweep_period_s,
            a.sweep_period_s,
        ),
        (
            "schedule.probe_cooldown_s",
            b.probe_cooldown_s,
            a.probe_cooldown_s,
        ),
    ] {
        if new < old {
            loosen(key, "a period or a cool-down was shortened");
        }
    }
    let caps: [(&str, u64, u64); 9] = [
        (
            "schedule.max_concurrent_agent_runs",
            b.max_concurrent_agent_runs.into(),
            a.max_concurrent_agent_runs.into(),
        ),
        (
            "schedule.max_agent_runs_per_day",
            b.max_agent_runs_per_day.into(),
            a.max_agent_runs_per_day.into(),
        ),
        (
            "issues.max_new_per_day",
            candidate.issues.max_new_per_day.into(),
            central.issues.max_new_per_day.into(),
        ),
        (
            "issues.max_comments_per_issue_per_day",
            candidate.issues.max_comments_per_issue_per_day.into(),
            central.issues.max_comments_per_issue_per_day.into(),
        ),
        (
            "gateway.max_calls_per_run",
            candidate.gateway.max_calls_per_run.into(),
            central.gateway.max_calls_per_run.into(),
        ),
        (
            "gateway.max_calls_per_10s",
            candidate.gateway.max_calls_per_10s.into(),
            central.gateway.max_calls_per_10s.into(),
        ),
        (
            "gateway.max_result_bytes",
            candidate.gateway.max_result_bytes,
            central.gateway.max_result_bytes,
        ),
        (
            "gateway.call_deadline_s",
            candidate.gateway.call_deadline_s,
            central.gateway.call_deadline_s,
        ),
        (
            "gateway.run_wall_clock_s",
            candidate.gateway.run_wall_clock_s,
            central.gateway.run_wall_clock_s,
        ),
    ];
    for (key, new, old) in caps {
        if new > old {
            loosen(key, "a cap was raised");
        }
    }
    if candidate.issues.labels != central.issues.labels {
        loosen("issues.labels", "the labels changed");
    }
    for tool in &candidate.tools {
        if !central.tools.contains(tool) {
            loosen("tools", "a gateway tool was added or remapped");
        }
    }
    let narrowing = (&central.upstreams, &candidate.upstreams);
    if narrowing
        .1
        .datadog
        .toolsets
        .iter()
        .any(|set| !narrowing.0.datadog.toolsets.contains(set))
    {
        loosen("upstreams.datadog.toolsets", "a toolset was added");
    }
    if narrowing
        .0
        .datadog
        .omit_tools
        .iter()
        .any(|tool| !narrowing.1.datadog.omit_tools.contains(tool))
    {
        loosen(
            "upstreams.datadog.omit_tools",
            "an omitted tool was put back",
        );
    }
    if narrowing
        .0
        .victoriametrics
        .disabled_tools
        .iter()
        .any(|tool| !narrowing.1.victoriametrics.disabled_tools.contains(tool))
    {
        loosen(
            "upstreams.victoriametrics.disabled_tools",
            "a disabled tool was put back",
        );
    }
    for probe in &candidate.probes {
        if central.probe(&probe.id).is_none() {
            loosen("probes", "a probe was added");
        }
    }
    found
}
