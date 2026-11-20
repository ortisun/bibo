//! `policies/troubleshooting.yaml` (ADR 0021): it loads, it agrees with the security policy and the
//! troubleshooter's manifest, and a file that breaks a rule does not load. The numeric rules are
//! tested at both sides of each boundary.

mod support;

use std::collections::BTreeSet;

use factory_contracts::policy::check::Problem;
use factory_contracts::policy::troubleshooting::{
    DATADOG_NOTEBOOK_TOOLS, VICTORIAMETRICS_DISABLED_TOOLS, security_problems_of,
    troubleshooting_problems,
};
use factory_contracts::policy::troubleshooting_policy::{
    Comparator, ProbeKind, TroubleshootingPolicy, Upstream, check_tighten,
};
use factory_contracts::policy::{
    PolicyErrorKind, PolicyLoader, ProtectedPolicySource, SecurityPolicy,
};
use support::{TempDir, read_text, repo_root};

fn source() -> ProtectedPolicySource {
    ProtectedPolicySource::protected_default_branch(&repo_root(), &[])
        .expect("the repository root exists")
}

fn security() -> SecurityPolicy {
    PolicyLoader::load_security(&source())
        .expect("security")
        .document
}

fn real() -> TroubleshootingPolicy {
    PolicyLoader::load_troubleshooting(&source(), &security())
        .unwrap_or_else(|e| panic!("{e}"))
        .document
}

fn real_text() -> String {
    read_text(&repo_root().join("policies/troubleshooting.yaml"))
}

fn load_text(text: &str) -> Result<(), factory_contracts::policy::PolicyError> {
    let dir = TempDir::new("troubleshooting");
    dir.write("policies/troubleshooting.yaml", text);
    let source =
        ProtectedPolicySource::protected_default_branch(dir.path(), &[]).expect("the directory");
    PolicyLoader::load_troubleshooting(&source, &security()).map(|_| ())
}

/// Every problem of the changed policy, as `path: message`.
fn problems_after(change: impl Fn(&mut TroubleshootingPolicy)) -> Vec<String> {
    let mut policy = real();
    change(&mut policy);
    let mut found: Vec<Problem> = troubleshooting_problems(&policy);
    found.extend(security_problems_of(&policy, &security()));
    found
        .into_iter()
        .map(|p| format!("{}: {}", p.path, p.message))
        .collect()
}

fn assert_refused_at(change: impl Fn(&mut TroubleshootingPolicy), key: &str) {
    let found = problems_after(change);
    assert!(
        found.iter().any(|m| m.starts_with(key)),
        "expected a problem at `{key}`: {found:#?}"
    );
}

fn assert_accepted(change: impl Fn(&mut TroubleshootingPolicy)) {
    let found = problems_after(change);
    assert!(found.is_empty(), "{found:#?}");
}

fn troubleshooter_manifest() -> serde_json::Value {
    serde_json::from_str(&read_text(
        &repo_root().join("agents/troubleshooter/manifest.json"),
    ))
    .expect("the manifest is JSON")
}

// ---- the shipped file -------------------------------------------------------------------------

#[test]
fn the_shipped_file_loads_with_a_stable_hash_and_says_what_waits_for_a_person() {
    let a = PolicyLoader::load_troubleshooting(&source(), &security()).expect("loads");
    let b = PolicyLoader::load_troubleshooting(&source(), &security()).expect("loads again");
    assert_eq!(a.hash, b.hash);
    assert!(a.file.ends_with("policies/troubleshooting.yaml"));
    let waiting = a.document.unconfirmed();
    assert!(waiting.iter().any(|w| w.contains("designed")));
    assert_eq!(
        waiting.iter().filter(|w| w.contains("unchecked")).count(),
        a.document.probes.len()
    );
}

#[test]
fn the_shipped_numbers_are_the_ones_adr_0021_names() {
    let policy = real();
    let s = &policy.schedule;
    assert_eq!(
        (s.probe_period_s, s.sweep_period_s, s.probe_cooldown_s),
        (300, 86_400, 21_600)
    );
    assert_eq!(
        (s.max_concurrent_agent_runs, s.max_agent_runs_per_day),
        (1, 8)
    );
    assert_eq!(policy.issues.max_new_per_day, 3);
    assert_eq!(policy.issues.max_comments_per_issue_per_day, 1);
    assert_eq!(
        policy.issues.labels,
        ["troubleshooter", "troubleshooter: triage"]
    );
    let g = &policy.gateway;
    assert_eq!(
        (
            g.max_calls_per_run,
            g.max_calls_per_10s,
            g.max_result_bytes,
            g.call_deadline_s,
            g.run_wall_clock_s
        ),
        (60, 40, 65_536, 20, 900)
    );
    assert_eq!(policy.upstreams.datadog.toolsets, ["core"]);
    assert_eq!(policy.upstreams.datadog.omit_tools, DATADOG_NOTEBOOK_TOOLS);
    assert_eq!(
        policy.upstreams.victoriametrics.disabled_tools,
        VICTORIAMETRICS_DISABLED_TOOLS
    );
}

#[test]
fn the_gateway_tools_are_the_mcp_entries_of_the_security_policy_and_of_the_manifest() {
    let policy = real();
    let allowlist: BTreeSet<String> = policy.tools.iter().map(|t| t.id.clone()).collect();
    let in_security: BTreeSet<String> = security()
        .tools
        .entries
        .iter()
        .filter(|e| e.id.starts_with("mcp."))
        .map(|e| e.id.clone())
        .collect();
    assert_eq!(allowlist, in_security);
    let in_manifest: BTreeSet<String> = troubleshooter_manifest()["allowed_tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .filter(|n| n.starts_with("mcp."))
        .map(str::to_owned)
        .collect();
    assert_eq!(allowlist, in_manifest);
    let per_upstream = |u: Upstream| policy.tools.iter().filter(|t| t.upstream == u).count();
    assert_eq!(per_upstream(Upstream::Datadog), 11);
    assert_eq!(per_upstream(Upstream::Victoriametrics), 9);
    assert_eq!(per_upstream(Upstream::Postgres), 8);
    assert_eq!(
        policy
            .tool_by_gateway_name("vm_query")
            .map(|t| t.upstream_tool.as_str()),
        Some("query")
    );
    assert_eq!(
        policy
            .tool_by_gateway_name("datadog_search_logs")
            .map(|t| t.upstream_tool.as_str()),
        Some("search_datadog_logs")
    );
}

#[test]
fn the_gateway_limits_are_within_the_troubleshooter_manifest() {
    let policy = real();
    let manifest = troubleshooter_manifest();
    let limits = &manifest["resource_limits"];
    assert!(
        u64::from(policy.gateway.max_calls_per_run)
            <= limits["max_tool_calls"].as_u64().expect("calls")
    );
    assert!(
        policy.gateway.run_wall_clock_s
            <= limits["max_wall_time_seconds"].as_u64().expect("seconds")
    );
}

#[test]
fn every_probe_metric_is_a_metric_of_the_conventions() {
    let conventions = read_text(&repo_root().join("docs/observability/conventions.md"));
    for probe in real()
        .probes
        .iter()
        .filter(|p| p.kind == ProbeKind::PromqlThreshold)
    {
        let names: Vec<&str> = probe
            .query
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| w.starts_with("factory_"))
            .collect();
        assert!(!names.is_empty(), "{} names no factory metric", probe.id);
        for name in names {
            assert!(
                conventions.contains(&format!("| `{name}` |")),
                "{}: `{name}` is not in the metrics table of the conventions",
                probe.id
            );
        }
    }
}

// ---- the loader refuses a broken file ---------------------------------------------------------

#[test]
fn a_file_with_an_unknown_key_another_version_or_no_file_does_not_load() {
    let text = real_text();
    let extra = text.replace(
        "  probe_period_s: 300",
        "  probe_period_s: 300\n  jitter_s: 5",
    );
    assert_ne!(extra, text);
    assert_eq!(
        load_text(&extra).expect_err("unknown key").kind,
        PolicyErrorKind::Type
    );
    let version = text.replace("schema_version: 1", "schema_version: 2");
    assert_eq!(
        load_text(&version).expect_err("version").kind,
        PolicyErrorKind::SchemaVersion
    );
    let dir = TempDir::new("troubleshooting-missing");
    let source = ProtectedPolicySource::protected_default_branch(dir.path(), &[]).expect("dir");
    assert_eq!(
        PolicyLoader::load_troubleshooting(&source, &security())
            .expect_err("no file")
            .kind,
        PolicyErrorKind::Unavailable
    );
}

#[test]
fn the_loader_reports_a_broken_rule_with_its_key_and_line() {
    let text = real_text().replace("max_calls_per_10s: 40", "max_calls_per_10s: 51");
    let error = load_text(&text).expect_err("over the fair-use limit");
    assert_eq!(error.kind, PolicyErrorKind::Constraint);
    assert_eq!(error.key.as_deref(), Some("gateway.max_calls_per_10s"));
    assert!(error.line.is_some());
}

#[test]
fn calls_per_10_seconds_stop_at_datadogs_fair_use_limit_of_50() {
    assert_accepted(|p| p.gateway.max_calls_per_10s = 50);
    assert_refused_at(
        |p| p.gateway.max_calls_per_10s = 51,
        "gateway.max_calls_per_10s",
    );
    assert_refused_at(
        |p| p.gateway.max_calls_per_10s = 0,
        "gateway.max_calls_per_10s",
    );
}

#[test]
fn every_number_is_positive_and_inside_its_cap_at_both_boundaries() {
    type Set = fn(&mut TroubleshootingPolicy, u64);
    #[allow(clippy::cast_possible_truncation)]
    let cases: [(&str, Set, u64, u64); 11] = [
        (
            "schedule.probe_period_s",
            |p, v| p.schedule.probe_period_s = v,
            60,
            3_600,
        ),
        (
            "schedule.sweep_period_s",
            |p, v| p.schedule.sweep_period_s = v,
            3_600,
            604_800,
        ),
        (
            "schedule.probe_cooldown_s",
            |p, v| p.schedule.probe_cooldown_s = v,
            300,
            604_800,
        ),
        (
            "schedule.max_agent_runs_per_day",
            |p, v| p.schedule.max_agent_runs_per_day = v as u32,
            1,
            24,
        ),
        (
            "schedule.max_concurrent_agent_runs",
            |p, v| p.schedule.max_concurrent_agent_runs = v as u32,
            1,
            1,
        ),
        (
            "issues.max_new_per_day",
            |p, v| p.issues.max_new_per_day = v as u32,
            1,
            10,
        ),
        (
            "issues.max_comments_per_issue_per_day",
            |p, v| p.issues.max_comments_per_issue_per_day = v as u32,
            1,
            1,
        ),
        (
            "gateway.max_calls_per_run",
            |p, v| p.gateway.max_calls_per_run = v as u32,
            1,
            100,
        ),
        (
            "gateway.max_result_bytes",
            |p, v| p.gateway.max_result_bytes = v,
            1_024,
            65_536,
        ),
        (
            "gateway.call_deadline_s",
            |p, v| p.gateway.call_deadline_s = v,
            1,
            20,
        ),
        (
            "gateway.run_wall_clock_s",
            |p, v| p.gateway.run_wall_clock_s = v,
            60,
            3_600,
        ),
    ];
    for (key, set, low, high) in cases {
        assert_accepted(|p| set(p, low));
        assert_accepted(|p| set(p, high));
        assert_refused_at(|p| set(p, low - 1), key);
        assert_refused_at(|p| set(p, high + 1), key);
    }
}

#[test]
fn the_gateway_may_not_allow_more_than_the_security_policy_gives_each_tool() {
    // 65536 bytes and 20 seconds are both the security policy's limit and inside the loader's
    // own caps, so one more is refused by the comparison with the security policy.
    let found = problems_after(|p| p.gateway.max_result_bytes = 65_537);
    assert!(
        found
            .iter()
            .any(|m| m.contains("more bytes per result than `mcp.")),
        "{found:#?}"
    );
    let found = problems_after(|p| p.gateway.call_deadline_s = 21);
    assert!(
        found.iter().any(|m| m.contains("a longer call than `mcp.")),
        "{found:#?}"
    );
}

#[test]
fn a_probe_window_and_a_call_deadline_are_bounded() {
    assert_accepted(|p| p.probes[0].window_s = 60);
    assert_accepted(|p| p.probes[0].window_s = 604_800);
    assert_refused_at(|p| p.probes[0].window_s = 59, "probes[0].window_s");
    assert_refused_at(|p| p.probes[0].window_s = 604_801, "probes[0].window_s");
    assert_refused_at(
        |p| p.probes[0].threshold = f64::INFINITY,
        "probes[0].threshold",
    );
    assert_refused_at(
        |p| {
            p.schedule.sweep_period_s = 3_600;
            p.schedule.probe_period_s = 3_600;
            p.schedule.probe_cooldown_s = 3_599;
        },
        "schedule.probe_cooldown_s",
    );
}

#[test]
fn every_probe_id_is_unique_and_well_formed() {
    assert_refused_at(|p| p.probes[1].id = p.probes[0].id.clone(), "probes[1].id");
    assert_refused_at(
        |p| p.probes[0].id = "Stage-Failures".to_owned(),
        "probes[0].id",
    );
    assert_refused_at(|p| p.probes.clear(), "probes");
}

#[test]
fn a_probe_of_each_kind_must_be_well_formed() {
    let index = |kind: ProbeKind| {
        real()
            .probes
            .iter()
            .position(|p| p.kind == kind)
            .expect("a probe of the kind")
    };
    let sql = index(ProbeKind::SqlCheck);
    assert_refused_at(
        move |p| p.probes[sql].query = "select 1".to_owned(),
        &format!("probes[{sql}].query"),
    );
    assert_refused_at(
        move |p| p.probes[sql].threshold = 0.5,
        &format!("probes[{sql}].threshold"),
    );
    let http = index(ProbeKind::HttpHealth);
    for route in ["https://api.example.test/readyz", "readyz", "//readyz"] {
        assert_refused_at(
            move |p| p.probes[http].query = route.to_owned(),
            &format!("probes[{http}].query"),
        );
    }
    assert_refused_at(
        move |p| p.probes[http].threshold = 600.0,
        &format!("probes[{http}].threshold"),
    );
    let datadog = index(ProbeKind::DatadogMonitorsAlerting);
    assert_refused_at(
        move |p| p.probes[datadog].threshold = -1.0,
        &format!("probes[{datadog}].threshold"),
    );
    assert_refused_at(
        |p| p.probes[0].checked_on = "last week".to_owned(),
        "probes[0].checked_on",
    );
}

#[test]
fn no_issue_label_is_the_trigger_label_or_in_the_factory_or_design_namespace() {
    for label in [
        "factory",
        "FACTORY",
        "factory: triage",
        "factory:done",
        "Design: approved",
        "design:proposed",
    ] {
        assert_refused_at(
            move |p| p.issues.labels.push(label.to_owned()),
            "issues.labels[2]",
        );
    }
    assert_refused_at(
        |p| p.issues.labels.push("Troubleshooter".to_owned()),
        "issues.labels[2]",
    );
    assert_refused_at(|p| p.issues.labels.clear(), "issues.labels");
    assert_refused_at(|p| p.issues.labels.push("x".repeat(51)), "issues.labels[2]");
    // A label that only contains the word is fine.
    assert_accepted(|p| p.issues.labels.push("factory-health".to_owned()));
}

#[test]
fn every_gateway_tool_maps_to_exactly_one_upstream_tool_by_the_naming_scheme() {
    assert_refused_at(
        |p| p.tools[1].upstream_tool = p.tools[0].upstream_tool.clone(),
        "tools[1].upstream_tool",
    );
    assert_refused_at(
        |p| p.tools[1].gateway_name = p.tools[0].gateway_name.clone(),
        "tools[1].gateway_name",
    );
    assert_refused_at(|p| p.tools[1].id = p.tools[0].id.clone(), "tools[1].id");
    assert_refused_at(
        |p| p.tools[0].gateway_name = "dd_search_logs".to_owned(),
        "tools[0].gateway_name",
    );
    assert_refused_at(
        |p| p.tools[0].upstream = Upstream::Victoriametrics,
        "tools[0].gateway_name",
    );
    assert_refused_at(|p| p.tools.clear(), "tools");
}

#[test]
fn a_gateway_tool_outside_the_security_policy_or_removed_upstream_is_refused() {
    // Not in the tool table of the security policy.
    assert_refused_at(
        |p| {
            let mut extra = p.tools[0].clone();
            extra.id = "mcp.datadog.list_dashboards".to_owned();
            extra.gateway_name = "datadog_list_dashboards".to_owned();
            extra.upstream_tool = "list_datadog_dashboards".to_owned();
            p.tools.push(extra);
        },
        "tools[28].id",
    );
    // Mapped to a notebook tool that the Datadog narrowing omits.
    assert_refused_at(
        |p| p.tools[0].upstream_tool = "create_datadog_notebook".to_owned(),
        "tools[0].upstream_tool",
    );
    // Mapped to a VictoriaMetrics tool that the server disables.
    let vm = real()
        .tools
        .iter()
        .position(|t| t.upstream == Upstream::Victoriametrics)
        .expect("a vm tool");
    assert_refused_at(
        move |p| p.tools[vm].upstream_tool = "export".to_owned(),
        &format!("tools[{vm}].upstream_tool"),
    );
}

#[test]
fn a_gateway_tool_the_security_policy_gives_to_another_role_or_profile_is_refused() {
    let policy = real();
    let mut security = security();
    let entry = security
        .tools
        .entries
        .iter_mut()
        .find(|e| e.id == "mcp.postgres.query")
        .expect("the entry");
    entry.roles.push("builder".to_owned());
    entry.profiles.push("agent".to_owned());
    let found: Vec<String> = security_problems_of(&policy, &security)
        .into_iter()
        .map(|p| p.message)
        .collect();
    assert!(
        found.iter().any(|m| m.contains("and no other")),
        "{found:#?}"
    );
    assert!(
        found.iter().any(|m| m.contains("names no sandbox profile")),
        "{found:#?}"
    );
}

#[test]
fn the_upstream_narrowing_cannot_be_loosened() {
    assert_refused_at(
        |p| p.upstreams.datadog.toolsets.push("alerting".to_owned()),
        "upstreams.datadog.toolsets",
    );
    for tool in DATADOG_NOTEBOOK_TOOLS {
        assert_refused_at(
            move |p| p.upstreams.datadog.omit_tools.retain(|t| t != tool),
            "upstreams.datadog.omit_tools",
        );
    }
    for tool in VICTORIAMETRICS_DISABLED_TOOLS {
        assert_refused_at(
            move |p| {
                p.upstreams
                    .victoriametrics
                    .disabled_tools
                    .retain(|t| t != tool);
            },
            "upstreams.victoriametrics.disabled_tools",
        );
    }
    assert_refused_at(
        |p| {
            p.upstreams
                .datadog
                .omit_tools
                .push("create_datadog_notebook".to_owned());
        },
        "upstreams.datadog.omit_tools",
    );
}

// ---- tighten only and the comparator ---------------------------------------------------------

#[test]
fn a_project_may_tighten_and_may_not_loosen() {
    let central = real();
    assert!(check_tighten(&central, &central).is_empty());
    let mut tighter = central.clone();
    tighter.schedule.max_agent_runs_per_day = 4;
    tighter.schedule.probe_period_s = 600;
    tighter.gateway.max_calls_per_10s = 20;
    tighter.tools.retain(|t| t.upstream != Upstream::Datadog);
    tighter.probes.truncate(3);
    assert!(check_tighten(&central, &tighter).is_empty());
    let looser = |change: &dyn Fn(&mut TroubleshootingPolicy)| -> Vec<String> {
        let mut project = central.clone();
        change(&mut project);
        check_tighten(&central, &project)
            .into_iter()
            .map(|l| l.key)
            .collect()
    };
    assert_eq!(
        looser(&|p| p.schedule.max_agent_runs_per_day += 1),
        ["schedule.max_agent_runs_per_day"]
    );
    assert_eq!(
        looser(&|p| p.schedule.probe_cooldown_s -= 1),
        ["schedule.probe_cooldown_s"]
    );
    assert_eq!(
        looser(&|p| p.gateway.max_result_bytes += 1),
        ["gateway.max_result_bytes"]
    );
    assert_eq!(
        looser(&|p| p.issues.labels.push("triage".to_owned())),
        ["issues.labels"]
    );
    assert_eq!(
        looser(&|p| p.tools[0].upstream_tool = "get_datadog_trace".to_owned()),
        ["tools"]
    );
    assert_eq!(
        looser(&|p| p
            .upstreams
            .datadog
            .omit_tools
            .pop()
            .map(|_| ())
            .unwrap_or(())),
        ["upstreams.datadog.omit_tools"]
    );
    assert_eq!(
        looser(&|p| {
            let mut extra = p.probes[0].clone();
            extra.id = "another".to_owned();
            p.probes.push(extra);
        }),
        ["probes"]
    );
}

#[test]
fn the_comparator_trips_on_its_side_of_the_threshold_and_never_on_not_a_number() {
    assert!(Comparator::Gt.trips(0.26, 0.25));
    assert!(!Comparator::Gt.trips(0.25, 0.25));
    assert!(Comparator::Ge.trips(1.0, 1.0));
    assert!(Comparator::Lt.trips(0.0, 1.0));
    assert!(Comparator::Le.trips(1.0, 1.0));
    assert!(Comparator::Eq.trips(200.0, 200.0));
    assert!(Comparator::Ne.trips(503.0, 200.0));
    assert!(!Comparator::Ne.trips(200.0, 200.0));
    for comparator in [
        Comparator::Gt,
        Comparator::Ge,
        Comparator::Lt,
        Comparator::Le,
        Comparator::Eq,
        Comparator::Ne,
    ] {
        assert!(!comparator.trips(f64::NAN, 0.0));
    }
}
