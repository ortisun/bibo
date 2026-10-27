//! The rules that `cargo metadata` can prove: DEP-01 to DEP-04 and DEP-08, plus a check that the
//! workspace holds the crates the rules file lists, in the directories it lists.

use crate::finding::Finding;
use crate::metadata::{DepKind, Dependency, Member, Workspace};
use crate::rules::{AllowEntry, CrateRule, Role, Rules, normalize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, Copy)]
pub struct Options {
    /// Fail when the rules file lists a crate or binary that the workspace does not have yet.
    pub require_all_crates: bool,
}

struct Known<'a> {
    member: &'a Member,
    role: Role<'a>,
    location: String,
}

struct Edge<'a> {
    from: &'a Known<'a>,
    to: &'a Known<'a>,
    kind: DepKind,
}

pub fn check(rules: &Rules, ws: &Workspace, options: Options) -> Vec<Finding> {
    let mut findings = Vec::new();
    let known = classify(rules, ws, &mut findings);
    if options.require_all_crates {
        require_every_listed_crate(rules, &known, &mut findings);
    }

    let by_package: BTreeMap<&str, &Known<'_>> =
        known.iter().map(|k| (k.member.name.as_str(), k)).collect();
    let mut edges = Vec::new();
    for from in &known {
        for dep in &from.member.dependencies {
            if !dep.is_path {
                continue;
            }
            if let Some(to) = by_package.get(dep.name.as_str()) {
                edges.push(Edge {
                    from,
                    to,
                    kind: dep.kind,
                });
            }
        }
    }

    for edge in &edges {
        only_listed_edges(edge, &mut findings);
        points_inward(rules, edge, &mut findings);
        testkit_is_dev_only(edge, &mut findings);
    }
    no_cycle(&edges, &mut findings);
    only_binaries_wire_adapters(&known, &edges, &mut findings);
    for from in &known {
        if let Role::Library(rule) = from.role {
            external_crates_and_features(rule, from, ws, &mut findings);
        }
    }
    findings
}

/// Match every workspace member to the rules file.
fn classify<'a>(
    rules: &'a Rules,
    ws: &'a Workspace,
    findings: &mut Vec<Finding>,
) -> Vec<Known<'a>> {
    let mut known = Vec::new();
    for member in &ws.members {
        let location = format!("{}/Cargo.toml", ws.relative_dir(member));
        let Some(role) = rules.role_of_package(&member.name) else {
            findings.push(Finding::new(
                "LAYOUT",
                location,
                format!(
                    "workspace package {} is not listed in crate-dependency-rules.json",
                    member.name
                ),
            ));
            continue;
        };
        if ws.relative_dir(member) != role.path() {
            findings.push(Finding::new(
                "LAYOUT",
                location.clone(),
                format!(
                    "{} is in {} but the rules file puts it in {}",
                    member.name,
                    ws.relative_dir(member),
                    role.path()
                ),
            ));
        }
        known.push(Known {
            member,
            role,
            location,
        });
    }
    known
}

fn require_every_listed_crate(rules: &Rules, known: &[Known<'_>], findings: &mut Vec<Finding>) {
    let present: BTreeSet<&str> = known.iter().map(|k| k.member.name.as_str()).collect();
    let listed = rules
        .crates
        .iter()
        .map(|c| (c.name.as_str(), c.path.as_str()))
        .chain(
            rules
                .apps
                .iter()
                .map(|a| (a.name.as_str(), a.path.as_str())),
        );
    for (name, path) in listed {
        if !present.contains(rules.package_name(name).as_str()) {
            findings.push(Finding::new(
                "LAYOUT",
                format!("{path}/Cargo.toml"),
                format!(
                    "{} is listed in crate-dependency-rules.json but is not in the workspace",
                    rules.package_name(name)
                ),
            ));
        }
    }
}

/// DEP-01: a crate depends only on the workspace crates its entry lists.
fn only_listed_edges(edge: &Edge<'_>, findings: &mut Vec<Finding>) {
    let allowed = match (edge.from.role, edge.to.role) {
        // Binaries are composition roots: they may wire any library.
        (Role::App(_), Role::Library(_)) => true,
        (Role::Library(from), Role::Library(to)) => {
            from.depends_on.contains(&to.name)
                || (edge.kind == DepKind::Dev && from.dev_depends_on.contains(&to.name))
        }
        _ => false,
    };
    if !allowed {
        findings.push(Finding::new(
            "DEP-01",
            &edge.from.location,
            format!(
                "{} has a {} dependency on {}, which the rules file does not allow",
                edge.from.member.name,
                kind_word(edge.kind),
                edge.to.member.name
            ),
        ));
    }
}

/// DEP-02: no normal or build dependency on a crate in the same or a higher ring. Dev
/// dependencies are limited by DEP-01 and DEP-03, because testkit sits in the same ring as the
/// crates it tests.
fn points_inward(rules: &Rules, edge: &Edge<'_>, findings: &mut Vec<Finding>) {
    if edge.kind == DepKind::Dev {
        return;
    }
    let (Some(from), Some(to)) = (ring_of(rules, edge.from.role), ring_of(rules, edge.to.role))
    else {
        return;
    };
    if to >= from {
        findings.push(Finding::new(
            "DEP-02",
            &edge.from.location,
            format!(
                "{} (ring {from}) depends on {} (ring {to}); dependencies must point to a lower ring",
                edge.from.member.name, edge.to.member.name
            ),
        ));
    }
}

fn ring_of(rules: &Rules, role: Role<'_>) -> Option<u64> {
    match role {
        Role::Library(c) => Some(c.ring),
        Role::App(_) => Some(rules.app_ring()),
        Role::Tooling(_) => None,
    }
}

/// DEP-03: only dev-dependencies may name the test-support crate.
fn testkit_is_dev_only(edge: &Edge<'_>, findings: &mut Vec<Finding>) {
    if let Role::Library(to) = edge.to.role
        && to.layer == "test-support"
        && edge.kind != DepKind::Dev
    {
        findings.push(Finding::new(
            "DEP-03",
            &edge.from.location,
            format!(
                "{} has a {} dependency on {}; test support may appear only as a dev-dependency",
                edge.from.member.name,
                kind_word(edge.kind),
                edge.to.member.name
            ),
        ));
    }
}

/// A cycle needs a ring violation to exist, but Cargo allows one that runs through a
/// dev-dependency, so look for it directly. Reported under DEP-02.
fn no_cycle(edges: &[Edge<'_>], findings: &mut Vec<Finding>) {
    let mut graph: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for e in edges {
        graph
            .entry(e.from.member.name.as_str())
            .or_default()
            .insert(e.to.member.name.as_str());
    }
    let mut finished: BTreeSet<&str> = BTreeSet::new();
    let mut reported: BTreeSet<Vec<&str>> = BTreeSet::new();
    for start in graph.keys().copied() {
        let mut path: Vec<&str> = Vec::new();
        visit(
            start,
            &graph,
            &mut path,
            &mut finished,
            &mut reported,
            findings,
        );
    }
}

fn visit<'a>(
    node: &'a str,
    graph: &BTreeMap<&'a str, BTreeSet<&'a str>>,
    path: &mut Vec<&'a str>,
    finished: &mut BTreeSet<&'a str>,
    reported: &mut BTreeSet<Vec<&'a str>>,
    findings: &mut Vec<Finding>,
) {
    if let Some(at) = path.iter().position(|n| *n == node) {
        let mut cycle: Vec<&str> = path[at..].to_vec();
        let mut key = cycle.clone();
        key.sort_unstable();
        if reported.insert(key) {
            cycle.push(node);
            findings.push(Finding::new(
                "DEP-02",
                cycle[0],
                format!("dependency cycle: {}", cycle.join(" -> ")),
            ));
        }
        return;
    }
    if !finished.insert(node) {
        return;
    }
    path.push(node);
    for next in graph.get(node).into_iter().flatten() {
        visit(next, graph, path, finished, reported, findings);
    }
    path.pop();
}

/// DEP-08: a library crate depends on at most one adapter. Only binaries wire several.
fn only_binaries_wire_adapters(
    known: &[Known<'_>],
    edges: &[Edge<'_>],
    findings: &mut Vec<Finding>,
) {
    for from in known {
        if !matches!(from.role, Role::Library(_)) {
            continue;
        }
        let adapters: BTreeSet<&str> = edges
            .iter()
            .filter(|e| std::ptr::eq(e.from, from))
            .filter(|e| matches!(e.to.role, Role::Library(c) if c.layer == "adapter"))
            .map(|e| e.to.member.name.as_str())
            .collect();
        if adapters.len() > 1 {
            findings.push(Finding::new(
                "DEP-08",
                &from.location,
                format!(
                    "{} depends on {} adapters ({}); only a binary may wire more than one",
                    from.member.name,
                    adapters.len(),
                    adapters.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
}

/// DEP-04: rings 0 and 1 and the application crates use only the external crates in
/// `external_allow`, with only the listed features. Adapters, test support and dev-dependencies
/// are outside this rule.
fn external_crates_and_features(
    rule: &CrateRule,
    from: &Known<'_>,
    ws: &Workspace,
    findings: &mut Vec<Finding>,
) {
    if rule.ring > 1 && rule.layer != "application" {
        return;
    }
    let workspace_members = ws.member_names();
    for dep in &from.member.dependencies {
        let is_workspace_edge = dep.is_path && workspace_members.contains(dep.name.as_str());
        if dep.kind == DepKind::Dev || is_workspace_edge {
            continue;
        }
        let entry = rule
            .external_allow
            .iter()
            .find(|e| normalize(&e.name) == normalize(&dep.name));
        let Some(entry) = entry else {
            findings.push(Finding::new(
                "DEP-04",
                &from.location,
                format!(
                    "{} depends on the external crate {}, which is not in its external_allow list; adding one needs an architect-reviewed change to crate-dependency-rules.json",
                    from.member.name, dep.name
                ),
            ));
            continue;
        };
        let extra = features_beyond_the_list(entry, dep, ws);
        if !extra.is_empty() {
            findings.push(Finding::new(
                "DEP-04",
                &from.location,
                format!(
                    "{} enables feature(s) {} of {} that its external_allow entry does not list (allowed: {})",
                    from.member.name,
                    extra.join(", "),
                    dep.name,
                    entry.features.iter().flatten().cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
    }
}

/// The features a dependency switches on, directly or through other features, minus the ones
/// the allow entry names (and what those imply).
fn features_beyond_the_list(entry: &AllowEntry, dep: &Dependency, ws: &Workspace) -> Vec<String> {
    let Some(allowed) = &entry.features else {
        return Vec::new();
    };
    let table = ws
        .package_features
        .get(&dep.name)
        .cloned()
        .unwrap_or_default();
    let allowed_closure = feature_closure(allowed.iter().cloned(), &table);
    let mut requested: Vec<String> = dep.features.clone();
    if dep.uses_default_features {
        requested.push("default".to_string());
    }
    let mut enabled = feature_closure(requested.into_iter(), &table);
    enabled.remove("default");
    enabled.difference(&allowed_closure).cloned().collect()
}

/// Every feature reachable from `start` through the crate's own feature table. Entries that
/// switch on another crate (`dep:x`, `x/feature`) do not add a feature of this crate.
fn feature_closure(
    start: impl Iterator<Item = String>,
    table: &BTreeMap<String, Vec<String>>,
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut pending: Vec<String> = start.collect();
    while let Some(feature) = pending.pop() {
        if !seen.insert(feature.clone()) {
            continue;
        }
        for implied in table.get(&feature).into_iter().flatten() {
            if !implied.contains('/') && !implied.starts_with("dep:") {
                pending.push(implied.clone());
            }
        }
    }
    seen
}

fn kind_word(kind: DepKind) -> &'static str {
    match kind {
        DepKind::Normal => "normal",
        DepKind::Dev => "dev",
        DepKind::Build => "build",
    }
}
