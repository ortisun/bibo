//! The rules that `cargo metadata` can prove: DEP-01 to DEP-04, DEP-08 and DEP-11, plus a check
//! that the workspace holds the crates the rules file lists, in the directories it lists.

use crate::finding::Finding;
use crate::metadata::{DepKind, Dependency, Member, Workspace};
use crate::rules::{AllowEntry, CrateRule, Role, Rules, normalize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, Copy)]
pub struct Options {
    /// Do not fail when the rules file lists a crate or binary that the workspace does not have.
    /// Only the tests use this, because their fixtures list far fewer crates than the real rules.
    pub allow_missing_crates: bool,
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
    if !options.allow_missing_crates {
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
        only_binaries_use_composition(edge, &mut findings);
    }
    no_cycle(&edges, &mut findings);
    only_binaries_wire_adapters(&known, &edges, &mut findings);
    composition_is_not_a_program(&known, &mut findings);
    for from in &known {
        if let Role::Library(rule) = from.role {
            external_crates_and_features(rule, from, ws, &mut findings);
            resolved_features_stay_within_the_limits(rules, rule, from, ws, &mut findings);
        }
        dependencies_come_from_the_registry(rules, from, ws, &mut findings);
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
    // A binary and the composition library share the ring of the composition roots (ADR 0015).
    // The binary may depend on the library; DEP-11 stops every other edge into it.
    if matches!(edge.from.role, Role::App(_))
        && matches!(edge.to.role, Role::Library(c) if c.is_composition())
    {
        return;
    }
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

/// DEP-11: only a binary may depend on the composition library. A library crate in rings 0 to 2
/// that did would invert the rule that dependencies point inward (DEP-02 reports the ring as
/// well; this names the reason).
fn only_binaries_use_composition(edge: &Edge<'_>, findings: &mut Vec<Finding>) {
    let Role::Library(to) = edge.to.role else {
        return;
    };
    if !to.is_composition() || matches!(edge.from.role, Role::App(_)) {
        return;
    }
    findings.push(Finding::new(
        "DEP-11",
        &edge.from.location,
        format!(
            "{} has a {} dependency on the composition library {}; only a binary in apps/ may use it",
            edge.from.member.name,
            kind_word(edge.kind),
            edge.to.member.name
        ),
    ));
}

/// DEP-11: the composition library is a library. It has no binary target, so no `main`, and a
/// build script is the only program-like file it may hold.
fn composition_is_not_a_program(known: &[Known<'_>], findings: &mut Vec<Finding>) {
    for from in known {
        let Role::Library(rule) = from.role else {
            continue;
        };
        if !rule.is_composition() {
            continue;
        }
        for target in &from.member.binary_targets {
            findings.push(Finding::new(
                "DEP-11",
                &from.location,
                format!(
                    "{} is the composition library but has the binary target {}; a binary belongs in apps/ and the library must not contain main",
                    from.member.name,
                    target.display()
                ),
            ));
        }
    }
}

/// DEP-08: a library crate depends on at most one adapter. Only binaries and the composition
/// library wire several.
fn only_binaries_wire_adapters(
    known: &[Known<'_>],
    edges: &[Edge<'_>],
    findings: &mut Vec<Finding>,
) {
    for from in known {
        // The composition library exists to wire adapters (ADR 0015).
        if !matches!(from.role, Role::Library(c) if !c.is_composition()) {
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

/// DEP-04: every library crate (rings 0 and 1, application crates and adapters) uses only the
/// external crates in `external_allow`, with only the listed features. Test support and
/// dev-dependencies are outside this rule. Adapters were exempt until review finding F-12: their
/// lists were read but never enforced, so an adapter could add any process-spawning or HTTP
/// crate and only a reviewer would notice.
fn external_crates_and_features(
    rule: &CrateRule,
    from: &Known<'_>,
    ws: &Workspace,
    findings: &mut Vec<Finding>,
) {
    if rule.layer == "test-support" {
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
            if let Some(optional_dependency) = implied.strip_prefix("dep:") {
                pending.push(optional_dependency.to_string());
            } else if let Some((dependency, _)) = implied.split_once('/') {
                // `mio/os-poll` also switches on the optional dependency `mio`, which Cargo
                // lists as a feature of its own unless the manifest uses `dep:` for it. A weak
                // reference (`mio?/os-poll`) does not.
                if !dependency.ends_with('?') {
                    pending.push(dependency.to_string());
                }
            } else {
                pending.push(implied.clone());
            }
        }
    }
    seen
}

/// DEP-04, sources: an external package comes from the public registry. A path or git
/// dependency named like an allowed crate would pass a check that reads names only (F-31), and
/// a path dependency named like a workspace crate must point at that crate's directory.
fn dependencies_come_from_the_registry(
    rules: &Rules,
    from: &Known<'_>,
    ws: &Workspace,
    findings: &mut Vec<Finding>,
) {
    let sources = &rules.source_scans.dep_04;
    for dep in &from.member.dependencies {
        let workspace_member = ws.members.iter().find(|m| m.name == dep.name);
        let problem = match (&dep.source, &dep.path, workspace_member) {
            (_, Some(path), Some(member)) if same_directory(path, &member.dir) => None,
            (_, Some(_), Some(member)) => Some(format!(
                "a path dependency named {} that does not point at the workspace crate in {}",
                dep.name,
                ws.relative_dir(member)
            )),
            (Some(source), _, _) if sources.registries.contains(source) => None,
            (Some(source), _, _) => Some(format!(
                "{} from {source}, which is not the public registry",
                dep.name
            )),
            (None, _, _) if sources.path_exceptions.contains(&dep.name) => None,
            (None, _, _) => Some(format!(
                "{} as a path dependency; an external package must come from the public registry, because a path or git source can carry the name of an allowed crate",
                dep.name
            )),
        };
        if let Some(problem) = problem {
            findings.push(Finding::new(
                "DEP-04",
                &from.location,
                format!("{} depends on {problem}", from.member.name),
            ));
        }
    }
}

fn same_directory(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// DEP-05, features: the features Cargo resolves for `time`, `uuid` and `tokio` as the inner
/// crates see them, with every workspace member's choices unified, stay within the limit in the
/// rules file. The manifest of the inner crate alone proves nothing: when another crate enables
/// `time/std`, `OffsetDateTime::now_utc` exists in the domain crate too (review finding F-12).
fn resolved_features_stay_within_the_limits(
    rules: &Rules,
    rule: &CrateRule,
    from: &Known<'_>,
    ws: &Workspace,
    findings: &mut Vec<Finding>,
) {
    if !rules.source_scans.dep_05.inner_crates.contains(&rule.name) {
        return;
    }
    for limit in &rules.source_scans.dep_05.resolved_features {
        let Some(resolved) = from.member.resolved_dependency_features.get(&limit.package) else {
            continue;
        };
        let table = ws
            .package_features
            .get(&limit.package)
            .cloned()
            .unwrap_or_default();
        let allowed = feature_closure(limit.allowed.iter().cloned(), &table);
        // Only real features count. Optional dependencies also appear in the resolved list under
        // their own names, and `default` is the set of features it implies.
        let extra: Vec<&String> = resolved
            .iter()
            .filter(|f| f.as_str() != "default" && (table.is_empty() || table.contains_key(*f)))
            .filter(|f| !allowed.contains(*f))
            .collect();
        if extra.is_empty() {
            continue;
        }
        let names = extra
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding::new(
            "DEP-05",
            &from.location,
            format!(
                "{} resolves {} with feature(s) {names}, which the limit in crate-dependency-rules.json (source_scans.dep_05.resolved_features) does not allow (allowed: {}). {} {}",
                from.member.name,
                limit.package,
                limit.allowed.iter().cloned().collect::<Vec<_>>().join(", "),
                enablers(ws, &limit.package, &extra, &table),
                limit.reason
            ),
        ));
    }
}

/// Which workspace members switch the features on, for the message.
fn enablers(
    ws: &Workspace,
    package: &str,
    extra: &[&String],
    table: &BTreeMap<String, Vec<String>>,
) -> String {
    let mut who = Vec::new();
    for member in &ws.members {
        for dep in member.dependencies.iter().filter(|d| d.name == package) {
            let mut requested: Vec<String> = dep.features.clone();
            if dep.uses_default_features {
                requested.push("default".to_string());
            }
            let enabled = feature_closure(requested.into_iter(), table);
            let hit: Vec<&str> = extra
                .iter()
                .filter(|f| enabled.contains(**f))
                .map(|f| f.as_str())
                .collect();
            if !hit.is_empty() {
                who.push(format!("{} ({})", member.name, hit.join(", ")));
            }
        }
    }
    if who.is_empty() {
        "A dependency outside the workspace enables them.".to_string()
    } else {
        format!("Enabled by {}.", who.join(", "))
    }
}

fn kind_word(kind: DepKind) -> &'static str {
    match kind {
        DepKind::Normal => "normal",
        DepKind::Dev => "dev",
        DepKind::Build => "build",
    }
}
