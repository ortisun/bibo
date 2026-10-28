//! A registry of the production stage handlers that the build checks (package
//! `s1-observability-instrumentation`, done criterion "every registered stage handler produces a
//! span").
//!
//! A stage handler opens no span itself: the engine opens the attempt span around the whole attempt
//! and the gate span around `evaluate`. The runtime half of the proof is
//! `crates/workflow/tests/every_handler_has_a_span.rs`, which runs every stage kind through the
//! engine and reads the spans. This file is the other half, and it needs to read the source tree:
//!
//! 1. A source scan finds every production `impl StageHandler` and compares it with the table
//!    below. A new handler that is not listed fails the build, with a message that says what to
//!    add. A stage kind that has neither a handler nor an entry in the list of kinds without one
//!    fails it too.
//! 2. The scan checks that `execute` and `evaluate` of a handler are called from the engine's
//!    attempt code and from nowhere else in the workflow crate, so no path runs a handler outside
//!    the spans.

mod telemetry_scan;

use std::collections::BTreeSet;

use factory_domain::vocabulary::StageKind;
use telemetry_scan::production_sources;

/// Every production `StageHandler`: the type, the stage kind it reports (the name of the Rust
/// variant), and the file it is in. Adding a handler means adding a line here. The spans need
/// nothing more, because the engine opens them around any handler.
const HANDLERS: &[(&str, &str, &str)] = &[
    (
        "ApprovalHandler",
        "Approval",
        "crates/workflow/src/stages/approval/handler.rs",
    ),
    (
        "ArchitectureHandler",
        "Architecture",
        "crates/workflow/src/stages/architecture/handler.rs",
    ),
    (
        "DeliveryHandler",
        "Delivery",
        "crates/workflow/src/stages/delivery/handler.rs",
    ),
    (
        "DocumentationReviewHandler",
        "DocumentationReview",
        "crates/workflow/src/stages/documentation_review/handler.rs",
    ),
    (
        "DocumentingHandler",
        "Documenting",
        "crates/workflow/src/stages/documenting/handler.rs",
    ),
    (
        "DomainDiscoveryHandler",
        "DomainDiscovery",
        "crates/workflow/src/stages/domain_discovery/mod.rs",
    ),
    (
        "ImplementationHandler",
        "Implementation",
        "crates/workflow/src/stages/implementation/handler.rs",
    ),
    (
        "IntakeHandler",
        "Intake",
        "crates/workflow/src/stages/intake/handler.rs",
    ),
    (
        "PlanningHandler",
        "TaskPlanning",
        "crates/workflow/src/stages/planning/handler.rs",
    ),
    (
        "RepoIntelHandler",
        "RepositoryIntelligence",
        "crates/workflow/src/stages/repo_intel/handler.rs",
    ),
    (
        "ReviewHandler",
        "Review",
        "crates/workflow/src/stages/review/handler.rs",
    ),
    (
        "SpecificationHandler",
        "Specification",
        "crates/workflow/src/stages/specification/handler.rs",
    ),
    (
        "ValidationHandler",
        "Validation",
        "crates/workflow/src/stages/validation/handler.rs",
    ),
];

/// Stage kinds that have no production handler yet. The engine opens the same spans for them when a
/// handler is registered, and the workflow scenario proves it with a scripted one for every kind in
/// its scope. `Merge` is not implemented and is outside the scope. `DomainDiscovery` used to be on
/// this list; it has a handler now (it skips the stage by a recorded rule when the domain profile
/// asks for no discovery), listed above.
const KINDS_WITHOUT_A_HANDLER: &[&str] = &["Merge"];

/// The `impl StageHandler for <Type>` blocks of a file: the type, and the stage kind named in the
/// body of its `fn kind`.
fn handlers_in(text: &str) -> Vec<(String, Option<String>)> {
    let mut found = Vec::new();
    for marker in [
        "impl StageHandler for ",
        "impl factory_workflow::handlers::StageHandler for ",
    ] {
        let mut from = 0;
        while let Some(at) = text[from..].find(marker) {
            let start = from + at + marker.len();
            let name: String = text[start..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let rest = &text[start..];
            let end = rest.find("\nimpl ").unwrap_or(rest.len());
            let body = &rest[..end];
            let kind = body.find("fn kind(&self)").and_then(|k| {
                let after = &body[k..];
                let literal = after.find("StageKind::")? + "StageKind::".len();
                Some(
                    after[literal..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric())
                        .collect::<String>(),
                )
            });
            found.push((name, kind));
            from = start;
        }
    }
    found
}

/// `RepositoryIntelligence` for the wire name `REPOSITORY_INTELLIGENCE`.
fn variant_name(kind: StageKind) -> String {
    kind.as_str()
        .split('_')
        .map(|word| {
            let lower = word.to_lowercase();
            let mut chars = lower.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

#[test]
fn every_production_stage_handler_is_listed_with_the_kind_it_reports() {
    let mut found: Vec<(String, String, String)> = Vec::new();
    for (path, text) in production_sources() {
        for (name, kind) in handlers_in(&text) {
            found.push((name, kind.unwrap_or_default(), path.clone()));
        }
    }
    found.sort();

    let mut listed: Vec<(String, String, String)> = HANDLERS
        .iter()
        .map(|(name, kind, file)| ((*name).to_owned(), (*kind).to_owned(), (*file).to_owned()))
        .collect();
    listed.sort();

    let unlisted: Vec<_> = found.iter().filter(|f| !listed.contains(f)).collect();
    let stale: Vec<_> = listed.iter().filter(|l| !found.contains(l)).collect();
    assert!(
        unlisted.is_empty(),
        "a StageHandler is not listed in HANDLERS of crates/composition/tests/handler_registry_scan.rs: \
         {unlisted:?}. Add it with the stage kind it reports. The engine opens the attempt and \
         gate spans around it, and crates/workflow/tests/every_handler_has_a_span.rs proves that \
         for the kind."
    );
    assert!(
        stale.is_empty(),
        "HANDLERS lists a handler that no longer exists, or whose kind or file changed: {stale:?}"
    );
}

#[test]
fn every_stage_kind_has_a_listed_handler_or_is_known_to_have_none() {
    let with_handler: BTreeSet<String> = HANDLERS
        .iter()
        .map(|(_, kind, _)| (*kind).to_owned())
        .collect();
    assert_eq!(
        with_handler.len(),
        HANDLERS.len(),
        "two handlers report the same stage kind"
    );
    let without: BTreeSet<String> = KINDS_WITHOUT_A_HANDLER
        .iter()
        .map(|k| (*k).to_owned())
        .collect();
    assert!(
        with_handler.is_disjoint(&without),
        "a kind is listed both with and without a handler: update KINDS_WITHOUT_A_HANDLER"
    );
    let all: BTreeSet<String> = StageKind::ALL.iter().map(|k| variant_name(*k)).collect();
    let covered: BTreeSet<String> = with_handler.union(&without).cloned().collect();
    assert_eq!(
        covered, all,
        "a stage kind has neither a handler in HANDLERS nor an entry in KINDS_WITHOUT_A_HANDLER"
    );
    assert_eq!(
        StageKind::ALL.len(),
        14,
        "a stage kind was added: list it above"
    );
}

#[test]
fn only_the_engines_attempt_code_calls_a_handler() {
    // The engine opens its spans around these two calls. A second call site, in production code,
    // would run a handler outside them.
    let mut callers: Vec<String> = Vec::new();
    for (path, text) in production_sources() {
        if !path.starts_with("crates/workflow/src/") {
            continue;
        }
        for (number, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if line.contains("handler.execute(") || line.contains("handler.evaluate(") {
                callers.push(format!("{path}:{}", number + 1));
            }
        }
    }
    assert!(
        !callers.is_empty(),
        "the scan found no caller; it is broken"
    );
    for caller in &callers {
        assert!(
            caller.starts_with("crates/workflow/src/engine/attempt.rs:"),
            "a handler is called outside the engine's attempt code: {caller}"
        );
    }
}
