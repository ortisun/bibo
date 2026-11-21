//! Log fields and span attributes: only names on the allowlist, and no text of unknown origin
//! (package `s1-observability-instrumentation`). The scan is here and not in the workflow crate
//! because the inner crates may not read files, tests included (rule DEP-05).
//!
//! The conventions page says log fields use the names of the attribute table, plus `message` and
//! `correlation_id`, and that nothing a person typed or a model produced is recorded: identifiers
//! and digests only (section 8). This target reads every `tracing` event macro in production code
//! and checks both rules. The scan sees text, so it misses a field built at run time and a value
//! that is free text under a harmless name. It is a guard rail and not a proof.
//!
//! * Every field name must be an attribute key of the page, `message`, `correlation_id`, or be on
//!   the reviewed list below with the reason it is safe. A new field that is on neither list fails
//!   the build and says where.
//! * Names that usually hold text from outside (`body`, `title`, `prompt`, `stderr`, `diff`,
//!   `header`, `content`, and so on) are never allowed, reviewed or not.
//! * A field recorded with `%` or `?` from an error value must be on the reviewed list, because the
//!   `Display` and `Debug` text of an error can carry a path, a query or a message from a tool.
//!   Untrusted text goes into telemetry only as an identifier, a digest or a count.

use std::collections::BTreeSet;

mod telemetry_scan;

use telemetry_scan::table;

/// Every production source file except the observability crate, whose job is to define the names.
fn production_sources() -> Vec<(String, String)> {
    telemetry_scan::production_sources()
        .into_iter()
        .filter(|(path, _)| !path.starts_with("crates/observability/"))
        .collect()
}

// ---- Reading a macro call ----------------------------------------------------------------

/// One field of an event macro.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    file: String,
    line: usize,
    name: String,
    /// `%` (Display), `?` (Debug) or none.
    sigil: Option<char>,
    /// The text of the value expression, for the reader of a failure.
    value: String,
}

const MACROS: &[&str] = &[
    "tracing::info!(",
    "tracing::warn!(",
    "tracing::error!(",
    "tracing::debug!(",
    "tracing::trace!(",
];

/// The arguments of the macro call whose opening parenthesis is at `open`, split at top-level
/// commas. Strings are skipped, so a comma inside a message does not split.
fn split_arguments(text: &str, open: usize) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut args = Vec::new();
    let mut current = String::new();
    let mut i = open;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '"' => {
                current.push(c);
                i += 1;
                while i < bytes.len() {
                    let d = bytes[i] as char;
                    current.push(d);
                    i += 1;
                    if d == '\\' && i < bytes.len() {
                        current.push(bytes[i] as char);
                        i += 1;
                    } else if d == '"' {
                        break;
                    }
                }
                continue;
            }
            '(' | '[' | '{' => {
                depth += 1;
                if depth > 1 {
                    current.push(c);
                }
            }
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    if !current.trim().is_empty() {
                        args.push(current.trim().to_owned());
                    }
                    return args;
                }
                current.push(c);
            }
            ',' if depth == 1 => {
                args.push(current.trim().to_owned());
                current.clear();
            }
            _ => current.push(c),
        }
        i += 1;
    }
    args
}

/// The fields of every event macro in `text`.
fn fields_in(file: &str, text: &str) -> Vec<Field> {
    let mut found = Vec::new();
    for marker in MACROS {
        let mut from = 0;
        while let Some(at) = text[from..].find(marker) {
            let open = from + at + marker.len() - 1;
            from = open + 1;
            let line = text[..open].matches('\n').count() + 1;
            for argument in split_arguments(text, open) {
                // The first plain string literal is the message. What follows are format arguments.
                if argument.starts_with('"') {
                    break;
                }
                if argument.starts_with("target:") || argument.starts_with("parent:") {
                    continue;
                }
                let (sigil, rest) = match argument.chars().next() {
                    Some(c @ ('%' | '?')) => (Some(c), argument[1..].trim().to_owned()),
                    _ => (None, argument.clone()),
                };
                if let Some((name, value)) = rest.split_once('=')
                    && !name.trim().ends_with(['!', '<', '>'])
                {
                    let value = value.trim();
                    let (sigil, value) = match value.chars().next() {
                        Some(c @ ('%' | '?')) => (Some(c), value[1..].trim()),
                        _ => (sigil, value),
                    };
                    found.push(Field {
                        file: file.to_owned(),
                        line,
                        name: name.trim().trim_matches('"').to_owned(),
                        sigil,
                        value: value.to_owned(),
                    });
                    continue;
                }
                // A shorthand field: `%error` or `?error` or `count`.
                found.push(Field {
                    file: file.to_owned(),
                    line,
                    name: rest.trim().to_owned(),
                    sigil,
                    value: rest,
                });
            }
        }
    }
    found
}

/// All event fields in production code, except the metric events: a metric event is not a log line
/// (the log layer skips it), and its labels are checked against the metrics table in
/// `crates/workflow/tests/metric_names.rs`.
fn event_fields() -> Vec<Field> {
    let mut all = Vec::new();
    for (file, text) in production_sources() {
        all.extend(fields_in(&file, &text));
    }
    let metric_lines: BTreeSet<(String, usize)> = all
        .iter()
        .filter(|f| {
            f.name.starts_with("monotonic_counter.")
                || f.name.starts_with("histogram.")
                || f.name.starts_with("gauge.")
        })
        .map(|f| (f.file.clone(), f.line))
        .collect();
    all.into_iter()
        .filter(|f| !metric_lines.contains(&(f.file.clone(), f.line)))
        .collect()
}

// ---- The allowlist -----------------------------------------------------------------------

/// Names that mean text from outside. Never allowed in a log field, reviewed or not.
const NEVER: &[&str] = &[
    "body",
    "title",
    "text",
    "prompt",
    "output",
    "stdout",
    "stderr",
    "diff",
    "patch",
    "content",
    "header",
    "headers",
    "cookie",
    "args",
    "argv",
    "command",
    "query",
    "comment",
    "issue",
    "description",
    "transcript",
];

/// Fields that are neither an attribute key of the page nor `message` or `correlation_id`, by file
/// and name, each with the reason it is safe. The file is where the macro is; the reason is what a
/// reviewer checked on 2026-10-28. Keep the reasons short and true. A new use of an old name in a
/// new file is a new line here, on purpose.
const REVIEWED: &[(&str, &str, &str)] = &[
    (
        "crates/workflow/src/engine/attempt.rs",
        "blocked_code",
        "why a gate could not run, a BlockedCode: a closed set of static strings",
    ),
    // The four fields of the day ceiling line were added with the line on 2026-11-11 by the
    // author of the line, and wait for a reviewer like the port notes of that change.
    (
        "crates/composition/src/authority.rs",
        "repository",
        "the identifier of a registered repository, a UUID",
    ),
    (
        "crates/composition/src/authority.rs",
        "rule",
        "the policy rule of a budget scope, a closed set of static strings",
    ),
    (
        "crates/composition/src/authority.rs",
        "metrics",
        "the budget metrics that reached a ceiling, a closed set of names",
    ),
    (
        "crates/composition/src/authority.rs",
        "readings",
        "budget metric names with the dollars and the job count the factory summed itself",
    ),
    (
        "crates/composition/src/decisions.rs",
        "admitted",
        "a boolean: whether the engine admitted the job",
    ),
    (
        "crates/composition/src/decisions.rs",
        "code",
        "the refusal code of the approval service, a closed set of static strings",
    ),
    (
        "crates/composition/src/decisions.rs",
        "decision",
        "the identifier of a decision record, a UUID",
    ),
    (
        "crates/composition/src/decisions.rs",
        "error",
        "StoreError and EngineError: static sentences written by the code; the one String payload, EngineError::Invalid, wraps a domain or serde error about a value the engine built itself and means a bug in the engine",
    ),
    (
        "crates/composition/src/decisions.rs",
        "job",
        "the identifier of a job, a UUID",
    ),
    (
        "crates/composition/src/dependency_decisions.rs",
        "code",
        "the code of an outcome of a decision on a dependency: `applied` or the code of a `Reason`, a closed set of static strings",
    ),
    (
        "crates/composition/src/dependency_decisions.rs",
        "error",
        "StoreError: a static sentence written by the code, as in the hook for the six verbs",
    ),
    (
        "crates/composition/src/stage_decisions.rs",
        "code",
        "the code of an outcome of a decision about a stage run: `applied` or the code of a `Reason`, a closed set of static strings",
    ),
    (
        "crates/composition/src/stage_decisions.rs",
        "error",
        "StoreError: a static sentence written by the code, as in the hook for the six verbs",
    ),
    (
        "crates/composition/src/intake_rejections.rs",
        "code",
        "the fixed reason code `unauthorized_actor`, a static string",
    ),
    (
        "crates/composition/src/intake_rejections.rs",
        "error",
        "StoreError: a static sentence written by the code, as in the hook for the six verbs",
    ),
    (
        "crates/composition/src/intake_rejections.rs",
        "replied",
        "a boolean: whether the one reply was posted",
    ),
    (
        "crates/composition/src/repository_changes.rs",
        "kind",
        "one of three static words, register, attest or enable: the kind of a request to change a repository",
    ),
    (
        "crates/composition/src/repository_changes.rs",
        "code",
        "the fixed refusal code of a request to change a repository, one of a closed set of static words written in this module",
    ),
    (
        "crates/composition/src/repository_changes.rs",
        "error",
        "StoreError: a static sentence written by the code, as in the hook for the six verbs",
    ),
    (
        "crates/composition/src/seams.rs",
        "github_user_id",
        "the numeric GitHub id of a person whom an allowlist entry narrows by name alone: a number from the protected file",
    ),
    (
        "crates/composition/src/seams.rs",
        "repositories",
        "the owner/name of the repositories that an allowlist entry lists by name alone: text from the protected allowlist file, written by the person who owns it, never from an issue or a model",
    ),
    (
        "crates/composition/src/seams.rs",
        "tenant",
        "the id of the tenant of an allowlist entry that narrows by name alone: a UUID that a person wrote in the protected file, as the tenant of every entry",
    ),
    (
        "crates/composition/src/issue_status.rs",
        "code",
        "the code of a failed try to write a job's state on its issue, `FailureCode::word`: one of seven static strings, never a message from GitHub",
    ),
    (
        "crates/composition/src/design_gate.rs",
        "reason",
        "why the design rule cannot be read: a sentence the code wrote about the policy file, which may carry the loader's message about it (the name of the file, a key path and a rule, from the protected checkout); no issue text, no model output and no secret",
    ),
    (
        "crates/composition/src/issue_status.rs",
        "reason",
        "why the status step is off: a sentence the code wrote about a policy file or an approval row, which may carry the loader's message about the file (a path and a rule, from the protected checkout), cut at 300 characters and stripped of control characters; no issue text, no model output and no secret",
    ),
    (
        "crates/composition/src/issue_status.rs",
        "gave_up",
        "a boolean: whether the step gave up on this version of the job",
    ),
    (
        "crates/composition/src/issue_status.rs",
        "tries",
        "a count: how many tries this version of the job has had",
    ),
    (
        "crates/composition/src/startup.rs",
        "unconfirmed",
        "a count: how many things in the routing policy still wait for the project owner",
    ),
    (
        "crates/composition/src/token_sweep.rs",
        "revoked",
        "a count: how many installation tokens of ended jobs the pass revoked",
    ),
    (
        "crates/composition/src/token_sweep.rs",
        "released",
        "a count: how many installation tokens of jobs that stayed blocked the pass revoked (LB-04)",
    ),
    (
        "apps/api/src/answers.rs",
        "error",
        "StoreError, a closed set",
    ),
    // Added with the process snapshot route on 2026-11-21 (ADR 0029). Only the two variants that
    // are not a store error reach the line.
    (
        "apps/api/src/process_metrics.rs",
        "error",
        "SnapshotError::Metric or EndsBeforeItStarts: fixed words of the code, numbers and a job id, no text from a person or a tool",
    ),
    (
        "apps/api/src/boot.rs",
        "kind",
        "label of a secret kind, a closed set",
    ),
    (
        "apps/api/src/limits.rs",
        "error",
        "StoreError, a closed set",
    ),
    ("apps/api/src/limits.rs", "dropped", "a count"),
    (
        "apps/api/src/main.rs",
        "listen",
        "the configured listen address",
    ),
    (
        "apps/api/src/main.rs",
        "profile",
        "profile name, a closed set",
    ),
    (
        "apps/api/src/server.rs",
        "error",
        "io and hyper errors of a connection; no request text",
    ),
    ("apps/worker/src/run.rs", "attempt", "attempt id"),
    ("apps/worker/src/run.rs", "attempts", "a count"),
    (
        "apps/worker/src/run.rs",
        "detail",
        "Debug form of EngineError, whose String variants hold adapter error text and no input",
    ),
    ("apps/worker/src/run.rs", "drain_s", "a number of seconds"),
    ("apps/worker/src/run.rs", "error", "EngineError"),
    ("apps/worker/src/run.rs", "lease_lost", "a count"),
    (
        "apps/worker/src/run.rs",
        "outcome",
        "AttemptOutcome, a closed enum",
    ),
    ("apps/worker/src/run.rs", "stage", "stage kind"),
    ("apps/worker/src/run.rs", "stage_run", "stage run id"),
    ("apps/worker/src/run.rs", "timed_out", "a count"),
    ("apps/worker/src/run.rs", "worker", "worker id"),
    (
        "crates/composition/src/assemble.rs",
        "kind",
        "label of a secret kind, a closed set",
    ),
    ("crates/composition/src/drift.rs", "created", "a count"),
    ("crates/composition/src/drift.rs", "error", "EngineError"),
    ("crates/composition/src/drift.rs", "superseded", "a count"),
    ("crates/composition/src/system.rs", "signal", "a constant"),
    (
        "crates/runtime/src/claude/mod.rs",
        "error",
        "probe error, a closed set",
    ),
    (
        "crates/runtime/src/claude/mod.rs",
        "found",
        "version number parsed from the tool's version output",
    ),
    (
        "crates/runtime/src/claude/mod.rs",
        "refusal",
        "a closed refusal enum",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "allowed_count",
        "a count of the stage's skills",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "allowed_sha256",
        "first 12 hex characters of the SHA-256 of the stage's skill names; the names are not logged",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "error",
        "probe error, a closed set",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "visible_count",
        "a count of the skills the tool listed",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "visible_sha256",
        "first 12 hex characters of the SHA-256 of the skill names the tool listed; the names are not logged",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "found",
        "version number parsed from the tool's version output",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "refusal",
        "a closed refusal enum",
    ),
    (
        "crates/runtime/src/io.rs",
        "error",
        "ArtifactError, a closed set",
    ),
    (
        "crates/runtime/src/probe.rs",
        "error",
        "SandboxError, a closed set",
    ),
    (
        "crates/runtime/src/probe.rs",
        "step",
        "probe step, a closed enum",
    ),
    (
        "crates/runtime/src/report.rs",
        "error",
        "io::Error of a read; no content",
    ),
    (
        "crates/sandbox/src/supervisor/cleanup.rs",
        "container",
        "name derived from ids",
    ),
    (
        "crates/sandbox/src/supervisor/cleanup.rs",
        "network",
        "name derived from ids",
    ),
    (
        "crates/sandbox/src/supervisor/cleanup.rs",
        "sandbox",
        "name derived from ids",
    ),
    (
        "crates/sandbox/src/supervisor/provision.rs",
        "deviations",
        "posture field names, a closed set",
    ),
    (
        "crates/sandbox/src/workspace/ingest.rs",
        "kind",
        "audit reason kind, a closed enum",
    ),
    (
        "crates/sandbox/src/workspace/ingest.rs",
        "path_sha256",
        "first 12 hex characters of the SHA-256 of a rejected path; the path is not logged",
    ),
    (
        "crates/sandbox/src/workspace/ingest.rs",
        "rejected",
        "a count",
    ),
    (
        "crates/storage/src/artifact_fs/mod.rs",
        "errno",
        "operating system error code",
    ),
    (
        "crates/storage/src/artifact_fs/mod.rs",
        "error",
        "io::Error of a file call; the code reads the kind only",
    ),
    (
        "crates/storage/src/artifact_fs/mod.rs",
        "kind",
        "io::ErrorKind, a closed enum",
    ),
    (
        "crates/storage/src/artifact_fs/mod.rs",
        "step",
        "a step named in words by the code",
    ),
    ("crates/storage/src/pg/conv.rs", "what", "a static string"),
    (
        "crates/storage/src/pg/error.rs",
        "column",
        "schema identifier",
    ),
    (
        "crates/storage/src/pg/error.rs",
        "constraint",
        "schema identifier",
    ),
    (
        "crates/storage/src/pg/error.rs",
        "failure",
        "closed failure set",
    ),
    (
        "crates/storage/src/pg/error.rs",
        "kind",
        "closed failure set",
    ),
    (
        "crates/storage/src/pg/error.rs",
        "operation",
        "static name of the store call",
    ),
    (
        "crates/storage/src/pg/error.rs",
        "table",
        "schema identifier",
    ),
    (
        "crates/storage/src/pg/pool.rs",
        "kind",
        "pool error kind, a closed set",
    ),
    ("crates/storage/src/pg/pool.rs", "pool", "label of the pool"),
    (
        "crates/workflow/src/scheduler/claim.rs",
        "error",
        "EngineError of a start that was set aside; its String variants hold adapter error text and no input",
    ),
    (
        "crates/workflow/src/scheduler/claim.rs",
        "guard",
        "guard name, a closed set",
    ),
    (
        "crates/workflow/src/scheduler/claim.rs",
        "stage_run",
        "stage run id",
    ),
];

/// Fields that put text of outside origin in a log line, as found on 2026-10-28 (confirmed gap
/// OBS-9, now closed). The three call sites log counts and short digests instead, under other
/// names, and the test at the end of this file proves that these (file, name) pairs are gone. The
/// JSON line escapes control characters and the redactor runs over the line, but the length was
/// not bounded and the content was not an identifier.
const FORMERLY_TRACKED_AS_OBS_9: &[(&str, &str, &str)] = &[
    (
        "crates/sandbox/src/workspace/ingest.rs",
        "path",
        "the path of a rejected workspace entry, written by the repository's author",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "visible",
        "skill names read from the tool's standard output, which the repository can influence",
    ),
    (
        "crates/runtime/src/codex/mod.rs",
        "allowed",
        "skill names of the stage; static, but logged next to the line above",
    ),
];

fn attribute_keys() -> BTreeSet<String> {
    table("attributes")
        .into_iter()
        .map(|row| row[0].clone())
        .collect()
}

fn allowed_names() -> BTreeSet<String> {
    let mut names = attribute_keys();
    for always in ["message", "correlation_id"] {
        names.insert(always.to_owned());
    }
    names
}

fn is_listed(list: &[(&str, &str, &str)], field: &Field) -> bool {
    list.iter()
        .any(|(file, name, _)| *file == field.file && *name == field.name)
}

#[test]
fn the_scan_finds_the_events_of_the_workspace() {
    // A guard against a scan that silently finds nothing.
    let fields = event_fields();
    assert!(fields.len() > 40, "only {} fields found", fields.len());
    assert!(fields.iter().any(|f| f.name == "factory.job_id"));
    assert!(fields.iter().any(|f| f.file.starts_with("crates/storage/")));
}

#[test]
fn every_log_field_is_on_the_allowlist_or_has_been_reviewed() {
    let allowed = allowed_names();
    let unknown: Vec<String> = event_fields()
        .into_iter()
        .filter(|f| !allowed.contains(&f.name) && !is_listed(REVIEWED, f))
        .map(|f| format!("{}:{} field `{}` = {}", f.file, f.line, f.name, f.value))
        .collect();
    assert!(
        unknown.is_empty(),
        "these log fields are not attribute keys of the conventions page and have not been \
         reviewed. Use an identifier, a digest, a count or a closed set, and add the field to \
         REVIEWED in crates/composition/tests/telemetry_allowlist.rs with the reason it is safe, or rename it to an \
         attribute key:\n  {}",
        unknown.join("\n  ")
    );
}

#[test]
fn no_log_field_has_a_name_that_means_text_from_outside() {
    let offenders: Vec<String> = event_fields()
        .into_iter()
        .filter(|f| NEVER.contains(&f.name.as_str()))
        .map(|f| format!("{}:{} field `{}`", f.file, f.line, f.name))
        .collect();
    assert!(
        offenders.is_empty(),
        "a log field is named like text from outside; record an identifier, a digest or a count:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_reviewed_lists_hold_no_stale_line() {
    let fields = event_fields();
    for (file, name, reason) in REVIEWED {
        assert!(!reason.is_empty());
        assert!(
            fields.iter().any(|f| f.file == *file && f.name == *name),
            "{file} no longer logs a field `{name}`: remove the line from the reviewed lists"
        );
    }
    for (_, name, _) in REVIEWED {
        assert!(
            !allowed_names().contains(*name),
            "`{name}` is on the allowlist already; a reviewed line for it is noise"
        );
    }
    let mut seen = BTreeSet::new();
    for (file, name, _) in REVIEWED {
        assert!(seen.insert((*file, *name)), "{file} lists `{name}` twice");
    }
}

#[test]
fn a_value_that_is_an_error_is_recorded_only_where_it_was_reviewed() {
    // `%error` and `?error` write the text of an error. A closed error enum says little; a library
    // error can say a path or a query. Every such field is on the reviewed list, so a new one is a
    // decision.
    let error_like = ["error", "detail", "failure"];
    for field in event_fields() {
        if field.sigil.is_some() && error_like.contains(&field.name.as_str()) {
            assert!(
                is_listed(REVIEWED, &field),
                "{}:{} records the text of an error in `{}` without a review",
                field.file,
                field.line,
                field.name
            );
        }
    }
}

/// Gap OBS-9, closed. Three log fields put text of outside origin in a line: the path of a
/// workspace entry that the audit rejected (`crates/sandbox/src/workspace/ingest.rs`), and the skill
/// names the tool printed (`crates/runtime/src/codex/mod.rs`, two fields). The repository's author
/// chooses both. The JSON line escapes control characters and the redactor scrubs the line, so this
/// was not an injection or a secret leak by itself, but the text was unbounded, and the conventions
/// page says text from a person or a tool is not recorded. The three sites now log counts and the
/// first 12 hex characters of a SHA-256 (`Sha256Digest`, the digest the workspace uses), and the
/// names are no longer logged anywhere.
#[test]
fn no_log_field_holds_text_chosen_by_a_repository_or_a_tool() {
    let still_logged: Vec<String> = event_fields()
        .into_iter()
        .filter(|f| is_listed(FORMERLY_TRACKED_AS_OBS_9, f))
        .map(|f| format!("{}:{} field `{}` = {}", f.file, f.line, f.name, f.value))
        .collect();
    assert!(
        still_logged.is_empty(),
        "text of outside origin is logged:\n  {}",
        still_logged.join("\n  ")
    );
}

#[test]
fn a_field_named_as_a_digest_is_filled_by_a_digest_helper() {
    // The replacement fields are named `*_sha256`. A name says nothing about the value, so check
    // that each such field is filled by a call whose name says digest, and not by the text itself.
    let mut seen = 0;
    for field in event_fields() {
        if field.name.ends_with("_sha256") && !field.name.starts_with("factory.") {
            seen += 1;
            assert!(
                field.value.to_ascii_lowercase().contains("digest")
                    || field.value.contains(".hex()"),
                "{}:{} `{}` is named as a digest and is filled with `{}`",
                field.file,
                field.line,
                field.name,
                field.value
            );
        }
    }
    assert!(seen >= 3, "the scan found only {seen} digest fields");
}
