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
        "apps/api/src/answers.rs",
        "error",
        "StoreError, a closed set",
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
        "error",
        "probe error, a closed set",
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
        "guard",
        "guard name, a closed set",
    ),
    (
        "crates/workflow/src/scheduler/claim.rs",
        "stage_run",
        "stage run id",
    ),
];

/// Fields that put text of outside origin in a log line, as found on 2026-10-28. They are tracked
/// as confirmed gap OBS-9 and tolerated by the allowlist test until the ignored test at the end of
/// this file passes. The JSON line escapes control characters and the redactor runs over the line,
/// but the length is not bounded and the content is not an identifier.
const TRACKED_AS_OBS_9: &[(&str, &str, &str)] = &[
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
        .filter(|f| {
            !allowed.contains(&f.name) && !is_listed(REVIEWED, f) && !is_listed(TRACKED_AS_OBS_9, f)
        })
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
    for (file, name, reason) in REVIEWED.iter().chain(TRACKED_AS_OBS_9) {
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
    for (file, name, _) in REVIEWED.iter().chain(TRACKED_AS_OBS_9) {
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

/// Confirmed gap OBS-9. Three log fields put text of outside origin in a line: the path of a
/// workspace entry that the audit rejected (`crates/sandbox/src/workspace/ingest.rs`), and the skill
/// names the tool printed (`crates/runtime/src/codex/mod.rs`, two fields). The repository's author
/// chooses both. The JSON line escapes control characters and the redactor scrubs the line, so this
/// is not an injection or a secret leak by itself, but the text is unbounded, and the conventions
/// page says text from a person or a tool is not recorded. There is no helper in the workspace that
/// encodes such text for a log line (escape, truncate to a length, add a digest).
///
/// Owner: `crates/sandbox` and `crates/runtime`. Smallest change: log the count of rejected entries
/// and the audit reason kind, with a digest of the path (`sha256` of the path, first 12 hex
/// characters) so two lines about one entry can be matched, and log the number of visible skills
/// instead of their names. The full text is already in the workspace report that
/// `ws.keep_report(report)` keeps.
#[test]
#[ignore = "confirmed gap OBS-9: three log fields hold text chosen by the repository"]
fn no_log_field_holds_text_chosen_by_a_repository_or_a_tool() {
    let tracked: Vec<String> = event_fields()
        .into_iter()
        .filter(|f| is_listed(TRACKED_AS_OBS_9, f))
        .map(|f| format!("{}:{} field `{}` = {}", f.file, f.line, f.name, f.value))
        .collect();
    assert!(
        tracked.is_empty(),
        "text of outside origin is logged:\n  {}",
        tracked.join("\n  ")
    );
}
