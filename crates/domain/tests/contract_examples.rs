//! The Rust contract types against the JSON schemas and their examples.
//!
//! * Every valid example under `schemas/examples` reads into its type and writes back as an equal
//!   JSON value.
//! * Every invalid example is rejected, and for the reason written next to it.
//! * The types and the schemas cannot drift apart silently: unknown fields, required and optional
//!   fields, patterns and closed sets are compared with the schema files themselves.
//!
//! The crate does no file I/O, so the schemas and examples are embedded at compile time. The list
//! is `tests/support/example_index.rs`, written by `tests/tools/gen_example_index.py`.

mod support;

use std::collections::BTreeSet;

use serde_json::Value;
use support::example_index::{EXAMPLES, Example, SCHEMAS};
use support::registry::{round_trip, round_trip_value};

fn valid_examples() -> impl Iterator<Item = &'static Example> {
    EXAMPLES.iter().filter(|example| example.valid)
}

fn invalid_examples() -> impl Iterator<Item = &'static Example> {
    EXAMPLES.iter().filter(|example| !example.valid)
}

fn schema_document(name: &str) -> Value {
    let (_, text) = SCHEMAS
        .iter()
        .find(|(schema, _)| *schema == name)
        .unwrap_or_else(|| panic!("no schema named {name}"));
    serde_json::from_str(text).expect("a schema is valid JSON")
}

// ---- coverage -----------------------------------------------------------------------------------

#[test]
fn every_schema_has_a_rust_type_and_both_kinds_of_example() {
    assert_eq!(SCHEMAS.len(), 11, "the plan has eleven schemas");
    for (schema, _) in SCHEMAS {
        assert!(
            valid_examples().any(|e| e.schema == *schema),
            "{schema} has no valid example"
        );
        assert!(
            invalid_examples().any(|e| e.schema == *schema),
            "{schema} has no invalid example"
        );
        // Panics with the schema name if no type is registered.
        let _ = round_trip(schema, "{}");
        assert_eq!(
            support::registry::declared_schema(schema),
            *schema,
            "the Rust type for {schema} declares a different schema name"
        );
    }
}

// ---- the examples -------------------------------------------------------------------------------

#[test]
fn every_valid_example_deserializes_and_serializes_back_to_an_equal_json_value() {
    let mut failures = Vec::new();
    for example in valid_examples() {
        let original: Value = serde_json::from_str(example.text).expect("an example is valid JSON");
        match round_trip(example.schema, example.text) {
            Ok(written_back) if written_back == original => {}
            Ok(written_back) => failures.push(format!(
                "{}/{}: written back as a different value:\n  read:    {original}\n  written: {written_back}",
                example.schema, example.file
            )),
            Err(error) => failures.push(format!("{}/{}: {error}", example.schema, example.file)),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_invalid_example_is_rejected() {
    let mut accepted = Vec::new();
    for example in invalid_examples() {
        if round_trip(example.schema, example.text).is_ok() {
            accepted.push(format!(
                "{}/{} was accepted. The schema rejects it because: {}",
                example.schema,
                example.file,
                example.expect.lines().next().unwrap_or("")
            ));
        }
    }
    assert!(accepted.is_empty(), "{}", accepted.join("\n"));
}

/// The message every empty-list rejection starts with. It does not name the field, so each
/// example that depends on it is also listed in `REPAIRS`.
const LIST_TOO_SHORT: &str = "must hold at least 1 item";

/// For each invalid example, a piece of the Rust error that shows it was rejected for the stated
/// reason and not by accident. The key is `<schema>/<file>`.
const REJECTED_FOR: &[(&str, &str)] = &[
    (
        "agent-manifest/agent-placed-directly-on-the-host.json",
        "\"host_direct\" is not a valid agent placement",
    ),
    (
        "agent-manifest/network-allowlist-without-hosts.json",
        "permissions.network_allowlist: a network allow list needs at least one host",
    ),
    (
        "agent-manifest/no-evaluation-suite.json",
        "missing field `evaluation_suite`",
    ),
    (
        "agent-manifest/production-access-granted.json",
        "is not a valid production access",
    ),
    (
        "agent-manifest/read-only-agent-with-a-shell.json",
        "permissions.shell: an agent whose tools are all read-only has no shell",
    ),
    (
        "agent-manifest/unrestricted-shell.json",
        "\"unrestricted\" is not a valid shell mode",
    ),
    (
        "domain-capability-profile/active-without-review.json",
        "review: an active profile must record who reviewed it",
    ),
    (
        "domain-capability-profile/active-without-tool-probes.json",
        "tool_probes: an active profile must say how each of its tools is probed",
    ),
    (
        "domain-capability-profile/approval-policy-as-sentence.json",
        "\"A human must approve live trading\" is not a valid slug",
    ),
    (
        "domain-capability-profile/id-not-machine-safe.json",
        "\"General Software\" is not a valid slug",
    ),
    (
        "domain-capability-profile/missing-forbidden-actions.json",
        "missing field `forbidden_autonomous_actions`",
    ),
    (
        "domain-capability-profile/no-mandatory-gates.json",
        LIST_TOO_SHORT,
    ),
    (
        "domain-event/event-type-not-aggregate-dot-verb.json",
        "\"StageRunPassed\" is not a valid event type",
    ),
    (
        "domain-event/heartbeat-as-domain-event.json",
        "heartbeats are not domain events",
    ),
    (
        "domain-event/missing-correlation-id.json",
        "missing field `correlation_id`",
    ),
    (
        "domain-event/transition-reason-not-machine-readable.json",
        "\"stage-passed\" is not a valid transition id",
    ),
    (
        "evidence-ledger-entry/entry-hash-without-algorithm-prefix.json",
        "is not a valid SHA-256 digest",
    ),
    (
        "evidence-ledger-entry/fake-adapter-in-production-mode.json",
        "metadata.execution_mode: a fake or simulated component may record evidence only when the job runs in test mode",
    ),
    (
        "evidence-ledger-entry/fake-adapter-supporting-an-assurance-level.json",
        "evidence from a fake or simulated component never supports an assurance level",
    ),
    (
        "evidence-ledger-entry/first-entry-with-a-previous-hash.json",
        "prev_entry_hash: the first entry of a job (sequence 1) has no previous entry",
    ),
    (
        "evidence-ledger-entry/hypothesis-or-assumption-with-assurance-level.json",
        "an assumption or a hypothesis cannot support an assurance level",
    ),
    (
        "evidence-ledger-entry/measured-fact-supported-only-by-opinion.json",
        "evidence[0].type: a measured fact must rest on",
    ),
    (
        "evidence-ledger-entry/measured-fact-without-evidence.json",
        "a measured fact needs at least one piece of evidence",
    ),
    (
        "evidence-manifest/blocked-gate-without-recorded-decision.json",
        "gate_reports[2].disposition_ledger_entry_id",
    ),
    (
        "evidence-manifest/failed-gate-in-delivery-manifest.json",
        "\"FAILED\" is not a valid delivered gate outcome",
    ),
    (
        "evidence-manifest/fake-adapter-in-production-manifest.json",
        "adapters[0].fidelity: a production job cannot list a fake adapter",
    ),
    (
        "evidence-manifest/manifest-without-limitations.json",
        LIST_TOO_SHORT,
    ),
    (
        "evidence-manifest/production-readiness-claim-left-unstated.json",
        "PRODUCTION_READY must appear in exactly one",
    ),
    (
        "evidence-manifest/review-that-did-not-pass.json",
        "\"CHANGES_REQUIRED\" is not a valid review verdict",
    ),
    (
        "evidence-ledger-entry/seed-above-the-largest-exact-integer.json",
        "use a whole number from -9007199254740991 to 9007199254740991",
    ),
    (
        "evidence-ledger-entry/source-url-not-https.json",
        "a source URL starts with https://",
    ),
    (
        "gate-report/blocked-report-with-warnings.json",
        "warnings: a BLOCKED report carries no warnings",
    ),
    (
        "gate-report/not-applicable-report-with-warnings.json",
        "warnings: a NOT_APPLICABLE report carries no warnings",
    ),
    (
        "gate-report/passed-with-failures.json",
        "failures: a PASSED report lists no failures",
    ),
    (
        "gate-report/warning-with-a-severity-field.json",
        "unknown field `severity`",
    ),
    (
        "gate-report/warning-without-suggested-fix.json",
        "missing field `suggested_fix`",
    ),
    (
        "gate-report/blocked-without-reason.json",
        "blocked_reason: a BLOCKED report must say what was missing",
    ),
    (
        "gate-report/fake-adapter-in-production-mode.json",
        "environment.fidelity: a production job cannot use a fake adapter",
    ),
    (
        "gate-report/passed-with-command-that-never-ran.json",
        "commands[1].executed: a PASSED report cannot include a command that never ran",
    ),
    (
        "gate-report/passed-with-failing-command.json",
        "commands[1].exit_code: a PASSED report needs every command to exit with code 0",
    ),
    (
        "gate-report/title-with-machine-prefix.json",
        "\"GATE-17 | BUILD | P1: run tests\" is not a valid title",
    ),
    (
        "project-manifest/blocking-readability-rule-switched-off.json",
        "\"title-opaque-prefix\" is not a valid readability rule",
    ),
    (
        "project-manifest/gate-command-as-a-shell-string.json",
        "invalid type: string \"cargo build --locked\"",
    ),
    (
        "project-manifest/gate-command-through-a-shell.json",
        "gates[0].argv: a gate command must not start a shell",
    ),
    (
        "project-manifest/manifest-does-not-protect-itself.json",
        "`.factory/**` must be a protected path",
    ),
    (
        "project-manifest/no-mandatory-gate.json",
        "at least one gate must be mandatory",
    ),
    (
        "project-manifest/project-title-with-machine-prefix.json",
        "\"WC-001 | CLI | P2: counting tool\" is not a valid title",
    ),
    (
        "project-manifest/spec-kit-version-not-pinned.json",
        "missing field `cli_version`",
    ),
    (
        "review-verdict/changes-required-without-findings.json",
        "a CHANGES_REQUIRED verdict needs at least one finding",
    ),
    (
        "review-verdict/needs-human-without-question.json",
        "human_question: a NEEDS_HUMAN verdict must carry the one question",
    ),
    (
        "review-verdict/non-pass-finding-without-a-line.json",
        "findings[0].location.line_start: a finding of a verdict other than PASS cites a line",
    ),
    (
        "review-verdict/non-pass-finding-without-location.json",
        "findings[0].location: a finding of a verdict other than PASS cites a file and a line",
    ),
    (
        "review-verdict/pass-with-blocking-finding.json",
        "findings[0].severity: a PASS verdict cannot carry a blocker",
    ),
    (
        "review-verdict/reviewer-saw-builder-summary.json",
        "the reviewer saw the builder's own account of the work",
    ),
    (
        "review-verdict/verdict-not-in-closed-set.json",
        "\"approved\" is not a valid review verdict",
    ),
    (
        "specification-contract/approved-with-blocking-open-question.json",
        "open_questions[0]: an approved specification cannot have a blocking question",
    ),
    (
        "specification-contract/approved-without-approver.json",
        "metadata.approved_by: an approved specification must say who approved it",
    ),
    (
        "specification-contract/fake-runtime-in-production.json",
        "provenance.host_runtime.fidelity: a production job cannot use a fake runtime",
    ),
    (
        "specification-contract/provenance-without-specification-artifact.json",
        "provenance.artifacts: the original Spec Kit specification file",
    ),
    (
        "specification-contract/requirement-id-not-in-spec-kit-form.json",
        "\"REQ-1\" is not a valid requirement id",
    ),
    (
        "specification-contract/revision-without-a-link-to-its-basis.json",
        "provenance.revision: a revision must record how it was made",
    ),
    (
        "specification-contract/spec-kit-plan-skill-invoked.json",
        "\"plan\" is not a valid Spec Kit skill",
    ),
    (
        "stage-contract/external-write-without-compensation.json",
        "idempotency.compensating_action: a stage that writes to an outside system",
    ),
    (
        "stage-contract/implementation-stage-outside-a-sandbox.json",
        "capabilities.placement: the implementation stage must run its agent inside the sandbox",
    ),
    (
        "stage-contract/method-without-alternatives.json",
        LIST_TOO_SHORT,
    ),
    (
        "stage-contract/no-machine-verifiable-criterion.json",
        "at least one acceptance criterion must be verifiable by a machine",
    ),
    (
        "stage-contract/repository-content-marked-trusted.json",
        "inputs[1].trust: content from outside the factory",
    ),
    (
        "stage-contract/retry-on-without-lease-lost.json",
        "timeout_and_retries.retry_on: must list LEASE_LOST and TIMED_OUT",
    ),
    (
        "stage-contract/reviewer-may-see-builder-summary.json",
        "evaluator.reviewer_must_not_see: a reviewer must never see",
    ),
    (
        "stage-contract/title-with-machine-prefix.json",
        "\"STAGE-03 | SPEC | P1: write spec\" is not a valid title",
    ),
    (
        "task-dag/model-tier-not-in-closed-set.json",
        "\"biggest\" is not a valid model tier",
    ),
    ("task-dag/plan-with-no-tasks.json", LIST_TOO_SHORT),
    (
        "task-dag/task-that-owns-nothing.json",
        "tasks[2]: a task must own at least one file pattern or one interface",
    ),
    (
        "task-dag/task-without-acceptance-mapping.json",
        "missing field `acceptance_mapping`",
    ),
    (
        "task-dag/title-with-machine-prefix-and-role-stamp.json",
        "\"TASK-13: [AGENT:BACKEND] Do work\" is not a valid title",
    ),
];

#[test]
fn every_invalid_example_is_rejected_for_the_reason_stated_next_to_it() {
    let mut problems = Vec::new();
    for example in invalid_examples() {
        let key = format!("{}/{}", example.schema, example.file);
        let Some((_, expected)) = REJECTED_FOR.iter().find(|(k, _)| *k == key) else {
            problems.push(format!("{key} has no entry in REJECTED_FOR"));
            continue;
        };
        match round_trip(example.schema, example.text) {
            Ok(_) => problems.push(format!("{key} was accepted")),
            Err(message) if message.contains(expected) => {}
            Err(message) => problems.push(format!(
                "{key} was rejected, but the message does not mention `{expected}`:\n  {message}"
            )),
        }
    }
    for (key, _) in REJECTED_FOR {
        assert!(
            invalid_examples().any(|e| format!("{}/{}", e.schema, e.file) == *key),
            "REJECTED_FOR names {key}, which is not an invalid example"
        );
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// A repair for an example whose rejection message does not name the field. The repair changes
/// that one field and nothing else. If the repaired document is accepted, the field was the only
/// defect, so the rejection was for the stated reason.
type Repair = fn(&mut Value);

fn repairs() -> Vec<(&'static str, Repair)> {
    fn valid_tasks() -> Value {
        let example = EXAMPLES
            .iter()
            .find(|e| e.valid && e.schema == "task-dag")
            .expect("a valid plan");
        serde_json::from_str::<Value>(example.text).unwrap()["tasks"].clone()
    }
    vec![
        ("domain-capability-profile/no-mandatory-gates.json", |doc| {
            doc["mandatory_gates"] = serde_json::json!(["build"]);
        }),
        (
            "evidence-manifest/manifest-without-limitations.json",
            |doc| {
                doc["limitations"] =
                    serde_json::json!(["Nothing was run on a physical device or a simulator."]);
            },
        ),
        ("stage-contract/method-without-alternatives.json", |doc| {
            doc["methods"][0]["alternatives_considered"] = serde_json::json!([
                { "name": "Ask the model to draft it freely", "why_not": "The result could not be checked by a machine." }
            ]);
        }),
        ("task-dag/plan-with-no-tasks.json", |doc| {
            doc["tasks"] = valid_tasks();
        }),
    ]
}

#[test]
fn examples_rejected_with_a_generic_list_message_have_that_list_as_their_only_defect() {
    let repairs = repairs();
    for (key, expected) in REJECTED_FOR {
        if *expected == LIST_TOO_SHORT {
            assert!(
                repairs.iter().any(|(k, _)| k == key),
                "{key} is rejected with the generic list message, so it needs an entry in repairs()"
            );
        }
    }
    for (key, repair) in repairs {
        let example = invalid_examples()
            .find(|e| format!("{}/{}", e.schema, e.file) == key)
            .unwrap_or_else(|| panic!("{key} is not an invalid example"));
        let mut document: Value = serde_json::from_str(example.text).unwrap();
        repair(&mut document);
        if let Err(message) = round_trip_value(example.schema, &document) {
            panic!("{key} is still rejected after repairing its list: {message}");
        }
    }
}

// ---- shape drift: unknown, required and optional fields -------------------------------------------

/// The schema subtree for a node of an instance. Follows `$ref` and picks the branch of a `oneOf`
/// whose `type` constant matches the instance.
fn resolve<'a>(root: &'a Value, node: &'a Value, instance: &Value) -> &'a Value {
    let mut node = node;
    for _ in 0..8 {
        if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
            let name = reference
                .strip_prefix("#/$defs/")
                .expect("a local reference");
            node = &root["$defs"][name];
        } else if let (Some(branches), true) = (
            node.get("oneOf").and_then(Value::as_array),
            instance.is_object(),
        ) {
            let tag = instance.get("type");
            let picked = branches.iter().find(|branch| {
                let branch = resolve(root, branch, instance);
                branch["properties"]["type"]["const"] == *tag.unwrap_or(&Value::Null)
            });
            match picked {
                Some(branch) => node = branch,
                None => return node,
            }
        } else {
            return node;
        }
    }
    node
}

/// Every object in `instance` that the schema describes with `properties`, as paths.
struct ObjectSite {
    path: Vec<String>,
    required: BTreeSet<String>,
    keys: Vec<String>,
}

fn object_sites(
    root: &Value,
    node: &Value,
    instance: &Value,
    path: &mut Vec<String>,
    out: &mut Vec<ObjectSite>,
) {
    let node = resolve(root, node, instance);
    match instance {
        Value::Object(map) => {
            let Some(properties) = node.get("properties").and_then(Value::as_object) else {
                return; // free-form object, such as a domain event payload
            };
            let required = node
                .get("required")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|k| k.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            out.push(ObjectSite {
                path: path.clone(),
                required,
                keys: map.keys().cloned().collect(),
            });
            for (key, child) in map {
                if let Some(child_schema) = properties.get(key) {
                    path.push(key.clone());
                    object_sites(root, child_schema, child, path, out);
                    path.pop();
                }
            }
        }
        Value::Array(items) => {
            if let Some(item_schema) = node.get("items") {
                for (index, item) in items.iter().enumerate() {
                    path.push(index.to_string());
                    object_sites(root, item_schema, item, path, out);
                    path.pop();
                }
            }
        }
        _ => {}
    }
}

fn at_mut<'a>(value: &'a mut Value, path: &[String]) -> &'a mut Value {
    let mut current = value;
    for segment in path {
        current = match current {
            Value::Array(items) => &mut items[segment.parse::<usize>().expect("an index")],
            other => &mut other[segment.as_str()],
        };
    }
    current
}

fn sites_of(example: &Example) -> (Value, Vec<ObjectSite>) {
    let instance: Value = serde_json::from_str(example.text).unwrap();
    let schema = schema_document(example.schema);
    let mut sites = Vec::new();
    object_sites(&schema, &schema, &instance, &mut Vec::new(), &mut sites);
    (instance, sites)
}

#[test]
fn an_unknown_field_is_rejected_at_every_level_of_every_valid_example() {
    let mut failures = Vec::new();
    for example in valid_examples() {
        let (instance, sites) = sites_of(example);
        for site in sites {
            let mut changed = instance.clone();
            at_mut(&mut changed, &site.path)["unexpected_extra_field"] = Value::Bool(true);
            if round_trip_value(example.schema, &changed).is_ok() {
                failures.push(format!(
                    "{}/{}: an unknown field was accepted at /{}",
                    example.schema,
                    example.file,
                    site.path.join("/")
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn required_fields_are_required_and_optional_fields_are_optional_as_the_schemas_say() {
    let mut failures = Vec::new();
    for example in valid_examples() {
        let (instance, sites) = sites_of(example);
        for site in sites {
            for key in &site.keys {
                let mut changed = instance.clone();
                at_mut(&mut changed, &site.path)
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
                let outcome = round_trip_value(example.schema, &changed);
                let place = format!(
                    "{}/{} at /{}",
                    example.schema,
                    example.file,
                    site.path.join("/")
                );
                if site.required.contains(key) {
                    match outcome {
                        Ok(_) => failures.push(format!("{place}: `{key}` is required by the schema but was accepted missing")),
                        Err(message) if !message.contains(key.as_str()) => failures.push(format!(
                            "{place}: `{key}` is required, but the rejection does not name it: {message}"
                        )),
                        Err(_) => {}
                    }
                } else if let Err(message) = outcome
                    && message.contains("missing field")
                {
                    failures.push(format!("{place}: `{key}` is optional in the schema but required by the Rust type: {message}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_document_with_another_schema_version_is_rejected() {
    for example in valid_examples() {
        let mut changed: Value = serde_json::from_str(example.text).unwrap();
        let Some(object) = changed.as_object_mut() else {
            continue;
        };
        if !object.contains_key("schema_version") {
            continue;
        }
        object.insert("schema_version".into(), Value::from(2));
        assert!(
            round_trip_value(example.schema, &changed).is_err(),
            "{}/{} accepted schema_version 2",
            example.schema,
            example.file
        );
    }
}

// ---- pattern and closed-set drift ----------------------------------------------------------------

fn collect_patterns(node: &Value, out: &mut BTreeSet<String>) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "pattern"
                    && let Some(text) = value.as_str()
                {
                    out.insert(text.to_owned());
                }
                collect_patterns(value, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_patterns(item, out)),
        _ => {}
    }
}

#[test]
fn patterns_in_the_schemas_equal_the_patterns_compiled_by_the_rust_types() {
    let mut in_schemas = BTreeSet::new();
    for (name, _) in SCHEMAS {
        collect_patterns(&schema_document(name), &mut in_schemas);
    }
    let in_rust: BTreeSet<String> = factory_domain::patterns::ALL
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
    let only_in_schemas: Vec<_> = in_schemas.difference(&in_rust).collect();
    let only_in_rust: Vec<_> = in_rust.difference(&in_schemas).collect();
    assert!(
        only_in_schemas.is_empty() && only_in_rust.is_empty(),
        "patterns only in the schemas: {only_in_schemas:#?}\npatterns only in Rust: {only_in_rust:#?}"
    );
}

/// The `enum` lists that define a type, not the ones that only filter inside `if`, `not` or
/// `contains`.
fn collect_type_enums(node: &Value, out: &mut BTreeSet<Vec<String>>) {
    let Some(map) = node.as_object() else { return };
    if let Some(values) = map.get("enum").and_then(Value::as_array) {
        let mut names: Vec<String> = values
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        names.sort();
        out.insert(names);
    }
    for key in ["properties", "$defs"] {
        if let Some(children) = map.get(key).and_then(Value::as_object) {
            children
                .values()
                .for_each(|child| collect_type_enums(child, out));
        }
    }
    for key in ["items", "additionalProperties"] {
        if let Some(child) = map.get(key) {
            collect_type_enums(child, out);
        }
    }
    if let Some(branches) = map.get("oneOf").and_then(Value::as_array) {
        branches
            .iter()
            .for_each(|branch| collect_type_enums(branch, out));
    }
}

#[test]
fn every_closed_set_in_the_schemas_is_a_rust_enum_with_the_same_names() {
    let mut in_schemas = BTreeSet::new();
    for (name, _) in SCHEMAS {
        collect_type_enums(&schema_document(name), &mut in_schemas);
    }
    let in_rust: BTreeSet<Vec<String>> = support::closed_sets::all()
        .into_iter()
        .map(|names| {
            let mut names: Vec<String> = names.into_iter().map(str::to_owned).collect();
            names.sort();
            names
        })
        .collect();
    let only_in_schemas: Vec<_> = in_schemas.difference(&in_rust).collect();
    assert!(
        only_in_schemas.is_empty(),
        "closed sets in the schemas with no Rust enum of the same names: {only_in_schemas:#?}"
    );
    let only_in_rust: Vec<_> = in_rust.difference(&in_schemas).collect();
    assert!(
        only_in_rust.is_empty(),
        "Rust enums used by contracts with no closed set of those names in a schema: {only_in_rust:#?}"
    );
}
