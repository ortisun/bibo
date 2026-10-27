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

use factory_domain::contracts::{
    AgentManifest, Contract, DomainCapabilityProfile, DomainEvent, EvidenceLedgerEntry,
    EvidenceManifest, GateReport, ProjectManifest, ReviewVerdict, SpecificationContract,
    StageContract, TaskDag,
};
use serde_json::Value;
use support::example_index::{EXAMPLES, Example, SCHEMAS};

/// Reads `text` as the type registered for `schema` and writes it back as a JSON value.
fn round_trip(schema: &str, text: &str) -> Result<Value, String> {
    fn through<T: Contract>(text: &str) -> Result<Value, String> {
        let value = T::from_json_str(text).map_err(|error| error.to_string())?;
        value.to_json_value().map_err(|error| error.to_string())
    }
    match schema {
        "agent-manifest" => through::<AgentManifest>(text),
        "domain-capability-profile" => through::<DomainCapabilityProfile>(text),
        "domain-event" => through::<DomainEvent>(text),
        "evidence-ledger-entry" => through::<EvidenceLedgerEntry>(text),
        "evidence-manifest" => through::<EvidenceManifest>(text),
        "gate-report" => through::<GateReport>(text),
        "project-manifest" => through::<ProjectManifest>(text),
        "review-verdict" => through::<ReviewVerdict>(text),
        "specification-contract" => through::<SpecificationContract>(text),
        "stage-contract" => through::<StageContract>(text),
        "task-dag" => through::<TaskDag>(text),
        other => panic!("no Rust type is registered for the schema {other}"),
    }
}

fn round_trip_value(schema: &str, value: &Value) -> Result<Value, String> {
    round_trip(schema, &value.to_string())
}

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

/// For each invalid example, a piece of the Rust error that shows it was rejected for the stated
/// reason and not by accident. The key is `<schema>/<file>`.
const REJECTED_FOR: &[(&str, &str)] = &[];

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

// ---- shape drift: unknown, required and optional fields -------------------------------------------

/// The schema subtree for a node of an instance. Follows `$ref` and picks the branch of a `oneOf`
/// whose `type` constant matches the instance.
fn resolve<'a>(root: &'a Value, node: &'a Value, instance: &Value) -> &'a Value {
    let mut node = node;
    for _ in 0..8 {
        if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
            let name = reference.strip_prefix("#/$defs/").expect("a local reference");
            node = &root["$defs"][name];
        } else if let (Some(branches), true) = (node.get("oneOf").and_then(Value::as_array), instance.is_object()) {
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

fn object_sites(root: &Value, node: &Value, instance: &Value, path: &mut Vec<String>, out: &mut Vec<ObjectSite>) {
    let node = resolve(root, node, instance);
    match instance {
        Value::Object(map) => {
            let Some(properties) = node.get("properties").and_then(Value::as_object) else {
                return; // free-form object, such as a domain event payload
            };
            let required = node
                .get("required")
                .and_then(Value::as_array)
                .map(|list| list.iter().filter_map(|k| k.as_str().map(str::to_owned)).collect())
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
                let place = format!("{}/{} at /{}", example.schema, example.file, site.path.join("/"));
                if site.required.contains(key) {
                    match outcome {
                        Ok(_) => failures.push(format!("{place}: `{key}` is required by the schema but was accepted missing")),
                        Err(message) if !message.contains(key.as_str()) => failures.push(format!(
                            "{place}: `{key}` is required, but the rejection does not name it: {message}"
                        )),
                        Err(_) => {}
                    }
                } else if let Err(message) = outcome {
                    if message.contains("missing field") {
                        failures.push(format!("{place}: `{key}` is optional in the schema but required by the Rust type: {message}"));
                    }
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
        let Some(object) = changed.as_object_mut() else { continue };
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
                if key == "pattern" {
                    if let Some(text) = value.as_str() {
                        out.insert(text.to_owned());
                    }
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
    let in_rust: BTreeSet<String> = factory_domain::patterns::ALL.iter().map(|p| (*p).to_owned()).collect();
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
        let mut names: Vec<String> = values.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect();
        names.sort();
        out.insert(names);
    }
    for key in ["properties", "$defs"] {
        if let Some(children) = map.get(key).and_then(Value::as_object) {
            children.values().for_each(|child| collect_type_enums(child, out));
        }
    }
    for key in ["items", "additionalProperties"] {
        if let Some(child) = map.get(key) {
            collect_type_enums(child, out);
        }
    }
    if let Some(branches) = map.get("oneOf").and_then(Value::as_array) {
        branches.iter().for_each(|branch| collect_type_enums(branch, out));
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
