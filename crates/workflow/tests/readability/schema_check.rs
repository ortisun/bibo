//! A small JSON Schema checker for `schemas/gate-report.schema.json`, used to validate the
//! reports of the gate against the schema file itself.
//!
//! The workflow crate may not depend on the `contracts` crate, where the repository's schema
//! engine lives (and the `jsonschema` crate fails `cargo deny`), so this test helper reads the
//! keywords that the gate report schema uses: `$ref`, `type`, `enum`, `const`, `required`,
//! `properties`, `additionalProperties`, `items`, `minItems`, `maxItems`, `minLength`,
//! `maxLength`, `minimum`, `allOf`, `anyOf`, `if`/`then`, `not` and `dependentSchemas`.
//!
//! It does not read `pattern`. The patterns of the schema (slugs, UUIDs, hashes, timestamps, the
//! shape of a title) are enforced by the domain types, whose Rust patterns are the schema's own
//! (`crates/domain/src/patterns.rs`), and every report these tests build is also read back through
//! `GateReport::from_json_value`. A negative control checks that this helper rejects the invalid
//! examples of `schemas/examples/gate-report/invalid/` that it can judge without a pattern.

use serde_json::Value;

/// `schemas/gate-report.schema.json`.
pub const SCHEMA: &str = include_str!("../../../../schemas/gate-report.schema.json");

fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let path = reference.strip_prefix("#/")?;
    path.split('/').try_fold(root, |node, key| node.get(key))
}

fn type_matches(name: &str, value: &Value) -> bool {
    match name {
        "string" => value.is_string(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        _ => false,
    }
}

/// The problems of `value` against `schema`, each with the path where it was found. Empty when
/// the value is valid.
pub fn problems(schema: &Value, value: &Value) -> Vec<String> {
    let mut found = Vec::new();
    check(schema, schema, value, "$", &mut found);
    found
}

fn is_valid(root: &Value, schema: &Value, value: &Value) -> bool {
    let mut found = Vec::new();
    check(root, schema, value, "$", &mut found);
    found.is_empty()
}

fn check(root: &Value, schema: &Value, value: &Value, path: &str, found: &mut Vec<String>) {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        match resolve(root, reference) {
            Some(target) => check(root, target, value, path, found),
            None => found.push(format!("{path}: unresolved reference {reference}")),
        }
    }
    if let Some(expected) = schema.get("type") {
        let names: Vec<&str> = match expected {
            Value::String(name) => vec![name.as_str()],
            Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !names.iter().any(|name| type_matches(name, value)) {
            found.push(format!("{path}: expected type {names:?}"));
            return;
        }
    }
    if let Some(options) = schema.get("enum").and_then(Value::as_array)
        && !options.contains(value)
    {
        found.push(format!("{path}: {value} is not one of {options:?}"));
    }
    if let Some(constant) = schema.get("const")
        && constant != value
    {
        found.push(format!("{path}: expected the constant {constant}"));
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|min| length < min)
        {
            found.push(format!("{path}: shorter than the minimum length"));
        }
        if schema
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|max| length > max)
        {
            found.push(format!("{path}: longer than the maximum length"));
        }
    }
    if let Some(number) = value.as_i64()
        && schema
            .get("minimum")
            .and_then(Value::as_i64)
            .is_some_and(|min| number < min)
    {
        found.push(format!("{path}: below the minimum"));
    }
    if let Some(items) = value.as_array() {
        let length = items.len() as u64;
        if schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|min| length < min)
        {
            found.push(format!("{path}: fewer items than the minimum"));
        }
        if schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|max| length > max)
        {
            found.push(format!("{path}: more items than the maximum"));
        }
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                check(root, item_schema, item, &format!("{path}[{index}]"), found);
            }
        }
    }
    if let Some(object) = value.as_object() {
        for name in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !object.contains_key(name) {
                found.push(format!("{path}: missing the required field {name}"));
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        for (name, member) in object {
            match properties.and_then(|p| p.get(name)) {
                Some(member_schema) => {
                    check(
                        root,
                        member_schema,
                        member,
                        &format!("{path}.{name}"),
                        found,
                    );
                }
                None => {
                    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                        found.push(format!("{path}: the field {name} is not allowed"));
                    }
                }
            }
        }
        if let Some(dependent) = schema.get("dependentSchemas").and_then(Value::as_object) {
            for (name, sub) in dependent {
                if object.contains_key(name) {
                    check(root, sub, value, path, found);
                }
            }
        }
    }
    for sub in schema
        .get("allOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        check(root, sub, value, path, found);
    }
    if let Some(options) = schema.get("anyOf").and_then(Value::as_array)
        && !options.iter().any(|sub| is_valid(root, sub, value))
    {
        found.push(format!("{path}: matches none of the alternatives"));
    }
    if let (Some(condition), Some(then)) = (schema.get("if"), schema.get("then"))
        && is_valid(root, condition, value)
    {
        check(root, then, value, path, found);
    }
    if let Some(forbidden) = schema.get("not")
        && forbidden.get("pattern").is_none()
        && is_valid(root, forbidden, value)
    {
        found.push(format!("{path}: matches a schema it must not match"));
    }
}
