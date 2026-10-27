//! A small JSON Schema (draft 2020-12) engine that supports exactly the keywords the eleven
//! contract schemas use, and nothing else.
//!
//! # Why this exists and the `jsonschema` crate is not used
//!
//! The architecture rules name the `jsonschema` crate for this job. On 2026-10-27 it was added to
//! this crate and `cargo deny --locked check` failed. `jsonschema` 0.60.2 pulls in `referencing`,
//! which depends on `fluent-uri` (and through it `borrow-or-share`, licence MIT-0) and on
//! `hashbrown` (and through it `foldhash`, licence Zlib). `deny.toml` allows MIT, Apache-2.0 and
//! Unicode-3.0 only, and adding a licence is a decision for a person, so the file was not edited.
//! The version found at that point (0.46.10) has the same two crates, and every version in
//! between uses `referencing`. If a person accepts those two licences later, this module can be
//! replaced by the crate behind the same two functions, [`Schema::compile`] and
//! [`Schema::validate`]. The tests in `tests/schema_examples.rs` are written against the
//! outcome, not against this module, so they would keep checking the replacement.
//!
//! # What makes a closed engine acceptable here
//!
//! * The schemas are ours, embedded at compile time and fixed. This is not a general validator.
//! * [`Schema::compile`] walks the whole schema first and refuses any keyword it does not know, any
//!   `$ref` that is not a local `#/$defs/name` pointer, and any `pattern` the `regex` crate cannot
//!   compile. A new schema that uses a new keyword therefore fails loudly when the crate is built
//!   or tested, not silently by accepting everything.
//! * `pattern` runs on the `regex` crate, which matches in linear time, so a hostile instance
//!   cannot cause catastrophic backtracking.
//! * Recursion depth is bounded: the instance depth is limited by the caller before validation,
//!   and `$ref` and keyword nesting is bounded by [`MAX_SCHEMA_DEPTH`].
//! * Error messages describe the rule, never the offending value, so a secret inside an
//!   instance cannot leak through a message. Property names are echoed only when they look like
//!   ordinary field names (see [`safe_name`]).
//!
//! # Keywords
//!
//! Applied: `type`, `enum`, `const`, `required`, `properties`, `additionalProperties` (only
//! `false`, which is what the schemas use, or a schema), `items`, `prefixItems`, `minItems`,
//! `maxItems`, `uniqueItems`, `minLength`, `maxLength`, `pattern`, `minimum`, `maximum`,
//! `exclusiveMinimum`, `exclusiveMaximum`, `allOf`, `anyOf`, `oneOf`, `not`, `if`/`then`/`else`,
//! `contains`, `dependentSchemas` and local `$ref`. Annotations that are accepted and ignored:
//! `$schema`, `$id`, `$defs`, `$comment`, `title`, `description`, `default`, `examples` and
//! `format`. `format` is an annotation in draft 2020-12, as it is in `check-jsonschema`, which
//! `schemas/validate.sh` uses; the schemas enforce times and hashes with `pattern` for that
//! reason.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

use regex::Regex;
use serde_json::{Map, Number, Value};

/// How deeply schemas may nest, counting `$ref` jumps. The deepest real schema is far below this.
pub const MAX_SCHEMA_DEPTH: usize = 64;

/// The most violations one validation reports. Further ones are counted, not listed.
pub const MAX_VIOLATIONS: usize = 100;

/// Which rule a violation is about. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Keyword {
    /// `type`.
    Type,
    /// `enum`.
    Enum,
    /// `const`.
    Const,
    /// `required`.
    Required,
    /// `additionalProperties`.
    AdditionalProperties,
    /// `minItems`.
    MinItems,
    /// `maxItems`.
    MaxItems,
    /// `uniqueItems`.
    UniqueItems,
    /// `minLength`.
    MinLength,
    /// `maxLength`.
    MaxLength,
    /// `pattern`.
    Pattern,
    /// `minimum`.
    Minimum,
    /// `maximum`.
    Maximum,
    /// `exclusiveMinimum`.
    ExclusiveMinimum,
    /// `exclusiveMaximum`.
    ExclusiveMaximum,
    /// `anyOf`.
    AnyOf,
    /// `oneOf`.
    OneOf,
    /// `not`.
    Not,
    /// `contains`.
    Contains,
    /// The schema nests deeper than the engine allows. Never raised by the embedded schemas.
    SchemaDepth,
}

/// One broken rule: where, which rule and what to change. The message never contains a value
/// taken from the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaViolation {
    /// The place in the instance, such as `$`, `permissions.shell` or `findings[0].severity`.
    pub path: String,
    /// The rule.
    pub keyword: Keyword,
    /// For `required` and `additionalProperties`, the property the rule is about, when it is safe
    /// to show.
    pub property: Option<String>,
    /// Plain English: what is wrong and what would make it right.
    pub message: String,
    /// How many segments the path has, which is how deep in the document the problem is.
    pub(crate) segments: usize,
    /// The last segment, when it is a property name.
    pub(crate) leaf: Option<String>,
}

/// Why a schema could not be compiled. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaLoadError {
    /// The schema text is not JSON.
    #[error("the schema is not valid JSON: {0}")]
    NotJson(String),
    /// A keyword the engine does not implement. Failing here is deliberate: an ignored keyword
    /// would make the schema accept documents it was written to refuse.
    #[error(
        "the schema uses the keyword `{keyword}` at {pointer}, which the engine does not support"
    )]
    UnsupportedKeyword {
        /// Where in the schema.
        pointer: String,
        /// The keyword.
        keyword: String,
    },
    /// A `$ref` that is not a local `#/$defs/name` pointer, or that names a missing definition.
    #[error(
        "the schema has a reference at {pointer} that does not point to a local definition: {reference}"
    )]
    BadReference {
        /// Where in the schema.
        pointer: String,
        /// The reference text.
        reference: String,
    },
    /// A `pattern` that does not compile.
    #[error("the pattern at {pointer} does not compile: {reason}")]
    BadPattern {
        /// Where in the schema.
        pointer: String,
        /// The compiler's reason.
        reason: String,
    },
    /// A keyword has a value of the wrong shape.
    #[error("the keyword at {pointer} has a value of the wrong shape")]
    BadShape {
        /// Where in the schema.
        pointer: String,
    },
}

/// A compiled schema: the JSON document plus its compiled patterns.
#[derive(Debug)]
pub struct Schema {
    root: Value,
    patterns: HashMap<String, Regex>,
}

const ANNOTATIONS: [&str; 9] = [
    "$schema",
    "$id",
    "$defs",
    "$comment",
    "title",
    "description",
    "default",
    "examples",
    "format",
];

impl Schema {
    /// Compiles a schema from JSON text.
    ///
    /// # Errors
    /// [`SchemaLoadError`] when the text is not JSON, uses an unsupported keyword, has a bad
    /// reference or has a pattern that does not compile.
    pub fn compile_text(text: &str) -> Result<Self, SchemaLoadError> {
        let root: Value =
            serde_json::from_str(text).map_err(|e| SchemaLoadError::NotJson(e.to_string()))?;
        Self::compile(root)
    }

    /// Compiles a schema from a JSON value.
    ///
    /// # Errors
    /// [`SchemaLoadError`], as for [`Schema::compile_text`].
    pub fn compile(root: Value) -> Result<Self, SchemaLoadError> {
        let mut patterns = HashMap::new();
        check_schema(&root, &root, "#", &mut patterns, 0)?;
        Ok(Self { root, patterns })
    }

    /// Every rule the instance breaks, at most [`MAX_VIOLATIONS`]. The order is stable: the
    /// instance is walked in schema order, and the keywords of one schema object are applied in
    /// alphabetical order. An empty list means the instance follows the schema. The second value counts violations beyond the
    /// cap.
    #[must_use]
    pub fn validate(&self, instance: &Value) -> (Vec<SchemaViolation>, usize) {
        let mut run = Run {
            schema: self,
            found: Vec::new(),
            dropped: 0,
            path: Vec::new(),
        };
        run.check(&self.root, instance, 0);
        (run.found, run.dropped)
    }
}

// ------------------------------------------------------------------------------------------
// Compile-time walk
// ------------------------------------------------------------------------------------------

fn check_schema(
    root: &Value,
    node: &Value,
    pointer: &str,
    patterns: &mut HashMap<String, Regex>,
    depth: usize,
) -> Result<(), SchemaLoadError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaLoadError::BadShape {
            pointer: pointer.to_owned(),
        });
    }
    let bad_shape = || SchemaLoadError::BadShape {
        pointer: pointer.to_owned(),
    };
    let map = match node {
        // `true` and `false` are schemas too.
        Value::Bool(_) => return Ok(()),
        Value::Object(map) => map,
        _ => return Err(bad_shape()),
    };
    for (keyword, value) in map {
        let here = format!("{pointer}/{keyword}");
        match keyword.as_str() {
            word if ANNOTATIONS.contains(&word) => {
                if word == "$defs" {
                    let defs = value.as_object().ok_or_else(bad_shape)?;
                    for (name, sub) in defs {
                        check_schema(root, sub, &format!("{here}/{name}"), patterns, depth + 1)?;
                    }
                }
            }
            "type" => {
                let ok = match value {
                    Value::String(name) => type_name_is_known(name),
                    Value::Array(names) => names
                        .iter()
                        .all(|n| n.as_str().is_some_and(type_name_is_known)),
                    _ => false,
                };
                if !ok {
                    return Err(bad_shape());
                }
            }
            "enum" => {
                if !value.is_array() {
                    return Err(bad_shape());
                }
            }
            "const" => {}
            "required" => {
                let list = value.as_array().ok_or_else(bad_shape)?;
                if !list.iter().all(Value::is_string) {
                    return Err(bad_shape());
                }
            }
            "properties" | "dependentSchemas" => {
                let entries = value.as_object().ok_or_else(bad_shape)?;
                for (name, sub) in entries {
                    check_schema(root, sub, &format!("{here}/{name}"), patterns, depth + 1)?;
                }
            }
            "additionalProperties" | "items" | "not" | "if" | "then" | "else" | "contains" => {
                check_schema(root, value, &here, patterns, depth + 1)?;
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                let list = value.as_array().ok_or_else(bad_shape)?;
                for (index, sub) in list.iter().enumerate() {
                    check_schema(root, sub, &format!("{here}/{index}"), patterns, depth + 1)?;
                }
            }
            "minItems" | "maxItems" | "minLength" | "maxLength" => {
                if value.as_u64().is_none() {
                    return Err(bad_shape());
                }
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                if !value.is_number() {
                    return Err(bad_shape());
                }
            }
            "uniqueItems" => {
                if !value.is_boolean() {
                    return Err(bad_shape());
                }
            }
            "pattern" => {
                let text = value.as_str().ok_or_else(bad_shape)?;
                if !patterns.contains_key(text) {
                    let compiled = Regex::new(text).map_err(|e| SchemaLoadError::BadPattern {
                        pointer: here.clone(),
                        reason: e.to_string(),
                    })?;
                    patterns.insert(text.to_owned(), compiled);
                }
            }
            "$ref" => {
                let reference = value.as_str().ok_or_else(bad_shape)?;
                if resolve(root, reference).is_none() {
                    return Err(SchemaLoadError::BadReference {
                        pointer: here,
                        reference: reference.to_owned(),
                    });
                }
            }
            other => {
                return Err(SchemaLoadError::UnsupportedKeyword {
                    pointer: pointer.to_owned(),
                    keyword: other.to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn type_name_is_known(name: &str) -> bool {
    matches!(
        name,
        "null" | "boolean" | "object" | "array" | "number" | "integer" | "string"
    )
}

/// Resolves `#/$defs/name` against the root. Nothing else is a valid reference.
fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let name = reference.strip_prefix("#/$defs/")?;
    if name.is_empty() || name.contains('/') || name.contains('~') {
        return None;
    }
    root.get("$defs")?.get(name)
}

// ------------------------------------------------------------------------------------------
// Validation
// ------------------------------------------------------------------------------------------

#[derive(Clone)]
enum Segment {
    Key(String),
    Index(usize),
}

struct Run<'s> {
    schema: &'s Schema,
    found: Vec<SchemaViolation>,
    dropped: usize,
    path: Vec<Segment>,
}

impl<'s> Run<'s> {
    fn render_path(&self) -> String {
        if self.path.is_empty() {
            return "$".to_owned();
        }
        let mut text = String::new();
        for segment in &self.path {
            match segment {
                Segment::Key(key) => {
                    if !text.is_empty() {
                        text.push('.');
                    }
                    text.push_str(&safe_name(key));
                }
                Segment::Index(index) => {
                    text.push_str(&format!("[{index}]"));
                }
            }
        }
        text
    }

    fn report(&mut self, keyword: Keyword, property: Option<&str>, message: String) {
        if self.found.len() >= MAX_VIOLATIONS {
            self.dropped += 1;
            return;
        }
        let path = self.render_path();
        self.found.push(SchemaViolation {
            path,
            keyword,
            property: property.and_then(|name| {
                let shown = safe_name(name);
                (shown != UNPRINTABLE_NAME).then_some(shown)
            }),
            message,
            segments: self.path.len(),
            leaf: match self.path.last() {
                Some(Segment::Key(key)) => Some(key.clone()),
                _ => None,
            },
        });
    }

    /// Runs `schema` on `instance` and returns what it found, leaving this run's own list alone.
    fn collect(&mut self, schema: &Value, instance: &Value, depth: usize) -> Attempt {
        let outer_found = std::mem::take(&mut self.found);
        let outer_dropped = std::mem::replace(&mut self.dropped, 0);
        self.check(schema, instance, depth);
        Attempt {
            violations: std::mem::replace(&mut self.found, outer_found),
            dropped: std::mem::replace(&mut self.dropped, outer_dropped),
        }
    }

    /// Tries the shapes of a `oneOf` or `anyOf` and returns how many matched and what each one
    /// that did not match found. An `anyOf` stops at the first match, because nothing more is
    /// needed. A `oneOf` tries every shape, because a second match is an error too.
    fn try_shapes(
        &mut self,
        shapes: &[Value],
        instance: &Value,
        depth: usize,
        stop_at_first_match: bool,
    ) -> (usize, Vec<Attempt>) {
        let mut matching = 0usize;
        let mut failed = Vec::new();
        for shape in shapes {
            let attempt = self.collect(shape, instance, depth);
            if attempt.violations.is_empty() && attempt.dropped == 0 {
                matching += 1;
                if stop_at_first_match {
                    break;
                }
            } else {
                failed.push(attempt);
            }
        }
        (matching, failed)
    }

    /// The properties that two or more shapes constrain with `const` or `enum`: how the schemas tell
    /// shapes apart. The empty name stands for a `const` or `enum` on the instance itself.
    fn discriminating_properties(&self, shapes: &[Value]) -> HashSet<String> {
        let mut shapes_constraining: HashMap<String, usize> = HashMap::new();
        for shape in shapes {
            let mut names = HashSet::new();
            self.collect_constrained(shape, &mut names, 0);
            for name in names {
                *shapes_constraining.entry(name).or_default() += 1;
            }
        }
        shapes_constraining
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .map(|(name, _)| name)
            .collect()
    }

    /// Adds the names of the properties `shape` constrains with `const` or `enum`, following local
    /// references and `allOf`.
    fn collect_constrained(&self, shape: &Value, names: &mut HashSet<String>, hops: usize) {
        const MAX_HOPS: usize = 8;
        let Some(map) = shape.as_object() else { return };
        if hops > MAX_HOPS {
            return;
        }
        if let Some(target) = map
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|reference| resolve(&self.schema.root, reference))
        {
            self.collect_constrained(target, names, hops + 1);
        }
        if map.contains_key("const") || map.contains_key("enum") {
            names.insert(String::new());
        }
        if let Some(properties) = map.get("properties").and_then(Value::as_object) {
            for (name, property) in properties {
                let resolved = property
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|reference| resolve(&self.schema.root, reference))
                    .unwrap_or(property);
                if resolved.get("const").is_some() || resolved.get("enum").is_some() {
                    names.insert(name.clone());
                }
            }
        }
        for part in map
            .get("allOf")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            self.collect_constrained(part, names, hops + 1);
        }
    }

    /// Reports a `oneOf` or `anyOf` that no shape matched.
    ///
    /// The generic violation always comes first. When one shape got past the keyword that tells
    /// the shapes apart, that shape's own violations follow, because they say what to change.
    /// See [`closest_shape`] for the choice.
    fn report_no_shape(&mut self, keyword: Keyword, shapes: &[Value], failed: Vec<Attempt>) {
        let base = self.path.len();
        let discriminators = self.discriminating_properties(shapes);
        let closest = closest_shape(&failed, base, &discriminators);
        let message = if closest.is_some() {
            "does not match any of the allowed shapes; the closest shape fails as listed next"
        } else {
            "does not match any of the allowed shapes"
        };
        self.report(keyword, None, message.to_owned());
        if let Some(index) = closest
            && let Some(attempt) = failed.into_iter().nth(index)
        {
            self.dropped += attempt.dropped;
            for violation in attempt.violations {
                if self.found.len() >= MAX_VIOLATIONS {
                    self.dropped += 1;
                } else {
                    self.found.push(violation);
                }
            }
        }
    }

    /// Runs `schema` on `instance` and returns how many violations it added. The violations stay
    /// in `found` when the caller wants them and are removed with `rollback`.
    fn count_violations(&mut self, schema: &Value, instance: &Value, depth: usize) -> usize {
        let before = self.found.len() + self.dropped;
        self.check(schema, instance, depth);
        self.found.len() + self.dropped - before
    }

    /// True when `schema` accepts `instance`. Violations found while asking are thrown away.
    fn accepts(&mut self, schema: &Value, instance: &Value, depth: usize) -> bool {
        let kept = self.found.len();
        let dropped = self.dropped;
        let added = self.count_violations(schema, instance, depth);
        self.found.truncate(kept);
        self.dropped = dropped;
        added == 0
    }

    fn check(&mut self, schema: &Value, instance: &Value, depth: usize) {
        if depth > MAX_SCHEMA_DEPTH {
            self.report(
                Keyword::SchemaDepth,
                None,
                "the document nests deeper than the validator allows".to_owned(),
            );
            return;
        }
        let map = match schema {
            Value::Bool(true) => return,
            Value::Bool(false) => {
                self.report(Keyword::Not, None, "no value is allowed here".to_owned());
                return;
            }
            Value::Object(map) => map,
            // Refused when the schema was compiled.
            _ => return,
        };
        for (keyword, value) in map {
            self.apply(keyword, value, map, instance, depth);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply(
        &mut self,
        keyword: &str,
        value: &Value,
        siblings: &Map<String, Value>,
        instance: &Value,
        depth: usize,
    ) {
        match keyword {
            "$ref" => {
                // Copy the reference out first, so the target is borrowed from the schema and
                // not from `self`.
                let schema: &'s Schema = self.schema;
                if let Some(target) = value
                    .as_str()
                    .and_then(|reference| resolve(&schema.root, reference))
                {
                    self.check(target, instance, depth + 1);
                }
            }
            "type" => self.apply_type(value, instance),
            "enum" => {
                if let Some(options) = value.as_array()
                    && !options.iter().any(|option| json_equal(option, instance))
                {
                    self.report(
                        Keyword::Enum,
                        None,
                        format!("must be one of: {}", render_options(options)),
                    );
                }
            }
            "const" => {
                if !json_equal(value, instance) {
                    self.report(
                        Keyword::Const,
                        None,
                        format!("must be exactly {}", render_constant(value)),
                    );
                }
            }
            "required" => {
                if let (Some(names), Some(object)) = (value.as_array(), instance.as_object()) {
                    for name in names.iter().filter_map(Value::as_str) {
                        if !object.contains_key(name) {
                            self.report(
                                Keyword::Required,
                                Some(name),
                                format!("the required property `{name}` is missing"),
                            );
                        }
                    }
                }
            }
            "properties" => {
                if let (Some(entries), Some(object)) = (value.as_object(), instance.as_object()) {
                    for (name, sub) in entries {
                        if let Some(child) = object.get(name) {
                            self.path.push(Segment::Key(name.clone()));
                            self.check(sub, child, depth + 1);
                            self.path.pop();
                        }
                    }
                }
            }
            "additionalProperties" => {
                if let Some(object) = instance.as_object() {
                    let declared = siblings.get("properties").and_then(Value::as_object);
                    for (name, child) in object {
                        if declared.is_some_and(|d| d.contains_key(name)) {
                            continue;
                        }
                        match value {
                            Value::Bool(false) => {
                                let shown = safe_name(name);
                                let message = if shown == UNPRINTABLE_NAME {
                                    "a property with an unusual name is not allowed; remove it"
                                        .to_owned()
                                } else {
                                    format!("the property `{shown}` is not allowed; remove it")
                                };
                                self.report(Keyword::AdditionalProperties, Some(name), message);
                            }
                            Value::Bool(true) => {}
                            sub => {
                                self.path.push(Segment::Key(name.clone()));
                                self.check(sub, child, depth + 1);
                                self.path.pop();
                            }
                        }
                    }
                }
            }
            "items" => {
                if let Some(items) = instance.as_array() {
                    let skip = siblings
                        .get("prefixItems")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len);
                    for (index, child) in items.iter().enumerate().skip(skip) {
                        self.path.push(Segment::Index(index));
                        self.check(value, child, depth + 1);
                        self.path.pop();
                    }
                }
            }
            "prefixItems" => {
                if let (Some(schemas), Some(items)) = (value.as_array(), instance.as_array()) {
                    for (index, (sub, child)) in schemas.iter().zip(items).enumerate() {
                        self.path.push(Segment::Index(index));
                        self.check(sub, child, depth + 1);
                        self.path.pop();
                    }
                }
            }
            "minItems" => {
                if let (Some(least), Some(items)) = (value.as_u64(), instance.as_array())
                    && (items.len() as u64) < least
                {
                    let message = if least == 1 {
                        "must not be empty; add at least one item".to_owned()
                    } else {
                        format!("must have at least {least} items but has {}", items.len())
                    };
                    self.report(Keyword::MinItems, None, message);
                }
            }
            "maxItems" => {
                if let (Some(most), Some(items)) = (value.as_u64(), instance.as_array())
                    && (items.len() as u64) > most
                {
                    self.report(
                        Keyword::MaxItems,
                        None,
                        format!("must have at most {most} items but has {}", items.len()),
                    );
                }
            }
            "uniqueItems" => {
                if value.as_bool() == Some(true)
                    && let Some(items) = instance.as_array()
                    && !all_distinct(items)
                {
                    self.report(
                        Keyword::UniqueItems,
                        None,
                        "items must be unique; remove the repeated item".to_owned(),
                    );
                }
            }
            "minLength" => {
                if let (Some(least), Some(text)) = (value.as_u64(), instance.as_str())
                    && (text.chars().count() as u64) < least
                {
                    let message = if least == 1 {
                        "must not be empty".to_owned()
                    } else {
                        format!("must be at least {least} characters long")
                    };
                    self.report(Keyword::MinLength, None, message);
                }
            }
            "maxLength" => {
                if let (Some(most), Some(text)) = (value.as_u64(), instance.as_str())
                    && (text.chars().count() as u64) > most
                {
                    self.report(
                        Keyword::MaxLength,
                        None,
                        format!("must be at most {most} characters long"),
                    );
                }
            }
            "pattern" => {
                if let (Some(pattern), Some(text)) = (value.as_str(), instance.as_str())
                    && let Some(regex) = self.schema.patterns.get(pattern)
                    && !regex.is_match(text)
                {
                    self.report(
                        Keyword::Pattern,
                        None,
                        format!("does not match the required pattern `{pattern}`"),
                    );
                }
            }
            "minimum" => self.apply_bound(value, instance, Keyword::Minimum),
            "maximum" => self.apply_bound(value, instance, Keyword::Maximum),
            "exclusiveMinimum" => self.apply_bound(value, instance, Keyword::ExclusiveMinimum),
            "exclusiveMaximum" => self.apply_bound(value, instance, Keyword::ExclusiveMaximum),
            "allOf" => {
                if let Some(list) = value.as_array() {
                    for sub in list {
                        self.check(sub, instance, depth + 1);
                    }
                }
            }
            "anyOf" => {
                if let Some(list) = value.as_array() {
                    let (matching, failed) = self.try_shapes(list, instance, depth + 1, true);
                    if matching == 0 {
                        self.report_no_shape(Keyword::AnyOf, list, failed);
                    }
                }
            }
            "oneOf" => {
                if let Some(list) = value.as_array() {
                    let (matching, failed) = self.try_shapes(list, instance, depth + 1, false);
                    if matching == 0 {
                        self.report_no_shape(Keyword::OneOf, list, failed);
                    } else if matching > 1 {
                        self.report(
                            Keyword::OneOf,
                            None,
                            "matches more than one of the shapes that exclude each other"
                                .to_owned(),
                        );
                    }
                }
            }
            "not" => {
                if self.accepts(value, instance, depth + 1) {
                    self.report(
                        Keyword::Not,
                        None,
                        "has a shape that is not allowed here".to_owned(),
                    );
                }
            }
            "if" => {
                // `then` and `else` are applied here, where the result of `if` is known. They are
                // skipped when their own turn comes.
                let condition = self.accepts(value, instance, depth + 1);
                let branch = if condition { "then" } else { "else" };
                if let Some(sub) = siblings.get(branch) {
                    self.check(sub, instance, depth + 1);
                }
            }
            "contains" => {
                if let Some(items) = instance.as_array()
                    && !items
                        .iter()
                        .any(|child| self.accepts(value, child, depth + 1))
                {
                    self.report(
                        Keyword::Contains,
                        None,
                        "must contain at least one item of the required shape; none does"
                            .to_owned(),
                    );
                }
            }
            "dependentSchemas" => {
                if let (Some(entries), Some(object)) = (value.as_object(), instance.as_object()) {
                    for (name, sub) in entries {
                        if object.contains_key(name) {
                            self.check(sub, instance, depth + 1);
                        }
                    }
                }
            }
            // Annotations, and `then` / `else`, which `if` applies.
            _ => {}
        }
    }

    fn apply_type(&mut self, value: &Value, instance: &Value) {
        let names: Vec<&str> = match value {
            Value::String(name) => vec![name.as_str()],
            Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
            _ => return,
        };
        if !names.iter().any(|name| has_type(instance, name)) {
            self.report(
                Keyword::Type,
                None,
                format!(
                    "expected {} but found {}",
                    names.join(" or "),
                    kind_of(instance)
                ),
            );
        }
    }

    fn apply_bound(&mut self, limit: &Value, instance: &Value, keyword: Keyword) {
        let (Value::Number(limit), Value::Number(actual)) = (limit, instance) else {
            return;
        };
        let Some(order) = compare_numbers(actual, limit) else {
            return;
        };
        let (broken, wording) = match keyword {
            Keyword::Minimum => (order == Ordering::Less, "at least"),
            Keyword::Maximum => (order == Ordering::Greater, "at most"),
            Keyword::ExclusiveMinimum => (order != Ordering::Greater, "greater than"),
            _ => (order != Ordering::Less, "less than"),
        };
        if broken {
            self.report(keyword, None, format!("must be {wording} {limit}"));
        }
    }
}

/// What one shape of a `oneOf` or `anyOf` found when it did not match.
struct Attempt {
    violations: Vec<SchemaViolation>,
    dropped: usize,
}

/// Chooses the shape whose violations best explain why the instance does not fit, or `None` when
/// no shape got past the keyword that tells the shapes apart.
///
/// This is the reference validator's "best deep match", with one safeguard. `check-jsonschema`
/// prints the generic error, its "best match" and its "best deep match". The deep match is the
/// deepest error among all the shapes, whichever shape it came from, and when several errors are
/// equally deep it takes the first, which is often a `type` mismatch from a shape that was never
/// meant. The safeguard keeps the choice to a shape that got past its discriminator.
///
/// 1. A shape is **out** when it fails on the instance's own type, or when it fails a `const` or
///    `enum` on the instance itself or on a direct property that tells shapes apart. A property
///    tells shapes apart when two or more shapes constrain it with `const` or `enum`
///    (`discriminators`, from the schema): that is how the schemas pick a shape, as in
///    `type: const "experiment"`. A shape that fails it is not the one the author meant. A `const`
///    or `enum` that only one shape checks (a `result` value, say) does not tell shapes apart, so a
///    shape that fails only that is still a candidate. If every shape is out, nothing is chosen
///    and the generic violation stands alone.
/// 2. Of the shapes left, the one with the **deepest** violation wins: the one that failed furthest
///    down into the instance, which is the one that matched best on the way. Ties go to the shape
///    with the **fewest** violations, then to the **first** in the schema.
///
/// `base` is the number of path segments of the instance the `oneOf` or `anyOf` applies to.
fn closest_shape(
    failed: &[Attempt],
    base: usize,
    discriminators: &HashSet<String>,
) -> Option<usize> {
    let relative = |violation: &SchemaViolation| violation.segments.saturating_sub(base);
    let fails_its_discriminator = |violation: &SchemaViolation| {
        if !matches!(violation.keyword, Keyword::Const | Keyword::Enum) {
            return false;
        }
        match relative(violation) {
            0 => discriminators.contains(""),
            1 => violation
                .leaf
                .as_deref()
                .is_some_and(|name| discriminators.contains(name)),
            _ => false,
        }
    };
    failed
        .iter()
        .enumerate()
        .filter(|(_, attempt)| {
            !attempt.violations.iter().any(|violation| {
                fails_its_discriminator(violation)
                    || (violation.keyword == Keyword::Type && relative(violation) == 0)
            })
        })
        .min_by_key(|(index, attempt)| {
            let deepest = attempt.violations.iter().map(relative).max().unwrap_or(0);
            (
                std::cmp::Reverse(deepest),
                attempt.violations.len() + attempt.dropped,
                *index,
            )
        })
        .map(|(index, _)| index)
}

// ------------------------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------------------------

/// What a name shows as when it is not safe to print.
pub const UNPRINTABLE_NAME: &str = "<unusual name>";

/// Returns `name` when it looks like an ordinary field name, and [`UNPRINTABLE_NAME`] otherwise.
///
/// A name is ordinary when it is 1 to 48 characters of lower-case ASCII letters, digits, `_`, `-`
/// and `.`, starts with a letter, and has no run of six digits. Property names come from the
/// document being checked, which can be hostile, and a secret can be hiding in a key. Real keys
/// are mixed case or long runs of digits and letters, so they fall outside this shape.
#[must_use]
pub fn safe_name(name: &str) -> String {
    let ordinary = !name.is_empty()
        && name.len() <= 48
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'))
        && !has_digit_run(name, 6)
        && !looks_like_key_prefix(name);
    if ordinary {
        name.to_owned()
    } else {
        UNPRINTABLE_NAME.to_owned()
    }
}

fn has_digit_run(text: &str, length: usize) -> bool {
    let mut run = 0usize;
    for c in text.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if run >= length {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Lower-case vendor key prefixes that are common enough to rule out. This is a belt on top of
/// the shape rule above, not the control.
fn looks_like_key_prefix(name: &str) -> bool {
    [
        "sk-", "ghp_", "gho_", "ghs_", "ghu_", "ghr_", "xox", "sfjt_", "npm_",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn has_type(value: &Value, name: &str) -> bool {
    match name {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_number().is_some_and(is_integral),
        _ => false,
    }
}

/// True for `5` and for `5.0`: draft 2020-12 and `check-jsonschema` both call a number with no
/// fractional part an integer.
fn is_integral(number: &Number) -> bool {
    number.is_i64()
        || number.is_u64()
        || number
            .as_f64()
            .is_some_and(|f| f.is_finite() && f.fract() == 0.0)
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn render_options(options: &[Value]) -> String {
    options
        .iter()
        .map(render_constant)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_constant(value: &Value) -> String {
    match value {
        Value::String(text) => format!("`{text}`"),
        other => other.to_string(),
    }
}

fn integer_of(number: &Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

/// Orders two numbers by value, so `1` and `1.0` are equal.
fn compare_numbers(a: &Number, b: &Number) -> Option<Ordering> {
    if let (Some(x), Some(y)) = (integer_of(a), integer_of(b)) {
        return Some(x.cmp(&y));
    }
    a.as_f64()?.partial_cmp(&b.as_f64()?)
}

/// JSON equality in which `1` equals `1.0` and key order does not matter.
fn json_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => compare_numbers(x, y) == Some(Ordering::Equal),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_equal(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(key, p)| y.get(key).is_some_and(|q| json_equal(p, q)))
        }
        _ => a == b,
    }
}

/// True when no two items are equal. Uses a canonical text for each item, so the cost is linear
/// in the size of the array and not quadratic.
fn all_distinct(items: &[Value]) -> bool {
    let mut seen = HashSet::with_capacity(items.len());
    items.iter().all(|item| seen.insert(canonical_text(item)))
}

fn canonical_text(value: &Value) -> String {
    match value {
        Value::Number(number) => match integer_of(number) {
            Some(whole) => whole.to_string(),
            None => match number.as_f64() {
                Some(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e30 => {
                    format!("{}", f as i128)
                }
                Some(f) => format!("{f:?}"),
                None => number.to_string(),
            },
        },
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_text).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let sorted: BTreeMap<&String, String> =
                map.iter().map(|(k, v)| (k, canonical_text(v))).collect();
            let parts: Vec<String> = sorted
                .into_iter()
                .map(|(k, v)| format!("{}:{v}", Value::String(k.clone())))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema(value: Value) -> Schema {
        Schema::compile(value).expect("the test schema compiles")
    }

    fn found(schema: &Schema, instance: &Value) -> Vec<(String, Keyword)> {
        schema
            .validate(instance)
            .0
            .into_iter()
            .map(|v| (v.path, v.keyword))
            .collect()
    }

    #[test]
    fn an_unsupported_keyword_is_refused_when_the_schema_is_compiled() {
        let error = Schema::compile(json!({"type": "object", "patternProperties": {}}))
            .expect_err("patternProperties is not supported");
        assert!(matches!(
            error,
            SchemaLoadError::UnsupportedKeyword { ref keyword, .. } if keyword == "patternProperties"
        ));
    }

    #[test]
    fn a_reference_outside_the_local_definitions_is_refused() {
        for reference in [
            "https://example.org/schema.json",
            "other.json#/x",
            "#/$defs/missing",
            "#/properties/a",
            "#/$defs/a/b",
        ] {
            let result =
                Schema::compile(json!({"$defs": {"a": {"type": "string"}}, "$ref": reference}));
            assert!(
                matches!(result, Err(SchemaLoadError::BadReference { .. })),
                "{reference}"
            );
        }
    }

    #[test]
    fn a_pattern_that_does_not_compile_is_refused() {
        let result = Schema::compile(json!({"pattern": "(?<=a)b"}));
        assert!(matches!(result, Err(SchemaLoadError::BadPattern { .. })));
    }

    #[test]
    fn type_distinguishes_integers_from_numbers_and_treats_whole_floats_as_integers() {
        let s = schema(json!({"type": "integer"}));
        assert!(found(&s, &json!(5)).is_empty());
        assert!(
            found(&s, &json!(5.0)).is_empty(),
            "5.0 is an integer in draft 2020-12"
        );
        assert_eq!(found(&s, &json!(5.5)), [("$".to_owned(), Keyword::Type)]);
        assert_eq!(found(&s, &json!("5")), [("$".to_owned(), Keyword::Type)]);
    }

    #[test]
    fn const_and_enum_compare_numbers_by_value() {
        let s = schema(json!({"const": 1}));
        assert!(found(&s, &json!(1.0)).is_empty());
        let s = schema(json!({"enum": [1, "a"]}));
        assert!(found(&s, &json!(1.0)).is_empty());
        assert_eq!(found(&s, &json!(2)), [("$".to_owned(), Keyword::Enum)]);
    }

    #[test]
    fn required_and_additional_properties_report_the_object_path() {
        let s = schema(json!({
            "properties": {"a": {"properties": {"b": {"type": "string"}}, "required": ["b"], "additionalProperties": false}},
            "required": ["a"]
        }));
        assert_eq!(found(&s, &json!({})), [("$".to_owned(), Keyword::Required)]);
        assert_eq!(
            found(&s, &json!({"a": {}})),
            [("a".to_owned(), Keyword::Required)]
        );
        assert_eq!(
            found(&s, &json!({"a": {"b": "x", "approved": true}})),
            [("a".to_owned(), Keyword::AdditionalProperties)]
        );
    }

    #[test]
    fn violation_paths_use_dots_for_keys_and_brackets_for_indexes() {
        let s = schema(json!({
            "properties": {"findings": {"items": {"properties": {"severity": {"enum": ["low"]}}}}}
        }));
        let (violations, dropped) =
            s.validate(&json!({"findings": [{"severity": "low"}, {"severity": "x"}]}));
        assert_eq!(dropped, 0);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, "findings[1].severity");
    }

    #[test]
    fn min_items_and_unique_items_apply_to_arrays_only() {
        let s = schema(json!({"minItems": 1, "uniqueItems": true}));
        assert_eq!(found(&s, &json!([])), [("$".to_owned(), Keyword::MinItems)]);
        assert_eq!(
            found(&s, &json!([1, 1.0])),
            [("$".to_owned(), Keyword::UniqueItems)]
        );
        assert!(found(&s, &json!("not an array")).is_empty());
        assert!(found(&s, &json!([1, 2])).is_empty());
    }

    #[test]
    fn string_length_counts_characters_not_bytes() {
        let s = schema(json!({"minLength": 2, "maxLength": 2}));
        assert!(found(&s, &json!("é€")).is_empty());
        assert_eq!(
            found(&s, &json!("é")),
            [("$".to_owned(), Keyword::MinLength)]
        );
    }

    #[test]
    fn pattern_is_a_search_not_a_full_match() {
        let s = schema(json!({"pattern": "ab"}));
        assert!(found(&s, &json!("xxabxx")).is_empty());
        assert_eq!(
            found(&s, &json!("xx")),
            [("$".to_owned(), Keyword::Pattern)]
        );
    }

    #[test]
    fn numeric_bounds_are_inclusive_and_exclusive_as_named() {
        let s = schema(json!({"minimum": 1, "maximum": 3, "exclusiveMinimum": 0}));
        assert!(found(&s, &json!(1)).is_empty());
        assert!(found(&s, &json!(3)).is_empty());
        assert_eq!(found(&s, &json!(4)), [("$".to_owned(), Keyword::Maximum)]);
        let mut zero = found(&s, &json!(0));
        zero.sort_by_key(|(_, keyword)| format!("{keyword:?}"));
        assert_eq!(
            zero,
            [
                ("$".to_owned(), Keyword::ExclusiveMinimum),
                ("$".to_owned(), Keyword::Minimum)
            ]
        );
    }

    #[test]
    fn if_then_else_apply_the_matching_branch_only() {
        let s = schema(json!({
            "if": {"properties": {"kind": {"const": "a"}}, "required": ["kind"]},
            "then": {"required": ["x"]},
            "else": {"required": ["y"]}
        }));
        assert_eq!(
            found(&s, &json!({"kind": "a"})),
            [("$".to_owned(), Keyword::Required)]
        );
        assert!(found(&s, &json!({"kind": "a", "x": 1})).is_empty());
        assert!(found(&s, &json!({"kind": "b", "y": 1})).is_empty());
        assert_eq!(
            found(&s, &json!({"kind": "b"})),
            [("$".to_owned(), Keyword::Required)]
        );
    }

    #[test]
    fn dependent_schemas_apply_only_when_the_property_is_present() {
        let s = schema(json!({"dependentSchemas": {"a": {"required": ["b"]}}}));
        assert!(found(&s, &json!({})).is_empty());
        assert_eq!(
            found(&s, &json!({"a": 1})),
            [("$".to_owned(), Keyword::Required)]
        );
    }

    #[test]
    fn contains_one_of_any_of_and_not_report_one_violation_each() {
        let contains = schema(json!({"contains": {"const": 1}}));
        assert_eq!(
            found(&contains, &json!([2])),
            [("$".to_owned(), Keyword::Contains)]
        );
        let one_of =
            schema(json!({"oneOf": [{"type": "string"}, {"type": "string", "minLength": 1}]}));
        assert_eq!(
            found(&one_of, &json!("x")),
            [("$".to_owned(), Keyword::OneOf)],
            "both match"
        );
        assert_eq!(
            found(&one_of, &json!(5)),
            [("$".to_owned(), Keyword::OneOf)],
            "none match"
        );
        let any_of = schema(json!({"anyOf": [{"type": "string"}, {"type": "integer"}]}));
        assert!(found(&any_of, &json!(5)).is_empty());
        assert_eq!(
            found(&any_of, &json!(null)),
            [("$".to_owned(), Keyword::AnyOf)]
        );
        let not = schema(json!({"not": {"const": 1}}));
        assert_eq!(found(&not, &json!(1)), [("$".to_owned(), Keyword::Not)]);
    }

    #[test]
    fn references_resolve_to_local_definitions() {
        let s = schema(json!({
            "$defs": {"name": {"type": "string", "minLength": 1}},
            "properties": {"a": {"$ref": "#/$defs/name"}}
        }));
        assert_eq!(
            found(&s, &json!({"a": ""})),
            [("a".to_owned(), Keyword::MinLength)]
        );
    }

    #[test]
    fn messages_never_contain_the_offending_value() {
        let s = schema(
            json!({"properties": {"a": {"enum": ["x"], "pattern": "^x$", "const": "x"}}, "additionalProperties": false}),
        );
        let secret = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let (violations, _) = s.validate(&json!({"a": secret, secret: 1}));
        assert!(!violations.is_empty());
        for violation in violations {
            assert!(
                !violation.message.contains("sk-ant") && !violation.path.contains("sk-ant"),
                "{violation:?}"
            );
        }
    }

    #[test]
    fn only_ordinary_field_names_are_echoed() {
        assert_eq!(safe_name("approved"), "approved");
        assert_eq!(safe_name("max_tokens"), "max_tokens");
        for unusual in [
            "",
            "Approved",
            "AKIAIOSFODNN7EXAMPLE",
            "sk-ant-api03-abc",
            "ghp_abcdefghijklmnop",
            "key123456789",
            &"a".repeat(49),
            "with space",
            "line\nbreak",
        ] {
            assert_eq!(safe_name(unusual), UNPRINTABLE_NAME, "{unusual:?}");
        }
    }

    /// Two shapes told apart by `type`, as the evidence items in the ledger schema are.
    fn shapes() -> Schema {
        schema(json!({
            "oneOf": [
                {
                    "required": ["type", "values"],
                    "properties": {
                        "type": {"const": "a"},
                        "values": {"type": "array", "items": {"type": "integer", "maximum": 5}}
                    }
                },
                {
                    "required": ["type", "name"],
                    "properties": {"type": {"const": "b"}, "name": {"type": "string", "minLength": 3}}
                }
            ]
        }))
    }

    fn keywords(schema: &Schema, instance: &Value) -> Vec<(String, Keyword)> {
        found(schema, instance)
    }

    #[test]
    fn a_one_of_with_no_match_reports_the_generic_violation_then_the_closest_shape() {
        let s = shapes();
        // Shape "a" is the closest: its `type` matches and its failure is two levels down.
        assert_eq!(
            keywords(&s, &json!({"type": "a", "values": [1, 9]})),
            [
                ("$".to_owned(), Keyword::OneOf),
                ("values[1]".to_owned(), Keyword::Maximum)
            ]
        );
        // Shape "b" is the closest here.
        assert_eq!(
            keywords(&s, &json!({"type": "b", "name": "x"})),
            [
                ("$".to_owned(), Keyword::OneOf),
                ("name".to_owned(), Keyword::MinLength)
            ]
        );
    }

    #[test]
    fn a_missing_property_of_the_shape_that_matches_its_type_is_reported() {
        let s = shapes();
        let (violations, _) = s.validate(&json!({"type": "a"}));
        let kinds: Vec<(&str, Keyword)> = violations
            .iter()
            .map(|v| (v.path.as_str(), v.keyword))
            .collect();
        assert_eq!(kinds, [("$", Keyword::OneOf), ("$", Keyword::Required)]);
        assert_eq!(violations[1].property.as_deref(), Some("values"));
    }

    #[test]
    fn a_one_of_where_no_shape_gets_past_its_type_keeps_only_the_generic_violation() {
        let s = shapes();
        for instance in [
            json!({"type": "c", "values": [1], "name": "abc"}),
            json!("a string"),
            json!(null),
            json!([1, 2]),
        ] {
            assert_eq!(
                keywords(&s, &instance),
                [("$".to_owned(), Keyword::OneOf)],
                "{instance}"
            );
        }
    }

    #[test]
    fn a_bad_value_in_every_shape_of_the_property_that_tells_them_apart_keeps_only_the_generic_violation()
     {
        // `kind` fails in both shapes, so it is what tells them apart and neither shape was chosen.
        let s = schema(json!({
            "oneOf": [
                {"properties": {"kind": {"enum": ["x"]}, "p": {"type": "string"}}},
                {"properties": {"kind": {"enum": ["y"]}, "q": {"type": "string"}}}
            ]
        }));
        assert_eq!(
            keywords(&s, &json!({"kind": "z", "p": 1})),
            [("$".to_owned(), Keyword::OneOf)]
        );
        // `p` is checked by one shape only, so a bad `p` does not hide which shape was meant.
        let s = schema(json!({
            "oneOf": [
                {"properties": {"kind": {"const": "x"}, "p": {"enum": ["ok"]}}},
                {"properties": {"kind": {"const": "y"}}}
            ]
        }));
        assert_eq!(
            keywords(&s, &json!({"kind": "x", "p": "bad"})),
            [
                ("$".to_owned(), Keyword::OneOf),
                ("p".to_owned(), Keyword::Enum)
            ]
        );
    }

    #[test]
    fn a_value_that_equals_none_of_the_constants_keeps_only_the_generic_violation() {
        // The constant is on the instance itself, so it is what tells the shapes apart.
        let s = schema(json!({"oneOf": [{"const": 1}, {"const": 2}]}));
        assert_eq!(keywords(&s, &json!(3)), [("$".to_owned(), Keyword::OneOf)]);
        let s = schema(json!({"anyOf": [{"enum": ["a"]}, {"enum": ["b"]}]}));
        assert_eq!(
            keywords(&s, &json!("c")),
            [("$".to_owned(), Keyword::AnyOf)]
        );
    }

    #[test]
    fn when_no_shape_can_be_told_apart_the_first_one_explains_what_is_missing() {
        // Neither shape sees its `type`, so both are still candidates and both miss two properties.
        // The tie goes to the first, whose list starts with the property that tells shapes apart.
        let s = shapes();
        let (violations, _) = s.validate(&json!({}));
        let at: Vec<(&str, Keyword, Option<&str>)> = violations
            .iter()
            .map(|v| (v.path.as_str(), v.keyword, v.property.as_deref()))
            .collect();
        assert_eq!(
            at,
            [
                ("$", Keyword::OneOf, None),
                ("$", Keyword::Required, Some("type")),
                ("$", Keyword::Required, Some("values"))
            ]
        );
    }

    #[test]
    fn a_one_of_that_matches_two_shapes_keeps_only_the_generic_violation() {
        let s = schema(json!({"oneOf": [{"type": "object"}, {"required": ["a"]}]}));
        assert_eq!(
            keywords(&s, &json!({"a": 1})),
            [("$".to_owned(), Keyword::OneOf)]
        );
        // And the details of the branches that did not fail are not invented.
        let (violations, _) = s.validate(&json!({"a": 1}));
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].message.contains("more than one"),
            "{violations:?}"
        );
    }

    #[test]
    fn the_closest_shape_is_the_deepest_then_the_one_with_fewest_violations_then_the_first() {
        // Three shapes that all pass their `kind`. The instance fails them at depth 1, 2 and 2.
        let s = schema(json!({
            "anyOf": [
                {"properties": {"kind": {"const": "x"}, "p": {"type": "string"}}},
                {"properties": {"kind": {"const": "x"}, "q": {"properties": {"r": {"type": "string"}, "s": {"type": "string"}}}}},
                {"properties": {"kind": {"const": "x"}, "q": {"properties": {"r": {"type": "string"}}}}}
            ]
        }));
        let instance = json!({"kind": "x", "p": 1, "q": {"r": 1, "s": 2}});
        // Shape 2 fails twice at depth 2 and shape 3 fails once at depth 2: shape 3 has fewer.
        let (violations, _) = s.validate(&instance);
        let at: Vec<&str> = violations.iter().map(|v| v.path.as_str()).collect();
        assert_eq!(at, ["$", "q.r"]);
        // Equal depth and equal counts: the first wins.
        let s = schema(json!({
            "anyOf": [
                {"properties": {"kind": {"const": "x"}, "first": {"type": "string"}}},
                {"properties": {"kind": {"const": "x"}, "second": {"type": "string"}}}
            ]
        }));
        let (violations, _) = s.validate(&json!({"kind": "x", "first": 1, "second": 1}));
        let at: Vec<&str> = violations.iter().map(|v| v.path.as_str()).collect();
        assert_eq!(at, ["$", "first"]);
    }

    #[test]
    fn an_any_of_with_a_matching_shape_reports_nothing() {
        let s = shapes();
        assert!(found(&s, &json!({"type": "a", "values": [1, 2]})).is_empty());
        let any = schema(json!({"anyOf": [{"type": "string"}, {"type": "integer"}]}));
        assert!(found(&any, &json!(5)).is_empty());
    }

    #[test]
    fn the_details_of_the_closest_shape_count_against_the_violation_cap() {
        let s = schema(json!({
            "oneOf": [
                {"properties": {"kind": {"const": "x"}, "items": {"items": {"type": "string"}}}},
                {"properties": {"kind": {"const": "y"}}}
            ]
        }));
        let many = Value::Array((0..(MAX_VIOLATIONS + 20)).map(|n| json!(n)).collect());
        let (violations, dropped) = s.validate(&json!({"kind": "x", "items": many}));
        assert_eq!(violations.len(), MAX_VIOLATIONS);
        assert!(dropped >= 20, "{dropped}");
        assert_eq!(violations[0].keyword, Keyword::OneOf);
    }

    #[test]
    fn a_nested_one_of_reports_its_closest_shape_too() {
        let s = schema(json!({
            "properties": {"list": {"items": {"oneOf": [
                {"properties": {"type": {"const": "a"}, "n": {"maximum": 5}}},
                {"properties": {"type": {"const": "b"}}}
            ]}}}
        }));
        let (violations, _) = s.validate(&json!({"list": [{"type": "b"}, {"type": "a", "n": 9}]}));
        let at: Vec<(&str, Keyword)> = violations
            .iter()
            .map(|v| (v.path.as_str(), v.keyword))
            .collect();
        assert_eq!(
            at,
            [("list[1]", Keyword::OneOf), ("list[1].n", Keyword::Maximum)]
        );
    }

    #[test]
    fn violations_are_capped_and_the_rest_counted() {
        let s = schema(json!({"items": {"type": "string"}}));
        let instance = Value::Array((0..(MAX_VIOLATIONS + 25)).map(|n| json!(n)).collect());
        let (violations, dropped) = s.validate(&instance);
        assert_eq!(violations.len(), MAX_VIOLATIONS);
        assert_eq!(dropped, 25);
    }
}
