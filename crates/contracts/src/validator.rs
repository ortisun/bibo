//! The output validator: checks a document against the schema of its contract kind, with hard
//! limits that are applied before anything is parsed or compiled against a schema.
//!
//! # Two entry points
//!
//! * [`SchemaOutputValidator::parse_and_validate`] takes the raw bytes an agent produced. This is
//!   the entry point for untrusted output. It rejects, in this order and before any later step
//!   runs: a body over the size limit, a body that is not UTF-8, a body that nests deeper than the
//!   depth limit (found by a scan that builds nothing), and only then parses. The parse itself is
//!   strict: it counts nodes against a budget, refuses duplicate object keys, and refuses
//!   trailing data. Then the schema runs, then the path-safety check.
//! * [`OutputValidator::validate_bytes`] (the port) is the same path, and also returns the SHA-256
//!   and the size of the exact bytes it checked, so the artifact that stores them has that hash.
//! * [`OutputValidator::validate_value`] (the port) takes a `serde_json::Value` that somebody already
//!   parsed. It cannot stop a parse that already happened, so it re-checks the limits on the value
//!   with an iterative walk (no recursion, so a deep value cannot overflow the stack) and stops at
//!   the first limit that is broken.
//!
//! # Limits are hard
//!
//! [`OutputLimits`] cannot be built above [`OutputLimits::CEILING`]. The default is the policy's
//! structured-output cap (`untrusted_content.structured_output.max_output_bytes`, 512 KiB).
//!
//! # Messages
//!
//! Every message says what rule was broken and what to change. None contains a value taken from
//! the document: a secret in an agent's output must not come back out in an error. Property names
//! are shown only when they look like ordinary field names (see
//! [`crate::schema_engine::safe_name`]).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use factory_domain::contracts::Violation;
use factory_domain::values::Sha256Digest;
use factory_ports::paths::RepoPath;
use factory_ports::registry::{ContractKind, OutputValidator, ValidatedOutput};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::schema_engine::{Keyword, Schema, SchemaLoadError, safe_name};
use crate::schemas::{EMBEDDED, SCHEMA_VERSION};

/// Limits on a document before it is parsed or checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputLimits {
    max_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
}

/// A limit was zero or above the hard ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the {which} limit must be between 1 and {ceiling}")]
pub struct LimitsError {
    /// Which limit.
    pub which: &'static str,
    /// The ceiling it exceeded.
    pub ceiling: usize,
}

impl OutputLimits {
    /// The default for agent output: the policy's structured-output cap of 512 KiB, 32 levels of
    /// nesting and 100,000 values.
    pub const AGENT_OUTPUT: OutputLimits = OutputLimits {
        max_bytes: 524_288,
        max_depth: 32,
        max_nodes: 100_000,
    };

    /// The most any caller may ask for: 4 MiB, 64 levels and 1,000,000 values.
    pub const CEILING: OutputLimits = OutputLimits {
        max_bytes: 4 * 1024 * 1024,
        max_depth: 64,
        max_nodes: 1_000_000,
    };

    /// Builds limits.
    ///
    /// # Errors
    /// [`LimitsError`] when a value is zero or above [`OutputLimits::CEILING`].
    pub fn new(max_bytes: usize, max_depth: usize, max_nodes: usize) -> Result<Self, LimitsError> {
        let ceiling = Self::CEILING;
        for (which, value, top) in [
            ("size in bytes", max_bytes, ceiling.max_bytes),
            ("nesting depth", max_depth, ceiling.max_depth),
            ("value count", max_nodes, ceiling.max_nodes),
        ] {
            if value == 0 || value > top {
                return Err(LimitsError {
                    which,
                    ceiling: top,
                });
            }
        }
        Ok(Self {
            max_bytes,
            max_depth,
            max_nodes,
        })
    }

    /// The size limit in bytes.
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// The nesting limit. A top-level object or array is depth 1.
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// The limit on the number of values (every scalar, array and object counts as one).
    #[must_use]
    pub const fn max_nodes(&self) -> usize {
        self.max_nodes
    }
}

impl Default for OutputLimits {
    fn default() -> Self {
        Self::AGENT_OUTPUT
    }
}

/// What kind of problem an [`Issue`] reports. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssueKind {
    /// A schema rule.
    Schema(Keyword),
    /// The body is over the size limit.
    TooLarge,
    /// The document nests deeper than the limit.
    TooDeep,
    /// The document has more values than the limit.
    TooManyNodes,
    /// The body is not UTF-8.
    NotUtf8,
    /// The body is not JSON.
    NotJson,
    /// An object repeats a key.
    DuplicateKey,
    /// A path field is not a safe repository-relative path.
    UnsafePath,
    /// The schema version asked for is not the one this build knows.
    UnknownVersion,
    /// More problems were found than are listed.
    MoreProblems,
}

/// One problem found in a document: where, what kind and what to change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Where in the document: `$` for the whole document, otherwise `a.b[0].c`.
    pub path: String,
    /// What kind of problem.
    pub kind: IssueKind,
    /// The property the problem is about, when it is safe to show.
    pub property: Option<String>,
    /// Plain English. Never contains a value from the document.
    pub message: String,
}

impl Issue {
    fn new(path: impl Into<String>, kind: IssueKind, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind,
            property: None,
            message: message.into(),
        }
    }

    /// The problem as the port's [`Violation`].
    #[must_use]
    pub fn to_violation(&self) -> Violation {
        Violation {
            path: self.path.clone(),
            message: self.message.clone(),
        }
    }
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// The schemas compiled once, plus the limits, behind the [`OutputValidator`] port.
#[derive(Debug)]
pub struct SchemaOutputValidator {
    schemas: BTreeMap<ContractKind, Schema>,
    limits: OutputLimits,
}

impl SchemaOutputValidator {
    /// Compiles the eleven embedded schemas with the default limits.
    ///
    /// # Errors
    /// [`SchemaLoadError`] when an embedded schema cannot be compiled. A unit test proves that
    /// none of them fails, so an error here means a schema was changed to use a keyword the
    /// engine does not know.
    pub fn new() -> Result<Self, SchemaLoadError> {
        Self::with_limits(OutputLimits::AGENT_OUTPUT)
    }

    /// Compiles the eleven embedded schemas with the given limits.
    ///
    /// # Errors
    /// [`SchemaLoadError`], as for [`SchemaOutputValidator::new`].
    pub fn with_limits(limits: OutputLimits) -> Result<Self, SchemaLoadError> {
        let mut schemas = BTreeMap::new();
        for embedded in &EMBEDDED {
            schemas.insert(embedded.kind, Schema::compile_text(embedded.text)?);
        }
        Ok(Self { schemas, limits })
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> OutputLimits {
        self.limits
    }

    /// Parses and checks the bytes of an untrusted document. On success, returns the parsed
    /// value, so the caller does not parse twice.
    ///
    /// The order is fixed: size, UTF-8, nesting depth, strict parse, schema, path safety. A step
    /// that fails ends the call, so a 10 MB body is rejected for its size without being read, and
    /// a body nested 10,000 deep is rejected for its depth without being parsed.
    ///
    /// # Errors
    /// The list of issues. A limit or syntax problem is a list of one.
    pub fn parse_and_validate(
        &self,
        kind: ContractKind,
        version: u32,
        bytes: &[u8],
    ) -> Result<Value, Vec<Issue>> {
        self.check_version(version)?;
        let text = prescan(bytes, self.limits).map_err(|issue| vec![issue])?;
        let value = parse_strict(text, self.limits).map_err(|issue| vec![issue])?;
        self.check_value(kind, &value)?;
        Ok(value)
    }

    /// Checks a value that was already parsed, with the same limits. See the module notes on why
    /// [`SchemaOutputValidator::parse_and_validate`] is the better entry point for raw output.
    ///
    /// # Errors
    /// The list of issues.
    pub fn check(
        &self,
        kind: ContractKind,
        version: u32,
        instance: &Value,
    ) -> Result<(), Vec<Issue>> {
        self.check_version(version)?;
        measure(instance, self.limits).map_err(|issue| vec![issue])?;
        self.check_value(kind, instance)
    }

    fn check_version(&self, version: u32) -> Result<(), Vec<Issue>> {
        if version == SCHEMA_VERSION {
            Ok(())
        } else {
            Err(vec![Issue::new(
                "$",
                IssueKind::UnknownVersion,
                format!(
                    "schema version {version} is not supported; this build validates version {SCHEMA_VERSION}"
                ),
            )])
        }
    }

    fn check_value(&self, kind: ContractKind, instance: &Value) -> Result<(), Vec<Issue>> {
        let mut issues = Vec::new();
        if let Some(schema) = self.schemas.get(&kind) {
            let (violations, dropped) = schema.validate(instance);
            issues.extend(violations.into_iter().map(|violation| Issue {
                path: violation.path,
                kind: IssueKind::Schema(violation.keyword),
                property: violation.property,
                message: violation.message,
            }));
            if dropped > 0 {
                issues.push(Issue::new(
                    "$",
                    IssueKind::MoreProblems,
                    format!(
                        "{dropped} more problems were found and are not listed; fix these first"
                    ),
                ));
            }
        }
        check_paths(instance, &mut Vec::new(), &mut issues);
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

impl OutputValidator for SchemaOutputValidator {
    fn validate_bytes(
        &self,
        kind: ContractKind,
        version: u32,
        bytes: &[u8],
    ) -> Result<ValidatedOutput, Vec<Violation>> {
        let value = self
            .parse_and_validate(kind, version, bytes)
            .map_err(|issues| issues.iter().map(Issue::to_violation).collect::<Vec<_>>())?;
        Ok(ValidatedOutput {
            value,
            sha256: Sha256Digest::of(bytes),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        })
    }

    fn validate_value(
        &self,
        kind: ContractKind,
        version: u32,
        instance: &Value,
    ) -> Result<(), Vec<Violation>> {
        self.check(kind, version, instance)
            .map_err(|issues| issues.iter().map(Issue::to_violation).collect())
    }
}

// ------------------------------------------------------------------------------------------
// Limits before parsing
// ------------------------------------------------------------------------------------------

/// Checks the size, the encoding and the nesting depth of a body without building anything. Public
/// so a test can show each rejection on its own.
///
/// # Errors
/// [`IssueKind::TooLarge`], [`IssueKind::NotUtf8`] or [`IssueKind::TooDeep`].
pub fn prescan(bytes: &[u8], limits: OutputLimits) -> Result<&str, Issue> {
    if bytes.len() > limits.max_bytes {
        return Err(Issue::new(
            "$",
            IssueKind::TooLarge,
            format!(
                "the document is {} bytes; the limit is {} bytes. Return a shorter document",
                bytes.len(),
                limits.max_bytes
            ),
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|error| {
        Issue::new(
            "$",
            IssueKind::NotUtf8,
            format!(
                "the document is not valid UTF-8 (first bad byte at offset {}). Return UTF-8 text",
                error.valid_up_to()
            ),
        )
    })?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > limits.max_depth {
                    return Err(too_deep(limits));
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(text)
}

fn too_deep(limits: OutputLimits) -> Issue {
    Issue::new(
        "$",
        IssueKind::TooDeep,
        format!(
            "the document nests deeper than {} levels. Flatten it",
            limits.max_depth
        ),
    )
}

fn too_many(limits: OutputLimits) -> Issue {
    Issue::new(
        "$",
        IssueKind::TooManyNodes,
        format!(
            "the document has more than {} values. Return less data",
            limits.max_nodes
        ),
    )
}

/// Measures an already-parsed value against the limits with an explicit stack, so a deeply nested
/// value cannot overflow the call stack. The size is estimated from the text it would take.
fn measure(root: &Value, limits: OutputLimits) -> Result<(), Issue> {
    let mut stack: Vec<(&Value, usize)> = vec![(root, 1)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > limits.max_nodes {
            return Err(too_many(limits));
        }
        bytes = bytes.saturating_add(match value {
            Value::Null => 4,
            Value::Bool(_) => 5,
            Value::Number(_) => 8,
            Value::String(text) => text.len().saturating_add(2),
            Value::Array(_) | Value::Object(_) => 2,
        });
        match value {
            Value::Array(items) => {
                if depth > limits.max_depth {
                    return Err(too_deep(limits));
                }
                bytes = bytes.saturating_add(items.len());
                stack.extend(items.iter().map(|item| (item, depth + 1)));
            }
            Value::Object(map) => {
                if depth > limits.max_depth {
                    return Err(too_deep(limits));
                }
                for (key, item) in map {
                    bytes = bytes.saturating_add(key.len().saturating_add(4));
                    stack.push((item, depth + 1));
                }
            }
            _ => {}
        }
        if bytes > limits.max_bytes {
            return Err(Issue::new(
                "$",
                IssueKind::TooLarge,
                format!(
                    "the document is larger than {} bytes. Return a shorter document",
                    limits.max_bytes
                ),
            ));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Strict parse
// ------------------------------------------------------------------------------------------

/// Why the strict parse stopped, recorded by the seeds because a serde error cannot carry it.
enum Stop {
    TooMany,
    Duplicate { path: String, key: String },
}

struct State {
    nodes_left: usize,
    stop: Option<Stop>,
    path: Vec<PathPart>,
}

enum PathPart {
    Key(String),
    Index(usize),
}

impl State {
    fn render(&self) -> String {
        if self.path.is_empty() {
            return "$".to_owned();
        }
        let mut text = String::new();
        for part in &self.path {
            match part {
                PathPart::Key(key) => {
                    if !text.is_empty() {
                        text.push('.');
                    }
                    text.push_str(&safe_name(key));
                }
                PathPart::Index(index) => text.push_str(&format!("[{index}]")),
            }
        }
        text
    }
}

struct Seed<'a> {
    state: &'a RefCell<State>,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        {
            let mut state = self.state.borrow_mut();
            if state.nodes_left == 0 {
                state.stop = Some(Stop::TooMany);
                return Err(D::Error::custom("too many values"));
            }
            state.nodes_left -= 1;
        }
        deserializer.deserialize_any(StrictVisitor { state: self.state })
    }
}

struct StrictVisitor<'a> {
    state: &'a RefCell<State>,
}

impl<'de> Visitor<'de> for StrictVisitor<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("a number that JSON cannot hold"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        let mut index = 0usize;
        loop {
            self.state.borrow_mut().path.push(PathPart::Index(index));
            let next = seq.next_element_seed(Seed { state: self.state });
            self.state.borrow_mut().path.pop();
            match next? {
                Some(item) => items.push(item),
                None => break,
            }
            index += 1;
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                let mut state = self.state.borrow_mut();
                let path = state.render();
                state.stop = Some(Stop::Duplicate {
                    path,
                    key: key.clone(),
                });
                return Err(A::Error::custom("duplicate key"));
            }
            self.state
                .borrow_mut()
                .path
                .push(PathPart::Key(key.clone()));
            let value = access.next_value_seed(Seed { state: self.state });
            self.state.borrow_mut().path.pop();
            map.insert(key, value?);
        }
        Ok(Value::Object(map))
    }
}

/// Parses JSON text into a value. Counts values against the budget, refuses duplicate keys and
/// refuses data after the document.
fn parse_strict(text: &str, limits: OutputLimits) -> Result<Value, Issue> {
    let state = RefCell::new(State {
        nodes_left: limits.max_nodes,
        stop: None,
        path: Vec::new(),
    });
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let outcome = Seed { state: &state }
        .deserialize(&mut deserializer)
        .and_then(|value| deserializer.end().map(|()| value));
    match outcome {
        Ok(value) => Ok(value),
        Err(error) => Err(match state.into_inner().stop {
            Some(Stop::TooMany) => too_many(limits),
            Some(Stop::Duplicate { path, key }) => {
                let shown = safe_name(&key);
                let which = if shown == crate::schema_engine::UNPRINTABLE_NAME {
                    "a key".to_owned()
                } else {
                    format!("the key `{shown}`")
                };
                Issue {
                    path,
                    kind: IssueKind::DuplicateKey,
                    property: (shown != crate::schema_engine::UNPRINTABLE_NAME).then_some(shown),
                    message: format!(
                        "the object repeats {which}. Two values for one key are ambiguous; keep one"
                    ),
                }
            }
            None => Issue::new("$", IssueKind::NotJson, describe_syntax_error(&error)),
        }),
    }
}

/// A fixed sentence per category. The text of a `serde_json` error is not used, because it can
/// quote part of the input.
fn describe_syntax_error(error: &serde_json::Error) -> String {
    use serde_json::error::Category;
    match error.classify() {
        Category::Eof => format!(
            "the document ends early (line {}, column {}). Close every string, array and object",
            error.line(),
            error.column()
        ),
        Category::Syntax | Category::Data | Category::Io => format!(
            "the document is not valid JSON near line {}, column {}. Check commas, quotes and brackets",
            error.line(),
            error.column()
        ),
    }
}

// ------------------------------------------------------------------------------------------
// Path safety
// ------------------------------------------------------------------------------------------

/// True for a property name that holds a repository path: `path`, `paths` or a name ending in
/// `_path` or `_paths`.
fn names_a_path(key: &str) -> bool {
    key == "path" || key == "paths" || key.ends_with("_path") || key.ends_with("_paths")
}

/// Checks every string under a path-named property with [`RepoPath`]. The walk recurses, and is
/// safe to, because the depth limit was enforced first.
fn check_paths(value: &Value, trail: &mut Vec<String>, issues: &mut Vec<Issue>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                trail.push(safe_key_part(key));
                if names_a_path(key) {
                    check_path_value(child, trail, issues);
                }
                check_paths(child, trail, issues);
                trail.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                trail.push(format!("[{index}]"));
                check_paths(child, trail, issues);
                trail.pop();
            }
        }
        _ => {}
    }
}

fn check_path_value(value: &Value, trail: &mut Vec<String>, issues: &mut Vec<Issue>) {
    match value {
        Value::String(text) => {
            if let Err(error) = RepoPath::new(text) {
                issues.push(Issue::new(
                    render_trail(trail),
                    IssueKind::UnsafePath,
                    format!(
                        "must be a path inside the repository: {error}. Use a relative path such as `src/main.rs`"
                    ),
                ));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                trail.push(format!("[{index}]"));
                check_path_value(item, trail, issues);
                trail.pop();
            }
        }
        _ => {}
    }
}

fn safe_key_part(key: &str) -> String {
    safe_name(key)
}

fn render_trail(trail: &[String]) -> String {
    if trail.is_empty() {
        return "$".to_owned();
    }
    let mut text = String::new();
    for part in trail {
        if part.starts_with('[') {
            text.push_str(part);
        } else {
            if !text.is_empty() {
                text.push('.');
            }
            text.push_str(part);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn validator() -> SchemaOutputValidator {
        SchemaOutputValidator::new().expect("the embedded schemas compile")
    }

    #[test]
    fn all_eleven_embedded_schemas_compile() {
        let validator = validator();
        assert_eq!(validator.schemas.len(), 11);
    }

    #[test]
    fn limits_cannot_be_zero_or_above_the_ceiling() {
        assert!(OutputLimits::new(0, 10, 10).is_err());
        assert!(OutputLimits::new(10, 0, 10).is_err());
        assert!(OutputLimits::new(10, 10, 0).is_err());
        assert!(OutputLimits::new(OutputLimits::CEILING.max_bytes() + 1, 10, 10).is_err());
        assert!(OutputLimits::new(10, OutputLimits::CEILING.max_depth() + 1, 10).is_err());
        assert!(OutputLimits::new(10, 10, OutputLimits::CEILING.max_nodes() + 1).is_err());
        let limits = OutputLimits::new(10, 10, 10).expect("small limits are fine");
        assert_eq!(
            (limits.max_bytes(), limits.max_depth(), limits.max_nodes()),
            (10, 10, 10)
        );
    }

    #[test]
    fn an_unknown_schema_version_is_one_violation() {
        let validator = validator();
        let violations = validator
            .validate_value(ContractKind::GateReport, 2, &json!({}))
            .expect_err("version 2 is unknown");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("version 2 is not supported"));
    }

    #[test]
    fn the_scan_checks_size_before_encoding_before_depth() {
        let limits = OutputLimits::new(64, 4, 100).expect("limits");
        // Too large AND not UTF-8 AND too deep: size is reported.
        let mut big = vec![b'['; 100];
        big[0] = 0xff;
        assert_eq!(
            prescan(&big, limits).expect_err("size").kind,
            IssueKind::TooLarge
        );
        // Not UTF-8 AND too deep: the encoding is reported.
        let mut bad = vec![b'['; 10];
        bad[3] = 0xff;
        assert_eq!(
            prescan(&bad, limits).expect_err("utf8").kind,
            IssueKind::NotUtf8
        );
        // Only too deep.
        assert_eq!(
            prescan(b"[[[[[", limits).expect_err("depth").kind,
            IssueKind::TooDeep
        );
        assert!(prescan(b"[[[[]]]]", limits).is_ok(), "depth 4 is allowed");
    }

    #[test]
    fn brackets_inside_strings_do_not_count_as_nesting() {
        let limits = OutputLimits::new(1024, 2, 100).expect("limits");
        assert!(prescan(br#"{"a": "[[[[[[[[[[ \" [[[[["}"#, limits).is_ok());
        assert_eq!(
            prescan(br#"{"a": {"b": {"c": 1}}}"#, limits)
                .expect_err("depth")
                .kind,
            IssueKind::TooDeep
        );
    }

    #[test]
    fn a_syntax_error_does_not_quote_the_input() {
        let validator = validator();
        let secret = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let body = format!("{{\"a\": {secret}}}");
        let issues = validator
            .parse_and_validate(ContractKind::GateReport, 1, body.as_bytes())
            .expect_err("not JSON");
        assert_eq!(issues[0].kind, IssueKind::NotJson);
        assert!(!issues[0].message.contains("sk-ant"));
    }

    #[test]
    fn a_duplicate_key_is_refused_with_the_object_path() {
        let validator = validator();
        let body = br#"{"a": {"b": 1, "b": 2}}"#;
        let issues = validator
            .parse_and_validate(ContractKind::GateReport, 1, body)
            .expect_err("duplicate");
        assert_eq!(issues[0].kind, IssueKind::DuplicateKey);
        assert_eq!(issues[0].path, "a");
        assert_eq!(issues[0].property.as_deref(), Some("b"));
    }

    #[test]
    fn data_after_the_document_is_refused() {
        let validator = validator();
        let issues = validator
            .parse_and_validate(ContractKind::GateReport, 1, b"{} {}")
            .expect_err("trailing data");
        assert_eq!(issues[0].kind, IssueKind::NotJson);
    }

    #[test]
    fn the_node_budget_stops_a_wide_document() {
        let limits = OutputLimits::new(1024, 8, 10).expect("limits");
        let validator = SchemaOutputValidator::with_limits(limits).expect("compile");
        let body = format!("[{}]", vec!["1"; 20].join(","));
        let issues = validator
            .parse_and_validate(ContractKind::GateReport, 1, body.as_bytes())
            .expect_err("too many values");
        assert_eq!(issues[0].kind, IssueKind::TooManyNodes);
    }

    #[test]
    fn a_value_that_is_too_deep_is_measured_without_recursion() {
        let limits = OutputLimits::new(1024, 5, 100).expect("limits");
        let validator = SchemaOutputValidator::with_limits(limits).expect("compile");
        let mut value = json!(1);
        for _ in 0..6 {
            value = json!([value]);
        }
        let issues = validator
            .check(ContractKind::GateReport, 1, &value)
            .expect_err("depth");
        assert_eq!(issues[0].kind, IssueKind::TooDeep);
    }

    #[test]
    fn a_value_with_too_many_values_is_refused_by_the_measure() {
        let limits = OutputLimits::new(1 << 20, 8, 20).expect("limits");
        let validator = SchemaOutputValidator::with_limits(limits).expect("compile");
        let wide = Value::Array((0..30).map(|n| json!(n)).collect());
        let issues = validator
            .check(ContractKind::GateReport, 1, &wide)
            .expect_err("too many values");
        assert_eq!(issues[0].kind, IssueKind::TooManyNodes);
        let narrow = Value::Array((0..5).map(|n| json!(n)).collect());
        let issues = validator
            .check(ContractKind::GateReport, 1, &narrow)
            .expect_err("a list is not a gate report");
        assert!(issues.iter().all(|i| i.kind != IssueKind::TooManyNodes));
    }

    #[test]
    fn path_fields_must_be_repository_relative() {
        let mut issues = Vec::new();
        check_paths(
            &json!({
                "files": [
                    {"path": "src/main.rs"},
                    {"path": "../../etc/passwd"},
                    {"path": "/etc/passwd"},
                    {"path": "a\\b"},
                    {"path": ".git/config"},
                    {"other": "../fine because the name is not a path"}
                ],
                "template_path": "agents/x/prompt.md",
                "changelog_path": "../CHANGELOG.md"
            }),
            &mut Vec::new(),
            &mut issues,
        );
        let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(
            paths,
            // Object keys are visited in sorted order.
            [
                "changelog_path",
                "files[1].path",
                "files[2].path",
                "files[3].path",
                "files[4].path"
            ]
        );
        assert!(issues.iter().all(|i| i.kind == IssueKind::UnsafePath));
    }
}
