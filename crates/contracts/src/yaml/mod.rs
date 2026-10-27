//! A reader for a restricted subset of YAML 1.2, built on an event parser.
//!
//! # The contract
//!
//! `policies/security.yaml` states the parser contract in its header, and `policies/approval.yaml`
//! shares it. This module is that contract as code:
//!
//! * a single document, with at most one explicit start marker and one end marker;
//! * no anchors, no aliases, no tags, no directives and no merge keys (`<<`);
//! * no duplicate key in any mapping, however deep, and no complex (non-string) keys;
//! * no null: an empty value, `~` and `null` are all refused;
//! * a bounded size, nesting depth, number of values and scalar length, all checked **before** the
//!   work they bound (see [`YamlLimits`]);
//! * scalars whose meaning cannot differ between readers (see [`scalar`]);
//! * a typed decode into `serde` structs in which an unknown key is an error, and every error
//!   carries the key path and the line.
//!
//! The header of `security.yaml` says "block style". The file itself uses flow style
//! (`{ a: 1 }`, `[a, b]`) in many places, so this reader accepts both and does not treat the
//! difference as meaningful. That is a gap between the written contract and the file. It is
//! reported in the hand-off notes, not fixed here.
//!
//! # The YAML parser: the decision and the evidence
//!
//! **Chosen: `saphyr-parser` 0.3.2, used as an event parser.** It reports scalars, sequences and
//! mappings with their line numbers and does not decide what a scalar means. The meaning, and every
//! refusal above, is in this module, where a test covers each one.
//!
//! The work package asked for a choice among at least two maintained candidates, with `serde_yaml`
//! excluded as deprecated. The candidates were tried on 2026-10-27 against the same documents. The
//! table shows what each does with the cases the contract forbids. "libyaml" crates wrap a C
//! parser ported to Rust and follow YAML 1.1 in places.
//!
//! | Candidate and version | Maintenance (crates.io) | `no` `yes` `on` `off` `y` `n` | `0o7` `1e3` `0777` | Duplicate key | `<<` merge key, anchors, aliases | Tags | Deep nesting |
//! |---|---|---|---|---|---|---|---|
//! | `serde_yaml` 0.9.34 | **deprecated** by its author | excluded | excluded | excluded | excluded | excluded | excluded |
//! | `serde-saphyr` 2.0.0 | released 2026-10-13, active | **read as booleans** into an untyped value | **`0o7` is 7, `1e3` is 1000.0, `0777` is 777.0** | refused | **merge applied, anchors expanded silently** | accepted and dropped | refused (recursion limit) |
//! | `serde_yaml_ng` 0.10.0 | last release 2024-05-26 (17 months) | strings | `0o7` is 7, `1e3` is 1000.0, `0777` is the string | **last value wins, silently** | `<<` kept as a key, anchors expanded silently | error | refused (recursion limit) |
//! | `serde_norway` 0.9.42 | last release 2024-12-21 | strings | as `serde_yaml_ng` | **last value wins, silently** | as `serde_yaml_ng` | error | refused |
//! | `serde_yaml_bw` 2.5.8 | released 2026-09-07, active | strings | as `serde_yaml_ng` | refused | as `serde_yaml_ng` | error | refused |
//! | `yaml-rust2` 0.13.0 | released 2026-09-11, active | strings | `0o7` is 7, `1e3` is real, `0777` is 777 | refused | `<<` kept, anchors expanded | accepted and dropped | not tried as a tree |
//! | `saphyr` 0.3.2 (tree) | released 2026-10-27, active | strings | `0o7` is 7, `1e3` is a float, `0777` is 777 | refused | `<<` kept, anchors expanded | kept as `Tagged` | not tried as a tree |
//! | **`saphyr-parser` 0.3.2 (events)** | **released 2026-10-26, active; the parser under `saphyr`** | **no meaning given, this module decides** | **no meaning given** | **not checked by the parser; this module checks** | **reported as events; refused here** | **reported as events; refused here** | **iterative; a depth limit stops it at the first deep start event** |
//!
//! What the table shows: no candidate is safe used as a deserializer. Each one decides for the
//! caller what `no` or `0777` means, and they disagree with each other, so the same document would
//! mean different things under different crates. The three YAML 1.1 style crates that also appear
//! unmaintained for over a year are not candidates for a security policy. `serde-saphyr` is
//! maintained but reads `no` as `false` when it fills an untyped value, expands anchors and
//! applies merge keys by default. The sound choice is to take events and decide in our own code.
//! Between the two event parsers, `saphyr-parser` is the one with a documented pass of the
//! `yaml-test-suite`, two small dependencies (`arraydeque`, `thiserror`), no `unsafe` code, an
//! alias-expansion guard added in 0.3.1, and an active maintainer group. Its licence is
//! MIT OR Apache-2.0, which `deny.toml` allows, and `cargo deny --locked check` passes with it.
//!
//! The comparison was made with a scratch program that parsed one document per case through each
//! crate. The numbers in the table are what it printed on 2026-10-27, not claims from the crates'
//! documentation. Versions move quickly (`saphyr-parser` went from 0.2.1 to 0.3.2 in two weeks),
//! so the dependency is pinned with `=` and `Cargo.lock` is committed.
//!
//! # Limits
//!
//! The size check runs on the text before the parser is created. The depth and node checks run on
//! each start event. The parser reads ahead of the events, and it has a recursion limit of its own
//! (256 levels of flow nesting, measured on 2026-10-27), so a body nested 10,000 deep is refused
//! either at the first start event past the limit or, beyond 255 levels, by the parser's own
//! limit, which this module reports as [`YamlErrorKind::TooDeep`]. Either way, nothing deeper than
//! the parser's limit is ever built, and the test
//! `yaml_a_flow_sequence_nested_10000_deep_is_refused_without_overflowing_the_stack` shows it.

pub mod scalar;
mod tree;

use std::collections::HashMap;
use std::fmt;

use saphyr_parser::{Event, Parser, ScalarStyle, Span};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub use scalar::{AmbiguousScalar, Refusal, Resolved, resolve_plain};
pub use tree::{Content, Entry, Node};

use tree::{DecodeError, NodeDeserializer};

/// Hard limits for one YAML text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YamlLimits {
    max_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
    max_scalar_bytes: usize,
}

/// A limit was zero or above the ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the {which} limit must be between 1 and {ceiling}")]
pub struct YamlLimitsError {
    /// Which limit.
    pub which: &'static str,
    /// The ceiling.
    pub ceiling: usize,
}

impl YamlLimits {
    /// For the policy files: 1 MiB, 16 levels, 50,000 values, scalars up to 64 KiB. The real
    /// `security.yaml` is under 100 KiB and 8 levels deep.
    pub const POLICY: YamlLimits = YamlLimits {
        max_bytes: 1 << 20,
        max_depth: 16,
        max_nodes: 50_000,
        max_scalar_bytes: 64 * 1024,
    };

    /// For agent manifests, capability profiles and project manifests: 256 KiB, 16 levels, 20,000
    /// values, scalars up to 64 KiB.
    pub const DEFINITION: YamlLimits = YamlLimits {
        max_bytes: 256 * 1024,
        max_depth: 16,
        max_nodes: 20_000,
        max_scalar_bytes: 64 * 1024,
    };

    /// The most any caller may ask for.
    pub const CEILING: YamlLimits = YamlLimits {
        max_bytes: 8 << 20,
        max_depth: 64,
        max_nodes: 1_000_000,
        max_scalar_bytes: 1 << 20,
    };

    /// Builds limits.
    ///
    /// # Errors
    /// [`YamlLimitsError`] when a value is zero or above [`YamlLimits::CEILING`].
    pub fn new(
        max_bytes: usize,
        max_depth: usize,
        max_nodes: usize,
        max_scalar_bytes: usize,
    ) -> Result<Self, YamlLimitsError> {
        let top = Self::CEILING;
        for (which, value, ceiling) in [
            ("size in bytes", max_bytes, top.max_bytes),
            ("nesting depth", max_depth, top.max_depth),
            ("value count", max_nodes, top.max_nodes),
            ("scalar length", max_scalar_bytes, top.max_scalar_bytes),
        ] {
            if value == 0 || value > ceiling {
                return Err(YamlLimitsError { which, ceiling });
            }
        }
        Ok(Self {
            max_bytes,
            max_depth,
            max_nodes,
            max_scalar_bytes,
        })
    }

    /// The size limit in bytes.
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// The nesting limit. The top-level collection is depth 1.
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// The limit on the number of values, keys included.
    #[must_use]
    pub const fn max_nodes(&self) -> usize {
        self.max_nodes
    }

    /// The limit on one scalar's length in bytes.
    #[must_use]
    pub const fn max_scalar_bytes(&self) -> usize {
        self.max_scalar_bytes
    }
}

/// What went wrong. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamlErrorKind {
    /// The text is over the size limit.
    TooLarge,
    /// The document nests deeper than the limit.
    TooDeep,
    /// The document has more values than the limit.
    TooManyNodes,
    /// A scalar is longer than the limit.
    ScalarTooLong,
    /// The text is not valid YAML.
    Syntax,
    /// The text holds more than one document.
    MultipleDocuments,
    /// The text holds no document.
    Empty,
    /// A `%` directive.
    Directive,
    /// An anchor (`&name`).
    Anchor,
    /// An alias (`*name`).
    Alias,
    /// A tag (`!name`).
    Tag,
    /// The merge key `<<`.
    MergeKey,
    /// A key appears twice in one mapping.
    DuplicateKey,
    /// A mapping key that is not a string.
    ComplexKey,
    /// A null, written or implied by a missing value.
    Null,
    /// A plain scalar that readers disagree about.
    Ambiguous(AmbiguousScalar),
    /// The document is valid YAML in the subset but does not fit the Rust type.
    Decode,
}

/// A YAML problem with the place it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    /// What went wrong.
    pub kind: YamlErrorKind,
    /// The line, counting from 1, when there is one.
    pub line: Option<usize>,
    /// The column, counting from 1, when there is one.
    pub column: Option<usize>,
    /// For a [`YamlErrorKind::Decode`] error, the key path such as `items[0].colour`.
    pub key: Option<String>,
    detail: String,
}

impl YamlError {
    fn new(kind: YamlErrorKind, span: Option<(usize, usize)>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            line: span.map(|(line, _)| line),
            column: span.map(|(_, column)| column),
            key: None,
            detail: detail.into(),
        }
    }

    /// The error text without the position.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => write!(f, "line {line}, column {column}")?,
            (Some(line), None) => write!(f, "line {line}")?,
            _ => f.write_str("document")?,
        }
        if let Some(key) = &self.key {
            write!(f, " (at `{key}`)")?;
        }
        write!(f, ": {}", self.detail)
    }
}

impl std::error::Error for YamlError {}

/// A document that passed every check of the reader.
#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    root: Node,
}

impl Document {
    /// The tree, with positions.
    #[must_use]
    pub fn root(&self) -> &Node {
        &self.root
    }

    /// The line and column of a field, written like `prompt.template_sha256`, `items[0].colour` or
    /// `$` for the whole document. `None` when the path leads nowhere. For a field of a mapping the
    /// position is the key's.
    #[must_use]
    pub fn locate(&self, path: &str) -> Option<(usize, usize)> {
        let mut node = &self.root;
        let mut position = (node.line, node.column);
        let mut rest = path.strip_prefix('$').unwrap_or(path);
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix('[') {
                let end = after.find(']')?;
                let index: usize = after[..end].parse().ok()?;
                let Content::Seq(items) = &node.content else {
                    return None;
                };
                node = items.get(index)?;
                position = (node.line, node.column);
                rest = &after[end + 1..];
            } else {
                rest = rest.strip_prefix('.').unwrap_or(rest);
                let end = rest.find(['.', '[']).unwrap_or(rest.len());
                let key = &rest[..end];
                let Content::Map(entries) = &node.content else {
                    return None;
                };
                let entry = entries.iter().find(|entry| entry.key == key)?;
                position = (entry.line, entry.column);
                node = &entry.value;
                rest = &rest[end..];
            }
        }
        Some(position)
    }

    /// The document as JSON, for schema validation.
    #[must_use]
    pub fn to_json(&self) -> Value {
        self.root.to_json()
    }

    /// Decodes the document into a Rust type. Whatever `deny_unknown_fields` and the type's own
    /// checks refuse is an error, with the key path and line.
    ///
    /// # Errors
    /// A [`YamlErrorKind::Decode`] error.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, YamlError> {
        T::deserialize(NodeDeserializer(&self.root)).map_err(|error: DecodeError| {
            let mut error = error;
            error.set_position_if_missing(self.root.line, self.root.column);
            let key = error.rendered_path();
            YamlError {
                kind: YamlErrorKind::Decode,
                line: error.line,
                column: error.column,
                key,
                detail: error.message,
            }
        })
    }
}

/// Reads and decodes in one step.
///
/// # Errors
/// Any [`YamlError`].
pub fn from_str<T: DeserializeOwned>(text: &str, limits: YamlLimits) -> Result<T, YamlError> {
    read(text, limits)?.decode()
}

// ------------------------------------------------------------------------------------------
// Reading
// ------------------------------------------------------------------------------------------

enum Frame {
    Seq {
        items: Vec<Node>,
        line: usize,
        column: usize,
    },
    Map {
        entries: Vec<Entry>,
        seen: HashMap<String, usize>,
        key: Option<(String, usize, usize)>,
        line: usize,
        column: usize,
    },
}

fn position(span: Span) -> (usize, usize) {
    let start = span.start;
    (start.line(), start.col() + 1)
}

/// Reads a document, enforcing the whole contract.
///
/// # Errors
/// A [`YamlError`] naming what is wrong and where.
pub fn read(text: &str, limits: YamlLimits) -> Result<Document, YamlError> {
    if text.len() > limits.max_bytes {
        return Err(YamlError::new(
            YamlErrorKind::TooLarge,
            None,
            format!(
                "the file is {} bytes; the limit is {} bytes",
                text.len(),
                limits.max_bytes
            ),
        ));
    }
    refuse_directives(text)?;

    let mut reader = Reader {
        limits,
        stack: Vec::new(),
        root: None,
        nodes: 0,
        documents: 0,
    };
    for item in Parser::new_from_str(text) {
        let (event, span) = item.map_err(|error| {
            let marker = *error.marker();
            let at = Some((marker.line(), marker.col() + 1));
            // The parser reads ahead of the events this module sees, and it has a recursion
            // limit of its own (256 levels of flow nesting). A body nested deeper than that stops
            // the parser before the first event reaches the depth check, so say what it means.
            if error.info().contains("recursion limit") {
                return YamlError::new(
                    YamlErrorKind::TooDeep,
                    at,
                    format!(
                        "the document nests deeper than {} levels; flatten it",
                        limits.max_depth
                    ),
                );
            }
            YamlError::new(
                YamlErrorKind::Syntax,
                at,
                format!(
                    "{}; check indentation, colons, brackets and quotes",
                    error.info()
                ),
            )
        })?;
        reader.on_event(event, span)?;
    }
    match reader.root {
        Some(root) => Ok(Document { root }),
        None => Err(YamlError::new(
            YamlErrorKind::Empty,
            None,
            "the file has no content; write the document",
        )),
    }
}

/// A line that starts with `%` before the first line of content is a directive.
fn refuse_directives(text: &str) -> Result<(), YamlError> {
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('%') {
            return Err(YamlError::new(
                YamlErrorKind::Directive,
                Some((index + 1, 1)),
                "YAML directives (lines that start with %) are not allowed; remove the line",
            ));
        }
        break;
    }
    Ok(())
}

struct Reader {
    limits: YamlLimits,
    stack: Vec<Frame>,
    root: Option<Node>,
    nodes: usize,
    documents: usize,
}

impl Reader {
    fn on_event(&mut self, event: Event<'_>, span: Span) -> Result<(), YamlError> {
        let at = position(span);
        match event {
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => Ok(()),
            Event::DocumentStart(_) => {
                self.documents += 1;
                if self.documents > 1 {
                    return Err(YamlError::new(
                        YamlErrorKind::MultipleDocuments,
                        Some(at),
                        "a second YAML document starts here; use one document per file",
                    ));
                }
                Ok(())
            }
            Event::Alias(_) => Err(YamlError::new(
                YamlErrorKind::Alias,
                Some(at),
                "aliases (*name) are not allowed; write the value out where it is used",
            )),
            Event::Scalar(text, style, anchor, tag) => {
                if anchor != 0 {
                    return Err(anchor_error(at));
                }
                if tag.is_some() {
                    return Err(tag_error(at));
                }
                self.count_node()?;
                self.on_scalar(&text, style, at)
            }
            Event::SequenceStart(anchor, tag) => {
                self.start_collection(anchor, tag.is_some(), at, true)
            }
            Event::MappingStart(anchor, tag) => {
                self.start_collection(anchor, tag.is_some(), at, false)
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let Some(frame) = self.stack.pop() else {
                    return Err(YamlError::new(
                        YamlErrorKind::Syntax,
                        Some(at),
                        "a closing bracket has no opening bracket",
                    ));
                };
                let node = match frame {
                    Frame::Seq {
                        items,
                        line,
                        column,
                    } => Node {
                        line,
                        column,
                        content: Content::Seq(items),
                    },
                    Frame::Map {
                        entries,
                        key,
                        line,
                        column,
                        ..
                    } => {
                        if let Some((name, key_line, key_column)) = key {
                            return Err(YamlError::new(
                                YamlErrorKind::Null,
                                Some((key_line, key_column)),
                                format!(
                                    "the key `{}` has no value; write a value or remove the key",
                                    shown(&name)
                                ),
                            ));
                        }
                        Node {
                            line,
                            column,
                            content: Content::Map(entries),
                        }
                    }
                };
                self.attach(node);
                Ok(())
            }
        }
    }

    fn count_node(&mut self) -> Result<(), YamlError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(YamlError::new(
                YamlErrorKind::TooManyNodes,
                None,
                format!(
                    "the document has more than {} values; split it or trim it",
                    self.limits.max_nodes
                ),
            ));
        }
        Ok(())
    }

    fn start_collection(
        &mut self,
        anchor: usize,
        tagged: bool,
        at: (usize, usize),
        is_sequence: bool,
    ) -> Result<(), YamlError> {
        if anchor != 0 {
            return Err(anchor_error(at));
        }
        if tagged {
            return Err(tag_error(at));
        }
        if self.expects_key() {
            return Err(YamlError::new(
                YamlErrorKind::ComplexKey,
                Some(at),
                "a mapping key must be a plain or quoted string, not a list or a mapping",
            ));
        }
        self.count_node()?;
        if self.stack.len() + 1 > self.limits.max_depth {
            return Err(YamlError::new(
                YamlErrorKind::TooDeep,
                Some(at),
                format!(
                    "the document nests deeper than {} levels; flatten it",
                    self.limits.max_depth
                ),
            ));
        }
        let (line, column) = at;
        self.stack.push(if is_sequence {
            Frame::Seq {
                items: Vec::new(),
                line,
                column,
            }
        } else {
            Frame::Map {
                entries: Vec::new(),
                seen: HashMap::new(),
                key: None,
                line,
                column,
            }
        });
        Ok(())
    }

    /// True when the next value in the innermost mapping is a key.
    fn expects_key(&self) -> bool {
        matches!(self.stack.last(), Some(Frame::Map { key: None, .. }))
    }

    fn on_scalar(
        &mut self,
        text: &str,
        style: ScalarStyle,
        at: (usize, usize),
    ) -> Result<(), YamlError> {
        if text.len() > self.limits.max_scalar_bytes {
            return Err(YamlError::new(
                YamlErrorKind::ScalarTooLong,
                Some(at),
                format!(
                    "this value is {} bytes long; the limit is {} bytes",
                    text.len(),
                    self.limits.max_scalar_bytes
                ),
            ));
        }
        let plain = style == ScalarStyle::Plain;
        if self.expects_key() {
            if plain {
                if text == "<<" {
                    return Err(YamlError::new(
                        YamlErrorKind::MergeKey,
                        Some(at),
                        "the merge key `<<` is not allowed; write each key out",
                    ));
                }
                // A plain key is text. It must not be a word that readers turn into something
                // else, so run it through the same rules as a value and accept only text.
                match resolve_plain(text) {
                    Ok(Resolved::Str) => {}
                    Ok(_) => {
                        return Err(YamlError::new(
                            YamlErrorKind::Ambiguous(AmbiguousScalar::Number),
                            Some(at),
                            format!(
                                "the key `{}` would be read as a number or a boolean; quote it: \"{}\"",
                                shown(text),
                                shown(text)
                            ),
                        ));
                    }
                    Err(refusal) => return Err(refusal_error(text, refusal, at, true)),
                }
            }
            return self.set_key(text.to_owned(), at);
        }
        let content = if plain {
            match resolve_plain(text) {
                Ok(Resolved::Bool(b)) => Content::Bool(b),
                Ok(Resolved::Int(i)) => Content::Int(i),
                Ok(Resolved::UInt(u)) => Content::UInt(u),
                Ok(Resolved::Float(f)) => Content::Float(f),
                Ok(Resolved::Str) => Content::Str(text.to_owned()),
                Err(refusal) => return Err(refusal_error(text, refusal, at, false)),
            }
        } else {
            Content::Str(text.to_owned())
        };
        let (line, column) = at;
        self.attach(Node {
            line,
            column,
            content,
        });
        Ok(())
    }

    fn set_key(&mut self, name: String, at: (usize, usize)) -> Result<(), YamlError> {
        let Some(Frame::Map { seen, key, .. }) = self.stack.last_mut() else {
            return Ok(());
        };
        if let Some(first) = seen.get(&name) {
            return Err(YamlError::new(
                YamlErrorKind::DuplicateKey,
                Some(at),
                format!(
                    "the key `{}` appears twice in this mapping (first on line {first}); keep one",
                    shown(&name)
                ),
            ));
        }
        seen.insert(name.clone(), at.0);
        *key = Some((name, at.0, at.1));
        Ok(())
    }

    /// Puts a finished value where it belongs: the pending key of the innermost mapping, the end
    /// of the innermost sequence, or the root.
    fn attach(&mut self, node: Node) {
        match self.stack.last_mut() {
            None => self.root = Some(node),
            Some(Frame::Seq { items, .. }) => items.push(node),
            Some(Frame::Map { entries, key, .. }) => {
                if let Some((name, line, column)) = key.take() {
                    entries.push(Entry {
                        key: name,
                        line,
                        column,
                        value: node,
                    });
                }
            }
        }
    }
}

fn anchor_error(at: (usize, usize)) -> YamlError {
    YamlError::new(
        YamlErrorKind::Anchor,
        Some(at),
        "anchors (&name) are not allowed; write the value out where it is used",
    )
}

fn tag_error(at: (usize, usize)) -> YamlError {
    YamlError::new(
        YamlErrorKind::Tag,
        Some(at),
        "tags (!name) are not allowed; remove the tag",
    )
}

/// Text shown in a message: at most 40 characters, one line.
fn shown(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(40)
        .collect();
    if text.chars().count() > 40 {
        format!("{flat}...")
    } else {
        flat
    }
}

fn refusal_error(text: &str, refusal: Refusal, at: (usize, usize), is_key: bool) -> YamlError {
    let what = if is_key { "key" } else { "value" };
    match refusal {
        Refusal::Null => YamlError::new(
            YamlErrorKind::Null,
            Some(at),
            if text.is_empty() {
                format!(
                    "this {what} is empty; null is not allowed, so write a value or remove the key"
                )
            } else {
                format!(
                    "`{}` is null; null is not allowed, so write a value or remove the key",
                    shown(text)
                )
            },
        ),
        Refusal::Ambiguous(kind) => {
            let reason = match kind {
                AmbiguousScalar::LegacyBoolean => {
                    "YAML 1.1 readers read it as a boolean and YAML 1.2 readers as text; use true or false, or quote it as text"
                }
                AmbiguousScalar::BooleanSpelling => {
                    "booleans are written in lower case, true or false; quote it if it is text"
                }
                AmbiguousScalar::Number => {
                    "readers disagree on how to read this number; write plain decimal digits, or quote it if it is text"
                }
                AmbiguousScalar::Timestamp => {
                    "some readers turn this into a date or time; quote it, because it is text here"
                }
            };
            YamlError::new(
                YamlErrorKind::Ambiguous(kind),
                Some(at),
                format!("the {what} `{}` is ambiguous: {reason}", shown(text)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_puts_the_position_first_and_the_key_path_in_parentheses() {
        let error = YamlError {
            kind: YamlErrorKind::Decode,
            line: Some(5),
            column: Some(3),
            key: Some("items[0].colour".to_owned()),
            detail: "unknown field `colour`".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "line 5, column 3 (at `items[0].colour`): unknown field `colour`"
        );
    }

    #[test]
    fn shown_text_is_one_short_line() {
        assert_eq!(shown("ok"), "ok");
        assert_eq!(shown("a\nb"), "a b");
        assert!(shown(&"x".repeat(100)).ends_with("..."));
    }
}
