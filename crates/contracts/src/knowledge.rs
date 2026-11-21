//! The header of a knowledge base entry read from its text (ADR 0028), with the restricted YAML
//! reader of [`crate::yaml`].
//!
//! The rules are the section "The header, exactly" of
//! `docs/architecture/project-knowledge-base.md`:
//!
//! 1. The text starts with a line `---`, then the header, then a line `---`, then the body. Lines
//!    end with a line feed; a carriage return is refused, so a file reads the same everywhere.
//! 2. The header is restricted YAML, read with [`KNOWLEDGE_LIMITS`].
//! 3. Its `kind` says which of the four headers it is: the one people write (checked by
//!    [`Entry::check`]) or one of the three the factory renders (`metric`, `measurement`,
//!    `improvement`, read into closed structs of their own and checked by
//!    [`FactoryEntry::check`]). An unknown field is refused in each.
//!
//! Every error carries the line of the file it is about, counted from 1, when one is known.

use factory_domain::knowledge::{Entry, FactoryEntry, Finding, Header, KnowledgeFile, RawEntry};
use factory_domain::values::{GitSha, Timestamp};
use serde::Deserialize;

use crate::yaml::{self, Document, YamlLimits};

/// The limits of one header: 64 KiB, 6 levels, 4,000 values, scalars up to 4 KiB. A header is a
/// few dozen lines; the limits leave room for long lists of sources.
pub const KNOWLEDGE_LIMITS: (usize, usize, usize, usize) = (64 * 1024, 6, 4_000, 4 * 1024);

/// Why the header of an entry cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}{detail}", line.map(|line| format!("line {line}: ")).unwrap_or_default())]
pub struct ReadError {
    /// The line of the file, counted from 1, when one is known.
    pub line: Option<usize>,
    /// What is wrong, in plain words.
    pub detail: String,
}

impl ReadError {
    fn new(line: Option<usize>, detail: impl Into<String>) -> Self {
        Self {
            line,
            detail: detail.into(),
        }
    }
}

/// The header of a `metric` entry, as `factory_domain::metrics::MetricDefinition::render_entry`
/// writes it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    dead_code,
    reason = "every field makes the shape closed; the knowledge base reads only id, kind, title and status"
)]
struct MetricHeader {
    id: String,
    kind: String,
    title: String,
    status: String,
    group: String,
    unit: String,
    better: String,
    shown_as: Vec<String>,
    minimum_sample: u64,
    cut_by: Vec<String>,
}

/// The window of a `measurement` header.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowHeader {
    from: String,
    to: String,
}

/// The header of a `measurement` entry, as `factory_domain::metrics::Measurement::render_entry`
/// writes it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasurementHeader {
    id: String,
    kind: String,
    title: String,
    window: WindowHeader,
    query_version: u64,
    computed_at_commit: String,
}

/// The header of an `improvement` entry, as `factory_domain::metrics::Improvement::render_entry`
/// writes it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    dead_code,
    reason = "every field makes the shape closed; the knowledge base reads only id, kind, title, status and decided_at"
)]
struct ImprovementHeader {
    id: String,
    kind: String,
    title: String,
    status: String,
    tier: String,
    experiment: String,
    setting: String,
    from: String,
    to: String,
    share_of_jobs: String,
    decision: String,
    decided_at: String,
}

/// Splits the text of an entry into its header and the line the header starts on.
fn split(text: &str) -> Result<(&str, usize), ReadError> {
    if text.contains('\r') {
        return Err(ReadError::new(
            None,
            "lines end with a line feed only; the file holds a carriage return",
        ));
    }
    let Some(rest) = text.strip_prefix("---\n") else {
        return Err(ReadError::new(
            Some(1),
            "an entry starts with a line ---, then its header",
        ));
    };
    // The header ends at the first line that is exactly `---`.
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        if line.trim_end_matches('\n') == "---" {
            return Ok((&rest[..offset], 2));
        }
        offset += line.len();
    }
    Err(ReadError::new(None, "the header has no closing line ---"))
}

/// The line of the file for a line of the header.
fn file_line(header_line: Option<usize>, first: usize) -> Option<usize> {
    header_line.map(|line| line + first - 1)
}

/// Decodes `document` into `T`, with the line of any error in the file.
fn decode<T: serde::de::DeserializeOwned>(
    document: &Document,
    first: usize,
) -> Result<T, ReadError> {
    document.decode().map_err(|error| {
        let detail = match &error.key {
            Some(key) => format!("{key}: {}", error.detail()),
            None => error.detail().to_owned(),
        };
        ReadError::new(file_line(error.line, first), detail)
    })
}

/// The line of a field of the header, for a rule the domain checked.
fn at(document: &Document, field: &str, first: usize) -> Option<usize> {
    file_line(document.locate(field).map(|(line, _)| line), first)
}

/// Reads the header of an entry from its text.
///
/// # Errors
/// A [`ReadError`] with the line: the text has no header, the header is not restricted YAML,
/// holds an unknown field, or breaks a rule of its kind.
pub fn read_header(text: &str) -> Result<Header, ReadError> {
    let (header, first) = split(text)?;
    let (bytes, depth, nodes, scalar) = KNOWLEDGE_LIMITS;
    let limits = YamlLimits::new(bytes, depth, nodes, scalar)
        .map_err(|error| ReadError::new(None, error.to_string()))?;
    let document = yaml::read(header, limits)
        .map_err(|error| ReadError::new(file_line(error.line, first), error.to_string()))?;
    let kind = document
        .to_json()
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ReadError::new(file_line(Some(1), first), "kind: a header names its kind")
        })?;
    let rule = |field: &str, detail: String| {
        ReadError::new(at(&document, field, first), format!("{field}: {detail}"))
    };
    match kind.as_str() {
        "metric" => {
            let raw: MetricHeader = decode(&document, first)?;
            FactoryEntry::check(&raw.id, &raw.kind, &raw.title, Some(&raw.status))
                .map(Header::Factory)
                .map_err(|error| rule(&error.field, error.rule))
        }
        "measurement" => {
            let raw: MeasurementHeader = decode(&document, first)?;
            for (field, instant) in [
                ("window.from", &raw.window.from),
                ("window.to", &raw.window.to),
            ] {
                Timestamp::parse(instant)
                    .map_err(|_| rule(field, "an instant in UTC, in quotes".to_owned()))?;
            }
            GitSha::parse(&raw.computed_at_commit).map_err(|_| {
                rule(
                    "computed_at_commit",
                    "the full commit id, in quotes".to_owned(),
                )
            })?;
            if raw.query_version == 0 {
                return Err(rule(
                    "query_version",
                    "a query version starts at 1".to_owned(),
                ));
            }
            FactoryEntry::check(&raw.id, &raw.kind, &raw.title, None)
                .map(Header::Factory)
                .map_err(|error| rule(&error.field, error.rule))
        }
        "improvement" => {
            let raw: ImprovementHeader = decode(&document, first)?;
            Timestamp::parse(&raw.decided_at)
                .map_err(|_| rule("decided_at", "an instant in UTC, in quotes".to_owned()))?;
            FactoryEntry::check(&raw.id, &raw.kind, &raw.title, Some(&raw.status))
                .map(Header::Factory)
                .map_err(|error| rule(&error.field, error.rule))
        }
        _ => {
            let raw: RawEntry = decode(&document, first)?;
            Entry::check(&raw)
                .map(|entry| Header::Entry(Box::new(entry)))
                .map_err(|error| rule(&error.field, error.rule))
        }
    }
}

/// Reads one file of the knowledge base. `file` is its path under `docs/knowledge/`. A file that
/// cannot be read is the finding [`Finding::Unreadable`], with the line, so one broken file never
/// hides the findings of the others.
///
/// # Errors
/// [`Finding::Unreadable`].
pub fn read_file(file: &str, text: &str) -> Result<KnowledgeFile, Finding> {
    read_header(text)
        .map(|header| KnowledgeFile {
            file: file.to_owned(),
            header,
        })
        .map_err(|error| Finding::Unreadable {
            file: file.to_owned(),
            detail: error.to_string(),
        })
}

#[cfg(test)]
mod tests;
