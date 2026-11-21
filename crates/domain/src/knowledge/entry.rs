//! An entry of the knowledge base: the raw header the YAML reader fills, and the checked entry.
//!
//! The rules are the table of the section "The header, exactly" of
//! `docs/architecture/project-knowledge-base.md`. A raw header holds only text; [`Entry::check`]
//! turns it into typed values or names the field that breaks a rule, so the reader can point at
//! its line.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::id::{EntryId, EntryKind};
use crate::macros::string_enum;
use crate::values::GitSha;

/// The longest title, in characters.
const LONGEST_TITLE: usize = 200;
/// The longest path, in bytes.
const LONGEST_PATH: usize = 1024;
/// The longest line of free text (an owner, a reason, a name), in characters.
const LONGEST_LINE: usize = 500;

string_enum! {
    /// Whether an entry is in force.
    pub enum Status("knowledge entry status") {
        /// Written, not yet accepted by a person.
        Proposed = "proposed",
        /// Accepted, and in force.
        Active = "active",
        /// No longer in force. Kept as history.
        Retired = "retired",
    }
}

string_enum! {
    /// Where the knowledge of an entry came from.
    pub enum RecordedFromKind("knowledge source kind") {
        /// A specification of a job.
        Specification = "specification",
        /// A person's answer to a question of the factory.
        Answer = "answer",
        /// A decision of the design phase.
        Design = "design",
        /// The harvest of the onboarding.
        Onboarding = "onboarding",
        /// An outside source on the MCP gateway.
        OutsideSource = "outside-source",
        /// A person who wrote it.
        Person = "person",
    }
}

/// The `sources` of a raw header: four lists of paths, each one optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSources {
    /// The specifications that describe it.
    #[serde(default)]
    pub specifications: Vec<String>,
    /// The code that does it.
    #[serde(default)]
    pub code: Vec<String>,
    /// The tests that enforce it.
    #[serde(default)]
    pub tests: Vec<String>,
    /// The decisions behind it.
    #[serde(default)]
    pub decisions: Vec<String>,
}

/// The `recorded_from` of a raw header.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRecordedFrom {
    /// Where it came from.
    pub kind: String,
    /// Who said or wrote it.
    pub by: String,
    /// When, as `YYYY-MM-DD`.
    pub date: String,
}

/// The header of an entry a person writes, as the YAML reader fills it: text only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEntry {
    /// The identifier.
    pub id: String,
    /// The kind.
    pub kind: String,
    /// The title.
    pub title: String,
    /// The status.
    pub status: String,
    /// The people or teams who own it.
    #[serde(default)]
    pub owners: Vec<String>,
    /// Its evidence.
    #[serde(default)]
    pub sources: RawSources,
    /// For a business rule with no enforcing test: why.
    #[serde(default)]
    pub no_test_yet: Option<String>,
    /// The entries it links to.
    #[serde(default)]
    pub links: Vec<String>,
    /// The commit at which it was last confirmed.
    #[serde(default)]
    pub last_verified: Option<String>,
    /// The entries it replaces.
    #[serde(default)]
    pub supersedes: Vec<String>,
    /// Where it came from.
    #[serde(default)]
    pub recorded_from: Option<RawRecordedFrom>,
}

/// A field of a header that breaks a rule. `field` is the key path, such as `sources.code[1]`, so
/// the reader can find its line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {rule}")]
pub struct EntryError {
    /// The key path of the field.
    pub field: String,
    /// The rule that was broken, in plain words.
    pub rule: String,
}

impl EntryError {
    fn new(field: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            rule: rule.into(),
        }
    }
}

/// A path in the repository: relative to its root, with `/`, no `..`, no `.`, no empty part. A
/// path that ends in `/` names a directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoPath(String);

impl RepoPath {
    /// Checks a path.
    ///
    /// # Errors
    /// The rule the path breaks, in plain words.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.is_empty() || text.len() > LONGEST_PATH {
            return Err(format!("a path has 1 to {LONGEST_PATH} bytes"));
        }
        if text.starts_with('/') || text.contains('\\') {
            return Err("a path is relative to the root of the repository and uses /".to_owned());
        }
        if text.chars().any(char::is_control) {
            return Err("a path holds no control character".to_owned());
        }
        let parts = text.strip_suffix('/').unwrap_or(text);
        if parts
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("a path has no empty part, no . and no ..".to_owned());
        }
        Ok(Self(text.to_owned()))
    }

    /// The path as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether it names a directory (it ends in `/`).
    pub fn is_directory(&self) -> bool {
        self.0.ends_with('/')
    }

    /// Whether `path` is this path, or lies under this directory.
    pub fn covers(&self, path: &str) -> bool {
        if self.is_directory() {
            path.starts_with(&self.0)
        } else {
            path == self.0
        }
    }

    /// Whether this path and `other` touch: one is the other, or one lies under the other.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.covers(other.as_str()) || other.covers(self.as_str())
    }
}

/// A test that enforces an entry: a path, and the name of a test in it when one is given.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TestReference {
    /// The file of the test.
    pub path: RepoPath,
    /// The name of the test, after `::`.
    pub name: Option<String>,
}

impl TestReference {
    fn parse(text: &str) -> Result<Self, String> {
        match text.split_once("::") {
            Some((path, name)) => {
                if name.trim().is_empty()
                    || name.chars().any(|c| c.is_control() || c.is_whitespace())
                {
                    return Err("the name of a test after :: is one word with no space".to_owned());
                }
                Ok(Self {
                    path: RepoPath::parse(path)?,
                    name: Some(name.to_owned()),
                })
            }
            None => Ok(Self {
                path: RepoPath::parse(text)?,
                name: None,
            }),
        }
    }
}

/// The evidence of an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sources {
    /// The specifications that describe it.
    pub specifications: Vec<RepoPath>,
    /// The code that does it.
    pub code: Vec<RepoPath>,
    /// The tests that enforce it.
    pub tests: Vec<TestReference>,
    /// The decisions behind it.
    pub decisions: Vec<RepoPath>,
}

impl Sources {
    /// Every path the entry names, with the key path of its field.
    pub fn paths(&self) -> Vec<(String, &RepoPath)> {
        let mut out = Vec::new();
        for (index, path) in self.specifications.iter().enumerate() {
            out.push((format!("sources.specifications[{index}]"), path));
        }
        for (index, path) in self.code.iter().enumerate() {
            out.push((format!("sources.code[{index}]"), path));
        }
        for (index, test) in self.tests.iter().enumerate() {
            out.push((format!("sources.tests[{index}]"), &test.path));
        }
        for (index, path) in self.decisions.iter().enumerate() {
            out.push((format!("sources.decisions[{index}]"), path));
        }
        out
    }
}

/// Where the knowledge of an entry came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedFrom {
    /// The kind of source.
    pub kind: RecordedFromKind,
    /// Who said or wrote it.
    pub by: String,
    /// When.
    pub date: time::Date,
}

/// An entry of one of the six kinds a person writes, with every rule of its header checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The identifier.
    pub id: EntryId,
    /// The title.
    pub title: String,
    /// The status.
    pub status: Status,
    /// The people or teams who own it.
    pub owners: Vec<String>,
    /// Its evidence.
    pub sources: Sources,
    /// For a business rule with no enforcing test: why.
    pub no_test_yet: Option<String>,
    /// The entries it links to.
    pub links: Vec<EntryId>,
    /// The commit at which it was last confirmed.
    pub last_verified: Option<GitSha>,
    /// The entries it replaces.
    pub supersedes: Vec<EntryId>,
    /// Where it came from.
    pub recorded_from: Option<RecordedFrom>,
}

/// One line of text: not empty, no control character, at most `longest` characters.
fn one_line(field: &str, text: &str, longest: usize) -> Result<String, EntryError> {
    let trimmed = text.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > longest
        || trimmed.chars().any(char::is_control)
    {
        return Err(EntryError::new(
            field,
            format!("one line of 1 to {longest} characters, with no control character"),
        ));
    }
    Ok(trimmed.to_owned())
}

/// A list of identifiers, each one valid and named once.
fn identifiers(field: &str, texts: &[String]) -> Result<Vec<EntryId>, EntryError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(texts.len());
    for (index, text) in texts.iter().enumerate() {
        let at = format!("{field}[{index}]");
        let id =
            EntryId::parse(text).map_err(|error| EntryError::new(&at, error.rule().to_owned()))?;
        if !seen.insert(id.clone()) {
            return Err(EntryError::new(at, "an identifier is named once in a list"));
        }
        out.push(id);
    }
    Ok(out)
}

fn paths(field: &str, texts: &[String]) -> Result<Vec<RepoPath>, EntryError> {
    texts
        .iter()
        .enumerate()
        .map(|(index, text)| {
            RepoPath::parse(text).map_err(|rule| EntryError::new(format!("{field}[{index}]"), rule))
        })
        .collect()
}

/// A calendar date written as `YYYY-MM-DD`.
fn date(field: &str, text: &str) -> Result<time::Date, EntryError> {
    let refuse = || {
        EntryError::new(
            field,
            "a date is written YYYY-MM-DD, in quotes, and exists in the calendar",
        )
    };
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(refuse());
    }
    let number = |range: std::ops::Range<usize>| -> Option<u16> {
        let part = &text[range];
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (
        number(0..4).ok_or_else(refuse)?,
        number(5..7).ok_or_else(refuse)?,
        number(8..10).ok_or_else(refuse)?,
    );
    let month = u8::try_from(month)
        .ok()
        .and_then(|m| time::Month::try_from(m).ok())
        .ok_or_else(refuse)?;
    let day = u8::try_from(day).map_err(|_| refuse())?;
    time::Date::from_calendar_date(i32::from(year), month, day).map_err(|_| refuse())
}

impl Entry {
    /// Checks every rule of a raw header.
    ///
    /// # Errors
    /// The first field that breaks a rule, with its key path.
    pub fn check(raw: &RawEntry) -> Result<Self, EntryError> {
        let kind = EntryKind::parse(&raw.kind)
            .map_err(|error| EntryError::new("kind", error.rule().to_owned()))?;
        if !kind.written_by_people() {
            return Err(EntryError::new(
                "kind",
                "a metric, a measurement and an improvement are written by the factory",
            ));
        }
        let id = EntryId::parse(&raw.id)
            .map_err(|error| EntryError::new("id", error.rule().to_owned()))?;
        if id.kind() != kind {
            return Err(EntryError::new(
                "id",
                format!(
                    "an entry of kind {} has an identifier that starts with {}-",
                    kind.as_str(),
                    kind.prefix()
                ),
            ));
        }
        let title = one_line("title", &raw.title, LONGEST_TITLE)?;
        let status = Status::parse(&raw.status)
            .map_err(|error| EntryError::new("status", error.rule().to_owned()))?;
        let owners = raw
            .owners
            .iter()
            .enumerate()
            .map(|(index, owner)| one_line(&format!("owners[{index}]"), owner, LONGEST_LINE))
            .collect::<Result<Vec<_>, _>>()?;
        let tests = raw
            .sources
            .tests
            .iter()
            .enumerate()
            .map(|(index, text)| {
                TestReference::parse(text)
                    .map_err(|rule| EntryError::new(format!("sources.tests[{index}]"), rule))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sources = Sources {
            specifications: paths("sources.specifications", &raw.sources.specifications)?,
            code: paths("sources.code", &raw.sources.code)?,
            tests,
            decisions: paths("sources.decisions", &raw.sources.decisions)?,
        };
        let no_test_yet = match &raw.no_test_yet {
            None => None,
            Some(_) if kind != EntryKind::BusinessRule => {
                return Err(EntryError::new(
                    "no_test_yet",
                    "only a business rule says why it has no enforcing test",
                ));
            }
            Some(_) if !sources.tests.is_empty() => {
                return Err(EntryError::new(
                    "no_test_yet",
                    "a rule that names an enforcing test does not also say it has none",
                ));
            }
            Some(reason) => Some(one_line("no_test_yet", reason, LONGEST_LINE)?),
        };
        let links = identifiers("links", &raw.links)?;
        if links.contains(&id) {
            return Err(EntryError::new("links", "an entry does not link to itself"));
        }
        let supersedes = identifiers("supersedes", &raw.supersedes)?;
        if supersedes.contains(&id) {
            return Err(EntryError::new(
                "supersedes",
                "an entry does not replace itself",
            ));
        }
        let last_verified = match &raw.last_verified {
            None => None,
            Some(text) => Some(GitSha::parse(text).map_err(|_| {
                EntryError::new(
                    "last_verified",
                    "the full commit id, 40 or 64 lowercase hexadecimal characters, in quotes",
                )
            })?),
        };
        let recorded_from = match &raw.recorded_from {
            None => None,
            Some(from) => Some(RecordedFrom {
                kind: RecordedFromKind::parse(&from.kind).map_err(|error| {
                    EntryError::new("recorded_from.kind", error.rule().to_owned())
                })?,
                by: one_line("recorded_from.by", &from.by, LONGEST_LINE)?,
                date: date("recorded_from.date", &from.date)?,
            }),
        };
        Ok(Self {
            id,
            title,
            status,
            owners,
            sources,
            no_test_yet,
            links,
            last_verified,
            supersedes,
            recorded_from,
        })
    }

    /// The identifiers this entry names: its links and the entries it replaces.
    pub fn named_entries(&self) -> impl Iterator<Item = (&'static str, &EntryId)> {
        self.links
            .iter()
            .map(|id| ("links", id))
            .chain(self.supersedes.iter().map(|id| ("supersedes", id)))
    }
}

/// The part of a header the factory writes that the knowledge base needs: what the entry is and
/// whether it is in force. The rest of such a header belongs to the module that renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryEntry {
    /// The identifier.
    pub id: EntryId,
    /// The title.
    pub title: String,
    /// The status. A measurement has none: it is a dated record, always in force.
    pub status: Option<Status>,
}

impl FactoryEntry {
    /// Checks the three fields every header the factory writes holds.
    ///
    /// # Errors
    /// The first field that breaks a rule.
    pub fn check(
        id: &str,
        kind: &str,
        title: &str,
        status: Option<&str>,
    ) -> Result<Self, EntryError> {
        let kind = EntryKind::parse(kind)
            .map_err(|error| EntryError::new("kind", error.rule().to_owned()))?;
        if kind.written_by_people() {
            return Err(EntryError::new(
                "kind",
                "this header is one the factory writes",
            ));
        }
        let id =
            EntryId::parse(id).map_err(|error| EntryError::new("id", error.rule().to_owned()))?;
        if id.kind() != kind {
            return Err(EntryError::new(
                "id",
                format!(
                    "an entry of kind {} has an identifier that starts with {}-",
                    kind.as_str(),
                    kind.prefix()
                ),
            ));
        }
        let status = match (kind, status) {
            (EntryKind::Measurement, None) => None,
            (EntryKind::Measurement, Some(_)) => {
                return Err(EntryError::new("status", "a measurement has no status"));
            }
            (_, None) => {
                return Err(EntryError::new(
                    "status",
                    "a metric and an improvement have a status",
                ));
            }
            (_, Some(text)) => Some(
                Status::parse(text)
                    .map_err(|error| EntryError::new("status", error.rule().to_owned()))?,
            ),
        };
        Ok(Self {
            id,
            title: one_line("title", title, LONGEST_TITLE)?,
            status,
        })
    }
}

/// The header of an entry, of either origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// One of the six kinds a person writes.
    Entry(Box<Entry>),
    /// One of the three kinds the factory writes.
    Factory(FactoryEntry),
}

impl Header {
    /// The identifier.
    pub fn id(&self) -> &EntryId {
        match self {
            Self::Entry(entry) => &entry.id,
            Self::Factory(entry) => &entry.id,
        }
    }

    /// The title.
    pub fn title(&self) -> &str {
        match self {
            Self::Entry(entry) => &entry.title,
            Self::Factory(entry) => &entry.title,
        }
    }

    /// The status, when the kind has one.
    pub fn status(&self) -> Option<Status> {
        match self {
            Self::Entry(entry) => Some(entry.status),
            Self::Factory(entry) => entry.status,
        }
    }

    /// The entry a person writes, when it is one.
    pub fn as_entry(&self) -> Option<&Entry> {
        match self {
            Self::Entry(entry) => Some(entry),
            Self::Factory(_) => None,
        }
    }
}

#[cfg(test)]
mod tests;
