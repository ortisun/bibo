//! The knowledge base of a repository at one commit: its files, its index and its checks.
//!
//! The checks are the five of the section "How it stays true" of
//! `docs/architecture/project-knowledge-base.md`, numbered the same way.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::entry::{Header, Status};
use super::id::{EntryId, EntryKind};
use crate::values::Slug;

/// The directory of the knowledge base in a repository.
pub const KNOWLEDGE_ROOT: &str = "docs/knowledge/";

/// The file of the index, under [`KNOWLEDGE_ROOT`].
pub const INDEX_FILE: &str = "README.md";

/// One entry of the knowledge base: the file it was read from, relative to [`KNOWLEDGE_ROOT`],
/// and its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeFile {
    /// The file, such as `business-rules/BR-0007-refund-needs-second-approval.md`.
    pub file: String,
    /// Its header.
    pub header: Header,
}

/// What a change looks like to the drift checks: every file at the head of the change, and the
/// files the change added, changed or removed. Paths are relative to the root of the repository.
#[derive(Debug, Clone, Copy)]
pub struct Change<'a> {
    /// Every file at the head.
    pub head_paths: &'a BTreeSet<String>,
    /// The files the change added, changed or removed.
    pub changed_paths: &'a BTreeSet<String>,
}

/// One finding of the checks. Each names the entry and the path or identifier it is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Finding {
    /// The file of an entry could not be read. The reader builds this finding.
    Unreadable {
        /// The file.
        file: String,
        /// What is wrong, with its line.
        detail: String,
    },
    /// Check 5: the file is not in the directory of its kind.
    FileOutsideItsDirectory {
        /// The file.
        file: String,
        /// The entry.
        entry: EntryId,
        /// The directory it belongs in.
        directory: &'static str,
    },
    /// Check 5: the file is not named after its identifier.
    FileNotNamedAfterItsIdentifier {
        /// The file.
        file: String,
        /// The entry.
        entry: EntryId,
    },
    /// Check 5: two files hold the same identifier.
    DuplicateIdentifier {
        /// The identifier.
        entry: EntryId,
        /// Every file that holds it.
        files: Vec<String>,
    },
    /// Check 1: a link or a `supersedes` names an entry the knowledge base does not have.
    UnknownEntry {
        /// The entry that names it.
        entry: EntryId,
        /// `links` or `supersedes`.
        field: &'static str,
        /// The identifier it names.
        named: EntryId,
    },
    /// Check 2: a path the entry names does not exist at the head.
    MissingSource {
        /// The entry.
        entry: EntryId,
        /// The key path of the field.
        field: String,
        /// The path.
        path: String,
    },
    /// Check 3: an active business rule names no enforcing test and does not say why.
    RuleWithoutTest {
        /// The rule.
        entry: EntryId,
    },
    /// Check 4: the change touched the code of an active entry and did not confirm the entry.
    Unconfirmed {
        /// The entry.
        entry: EntryId,
        /// The first changed path of its code.
        path: String,
    },
    /// Check 5: there is no index.
    IndexMissing,
    /// Check 5: the index lacks the line of an entry.
    IndexLineMissing {
        /// The line to add.
        line: String,
    },
    /// Check 5: the index has a line for no entry, or a line that is out of date.
    IndexLineUnknown {
        /// The line.
        line: String,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { file, detail } => write!(f, "{file} cannot be read: {detail}"),
            Self::FileOutsideItsDirectory {
                file,
                entry,
                directory,
            } => {
                write!(f, "{file}: {entry} belongs in {KNOWLEDGE_ROOT}{directory}/")
            }
            Self::FileNotNamedAfterItsIdentifier { file, entry } => {
                write!(f, "{file}: the file of {entry} is named {entry}-<words>.md")
            }
            Self::DuplicateIdentifier { entry, files } => {
                write!(
                    f,
                    "{entry} is the identifier of more than one file: {}",
                    files.join(", ")
                )
            }
            Self::UnknownEntry {
                entry,
                field,
                named,
            } => {
                write!(f, "{entry}: {field} names {named}, which is not an entry")
            }
            Self::MissingSource { entry, field, path } => {
                write!(
                    f,
                    "{entry}: {field} names {path}, which does not exist at the head"
                )
            }
            Self::RuleWithoutTest { entry } => write!(
                f,
                "{entry} is an active business rule with no enforcing test in sources.tests and no reason in no_test_yet"
            ),
            Self::Unconfirmed { entry, path } => write!(
                f,
                "the change touches {path}, code of the active entry {entry}, and does not confirm {entry}: update it, or move its last_verified"
            ),
            Self::IndexMissing => write!(f, "{KNOWLEDGE_ROOT}{INDEX_FILE} is missing"),
            Self::IndexLineMissing { line } => {
                write!(f, "{KNOWLEDGE_ROOT}{INDEX_FILE} lacks the line: {line}")
            }
            Self::IndexLineUnknown { line } => {
                write!(
                    f,
                    "{KNOWLEDGE_ROOT}{INDEX_FILE} has a line for no entry, or out of date: {line}"
                )
            }
        }
    }
}

/// The knowledge base of a repository at one commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeBase {
    files: Vec<KnowledgeFile>,
}

/// A title in a cell of a Markdown table: a `|` would end the cell.
fn cell(text: &str) -> String {
    text.replace('|', "\\|")
}

impl KnowledgeBase {
    /// The knowledge base of these files, in the order of their identifiers and then of their
    /// files.
    pub fn new(mut files: Vec<KnowledgeFile>) -> Self {
        files.sort_by(|a, b| (a.header.id(), &a.file).cmp(&(b.header.id(), &b.file)));
        Self { files }
    }

    /// Every file, in the order of their identifiers.
    pub fn files(&self) -> &[KnowledgeFile] {
        &self.files
    }

    /// The first file of each identifier. A duplicate is a finding of check 5 and is ignored by
    /// every other rule, so one mistake gives one finding.
    pub(super) fn by_id(&self) -> BTreeMap<&EntryId, &KnowledgeFile> {
        let mut map = BTreeMap::new();
        for file in &self.files {
            map.entry(file.header.id()).or_insert(file);
        }
        map
    }

    /// The file an entry belongs in, by the rule of the design: `<directory>/<id>-<words>.md`, or
    /// `measurements/<id>.md` for a measurement.
    fn placement(file: &KnowledgeFile) -> Option<Finding> {
        let id = file.header.id();
        let kind = id.kind();
        let directory = kind.directory();
        let Some(name) = file
            .file
            .strip_prefix(directory)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            return Some(Finding::FileOutsideItsDirectory {
                file: file.file.clone(),
                entry: id.clone(),
                directory,
            });
        };
        if name.contains('/') {
            return Some(Finding::FileOutsideItsDirectory {
                file: file.file.clone(),
                entry: id.clone(),
                directory,
            });
        }
        let named = match kind {
            EntryKind::Measurement => name == format!("{id}.md"),
            _ => name
                .strip_prefix(&format!("{id}-"))
                .and_then(|rest| rest.strip_suffix(".md"))
                .is_some_and(|words| Slug::parse(words).is_ok()),
        };
        (!named).then(|| Finding::FileNotNamedAfterItsIdentifier {
            file: file.file.clone(),
            entry: id.clone(),
        })
    }

    /// Checks 1 and 5, except the index: the placement and the names of the files, identifiers used
    /// once, and links that resolve.
    pub fn well_formed(&self) -> Vec<Finding> {
        let mut findings: Vec<Finding> = self.files.iter().filter_map(Self::placement).collect();
        let mut files_of: BTreeMap<&EntryId, Vec<String>> = BTreeMap::new();
        for file in &self.files {
            files_of
                .entry(file.header.id())
                .or_default()
                .push(file.file.clone());
        }
        for (id, files) in files_of {
            if files.len() > 1 {
                findings.push(Finding::DuplicateIdentifier {
                    entry: id.clone(),
                    files,
                });
            }
        }
        let known = self.by_id();
        for file in known.values() {
            let Some(entry) = file.header.as_entry() else {
                continue;
            };
            for (field, named) in entry.named_entries() {
                if !known.contains_key(named) {
                    findings.push(Finding::UnknownEntry {
                        entry: entry.id.clone(),
                        field,
                        named: named.clone(),
                    });
                }
            }
        }
        findings
    }

    /// The line of the index for one file.
    fn index_line(file: &KnowledgeFile) -> String {
        let status = file.header.status().map_or("recorded", Status::as_str);
        format!(
            "| [{id}]({path}) | {title} | {status} |",
            id = file.header.id(),
            path = file.file,
            title = cell(file.header.title())
        )
    }

    /// The index the factory writes: one section for each kind that has an entry, in the order of
    /// the kinds, and one line for each entry, in the order of the identifiers.
    pub fn render_index(&self) -> String {
        let mut out = String::from(
            "# Knowledge base\n\n\
             Every entry of the knowledge base, by kind. The factory writes this file from the \
             entries, and its documentation gate reports a line that is missing or out of date.\n",
        );
        let known = self.by_id();
        for kind in EntryKind::ALL {
            let lines: Vec<String> = known
                .values()
                .filter(|file| file.header.id().kind() == *kind)
                .map(|file| Self::index_line(file))
                .collect();
            if lines.is_empty() {
                continue;
            }
            out.push_str(&format!(
                "\n## {}\n\n| Identifier | Title | Status |\n|---|---|---|\n",
                kind.heading()
            ));
            for line in lines {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }

    /// Check 5 on the index: every entry has its line, and no line is for nothing. `index` is the
    /// text of `docs/knowledge/README.md`, or `None` when it does not exist.
    pub fn check_index(&self, index: Option<&str>) -> Vec<Finding> {
        let Some(index) = index else {
            return vec![Finding::IndexMissing];
        };
        let expected: BTreeSet<String> = self
            .by_id()
            .values()
            .map(|file| Self::index_line(file))
            .collect();
        let present: BTreeSet<String> = index
            .lines()
            .map(str::trim_end)
            .filter(|line| line.starts_with("| ["))
            .map(str::to_owned)
            .collect();
        let missing = expected
            .difference(&present)
            .map(|line| Finding::IndexLineMissing { line: line.clone() });
        let unknown = present
            .difference(&expected)
            .map(|line| Finding::IndexLineUnknown { line: line.clone() });
        missing.chain(unknown).collect()
    }

    /// Checks 2 to 4 against a change. A retired entry is exempt; checks 3 and 4 apply to active
    /// entries only.
    pub fn check_change(&self, change: Change<'_>) -> Vec<Finding> {
        let exists = |path: &super::entry::RepoPath| {
            if path.is_directory() {
                change.head_paths.iter().any(|head| path.covers(head))
            } else {
                change.head_paths.contains(path.as_str())
            }
        };
        let mut findings = Vec::new();
        for file in self.by_id().values() {
            let Some(entry) = file.header.as_entry() else {
                continue;
            };
            if entry.status == Status::Retired {
                continue;
            }
            for (field, path) in entry.sources.paths() {
                if !exists(path) {
                    findings.push(Finding::MissingSource {
                        entry: entry.id.clone(),
                        field,
                        path: path.as_str().to_owned(),
                    });
                }
            }
            if entry.status != Status::Active {
                continue;
            }
            if entry.id.kind() == EntryKind::BusinessRule
                && entry.sources.tests.is_empty()
                && entry.no_test_yet.is_none()
            {
                findings.push(Finding::RuleWithoutTest {
                    entry: entry.id.clone(),
                });
            }
            let confirmed = change
                .changed_paths
                .contains(&format!("{KNOWLEDGE_ROOT}{}", file.file));
            if confirmed {
                continue;
            }
            let touched = change
                .changed_paths
                .iter()
                .find(|changed| entry.sources.code.iter().any(|code| code.covers(changed)));
            if let Some(path) = touched {
                findings.push(Finding::Unconfirmed {
                    entry: entry.id.clone(),
                    path: path.clone(),
                });
            }
        }
        findings
    }

    /// Every check: the files, the index and the change, sorted so that the same knowledge base
    /// and change always give the same list.
    pub fn check(&self, index: Option<&str>, change: Change<'_>) -> Vec<Finding> {
        let mut findings = self.well_formed();
        findings.extend(self.check_index(index));
        findings.extend(self.check_change(change));
        findings.sort();
        findings
    }
}

#[cfg(test)]
mod tests;
