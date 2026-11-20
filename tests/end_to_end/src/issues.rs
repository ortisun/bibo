//! The issue texts the scenarios submit, loaded from `tests/end_to_end/issues/`.
//!
//! The files are embedded when the crate is built, so a caller that links this library does not
//! need the directory at run time. `issues/README.md` explains each file.

use serde::Deserialize;

/// The files, by id.
const FILES: [(&str, &str); 7] = [
    (
        "json-output-en",
        include_str!("../issues/json-output-en.json"),
    ),
    (
        "json-output-pt",
        include_str!("../issues/json-output-pt.json"),
    ),
    (
        "hostile-injection",
        include_str!("../issues/hostile-injection.json"),
    ),
    (
        "unauthorized-requester",
        include_str!("../issues/unauthorized-requester.json"),
    ),
    (
        "edited-after-authorization",
        include_str!("../issues/edited-after-authorization.json"),
    ),
    (
        "ambiguous-request",
        include_str!("../issues/ambiguous-request.json"),
    ),
    (
        "out-of-policy-request",
        include_str!("../issues/out-of-policy-request.json"),
    ),
];

/// Who files the issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Requester {
    /// A person on the requester allowlist.
    Authorized,
    /// A person who is not.
    Unauthorized,
}

/// One version of the text.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    /// The title.
    pub title: String,
    /// The body, one entry for each line.
    pub body: Vec<String>,
}

impl Revision {
    /// The body as one text.
    #[must_use]
    pub fn body_text(&self) -> String {
        self.body.join("\n")
    }
}

/// A change to who files the issue, or to its labels, for a second run.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    /// The variant id.
    pub id: String,
    /// Who files it.
    pub requester: Requester,
    /// The labels.
    pub labels: Vec<String>,
}

/// What a hostile text demands.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Injection {
    /// The actions it demands, in words.
    pub demanded_actions: Vec<String>,
    /// Phrases that mark the attack in the text.
    pub markers: Vec<String>,
}

/// One check of what must survive a translation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentCheck {
    /// The check id.
    pub id: String,
    /// What it means.
    pub description: String,
    /// Lower-case texts, each possibly several alternatives joined with `|`. The check holds when
    /// the text has every entry (any one of its alternatives).
    pub all_of: Vec<String>,
}

impl IntentCheck {
    /// True when `english_text` holds every entry.
    #[must_use]
    pub fn holds_in(&self, english_text: &str) -> bool {
        let text = english_text.to_lowercase();
        self.all_of.iter().all(|entry| {
            entry
                .split('|')
                .any(|alternative| text.contains(alternative))
        })
    }
}

/// What must survive from the request into the English artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// Exact texts that must appear unchanged (option names and file names).
    pub must_preserve: Vec<String>,
    /// The checks.
    pub checks: Vec<IntentCheck>,
    /// A note on how `all_of` is read.
    #[serde(default)]
    pub r#match: Option<String>,
}

/// What the factory must do with the request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    /// A closed word: `draft_pull_request`, `rejected_at_admission`, `no_effect`,
    /// `restart_from_intake`, `one_question` or `declined`.
    pub outcome: String,
    /// The behavior, in plain-English sentences.
    pub behavior: Vec<String>,
}

/// An issue text and what the factory must do with it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    /// The format version of the file.
    pub issue_format: u32,
    /// The id, equal to the file name without `.json`.
    pub id: String,
    /// A sentence for a person.
    pub summary: String,
    /// `en` or `pt-BR`.
    pub language: String,
    /// The issue this one translates or repeats.
    #[serde(default)]
    pub same_intent_as: Option<String>,
    /// Who files it.
    pub requester: Requester,
    /// The labels when it is filed.
    pub labels: Vec<String>,
    /// Changes for a second run.
    #[serde(default)]
    pub variants: Vec<Variant>,
    /// The versions of the text. A second one is an edit made after authorization.
    pub revisions: Vec<Revision>,
    /// A hostile text's demands.
    #[serde(default)]
    pub injection: Option<Injection>,
    /// What must survive into the English artifacts.
    pub intent: Intent,
    /// What the factory must do.
    pub expected: Expected,
}

impl Issue {
    /// The first (authorized) revision.
    ///
    /// # Panics
    /// Never for an issue loaded by [`load`], which refuses an issue with no revision.
    #[must_use]
    pub fn first(&self) -> &Revision {
        &self.revisions[0]
    }

    /// The last revision: the text as it stands on the issue now.
    ///
    /// # Panics
    /// Never for an issue loaded by [`load`].
    #[must_use]
    pub fn current(&self) -> &Revision {
        &self.revisions[self.revisions.len() - 1]
    }
}

/// The ids of all issues, in a fixed order.
#[must_use]
pub fn ids() -> Vec<&'static str> {
    FILES.iter().map(|(id, _)| *id).collect()
}

/// Loads one issue.
///
/// # Errors
/// A sentence saying what is wrong with the file.
pub fn load(id: &str) -> Result<Issue, String> {
    let (_, text) = FILES
        .iter()
        .find(|(name, _)| *name == id)
        .ok_or_else(|| format!("there is no issue called {id}"))?;
    let issue: Issue =
        serde_json::from_str(text).map_err(|error| format!("issues/{id}.json: {error}"))?;
    if issue.id != id {
        return Err(format!("issues/{id}.json has the id {}", issue.id));
    }
    if issue.issue_format != 1 {
        return Err(format!(
            "issues/{id}.json has the format {}",
            issue.issue_format
        ));
    }
    if issue.revisions.is_empty() {
        return Err(format!("issues/{id}.json has no revision"));
    }
    Ok(issue)
}

/// Loads every issue.
///
/// # Errors
/// The first file that does not load.
pub fn load_all() -> Result<Vec<Issue>, String> {
    ids().into_iter().map(load).collect()
}
