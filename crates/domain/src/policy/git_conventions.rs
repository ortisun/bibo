//! The git conventions of a project: Conventional Commits and gitflow, as the project records them
//! in `.factory/repository.json`.
//!
//! The installer writes that file (`scripts/lib/git_policy.py`, which the project keeps as
//! `.github/scripts/git_policy.py` and runs in its git hooks and its pull request check). This
//! module reads the same file with the same rules, so that what the factory itself writes passes
//! the project's own check:
//!
//! * the branch the factory starts from and opens its pull request against
//!   ([`GitConventions::integration_branch`]): `develop` in the `develop` closing mode, the one open
//!   `release/` branch in the `release` closing mode;
//! * the first line of each commit and the pull request title ([`GitConventions::header`]): a
//!   Conventional Commits header whose type and scope the project allows and whose length is within
//!   its limit.
//!
//! The file is read from the protected base commit, never from a branch an agent wrote, and the path
//! `.factory/**` is a protected path. A project without the file keeps the factory's earlier
//! behavior: it works from the default branch and writes plain titles. A file that is there and
//! wrong is an error, not a silent fallback.
//!
//! Pure: the caller reads the bytes and lists the remote branches.

use serde::Deserialize;
use serde_json::Value;

/// Where the settings live in the project.
pub const SETTINGS_PATH: &str = ".factory/repository.json";

/// The `schema` value of the settings this module reads.
pub const SCHEMA: &str = "factory-repository-settings/1";

/// The most bytes of settings that are read. The installer's file is about one kilobyte.
pub const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

/// The smallest and largest header limit a project may set (inclusive).
pub const HEADER_LIMIT_RANGE: (usize, usize) = (20, 200);

/// The kinds of gitflow branch, in the order the installer checks them.
const KINDS: [&str; 5] = ["feature", "bugfix", "release", "hotfix", "support"];

/// Where feature and bugfix branches close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosingMode {
    /// Classic gitflow: they close into the develop branch.
    Develop,
    /// They close straight into the open release branch.
    Release,
}

/// A branch that is not the main or develop branch and closes by pull request into named places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalFlow {
    /// The prefix of the head branch, ending in `/`.
    pub head_prefix: String,
    /// Branch names, or prefixes ending in `/`.
    pub into: Vec<String>,
}

/// The settings of `.factory/repository.json`, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitConventions {
    /// The repository owner.
    pub owner: String,
    /// The repository name.
    pub name: String,
    /// The GitHub Projects board, if any.
    pub board: Option<(String, u64)>,
    /// The allowed commit types, in lower case.
    pub types: Vec<String>,
    /// The allowed scopes; empty allows any.
    pub scopes: Vec<String>,
    /// Whether a header must have a scope.
    pub require_scope: bool,
    /// The longest first line, in characters.
    pub header_max_length: usize,
    /// Where feature and bugfix branches close.
    pub closing_mode: ClosingMode,
    /// The production branch.
    pub main_branch: String,
    /// The integration branch.
    pub develop_branch: String,
    /// The prefixes of each kind of branch: `feature`, `bugfix`, `release`, `hotfix`, `support`.
    pub prefixes: Vec<(String, Vec<String>)>,
    /// Other branches and where they close.
    pub additional_flows: Vec<AdditionalFlow>,
}

/// Why the settings were refused. Each problem is one sentence, in the words of the installer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the settings in .factory/repository.json are not valid: {}", .0.join("; "))]
pub struct SettingsRejected(pub Vec<String>);

/// Why no integration branch could be chosen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrationRefusal {
    /// The project closes into the release branch and none is open.
    #[error(
        "the project closes feature branches into the open release branch, and the remote has none"
    )]
    NoOpenRelease,
    /// More than one release branch is open: the factory does not guess between them.
    #[error("the project closes feature branches into the open release branch, and the remote has {}: {}", .0.len(), .0.join(", "))]
    SeveralOpenReleases(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    schema: String,
    repository: RawRepository,
    project_board: Option<RawBoard>,
    commits: RawCommits,
    gitflow: RawGitflow,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepository {
    owner: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBoard {
    owner: String,
    number: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommits {
    convention: String,
    types: Vec<String>,
    scopes: Vec<String>,
    require_scope: bool,
    header_max_length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGitflow {
    closing_mode: String,
    main_branch: String,
    develop_branch: String,
    prefixes: RawPrefixes,
    additional_flows: Vec<RawFlow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrefixes {
    feature: Vec<String>,
    bugfix: Vec<String>,
    release: Vec<String>,
    hotfix: Vec<String>,
    support: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFlow {
    head_prefix: String,
    into: Vec<String>,
}

fn is_owner(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && text.len() <= 39
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 100
        && text != "."
        && text != ".."
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// One path segment of a branch name: starts with a letter or digit, then letters, digits, `.`,
/// `_` and `-`.
fn is_segment(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A branch name, or the part of one after its prefix: segments separated by single `/`.
fn is_slug(text: &str) -> bool {
    !text.is_empty() && text.split('/').all(is_segment)
}

fn is_prefix(text: &str) -> bool {
    text.strip_suffix('/').is_some_and(is_segment)
}

fn is_type(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn is_scope_value(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-')
        })
}

fn is_flow_target(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

fn list(
    problems: &mut Vec<String>,
    where_: &str,
    items: &[String],
    valid: fn(&str) -> bool,
    allow_empty: bool,
) {
    if items.is_empty() && !allow_empty {
        problems.push(format!("{where_} must not be empty"));
    }
    for item in items {
        if !valid(item) {
            problems.push(format!(
                "{where_} has a value that is not allowed: {item:?}"
            ));
        }
    }
    let mut seen: Vec<&String> = items.iter().collect();
    seen.sort();
    seen.dedup();
    if seen.len() != items.len() {
        problems.push(format!("{where_} lists a value twice"));
    }
}

impl GitConventions {
    /// Reads and checks the bytes of `.factory/repository.json`.
    ///
    /// # Errors
    /// [`SettingsRejected`] with every problem found, when the bytes are not the settings this
    /// module knows: not JSON, an unknown or missing key, a value of the wrong kind or out of range.
    pub fn parse(bytes: &[u8]) -> Result<Self, SettingsRejected> {
        let too_big = u64::try_from(bytes.len()).map_or(true, |n| n > MAX_SETTINGS_BYTES);
        if too_big {
            return Err(SettingsRejected(vec![format!(
                "the file is larger than {MAX_SETTINGS_BYTES} bytes"
            )]));
        }
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| SettingsRejected(vec![format!("the file is not JSON: {error}")]))?;
        // `project_board` may be null but must be there, as the installer writes it.
        if value.get("project_board").is_none() {
            return Err(SettingsRejected(vec![
                "the settings are missing the key 'project_board'".to_owned(),
            ]));
        }
        let raw: RawSettings = serde_json::from_value(value)
            .map_err(|error| SettingsRejected(vec![error.to_string()]))?;
        Self::check(raw)
    }

    fn check(raw: RawSettings) -> Result<Self, SettingsRejected> {
        let mut problems = Vec::new();
        if raw.schema != SCHEMA {
            problems.push(format!("schema must be {SCHEMA:?}"));
        }
        if !is_owner(&raw.repository.owner) {
            problems.push("repository.owner must be a GitHub login".to_owned());
        }
        if !is_name(&raw.repository.name) {
            problems.push("repository.name must be a GitHub repository name".to_owned());
        }
        let board = raw.project_board.map(|b| (b.owner, b.number));
        if let Some((owner, number)) = &board {
            if !is_owner(owner) {
                problems.push("project_board.owner must be a GitHub login".to_owned());
            }
            if *number < 1 {
                problems
                    .push("project_board.number must be a whole number of 1 or more".to_owned());
            }
        }
        let commits = raw.commits;
        if commits.convention != "conventional-commits" {
            problems.push("commits.convention must be 'conventional-commits'".to_owned());
        }
        list(
            &mut problems,
            "commits.types",
            &commits.types,
            is_type,
            false,
        );
        list(
            &mut problems,
            "commits.scopes",
            &commits.scopes,
            is_scope_value,
            true,
        );
        let (low, high) = HEADER_LIMIT_RANGE;
        let header_max_length = usize::try_from(commits.header_max_length).unwrap_or(usize::MAX);
        if !(low..=high).contains(&header_max_length) {
            problems.push(format!(
                "commits.header_max_length must be a whole number from {low} to {high}"
            ));
        }
        let flow = raw.gitflow;
        let closing_mode = match flow.closing_mode.as_str() {
            "develop" => ClosingMode::Develop,
            "release" => ClosingMode::Release,
            _ => {
                problems.push("gitflow.closing_mode must be 'develop' or 'release'".to_owned());
                ClosingMode::Develop
            }
        };
        for (key, value) in [
            ("main_branch", &flow.main_branch),
            ("develop_branch", &flow.develop_branch),
        ] {
            if !is_slug(value) {
                problems.push(format!("gitflow.{key} must be a branch name"));
            }
        }
        if flow.main_branch == flow.develop_branch {
            problems.push("gitflow.main_branch and gitflow.develop_branch must differ".to_owned());
        }
        let p = flow.prefixes;
        let prefixes = vec![
            ("feature".to_owned(), p.feature),
            ("bugfix".to_owned(), p.bugfix),
            ("release".to_owned(), p.release),
            ("hotfix".to_owned(), p.hotfix),
            ("support".to_owned(), p.support),
        ];
        let mut seen: Vec<(&str, &str)> = Vec::new();
        for (kind, items) in &prefixes {
            list(
                &mut problems,
                &format!("gitflow.prefixes.{kind}"),
                items,
                is_prefix,
                false,
            );
            for prefix in items {
                if let Some((_, other)) = seen.iter().find(|(p, k)| *p == prefix && k != kind) {
                    problems.push(format!(
                        "gitflow.prefixes: {prefix:?} is listed for both {other} and {kind}"
                    ));
                }
                seen.push((prefix, kind));
            }
        }
        let mut additional_flows = Vec::new();
        for (index, raw_flow) in flow.additional_flows.into_iter().enumerate() {
            let where_ = format!("gitflow.additional_flows[{index}]");
            if !is_prefix(&raw_flow.head_prefix) {
                problems.push(format!("{where_}.head_prefix must look like 'name/'"));
                continue;
            }
            if seen.iter().any(|(p, _)| *p == raw_flow.head_prefix) {
                problems.push(format!(
                    "{where_}.head_prefix {:?} is already a gitflow prefix",
                    raw_flow.head_prefix
                ));
            }
            list(
                &mut problems,
                &format!("{where_}.into"),
                &raw_flow.into,
                is_flow_target,
                false,
            );
            additional_flows.push(AdditionalFlow {
                head_prefix: raw_flow.head_prefix,
                into: raw_flow.into,
            });
        }
        if !problems.is_empty() {
            return Err(SettingsRejected(problems));
        }
        Ok(Self {
            owner: raw.repository.owner,
            name: raw.repository.name,
            board,
            types: commits.types,
            scopes: commits.scopes,
            require_scope: commits.require_scope,
            header_max_length,
            closing_mode,
            main_branch: flow.main_branch,
            develop_branch: flow.develop_branch,
            prefixes,
            additional_flows,
        })
    }

    /// The prefixes of one kind of branch (`feature`, `bugfix`, `release`, `hotfix`, `support`).
    #[must_use]
    pub fn prefixes_of(&self, kind: &str) -> &[String] {
        debug_assert!(KINDS.contains(&kind));
        self.prefixes
            .iter()
            .find(|(k, _)| k == kind)
            .map_or(&[], |(_, items)| items.as_slice())
    }

    /// Whether `branch` is a release branch: a release prefix and a name after it.
    #[must_use]
    pub fn is_release_branch(&self, branch: &str) -> bool {
        self.prefixes_of("release")
            .iter()
            .any(|prefix| branch.strip_prefix(prefix.as_str()).is_some_and(is_slug))
    }

    /// The branch the factory starts from and opens its pull request against.
    ///
    /// `remote_branches` are the names of the branches the remote has, without `refs/heads/`; only
    /// the release branches among them matter, and only in the `release` mode.
    ///
    /// # Errors
    /// [`IntegrationRefusal`] in the `release` mode when no release branch is open, or more than one.
    pub fn integration_branch(
        &self,
        remote_branches: &[String],
    ) -> Result<String, IntegrationRefusal> {
        match self.closing_mode {
            ClosingMode::Develop => Ok(self.develop_branch.clone()),
            ClosingMode::Release => {
                let mut open: Vec<String> = remote_branches
                    .iter()
                    .filter(|b| self.is_release_branch(b))
                    .cloned()
                    .collect();
                open.sort();
                open.dedup();
                match open.len() {
                    0 => Err(IntegrationRefusal::NoOpenRelease),
                    1 => Ok(open.remove(0)),
                    _ => Err(IntegrationRefusal::SeveralOpenReleases(open)),
                }
            }
        }
    }

    /// The commit type for work of this kind, as the project allows it. `preferred` is tried first,
    /// then `chore`, then the first allowed type.
    #[must_use]
    pub fn commit_type(&self, preferred: &str) -> &str {
        [preferred, "chore"]
            .into_iter()
            .find_map(|wanted| self.types.iter().find(|t| *t == wanted))
            .or_else(|| self.types.first())
            .map_or("chore", String::as_str)
    }

    /// A Conventional Commits header: `type(scope): subject`, within the project's limit.
    ///
    /// The type is [`commit_type`](Self::commit_type) of `preferred`. The scope is `scope` when the
    /// project allows it; when the project requires one, its first allowed scope, or `scope`, or
    /// `factory`. The subject is put on one line, its spaces are collapsed and a final full stop is
    /// dropped; a subject that is too long is cut at a space. An empty subject becomes
    /// `update the project`.
    #[must_use]
    pub fn header(&self, preferred: &str, scope: Option<&str>, subject: &str) -> String {
        let kind = self.commit_type(preferred);
        let allowed = |s: &str| {
            is_scope_value(s) && (self.scopes.is_empty() || self.scopes.iter().any(|a| a == s))
        };
        let scope = match scope {
            Some(s) if allowed(s) => Some(s.to_owned()),
            _ if self.require_scope => self
                .scopes
                .first()
                .cloned()
                .or_else(|| scope.filter(|s| is_scope_value(s)).map(str::to_owned))
                .or_else(|| Some("factory".to_owned())),
            _ => None,
        };
        let prefix = match &scope {
            Some(s) => format!("{kind}({s}): "),
            None => format!("{kind}: "),
        };
        let mut words: Vec<&str> = subject
            .split(|c: char| c.is_whitespace() || c.is_control())
            .filter(|w| !w.is_empty())
            .collect();
        let room = self
            .header_max_length
            .saturating_sub(prefix.chars().count());
        let mut text = words.join(" ");
        while text.chars().count() > room && words.len() > 1 {
            words.pop();
            text = words.join(" ");
        }
        if text.chars().count() > room {
            text = text.chars().take(room).collect();
        }
        let text = text.trim_end_matches(['.', ' ', ',', ';', ':']).to_owned();
        let text = if text.is_empty() {
            "update the project".chars().take(room.max(1)).collect()
        } else {
            text
        };
        format!("{prefix}{text}")
    }

    /// What is wrong with a header under these settings, in the words of the project's own check.
    /// Empty when the header passes.
    #[must_use]
    pub fn check_header(&self, header: &str) -> Vec<String> {
        let mut problems = Vec::new();
        let Some((head, rest)) = header.split_once(':') else {
            return vec!["the first line must look like 'type(scope): description'".to_owned()];
        };
        let head = head.strip_suffix('!').unwrap_or(head);
        let (kind, scope) = match head.split_once('(') {
            Some((kind, scope)) => match scope.strip_suffix(')') {
                Some(scope) if !scope.contains(['(', ')']) => (kind, Some(scope)),
                _ => return vec!["the scope must be closed by ')'".to_owned()],
            },
            None => (head, None),
        };
        if !self.types.iter().any(|t| t == kind) {
            problems.push(format!("'{kind}' is not an allowed type"));
        }
        match scope {
            Some(s) if s.trim().is_empty() || s != s.trim() => {
                problems.push(
                    "the scope in parentheses must be a word with no spaces around it".to_owned(),
                );
            }
            Some(s) if !self.scopes.is_empty() && !self.scopes.iter().any(|a| a == s) => {
                problems.push(format!("'{s}' is not an allowed scope"));
            }
            None if self.require_scope => problems.push("this project requires a scope".to_owned()),
            _ => {}
        }
        match rest.strip_prefix(' ') {
            Some(subject) if subject.starts_with(' ') => {
                problems.push("put exactly one space after the colon".to_owned());
            }
            Some(subject) if subject.trim().is_empty() => {
                problems.push("the description after the colon is empty".to_owned());
            }
            Some(_) => {}
            None => problems.push("put exactly one space after the colon".to_owned()),
        }
        let length = header.chars().count();
        if length > self.header_max_length {
            problems.push(format!(
                "the first line has {length} characters; the limit is {}",
                self.header_max_length
            ));
        }
        problems
    }
}

/// The commit type for a request of this kind, as the intake classifier spells it
/// (`normalized-request.request_kind`).
#[must_use]
pub fn type_for_request(request_kind: &str) -> &'static str {
    match request_kind {
        "bugfix" => "fix",
        "documentation" => "docs",
        "refactor" => "refactor",
        "chore" => "chore",
        _ => "feat",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn document() -> Value {
        json!({
            "schema": SCHEMA,
            "repository": {"owner": "acme", "name": "widgets"},
            "project_board": {"owner": "acme", "number": 3},
            "commits": {
                "convention": "conventional-commits",
                "types": ["build", "chore", "ci", "docs", "feat", "fix", "perf", "refactor", "revert", "style", "test"],
                "scopes": [],
                "require_scope": false,
                "header_max_length": 100
            },
            "gitflow": {
                "closing_mode": "develop",
                "main_branch": "main",
                "develop_branch": "develop",
                "prefixes": {
                    "feature": ["feature/", "factory/"], "bugfix": ["bugfix/"], "release": ["release/"],
                    "hotfix": ["hotfix/"], "support": ["support/"]
                },
                "additional_flows": []
            }
        })
    }

    fn with(path: &[&str], value: Value) -> Value {
        let mut doc = document();
        let mut target = &mut doc;
        for key in &path[..path.len() - 1] {
            target = target.get_mut(*key).expect("a key of the document");
        }
        let last = path[path.len() - 1];
        if value.is_null() && last != "project_board" {
            target.as_object_mut().expect("an object").remove(last);
        } else {
            target[last] = value;
        }
        doc
    }

    fn parse(doc: &Value) -> Result<GitConventions, SettingsRejected> {
        GitConventions::parse(doc.to_string().as_bytes())
    }

    fn settings() -> GitConventions {
        parse(&document()).expect("the installer's settings")
    }

    #[test]
    fn the_installers_settings_are_read() {
        let s = settings();
        assert_eq!((s.owner.as_str(), s.name.as_str()), ("acme", "widgets"));
        assert_eq!(s.board, Some(("acme".to_owned(), 3)));
        assert_eq!(s.closing_mode, ClosingMode::Develop);
        assert_eq!(s.prefixes_of("feature"), ["feature/", "factory/"]);
        let none = parse(&with(&["project_board"], Value::Null)).expect("no board");
        assert_eq!(none.board, None);
    }

    #[test]
    fn every_mistake_is_refused_with_its_reason() {
        let cases: Vec<(Value, &str)> = vec![
            (
                with(&["schema"], json!("factory-repository-settings/2")),
                "schema must be",
            ),
            (with(&["extra"], json!(1)), "unknown field"),
            (with(&["gitflow", "extra"], json!(1)), "unknown field"),
            (
                with(&["repository", "owner"], json!("-acme")),
                "repository.owner",
            ),
            (
                with(&["repository", "name"], json!("..")),
                "repository.name",
            ),
            (
                with(&["project_board", "number"], json!(0)),
                "project_board.number",
            ),
            (
                with(&["project_board", "number"], json!(true)),
                "invalid type",
            ),
            (
                with(&["commits", "types"], json!([])),
                "commits.types must not be empty",
            ),
            (
                with(&["commits", "types"], json!(["Feat"])),
                "commits.types has a value",
            ),
            (
                with(&["commits", "types"], json!(["feat", "feat"])),
                "lists a value twice",
            ),
            (
                with(&["commits", "header_max_length"], json!(19)),
                "header_max_length",
            ),
            (
                with(&["commits", "header_max_length"], json!(201)),
                "header_max_length",
            ),
            (
                with(&["commits", "header_max_length"], json!(100.0)),
                "invalid type",
            ),
            (
                with(&["commits", "convention"], Value::Null),
                "missing field",
            ),
            (
                with(&["gitflow", "closing_mode"], json!("main")),
                "closing_mode",
            ),
            (
                with(&["gitflow", "develop_branch"], json!("main")),
                "must differ",
            ),
            (
                with(&["gitflow", "prefixes", "bugfix"], json!(["feature/"])),
                "listed for both feature and bugfix",
            ),
            (
                with(&["gitflow", "prefixes", "hotfix"], json!(["hotfix"])),
                "gitflow.prefixes.hotfix has a value",
            ),
            (
                with(
                    &["gitflow", "additional_flows"],
                    json!([{"head_prefix": "feature/", "into": ["develop"]}]),
                ),
                "already a gitflow",
            ),
            (
                with(
                    &["gitflow", "additional_flows"],
                    json!([{"head_prefix": "deps/", "into": []}]),
                ),
                "into must not be empty",
            ),
            (json!([]), "missing the key 'project_board'"),
        ];
        for (doc, words) in cases {
            let problems = parse(&doc).expect_err(words).0.join("; ");
            assert!(problems.contains(words), "{words}: {problems}");
        }
        let missing = document().as_object().map(|o| {
            let mut o = o.clone();
            o.remove("project_board");
            Value::Object(o)
        });
        assert!(parse(&missing.expect("an object")).is_err());
        assert!(GitConventions::parse(b"{").is_err());
    }

    #[test]
    fn the_header_limit_bounds_are_inclusive() {
        for (value, valid) in [(19, false), (20, true), (200, true), (201, false)] {
            let doc = with(&["commits", "header_max_length"], json!(value));
            assert_eq!(parse(&doc).is_ok(), valid, "{value}");
        }
    }

    #[test]
    fn develop_mode_always_works_from_develop() {
        assert_eq!(
            settings().integration_branch(&["release/1.0".to_owned()]),
            Ok("develop".to_owned())
        );
    }

    #[test]
    fn release_mode_needs_exactly_one_open_release_branch() {
        let s = parse(&with(&["gitflow", "closing_mode"], json!("release"))).expect("release mode");
        let names = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            s.integration_branch(&names(&["main", "develop"])),
            Err(IntegrationRefusal::NoOpenRelease)
        );
        assert_eq!(
            s.integration_branch(&names(&["main", "develop", "release/1.2.0", "feature/x"])),
            Ok("release/1.2.0".to_owned())
        );
        assert_eq!(
            s.integration_branch(&names(&["release/1.3.0", "release/1.2.0", "release/1.2.0"])),
            Err(IntegrationRefusal::SeveralOpenReleases(names(&[
                "release/1.2.0",
                "release/1.3.0"
            ])))
        );
        // A bare prefix or a broken name is not a release branch.
        assert_eq!(
            s.integration_branch(&names(&["release/", "release//x", "releases/1"])),
            Err(IntegrationRefusal::NoOpenRelease)
        );
    }

    #[test]
    fn the_type_falls_back_to_chore_then_to_the_first_allowed() {
        let s = settings();
        assert_eq!(s.commit_type("feat"), "feat");
        assert_eq!(s.commit_type("unknown"), "chore");
        let narrow =
            parse(&with(&["commits", "types"], json!(["fix", "docs"]))).expect("two types");
        assert_eq!(narrow.commit_type("feat"), "fix");
        assert_eq!(narrow.commit_type("docs"), "docs");
    }

    #[test]
    fn headers_pass_the_projects_own_check() {
        let s = settings();
        assert_eq!(
            s.header("feat", None, "Count words in standard input."),
            "feat: Count words in standard input"
        );
        assert_eq!(
            s.header("docs", Some("spec"), "write\nthe   spec"),
            "docs(spec): write the spec"
        );
        assert_eq!(s.header("feat", None, "  \n "), "feat: update the project");
        let scoped =
            parse(&with(&["commits", "require_scope"], json!(true))).expect("scope required");
        assert_eq!(scoped.header("feat", None, "x"), "feat(factory): x");
        let listed = parse(&with(&["commits", "scopes"], json!(["api", "cli"]))).expect("scopes");
        assert_eq!(listed.header("feat", Some("spec"), "x"), "feat: x");
        let mut both = listed.clone();
        both.require_scope = true;
        assert_eq!(both.header("feat", Some("spec"), "x"), "feat(api): x");
        for config in [&s, &scoped, &listed, &both] {
            for subject in [
                "a",
                "Add a --json flag that prints the counts as one line",
                &"word ".repeat(80),
                &"x".repeat(300),
                "trailing.",
                "\u{7}bell",
            ] {
                for (kind, scope) in [
                    ("feat", None),
                    ("docs", Some("spec")),
                    ("fix", Some("Not A Scope")),
                ] {
                    let header = config.header(kind, scope, subject);
                    assert_eq!(
                        config.check_header(&header),
                        Vec::<String>::new(),
                        "{header}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_cut_is_at_a_space_and_the_length_is_the_limit_or_less() {
        let doc = with(&["commits", "header_max_length"], json!(20));
        let s = parse(&doc).expect("limit 20");
        let header = s.header("feat", None, "one two three four five");
        assert_eq!(header, "feat: one two three");
        assert!(header.chars().count() <= 20);
        let exact = s.header("feat", None, "abcdefghijklmn");
        assert_eq!(exact.chars().count(), 20);
        assert_eq!(s.check_header(&exact), Vec::<String>::new());
        assert_eq!(s.check_header(&format!("{exact}x")).len(), 1);
    }

    #[test]
    fn the_check_names_what_is_wrong() {
        let s = settings();
        for (header, words) in [
            ("add the parser", "must look like"),
            ("feature: x", "not an allowed type"),
            ("feat:x", "exactly one space"),
            ("feat:  x", "exactly one space"),
            ("feat: ", "empty"),
            ("feat(): x", "scope in parentheses"),
        ] {
            let problems = s.check_header(header).join("; ");
            assert!(problems.contains(words), "{header}: {problems}");
        }
        assert_eq!(s.check_header("feat(api)!: drop v1"), Vec::<String>::new());
    }

    #[test]
    fn request_kinds_map_to_types() {
        for (kind, expected) in [
            ("feature", "feat"),
            ("bugfix", "fix"),
            ("documentation", "docs"),
            ("refactor", "refactor"),
            ("chore", "chore"),
            ("unclear", "feat"),
        ] {
            assert_eq!(type_for_request(kind), expected);
        }
    }
}
