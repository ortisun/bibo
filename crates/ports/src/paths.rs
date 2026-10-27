//! Names for places in a repository: paths, globs, branches and the repository itself.
//!
//! These are checked values. Holding one is proof that it has a safe shape, so a port method that
//! takes a `RepoPath` never has to wonder whether it contains `..` or starts at the filesystem
//! root. Nothing here touches the filesystem: the checks read the text only.

use std::fmt;

use factory_domain::values::{GitSha, Slug};

/// A git commit id: 40 or 64 lowercase hex characters.
pub type CommitSha = GitSha;

/// Why a path, glob, branch or repository name was refused. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// The text is empty.
    #[error("the name is empty")]
    Empty,
    /// The text is longer than the limit for its kind.
    #[error("the name is longer than {limit} bytes")]
    TooLong {
        /// The limit for this kind of name.
        limit: usize,
    },
    /// A path starts at the filesystem root.
    #[error("the path is absolute; give a path relative to the repository root")]
    Absolute,
    /// A backslash appears; paths use `/` only.
    #[error("the name contains a backslash; paths use `/` only")]
    Backslash,
    /// A control character (including NUL and newline) appears.
    #[error("the name contains a control character")]
    ControlCharacter,
    /// Two `/` in a row, or a `/` at the end.
    #[error("the name has an empty component (a doubled or trailing `/`)")]
    EmptyComponent,
    /// A `.` component.
    #[error("the name has a `.` component")]
    DotComponent,
    /// A `..` component, which could leave the repository.
    #[error("the name has a `..` component, which could leave the repository")]
    ParentComponent,
    /// A `.git` component in any letter case. Git stores its own data there and never tracks it.
    #[error("the path names a `.git` directory, which is never part of the tracked tree")]
    GitDirectory,
    /// A character that git forbids in a branch name.
    #[error("the branch name has a character or sequence that git forbids")]
    BadBranchCharacter,
    /// A repository name that is not `owner/name`.
    #[error("a repository is written `owner/name` with letters, digits, `_`, `.` and `-`")]
    BadRepository,
}

const PATH_LIMIT: usize = 4096;
const GLOB_LIMIT: usize = 1024;
const BRANCH_LIMIT: usize = 200;

fn check_text(text: &str, limit: usize) -> Result<(), NameError> {
    if text.is_empty() {
        return Err(NameError::Empty);
    }
    if text.len() > limit {
        return Err(NameError::TooLong { limit });
    }
    if text.starts_with('/') {
        return Err(NameError::Absolute);
    }
    if text.contains('\\') {
        return Err(NameError::Backslash);
    }
    if text.chars().any(char::is_control) {
        return Err(NameError::ControlCharacter);
    }
    Ok(())
}

/// A path relative to the repository root, written with `/`.
///
/// It is never empty, never absolute, and has no `.`, `..`, empty or `.git` component, so joining
/// it to a directory cannot leave that directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoPath(String);

impl RepoPath {
    /// Checks `text` and wraps it.
    ///
    /// # Errors
    /// Returns the [`NameError`] for the first rule the text breaks.
    pub fn new(text: &str) -> Result<Self, NameError> {
        check_text(text, PATH_LIMIT)?;
        for component in text.split('/') {
            match component {
                "" => return Err(NameError::EmptyComponent),
                "." => return Err(NameError::DotComponent),
                ".." => return Err(NameError::ParentComponent),
                other if other.eq_ignore_ascii_case(".git") => {
                    return Err(NameError::GitDirectory);
                }
                _ => {}
            }
        }
        Ok(Self(text.to_owned()))
    }

    /// The path as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The components, in order.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// True when `self` is `ancestor` or lies below it.
    #[must_use]
    pub fn is_within(&self, ancestor: &RepoPath) -> bool {
        self.0 == ancestor.0
            || self
                .0
                .strip_prefix(ancestor.0.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pattern that selects repository paths.
///
/// The syntax is deliberately small so every adapter can match it the same way:
///
/// * `?` matches one character other than `/`.
/// * `*` matches any run of characters other than `/`.
/// * `**` as a whole component matches zero or more whole components.
/// * Everything else matches itself. A pattern matches a whole path, not a part of it.
///
/// A glob has the same safety rules as a [`RepoPath`] (relative, no `..`), so a pattern cannot
/// name a place outside the repository.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoGlob(String);

impl RepoGlob {
    /// Checks `text` and wraps it.
    ///
    /// # Errors
    /// Returns the [`NameError`] for the first rule the text breaks.
    pub fn new(text: &str) -> Result<Self, NameError> {
        check_text(text, GLOB_LIMIT)?;
        for component in text.split('/') {
            match component {
                "" => return Err(NameError::EmptyComponent),
                "." => return Err(NameError::DotComponent),
                ".." => return Err(NameError::ParentComponent),
                _ => {}
            }
        }
        Ok(Self(text.to_owned()))
    }

    /// The pattern as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when the whole of `path` matches the pattern.
    #[must_use]
    pub fn matches(&self, path: &RepoPath) -> bool {
        let pattern: Vec<&str> = self.0.split('/').collect();
        let parts: Vec<&str> = path.components().collect();
        match_components(&pattern, &parts)
    }
}

impl fmt::Display for RepoGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn match_components(pattern: &[&str], parts: &[&str]) -> bool {
    match pattern.split_first() {
        None => parts.is_empty(),
        Some((&"**", rest)) => (0..=parts.len()).any(|skip| match_components(rest, &parts[skip..])),
        Some((head, rest)) => parts.split_first().is_some_and(|(part, others)| {
            match_segment(head, part) && match_components(rest, others)
        }),
    }
}

fn match_segment(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    match_chars(&pattern, &text)
}

fn match_chars(pattern: &[char], text: &[char]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some(('*', rest)) => (0..=text.len()).any(|skip| match_chars(rest, &text[skip..])),
        Some(('?', rest)) => text
            .split_first()
            .is_some_and(|(_, others)| match_chars(rest, others)),
        Some((literal, rest)) => text
            .split_first()
            .is_some_and(|(c, others)| c == literal && match_chars(rest, others)),
    }
}

/// The name of a git branch, for example `factory/job-42`.
///
/// Follows the rules of `git check-ref-format` that matter here: no `..`, no space, no control
/// character, none of `~ ^ : ? * [ \`, no `@{`, no doubled, leading or trailing `/`, no component
/// that starts with `.` or ends with `.lock`, no trailing `.`, and not the single character `@`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BranchName(String);

/// The prefix of every branch the factory may push to. The factory never pushes anywhere else.
pub const FACTORY_BRANCH_PREFIX: &str = "factory/";

impl BranchName {
    /// Checks `text` and wraps it.
    ///
    /// # Errors
    /// Returns the [`NameError`] for the first rule the text breaks.
    pub fn new(text: &str) -> Result<Self, NameError> {
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        if text.len() > BRANCH_LIMIT {
            return Err(NameError::TooLong {
                limit: BRANCH_LIMIT,
            });
        }
        if text.chars().any(char::is_control) {
            return Err(NameError::ControlCharacter);
        }
        let forbidden = [' ', '~', '^', ':', '?', '*', '[', '\\'];
        if text.chars().any(|c| forbidden.contains(&c))
            || text.contains("..")
            || text.contains("@{")
            || text == "@"
            || text.ends_with('.')
        {
            return Err(NameError::BadBranchCharacter);
        }
        for component in text.split('/') {
            if component.is_empty() {
                return Err(NameError::EmptyComponent);
            }
            if component.starts_with('.') || component.ends_with(".lock") {
                return Err(NameError::BadBranchCharacter);
            }
        }
        Ok(Self(text.to_owned()))
    }

    /// The branch name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when the branch is under `factory/`, the only place the factory may push.
    #[must_use]
    pub fn is_factory_branch(&self) -> bool {
        self.0.starts_with(FACTORY_BRANCH_PREFIX) && self.0.len() > FACTORY_BRANCH_PREFIX.len()
    }
}

impl fmt::Display for BranchName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A repository on the code host, written `owner/name`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoRef {
    owner: String,
    name: String,
}

impl RepoRef {
    /// Reads `owner/name`.
    ///
    /// # Errors
    /// Returns [`NameError::BadRepository`] unless the text is two non-empty parts joined by one
    /// `/`, each made of letters, digits, `_`, `.` and `-`, and neither is `.` or `..`.
    pub fn parse(full_name: &str) -> Result<Self, NameError> {
        let valid = |part: &str| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        };
        match full_name.split_once('/') {
            Some((owner, name)) if valid(owner) && valid(name) => Ok(Self {
                owner: owner.to_owned(),
                name: name.to_owned(),
            }),
            _ => Err(NameError::BadRepository),
        }
    }

    /// The owner (user or organization).
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The repository name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for RepoRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

/// One thing a scan found. It names the rule and the place. It **never** holds the matched text,
/// because a finding is stored and logged and must not become a second copy of a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule that matched, for example `github-token`.
    pub rule: Slug,
    /// The file, when the finding is in a file.
    pub path: Option<RepoPath>,
    /// The line, counted from 1, when known.
    pub line: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_relative_paths_are_accepted() {
        for text in [
            "README.md",
            "src/lib.rs",
            "a/b/c.txt",
            ".github/workflows/ci.yml",
        ] {
            assert!(RepoPath::new(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn each_unsafe_path_shape_is_refused_for_its_own_reason() {
        let cases = [
            ("", NameError::Empty),
            ("/etc/passwd", NameError::Absolute),
            ("a\\b", NameError::Backslash),
            ("a\0b", NameError::ControlCharacter),
            ("a\nb", NameError::ControlCharacter),
            ("a//b", NameError::EmptyComponent),
            ("a/b/", NameError::EmptyComponent),
            ("./a", NameError::DotComponent),
            ("a/./b", NameError::DotComponent),
            ("../a", NameError::ParentComponent),
            ("a/../../b", NameError::ParentComponent),
            (".git/config", NameError::GitDirectory),
            ("sub/.GIT/hooks/post-commit", NameError::GitDirectory),
        ];
        for (text, expected) in cases {
            assert_eq!(RepoPath::new(text), Err(expected), "{text:?}");
        }
    }

    #[test]
    fn a_dot_git_prefix_in_a_longer_name_is_not_a_git_directory() {
        assert!(RepoPath::new(".gitignore").is_ok());
        assert!(RepoPath::new("a/.github/x").is_ok());
        assert!(RepoPath::new("a/.gitattributes").is_ok());
    }

    #[test]
    fn a_path_longer_than_the_limit_is_refused() {
        let long = "a/".repeat(3000) + "b";
        assert_eq!(
            RepoPath::new(&long),
            Err(NameError::TooLong { limit: 4096 })
        );
    }

    #[test]
    fn is_within_matches_whole_components_only() {
        let dir = RepoPath::new("src/app").unwrap();
        assert!(RepoPath::new("src/app").unwrap().is_within(&dir));
        assert!(RepoPath::new("src/app/main.rs").unwrap().is_within(&dir));
        assert!(!RepoPath::new("src/application.rs").unwrap().is_within(&dir));
        assert!(!RepoPath::new("src").unwrap().is_within(&dir));
    }

    fn glob(pattern: &str, path: &str) -> bool {
        RepoGlob::new(pattern)
            .unwrap()
            .matches(&RepoPath::new(path).unwrap())
    }

    #[test]
    fn a_literal_glob_matches_only_that_path() {
        assert!(glob("src/lib.rs", "src/lib.rs"));
        assert!(!glob("src/lib.rs", "src/lib.rs.bak"));
        assert!(!glob("src/lib.rs", "x/src/lib.rs"));
    }

    #[test]
    fn a_star_does_not_cross_a_slash() {
        assert!(glob("src/*.rs", "src/lib.rs"));
        assert!(!glob("src/*.rs", "src/deep/lib.rs"));
        assert!(glob("*.md", "README.md"));
        assert!(!glob("*.md", "docs/README.md"));
    }

    #[test]
    fn a_question_mark_matches_one_character() {
        assert!(glob("a?c", "abc"));
        assert!(!glob("a?c", "ac"));
        assert!(!glob("a?c", "abbc"));
    }

    #[test]
    fn a_double_star_component_matches_any_depth_including_none() {
        assert!(glob("**/*.rs", "lib.rs"));
        assert!(glob("**/*.rs", "src/lib.rs"));
        assert!(glob("**/*.rs", "src/a/b/lib.rs"));
        assert!(glob("docs/**", "docs"));
        assert!(glob("docs/**", "docs/a/b.md"));
        assert!(!glob("docs/**", "other/a.md"));
        assert!(glob("a/**/z", "a/z"));
        assert!(glob("a/**/z", "a/b/c/z"));
    }

    #[test]
    fn a_glob_with_a_parent_component_or_an_absolute_start_is_refused() {
        assert_eq!(RepoGlob::new("../x"), Err(NameError::ParentComponent));
        assert_eq!(RepoGlob::new("/x"), Err(NameError::Absolute));
        assert_eq!(RepoGlob::new(""), Err(NameError::Empty));
        assert_eq!(RepoGlob::new("a//b"), Err(NameError::EmptyComponent));
    }

    #[test]
    fn branch_names_follow_git_ref_rules() {
        for good in ["main", "factory/job-42", "feature/a.b", "a/b/c"] {
            assert!(BranchName::new(good).is_ok(), "{good}");
        }
        let bad = [
            "",
            "a b",
            "a..b",
            "a~1",
            "a^",
            "a:b",
            "a?",
            "a*",
            "a[",
            "a\\b",
            "@",
            "a@{b",
            "/a",
            "a/",
            "a//b",
            "a.",
            ".hidden",
            "a/.hidden",
            "a.lock",
            "x/y.lock",
        ];
        for text in bad {
            assert!(BranchName::new(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn only_branches_under_factory_slash_are_factory_branches() {
        assert!(
            BranchName::new("factory/job-1")
                .unwrap()
                .is_factory_branch()
        );
        assert!(!BranchName::new("main").unwrap().is_factory_branch());
        assert!(!BranchName::new("factory").unwrap().is_factory_branch());
        assert!(
            !BranchName::new("factory-evil/x")
                .unwrap()
                .is_factory_branch()
        );
        assert!(
            !BranchName::new("feature/factory/x")
                .unwrap()
                .is_factory_branch()
        );
    }

    #[test]
    fn repositories_are_owner_slash_name() {
        let repo = RepoRef::parse("example-org/word-count").unwrap();
        assert_eq!(repo.owner(), "example-org");
        assert_eq!(repo.name(), "word-count");
        assert_eq!(repo.to_string(), "example-org/word-count");
        for bad in [
            "", "a", "a/", "/b", "a/b/c", "a b/c", "../x", "a/..", "a/b c",
        ] {
            assert_eq!(
                RepoRef::parse(bad),
                Err(NameError::BadRepository),
                "{bad:?}"
            );
        }
    }
}
