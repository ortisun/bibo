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
    /// A character that changes how the name reads without showing: a bidirectional control, a
    /// zero width or other format character (Unicode category Cf), a line or paragraph separator
    /// (Zl, Zp), a tag character, or a filler that renders as nothing.
    #[error("the name contains a character that hides or reorders text")]
    HiddenCharacter,
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

/// True for a character that changes how a name reads without showing: the whole Unicode
/// category Cf (format characters: the bidirectional controls U+202A to U+202E and U+2066 to
/// U+2069, the zero width characters U+200B to U+200F and U+2060, the byte order mark U+FEFF, the
/// soft hyphen, the Arabic number signs, the interlinear annotation marks and the others), the
/// line and paragraph separators U+2028 and U+2029 (categories Zl and Zp), the tag block and the
/// variation selector supplement (U+E0000 to U+E0FFF: tag characters can carry a hidden message),
/// and the fillers that render as nothing and are not format characters (the combining grapheme
/// joiner, the Hangul fillers, the Khmer inherent vowels).
///
/// The standard library has no category lookup, so the Cf ranges are listed, from Unicode 16, as
/// the sandbox's audit of a checkout lists them (`workspace/audit.rs`, `hides_text`): a path the
/// audit refuses is a path no other text can name either. Letters, digits, marks, punctuation,
/// symbols, emoji and the variation selectors U+FE00 to U+FE0F, which emoji and CJK ideographs
/// need, are not here: a name in any script passes. Two legitimate uses are refused with the rest
/// of the category: the zero width non-joiner of Persian and the zero width joiner of emoji
/// sequences and of some Indic scripts. A person renames such a file, which is the safe side.
#[must_use]
pub fn hides_text(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

const PATH_LIMIT: usize = 4096;
const GLOB_LIMIT: usize = 1024;
const BRANCH_LIMIT: usize = 200;

/// The checks every path and glob passes: the shape of the text, then that no character hides
/// or reorders it.
fn check_text(text: &str, limit: usize) -> Result<(), NameError> {
    check_shape(text, limit)?;
    check_visible(text)
}

/// That no character of the text hides or reorders it ([`hides_text`]).
fn check_visible(text: &str) -> Result<(), NameError> {
    if text.chars().any(hides_text) {
        return Err(NameError::HiddenCharacter);
    }
    Ok(())
}

fn check_shape(text: &str, limit: usize) -> Result<(), NameError> {
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
        check_shape(text, PATH_LIMIT)?;
        for component in text.split('/') {
            match component {
                "" => return Err(NameError::EmptyComponent),
                "." => return Err(NameError::DotComponent),
                ".." => return Err(NameError::ParentComponent),
                other if is_git_directory_alias(other) => {
                    return Err(NameError::GitDirectory);
                }
                _ => {}
            }
        }
        // After the components, so that `.g\u{200c}it` is named as the git directory it is.
        check_visible(text)?;
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

    /// True when the whole of `path` matches, after both are folded the way the policy says:
    /// Unicode NFC, then case folding. `matches` (exact, case-sensitive) stays for tests.
    ///
    /// The policy (`protected_paths.normalization`) says `.GitHub/Workflows` must not dodge
    /// `.github/**` on a case-insensitive file system, and that a decomposed spelling of a name is
    /// the same name.
    #[must_use]
    pub fn matches_folded(&self, path: &RepoPath) -> bool {
        let pattern = fold(&self.0);
        let path = fold(path.as_str());
        let pattern: Vec<&str> = pattern.split('/').collect();
        let parts: Vec<&str> = path.split('/').collect();
        match_components(&pattern, &parts)
    }
}

/// Unicode NFC, then lower case, then NFC again (lower-casing can leave a sequence that
/// composes). `*`, `?` and `/` are unaffected, so a folded glob keeps its shape.
fn fold(text: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let composed: String = text.nfc().collect();
    let lowered: String = composed.chars().flat_map(char::to_lowercase).collect();
    lowered.nfc().collect()
}

/// The characters git's own HFS and NTFS protections ignore inside a name: U+200C to U+200F,
/// U+202A to U+202E, U+206A to U+206F and U+FEFF.
fn is_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}'
    )
}

/// The check `RepoPath::new` makes for the `.git` component, replacing the ASCII-only
/// comparison. A component is an alias of the git directory when, after removing the characters
/// git's own HFS and NTFS protections ignore (U+200C to U+200F, U+202A to U+202E, U+206A to
/// U+206F, U+FEFF), trimming trailing dots and spaces, applying NFC and folding case, it equals
/// `.git`, or it equals the short name `git~1` followed by nothing or by digits.
#[must_use]
pub fn is_git_directory_alias(component: &str) -> bool {
    let visible: String = component.chars().filter(|c| !is_ignorable(*c)).collect();
    let trimmed = visible.trim_end_matches(['.', ' ']);
    let folded = fold(trimmed);
    if folded == ".git" {
        return true;
    }
    folded
        .strip_prefix("git~1")
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
}

/// What the policy does with a path (`policies/security.yaml`, section `protected_paths`). When
/// several rules match one path, the most restrictive wins, in this order: `Hidden`,
/// `DenyWrite`, `AppendOnly`, `AdditionsOnly`, `Sensitive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathMode {
    /// Not in the checkout at all, and not readable.
    Hidden,
    /// Any add, modify, delete, rename or mode change is refused.
    DenyWrite,
    /// New files are allowed; modifying, deleting or renaming an existing file is refused.
    AppendOnly,
    /// New files are allowed; an existing file may only gain lines. Deleting or renaming it is
    /// refused.
    AdditionsOnly,
    /// The change is allowed and is reported for the semantic checks and extra review.
    Sensitive,
}

/// One rule of a [`PathRules`] list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRule {
    /// Paths that match the glob get the mode.
    Mode {
        /// The pattern.
        glob: RepoGlob,
        /// What the policy does with a matching path.
        mode: PathMode,
    },
    /// A policy entry written with a leading `!`: a path that matches the glob is taken out of
    /// the matching rules *of the same group*.
    Reinclude {
        /// The pattern, without the `!`.
        glob: RepoGlob,
        /// The group the re-inclusion belongs to (the policy group id), so that it cannot lift
        /// a protection from another group.
        group: String,
    },
}

/// The ordered path rules for a job, built from the central policy and the project's
/// tighten-only overrides. This is the **only** place that decides what a path is: every adapter
/// and every fake calls [`PathRules::classify`], and none matches globs by itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathRules {
    rules: Vec<(String, PathRule)>,
}

impl PathRules {
    /// Builds the rules from `(group id, rule)` pairs in policy order.
    #[must_use]
    pub fn new(rules: Vec<(String, PathRule)>) -> Self {
        Self { rules }
    }

    /// The mode that applies to `path`, or `None` for a free path. The path is folded the way
    /// the policy says (Unicode NFC, then case-insensitive) before any glob is tried. A
    /// `Reinclude` is applied after all the `Mode` rules, and lifts only the matches that come
    /// from its own group (the policy loader applies a leading `!` last).
    #[must_use]
    pub fn classify(&self, path: &RepoPath) -> Option<PathMode> {
        let mut matched: Vec<(&str, PathMode)> = Vec::new();
        for (group, rule) in &self.rules {
            if let PathRule::Mode { glob, mode } = rule
                && glob.matches_folded(path)
            {
                matched.push((group.as_str(), *mode));
            }
        }
        for (_, rule) in &self.rules {
            if let PathRule::Reinclude { glob, group } = rule
                && glob.matches_folded(path)
            {
                matched.retain(|(matched_group, _)| *matched_group != group.as_str());
            }
        }
        matched.into_iter().map(|(_, mode)| mode).min()
    }

    /// The rules, for adapters that must show them in a report.
    #[must_use]
    pub fn rules(&self) -> &[(String, PathRule)] {
        &self.rules
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
        if text.chars().any(hides_text) {
            return Err(NameError::HiddenCharacter);
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

    /// True when both name the same repository. GitHub owner and repository names are not case
    /// sensitive, so `Octo/Hello` and `octo/hello` are one repository. The derived equality of
    /// this type is exact and keeps the case that was registered, for display; every place that
    /// asks whether two names are the same repository uses this one (finding STS-8).
    #[must_use]
    pub fn same_repository(&self, other: &Self) -> bool {
        self.owner.eq_ignore_ascii_case(&other.owner) && self.name.eq_ignore_ascii_case(&other.name)
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
    fn two_spellings_of_one_repository_are_the_same_repository_and_keep_their_case() {
        let registered = RepoRef::parse("octo/Hello-World").unwrap();
        let shouted = RepoRef::parse("OCTO/hello-world").unwrap();
        assert!(registered.same_repository(&shouted));
        assert!(shouted.same_repository(&registered));
        assert_ne!(registered, shouted, "the exact equality keeps the case");
        assert_eq!(
            registered.to_string(),
            "octo/Hello-World",
            "and so does the display"
        );
        for other in ["octo/Hello", "octo2/Hello-World", "oct/oHello-World"] {
            assert!(
                !registered.same_repository(&RepoRef::parse(other).unwrap()),
                "{other}"
            );
        }
    }

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

    /// The names that reorder or hide text, in every constructor that takes a path, a glob or a
    /// branch (SBX-2). The same list the sandbox's audit refuses in a checkout.
    const HOSTILE: [&str; 12] = [
        "gpj.\u{202E}rs",
        "a\u{2028}b.rs",
        "a\u{2029}b.rs",
        "a\u{200B}b.rs",
        "a\u{200D}b.rs",
        "a\u{FEFF}b.rs",
        "a\u{2066}b.rs",
        "a\u{E0041}b.rs",
        "a\u{3164}b.rs",
        "a\u{00AD}b.rs",
        "a\u{061C}b.rs",
        "a\u{2060}b.rs",
    ];

    #[test]
    fn a_name_that_hides_or_reorders_text_is_refused_by_every_constructor() {
        for name in HOSTILE {
            assert_eq!(
                RepoPath::new(&format!("src/{name}")),
                Err(NameError::HiddenCharacter),
                "path {name:?}"
            );
            assert_eq!(
                RepoPath::new(name),
                Err(NameError::HiddenCharacter),
                "path {name:?}"
            );
            assert_eq!(
                RepoGlob::new(&format!("src/{name}")),
                Err(NameError::HiddenCharacter),
                "glob {name:?}"
            );
            assert_eq!(
                BranchName::new(&format!("factory/{name}")),
                Err(NameError::HiddenCharacter),
                "branch {name:?}"
            );
        }
    }

    #[test]
    fn a_name_in_any_script_is_still_valid() {
        for name in [
            "caf\u{e9}.rs",
            "\u{65e5}\u{672c}\u{8a9e}.md",
            "\u{444}\u{430}\u{439}\u{43b}.txt",
            "smile\u{1F600}.png",
            "\u{1F468}\u{1F3FD}.png",
            "e\u{0301}.rs",
            "emoji\u{2764}\u{FE0F}.png",
            "\u{0915}\u{094D}\u{0937}.txt",
        ] {
            assert!(RepoPath::new(&format!("src/{name}")).is_ok(), "{name:?}");
            assert!(RepoGlob::new(&format!("src/{name}")).is_ok(), "{name:?}");
            assert!(
                BranchName::new(&format!("factory/{name}")).is_ok(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn the_rule_is_the_one_the_sandbox_audit_applies_to_a_checkout() {
        // Letters, digits, marks, punctuation and symbols are not hidden; the format characters,
        // the separators and the tags are.
        for c in [
            'a',
            'Z',
            '0',
            '-',
            '_',
            '.',
            ' ',
            '\u{e9}',
            '\u{FE0F}',
            '\u{1F600}',
        ] {
            assert!(!hides_text(c), "{c:?}");
        }
        for c in ['\u{200B}', '\u{202E}', '\u{2028}', '\u{FEFF}', '\u{E0041}'] {
            assert!(hides_text(c), "{c:?}");
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

    // ---- ports-v1.1: git directory aliases, folded matching and the path rules -------------------

    #[test]
    fn the_git_directory_is_refused_in_every_spelling_git_itself_protects() {
        for text in [
            ".git",
            ".GIT/config",
            "a/.Git/hooks",
            ".git./x",
            ".git /x",
            "a/.git.../x",
            ".g\u{200c}it/config",
            ".\u{200e}git/config",
            ".\u{feff}git",
            ".gi\u{202a}t",
            "git~1/config",
            "GIT~1",
            "x/git~12/y",
        ] {
            assert_eq!(
                RepoPath::new(text),
                Err(NameError::GitDirectory),
                "{text:?} must be refused"
            );
        }
    }

    #[test]
    fn names_that_only_look_like_the_git_directory_are_allowed() {
        for text in [
            ".gitignore",
            ".github/x",
            "git~1x/y",
            "git~a",
            "my.git/x",
            "git/x",
            "gitx",
        ] {
            assert!(RepoPath::new(text).is_ok(), "{text:?}");
        }
    }

    #[test]
    fn the_alias_check_works_on_one_component() {
        assert!(is_git_directory_alias(".git"));
        assert!(is_git_directory_alias(".GiT"));
        assert!(is_git_directory_alias("git~1"));
        assert!(!is_git_directory_alias(".gitmodules"));
        assert!(!is_git_directory_alias(""));
    }

    fn folded(pattern: &str, path: &str) -> bool {
        RepoGlob::new(pattern)
            .unwrap()
            .matches_folded(&RepoPath::new(path).unwrap())
    }

    #[test]
    fn folded_matching_ignores_letter_case() {
        assert!(folded(".github/**", ".GitHub/Workflows/ci.yml"));
        assert!(folded("Dockerfile", "dockerfile"));
        assert!(
            !glob(".github/**", ".GitHub/Workflows/ci.yml"),
            "exact matching stays exact"
        );
    }

    #[test]
    fn folded_matching_ignores_the_unicode_normalization_form() {
        // "é" as one character and as "e" plus a combining accent are the same name once folded.
        let composed = "docs/caf\u{e9}.md";
        let decomposed = "docs/cafe\u{301}.md";
        assert!(folded(composed, decomposed));
        assert!(folded(decomposed, composed));
        assert!(!glob(composed, decomposed), "exact matching stays exact");
    }

    #[test]
    fn folded_matching_keeps_the_wildcard_rules() {
        assert!(folded("src/*.RS", "src/Lib.rs"));
        assert!(!folded("src/*.rs", "src/deep/lib.rs"));
        assert!(folded("**/Cargo.TOML", "a/b/cargo.toml"));
    }

    fn rules(list: &[(&str, PathRule)]) -> PathRules {
        PathRules::new(
            list.iter()
                .map(|(g, r)| ((*g).to_owned(), r.clone()))
                .collect(),
        )
    }

    fn mode(glob: &str, mode: PathMode) -> PathRule {
        PathRule::Mode {
            glob: RepoGlob::new(glob).unwrap(),
            mode,
        }
    }

    fn reinclude(glob: &str, group: &str) -> PathRule {
        PathRule::Reinclude {
            glob: RepoGlob::new(glob).unwrap(),
            group: group.to_owned(),
        }
    }

    fn classify(rules: &PathRules, path: &str) -> Option<PathMode> {
        rules.classify(&RepoPath::new(path).unwrap())
    }

    #[test]
    fn a_free_path_has_no_mode_and_a_protected_path_has_its_mode() {
        let rules = rules(&[
            ("ci", mode(".github/**", PathMode::DenyWrite)),
            ("fixtures", mode("tests/golden/**", PathMode::AppendOnly)),
        ]);
        assert_eq!(classify(&rules, "src/lib.rs"), None);
        assert_eq!(
            classify(&rules, ".github/workflows/ci.yml"),
            Some(PathMode::DenyWrite)
        );
        assert_eq!(
            classify(&rules, "tests/golden/a.txt"),
            Some(PathMode::AppendOnly)
        );
    }

    #[test]
    fn a_case_variant_of_a_protected_path_is_protected() {
        let rules = rules(&[("ci", mode(".github/**", PathMode::DenyWrite))]);
        assert_eq!(
            classify(&rules, ".GitHub/Workflows/ci.yml"),
            Some(PathMode::DenyWrite)
        );
        assert_eq!(classify(&rules, ".GITHUB/x"), Some(PathMode::DenyWrite));
    }

    #[test]
    fn a_decomposed_spelling_of_a_protected_path_is_protected() {
        let rules = rules(&[("docs", mode("docs/caf\u{e9}/**", PathMode::DenyWrite))]);
        assert_eq!(
            classify(&rules, "docs/cafe\u{301}/x.md"),
            Some(PathMode::DenyWrite)
        );
    }

    #[test]
    fn the_most_restrictive_mode_wins_in_the_documented_order() {
        let order = [
            PathMode::Hidden,
            PathMode::DenyWrite,
            PathMode::AppendOnly,
            PathMode::AdditionsOnly,
            PathMode::Sensitive,
        ];
        for (index, strict) in order.iter().enumerate() {
            for loose in &order[index + 1..] {
                // The loose rule comes first in the list, the strict one second, and then the
                // other way round: the answer does not depend on the order of the list.
                let a = rules(&[("x", mode("p/**", *loose)), ("y", mode("p/**", *strict))]);
                let b = rules(&[("y", mode("p/**", *strict)), ("x", mode("p/**", *loose))]);
                assert_eq!(classify(&a, "p/f"), Some(*strict));
                assert_eq!(classify(&b, "p/f"), Some(*strict));
            }
        }
    }

    #[test]
    fn a_reinclusion_lifts_a_protection_of_its_own_group() {
        let rules = rules(&[
            ("secrets", mode(".env*", PathMode::Hidden)),
            ("secrets", reinclude(".env.example", "secrets")),
        ]);
        assert_eq!(classify(&rules, ".env"), Some(PathMode::Hidden));
        assert_eq!(classify(&rules, ".env.local"), Some(PathMode::Hidden));
        assert_eq!(classify(&rules, ".env.example"), None);
    }

    #[test]
    fn a_reinclusion_is_applied_after_the_rules_of_its_group_wherever_it_is_listed() {
        let rules = rules(&[
            ("secrets", reinclude(".env.example", "secrets")),
            ("secrets", mode(".env*", PathMode::Hidden)),
        ]);
        assert_eq!(classify(&rules, ".env.example"), None);
    }

    #[test]
    fn a_reinclusion_cannot_lift_a_protection_of_another_group() {
        let rules = rules(&[
            ("secrets", mode(".env*", PathMode::Hidden)),
            ("ci", mode(".env.example", PathMode::DenyWrite)),
            ("secrets", reinclude(".env.example", "secrets")),
        ]);
        // The secrets group let the file go, the ci group still protects it.
        assert_eq!(classify(&rules, ".env.example"), Some(PathMode::DenyWrite));
    }

    #[test]
    fn a_reinclusion_is_matched_with_the_same_folding() {
        let rules = rules(&[
            ("secrets", mode(".env*", PathMode::Hidden)),
            ("secrets", reinclude(".env.example", "secrets")),
        ]);
        assert_eq!(classify(&rules, ".ENV.Example"), None);
        assert_eq!(classify(&rules, ".ENV.LOCAL"), Some(PathMode::Hidden));
    }

    #[test]
    fn empty_rules_protect_nothing() {
        assert_eq!(classify(&PathRules::default(), "anything"), None);
        assert!(PathRules::default().rules().is_empty());
    }
}
