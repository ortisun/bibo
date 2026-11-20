//! Path normalization, folding and protected-path rules (`matching`, `protected_paths` and
//! `path_access` of `policies/security.yaml`).
//!
//! # What a path is
//!
//! A path arrives as text from an agent, a tool call or a git diff. [`normalize`] turns it into a
//! [`NormalizedPath`] or refuses it. It refuses what cannot be a safe repository-relative path:
//! an empty, over-long or absolute path, a backslash, a control character (NUL included), a `..`
//! component, a percent escape, a colon (drive letters and NTFS streams), a component made only of
//! dots and spaces, a lookalike of `.`, `..` or `/`, and any spelling of the `.git` directory.
//!
//! It keeps two forms. [`NormalizedPath::as_str`] is the original spelling with `.` and empty
//! components removed, which a POSIX file system resolves to the same file, so a caller that
//! opens the file can use it. [`NormalizedPath::key`] is the folded form every rule matches on.
//!
//! # How the key is folded
//!
//! Per component: remove the characters git's own HFS and NTFS protections ignore (U+200C to
//! U+200F, U+202A to U+202E, U+206A to U+206F, U+FEFF) and also zero-width space, word joiner and
//! the bidirectional isolates; map fullwidth ASCII to ASCII (so `．．` is `..` and is refused); map
//! the three characters whose canonical form is ASCII (U+212A Kelvin sign, U+037E, U+1FEF); trim
//! trailing dots and spaces (Windows ignores them); lower-case character by character, with `ſ`,
//! `ı` and `İ` folded to `s` and `i`; and turn the NTFS short names of the git files (`git~1`,
//! `gitmod~1`, `gitatt~1`, `gitign~1`) into their long names.
//!
//! # What is not here
//!
//! Unicode NFC. The domain crate has no normalization tables and may not add the crate that
//! provides them. Every glob in the central policy is ASCII, and an ASCII glob cannot be matched
//! by a different spelling of an ASCII name except through the characters listed above, so the
//! gap is closed for the central policy. A glob with a non-ASCII character is refused when the
//! rules are built ([`BuildError::NonAsciiGlob`]), so a project cannot add one that a decomposed
//! spelling would dodge.
//!
//! The 8.3 short names of Windows other than the four git files are not mapped. The factory runs
//! on Linux hosts and in Linux containers.
//!
//! # Rules, not guesses
//!
//! [`PathPolicy`] holds the protected groups. A group matches a path when one of its globs does
//! and none of its `!` re-inclusions does. A re-inclusion lifts a protection from its own group
//! only. When several groups match, the most restrictive mode decides:
//! `hidden > deny_write > append_only > additions_only > sensitive`. A path that no group names
//! is free, but a write must also be inside `path_access.write_allow` and inside the task's
//! owned files. A protected group always beats `write_allow` (deny overrides).

use std::collections::BTreeSet;

use globset::{GlobBuilder, GlobMatcher};

use super::decision::AuthorizedApproval;
use super::security::{AppliesTo, ProtectionMode, SecurityPolicy};
use super::{BuildError, RepoKind, RuleRef};

/// The longest path accepted, in bytes (`path_longer_than_4096_bytes`).
pub const MAX_PATH_BYTES: usize = 4096;
/// The longest component accepted, in bytes (`name_longer_than_255_bytes`).
pub const MAX_COMPONENT_BYTES: usize = 255;
/// The most components accepted. A path of 4096 bytes cannot have more than 2048 components, and
/// no real tree is near 256 deep.
pub const MAX_COMPONENTS: usize = 256;

/// Why a path was refused before any rule looked at it. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum PathRefusal {
    /// The text is empty, or only `.` and `/`.
    #[error("the path is empty")]
    Empty,
    /// The path is longer than 4096 bytes.
    #[error("the path is longer than {MAX_PATH_BYTES} bytes")]
    TooLong,
    /// A component is longer than 255 bytes.
    #[error("a component is longer than {MAX_COMPONENT_BYTES} bytes")]
    ComponentTooLong,
    /// The path has more than 256 components.
    #[error("the path has more than {MAX_COMPONENTS} components")]
    TooDeep,
    /// The path starts at the file system root.
    #[error("the path is absolute")]
    Absolute,
    /// A backslash appears.
    #[error("the path contains a backslash")]
    Backslash,
    /// A control character appears, NUL included.
    #[error("the path contains a control character")]
    ControlCharacter,
    /// A percent escape such as `%2e` appears.
    #[error("the path contains a percent escape")]
    PercentEncoded,
    /// A colon appears (a drive letter or an NTFS stream).
    #[error("the path contains a colon")]
    Colon,
    /// A component is `..`, in any spelling.
    #[error("the path has a parent component")]
    ParentComponent,
    /// A component is a lookalike of `.` or `..`, or is made only of dots and spaces.
    #[error("a component is made only of dots, spaces or lookalikes of them")]
    DotLike,
    /// A component looks like a path separator.
    #[error("a component contains a character that looks like a path separator")]
    SeparatorLookalike,
    /// A component is the git directory in some spelling.
    #[error("a component names the git directory")]
    GitDirectory,
}

/// A path that passed [`normalize`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NormalizedPath {
    shown: String,
    key: String,
}

impl NormalizedPath {
    /// The original spelling, with `.` components and doubled or trailing `/` removed. Safe to
    /// give to a file system: it names the same file as the input.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.shown
    }

    /// The folded form every rule matches on.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The folded components.
    pub fn key_components(&self) -> impl Iterator<Item = &str> {
        self.key.split('/')
    }
}

fn is_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{00ad}'
            | '\u{180e}'
    )
}

/// Replaces lookalikes by the character they imitate, and drops the ignorable characters.
fn squash(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if is_ignorable(c) {
            continue;
        }
        match c {
            '\u{2025}' => out.push_str(".."),
            '\u{2026}' => out.push_str("..."),
            '\u{2215}' | '\u{2044}' | '\u{29f8}' => out.push('/'),
            '\u{2216}' | '\u{29f5}' => out.push('\\'),
            '\u{2024}' | '\u{fe52}' | '\u{ff61}' | '\u{3002}' | '\u{ff0e}' => out.push('.'),
            '\u{ff01}'..='\u{ff5e}' => {
                out.push(char::from_u32(u32::from(c).saturating_sub(0xfee0)).unwrap_or(c));
            }
            '\u{037e}' => out.push(';'),
            '\u{1fef}' => out.push('`'),
            other => out.push(other),
        }
    }
    out
}

/// Lower-cases character by character, with the folds the module notes list.
fn fold_chars(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\u{17f}' => out.push('s'),
            '\u{131}' | '\u{130}' => out.push('i'),
            other => out.extend(other.to_lowercase()),
        }
    }
    out
}

/// The git files whose NTFS short names git itself protects, as `(short prefix, long name)`.
const GIT_SHORT_NAMES: [(&str, &str); 4] = [
    ("git~", ".git"),
    ("gitmod~", ".gitmodules"),
    ("gitatt~", ".gitattributes"),
    ("gitign~", ".gitignore"),
];

fn long_name_of_short(key: &str) -> Option<&'static str> {
    GIT_SHORT_NAMES.iter().find_map(|(prefix, long)| {
        let digits = key.strip_prefix(prefix)?;
        (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some(*long)
    })
}

/// True when one path component names the git directory: `.git` in any letter case, with ignorable
/// characters, trailing dots or spaces, or as the short name `git~1`.
#[must_use]
pub fn is_git_directory_component(component: &str) -> bool {
    let key = component_key(&squash(component));
    key == ".git"
}

fn component_key(squashed: &str) -> String {
    let trimmed = squashed.trim_end_matches(['.', ' ']);
    let folded = fold_chars(trimmed);
    match long_name_of_short(&folded) {
        Some(long) => long.to_owned(),
        None => folded,
    }
}

fn has_percent_escape(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(i, b)| {
        *b == b'%'
            && matches!(
                (bytes.get(i + 1), bytes.get(i + 2)),
                (Some(x), Some(y)) if x.is_ascii_hexdigit() && y.is_ascii_hexdigit()
            )
    })
}

/// Normalizes a repository-relative path, or says why it cannot be one.
///
/// # Errors
/// The [`PathRefusal`] for the first rule the text breaks.
pub fn normalize(text: &str) -> Result<NormalizedPath, PathRefusal> {
    if text.is_empty() {
        return Err(PathRefusal::Empty);
    }
    if text.len() > MAX_PATH_BYTES {
        return Err(PathRefusal::TooLong);
    }
    if text.contains('\\') {
        return Err(PathRefusal::Backslash);
    }
    if text.chars().any(char::is_control) {
        return Err(PathRefusal::ControlCharacter);
    }
    if text.starts_with('/') {
        return Err(PathRefusal::Absolute);
    }
    let mut shown: Vec<&str> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    for raw in text.split('/') {
        if raw.is_empty() || raw == "." {
            continue;
        }
        if raw.len() > MAX_COMPONENT_BYTES {
            return Err(PathRefusal::ComponentTooLong);
        }
        let squashed = squash(raw);
        if squashed.contains('\\') {
            return Err(PathRefusal::Backslash);
        }
        if squashed.contains('/') {
            return Err(PathRefusal::SeparatorLookalike);
        }
        if squashed.chars().any(char::is_control) {
            return Err(PathRefusal::ControlCharacter);
        }
        if has_percent_escape(&squashed) {
            return Err(PathRefusal::PercentEncoded);
        }
        if squashed.contains(':') {
            return Err(PathRefusal::Colon);
        }
        if squashed == ".." {
            return Err(PathRefusal::ParentComponent);
        }
        if squashed.chars().all(|c| c == '.' || c == ' ') {
            // `.`, `...`, `. ` and the like: Windows would read them as `.` or `..`.
            return Err(PathRefusal::DotLike);
        }
        let key = component_key(&squashed);
        if key == ".git" {
            return Err(PathRefusal::GitDirectory);
        }
        if keys.len() >= MAX_COMPONENTS {
            return Err(PathRefusal::TooDeep);
        }
        shown.push(raw);
        keys.push(key);
    }
    if keys.is_empty() {
        return Err(PathRefusal::Empty);
    }
    Ok(NormalizedPath {
        shown: shown.join("/"),
        key: keys.join("/"),
    })
}

/// What is being done to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// The content is read, or the path is listed.
    Read,
    /// A new file, directory or link appears at the path.
    Add,
    /// An existing file changes. `gained_lines_only` is true when the diff has no removed or
    /// changed line, only added ones.
    Modify {
        /// Whether the diff only adds lines.
        gained_lines_only: bool,
    },
    /// An existing file is removed.
    Delete,
    /// An existing file leaves this path because it is renamed (the source side of a rename).
    RenameFrom,
    /// The mode changes, such as `chmod +x`. It counts as a modification.
    ModeChange,
    /// The type changes, such as a file becoming a symbolic link. It counts as a modification.
    TypeChange,
}

/// What a protected change needs before it can be accepted (`default_change_requires`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChangeRequirement {
    /// The approved specification authorizes the change, recorded in a structured field written
    /// through the approval flow. Prose never counts.
    SpecAuthorization,
    /// An independent policy review approved it.
    IndependentPolicyReview,
    /// An authorized human approved it.
    HumanApproval,
}

impl ChangeRequirement {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "spec_authorization" => Some(Self::SpecAuthorization),
            "independent_policy_review" => Some(Self::IndependentPolicyReview),
            "human_approval" => Some(Self::HumanApproval),
            _ => None,
        }
    }

    /// The spelling the policy file uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpecAuthorization => "spec_authorization",
            Self::IndependentPolicyReview => "independent_policy_review",
            Self::HumanApproval => "human_approval",
        }
    }
}

/// The recorded facts that can turn a refused protected-path change into an accepted one.
///
/// `human_approval` is an [`AuthorizedApproval`], which only the authority evaluator can make, so
/// a caller cannot satisfy it with a flag.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChangeEvidence<'a> {
    /// The structured `spec_authorization` field exists for this change.
    pub spec_authorization: bool,
    /// An independent policy review approved this change.
    pub independent_policy_review: bool,
    /// The human decision, made for the action `change_protected_path`.
    pub human_approval: Option<&'a AuthorizedApproval>,
}

impl ChangeEvidence<'_> {
    fn holds(&self, requirement: ChangeRequirement) -> bool {
        match requirement {
            ChangeRequirement::SpecAuthorization => self.spec_authorization,
            ChangeRequirement::IndependentPolicyReview => self.independent_policy_review,
            ChangeRequirement::HumanApproval => self
                .human_approval
                .is_some_and(|a| a.action() == "change_protected_path"),
        }
    }
}

/// Why a path operation was refused. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathDenialReason {
    /// The path could not be normalized.
    Unnormalizable(PathRefusal),
    /// The path is in a hidden group: it is not in the checkout and cannot be read or created.
    Hidden,
    /// The path is in a `deny_write` group.
    DenyWrite,
    /// The path is in an `append_only` group and the operation changes an existing file.
    AppendOnly,
    /// The path is in an `additions_only` group and the operation removes or changes content.
    AdditionsOnly,
    /// The path is outside `path_access.write_allow`.
    OutsideWriteAllow,
    /// The path is outside the files the task owns.
    OutsideTaskScope,
    /// A gitlink (mode 160000) appears in the diff.
    Gitlink,
    /// A symbolic link points outside the workspace, or is not a relative path.
    SymlinkEscapes,
    /// A symbolic link points at a hidden path or at the git directory.
    SymlinkIntoProtected,
    /// The diff changes more files than `path_access.max_files_changed_per_task`.
    TooManyFiles,
}

/// A refused path operation: the reason, the rule behind it, and, for a protected group that an
/// exception could lift, the requirements that are still missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDenial {
    /// Why.
    pub reason: PathDenialReason,
    /// The policy rule, such as `protected_paths.groups:ci_workflows` or `matching:reject_dotdot`.
    pub rule: RuleRef,
    /// The change requirements the evidence did not meet. Empty when no exception can apply.
    pub missing: Vec<ChangeRequirement>,
}

/// A sensitive-file group that matched: the change is allowed but the listed checks and extra
/// reviews apply.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SensitiveHit {
    /// The group id, such as `dependency_manifests`.
    pub group: String,
    /// The semantic checks to run.
    pub checks: Vec<String>,
    /// The extra reviewers.
    pub extra_review: Vec<String>,
}

/// The answer for one path operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathVerdict {
    /// Allowed.
    Allowed(PathAllowance),
    /// Refused.
    Denied(PathDenial),
}

impl PathVerdict {
    /// True when the operation is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }
}

/// An allowed operation, with what the caller must still do about it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathAllowance {
    /// Sensitive groups that matched.
    pub sensitive: Vec<SensitiveHit>,
    /// The protected groups whose refusal was lifted by complete change evidence.
    pub exception_for: Vec<RuleRef>,
}

/// One entry of the trusted tree diff (base tree against head tree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffEntry {
    /// A new file.
    Added {
        /// The path.
        path: String,
    },
    /// A changed file.
    Modified {
        /// The path.
        path: String,
        /// True when the diff only adds lines.
        gained_lines_only: bool,
    },
    /// A removed file.
    Deleted {
        /// The path.
        path: String,
    },
    /// A rename. It counts as two paths.
    Renamed {
        /// The old path.
        from: String,
        /// The new path.
        to: String,
    },
    /// A copy. It counts as two paths: the source is read, the destination is added.
    Copied {
        /// The source path.
        from: String,
        /// The destination path.
        to: String,
    },
    /// A mode change.
    ModeChanged {
        /// The path.
        path: String,
    },
    /// A type change.
    TypeChanged {
        /// The path.
        path: String,
    },
    /// A new or changed symbolic link.
    Symlink {
        /// The path of the link.
        path: String,
        /// What the link points at.
        target: String,
    },
    /// A gitlink (submodule pointer).
    Gitlink {
        /// The path.
        path: String,
    },
}

/// A refused path in a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDenied {
    /// The path as given, cut at 256 characters so that the answer stays small.
    pub path: String,
    /// Why.
    pub denial: PathDenial,
}

/// The answer for a whole diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffVerdict {
    /// Every path is allowed.
    Allowed {
        /// The sensitive groups touched, deduplicated.
        sensitive: Vec<SensitiveHit>,
        /// Protected groups whose refusal was lifted by evidence.
        exception_for: Vec<RuleRef>,
    },
    /// At least one path is refused. The job is blocked.
    Blocked {
        /// Every refused path.
        denials: Vec<PathDenied>,
    },
}

impl DiffVerdict {
    /// True when the whole diff is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

/// The files a task owns (`path_access.write_scope_source: task_owned_files`), compiled.
#[derive(Debug, Clone)]
pub struct WriteScope {
    owned: Vec<GlobMatcher>,
}

#[derive(Debug)]
struct Group {
    id: String,
    mode: ProtectionMode,
    applies_to: AppliesTo,
    includes: Vec<GlobMatcher>,
    reincludes: Vec<GlobMatcher>,
}

#[derive(Debug)]
struct Sensitive {
    hit: SensitiveHit,
    applies_to: Option<AppliesTo>,
    globs: Vec<GlobMatcher>,
}

/// The protected-path rules of one security policy, compiled once.
#[derive(Debug)]
pub struct PathPolicy {
    groups: Vec<Group>,
    sensitive: Vec<Sensitive>,
    write_allow: Vec<GlobMatcher>,
    requirements: Vec<ChangeRequirement>,
    max_files_changed: usize,
}

fn compile_glob(place: &str, text: &str) -> Result<Vec<GlobMatcher>, BuildError> {
    if !text.is_ascii() {
        return Err(BuildError::NonAsciiGlob {
            place: place.to_owned(),
            glob: text.to_owned(),
        });
    }
    let lowered = text.to_ascii_lowercase();
    let mut forms = vec![lowered.clone()];
    // `dir/**` names everything inside `dir`. The directory itself, or a file put in its place, is
    // protected too.
    if let Some(dir) = lowered.strip_suffix("/**")
        && !dir.is_empty()
    {
        forms.push(dir.to_owned());
    }
    forms
        .iter()
        .map(|form| {
            GlobBuilder::new(form)
                .literal_separator(true)
                .build()
                .map(|g| g.compile_matcher())
                .map_err(|e| BuildError::Glob {
                    place: place.to_owned(),
                    glob: text.to_owned(),
                    message: e.to_string(),
                })
        })
        .collect()
}

fn mode_strictness(mode: ProtectionMode) -> u8 {
    match mode {
        ProtectionMode::Hidden => 4,
        ProtectionMode::DenyWrite => 3,
        ProtectionMode::AppendOnly => 2,
        ProtectionMode::AdditionsOnly => 1,
    }
}

fn applies(applies_to: AppliesTo, repo: RepoKind) -> bool {
    matches!(
        (applies_to, repo),
        (AppliesTo::Both, _)
            | (AppliesTo::TargetRepo, RepoKind::Target)
            | (AppliesTo::FactoryRepo, RepoKind::Factory)
    )
}

/// True when the mode lets the operation through.
fn mode_allows(mode: ProtectionMode, op: Operation) -> bool {
    match mode {
        ProtectionMode::Hidden => false,
        ProtectionMode::DenyWrite => matches!(op, Operation::Read),
        ProtectionMode::AppendOnly => matches!(op, Operation::Read | Operation::Add),
        ProtectionMode::AdditionsOnly => matches!(
            op,
            Operation::Read
                | Operation::Add
                | Operation::Modify {
                    gained_lines_only: true
                }
        ),
    }
}

fn denial_reason(mode: ProtectionMode) -> PathDenialReason {
    match mode {
        ProtectionMode::Hidden => PathDenialReason::Hidden,
        ProtectionMode::DenyWrite => PathDenialReason::DenyWrite,
        ProtectionMode::AppendOnly => PathDenialReason::AppendOnly,
        ProtectionMode::AdditionsOnly => PathDenialReason::AdditionsOnly,
    }
}

fn truncate(text: &str) -> String {
    text.chars().take(256).collect()
}

impl PathPolicy {
    /// Compiles the path rules of `policy`.
    ///
    /// # Errors
    /// A [`BuildError`] when a glob does not compile or is not ASCII, when the document turns off
    /// a rule this engine always applies, or when `deny_read_globs_ref` does not name exactly the
    /// hidden groups.
    pub fn from_policy(policy: &SecurityPolicy) -> Result<Self, BuildError> {
        let m = &policy.matching;
        let must_hold = [
            ("matching.case_insensitive", m.case_insensitive),
            ("matching.reject_dotdot", m.reject_dotdot),
            ("matching.reject_absolute", m.reject_absolute),
            (
                "matching.reject_nul_and_backslash",
                m.reject_nul_and_backslash,
            ),
            (
                "matching.count_rename_source_and_destination",
                m.count_rename_source_and_destination,
            ),
            (
                "matching.mode_and_type_changes_are_modifications",
                m.mode_and_type_changes_are_modifications,
            ),
            (
                "matching.reject_dot_git_components",
                m.reject_dot_git_components,
            ),
            ("matching.reject_gitlinks", m.reject_gitlinks),
        ];
        for (key, value) in must_hold {
            if !value {
                return Err(BuildError::ProtectionDisabled {
                    key,
                    found: "false".to_owned(),
                });
            }
        }
        if m.normalization != "nfc" {
            return Err(BuildError::UnknownValue {
                key: "matching.normalization",
                found: m.normalization.clone(),
            });
        }
        if m.symlinks != "reject_if_target_outside_workspace" {
            return Err(BuildError::UnknownValue {
                key: "matching.symlinks",
                found: m.symlinks.clone(),
            });
        }

        let mut groups = Vec::new();
        let mut seen = BTreeSet::new();
        for g in &policy.protected_paths.groups {
            if !seen.insert(g.id.clone()) {
                return Err(BuildError::Duplicate {
                    what: "protected group",
                    name: g.id.clone(),
                });
            }
            let place = format!("protected_paths.groups[{}]", g.id);
            let (mut includes, mut reincludes) = (Vec::new(), Vec::new());
            for glob in &g.globs {
                let compiled = compile_glob(&place, glob.pattern())?;
                if glob.is_reinclusion() {
                    reincludes.extend(compiled);
                } else {
                    includes.extend(compiled);
                }
            }
            groups.push(Group {
                id: g.id.clone(),
                mode: g.mode,
                applies_to: g.applies_to,
                includes,
                reincludes,
            });
        }

        let hidden: BTreeSet<&str> = groups
            .iter()
            .filter(|g| g.mode == ProtectionMode::Hidden)
            .map(|g| g.id.as_str())
            .collect();
        let named = policy
            .path_access
            .deny_read_globs_ref
            .strip_prefix("protected_paths.groups[")
            .and_then(|rest| rest.strip_suffix(']'))
            .map(|list| list.split(',').map(str::trim).collect::<BTreeSet<_>>());
        if named.as_ref() != Some(&hidden) {
            return Err(BuildError::Contradiction(format!(
                "path_access.deny_read_globs_ref names {:?} but the hidden groups are {hidden:?}; a hidden path must be unreadable and an unreadable path must be hidden",
                policy.path_access.deny_read_globs_ref
            )));
        }

        let mut sensitive = Vec::new();
        for s in &policy.protected_paths.sensitive_files {
            let place = format!("protected_paths.sensitive_files[{}]", s.id);
            let mut globs = Vec::new();
            for glob in &s.globs {
                if glob.is_reinclusion() {
                    return Err(BuildError::UnknownValue {
                        key: "protected_paths.sensitive_files.globs",
                        found: glob.0.clone(),
                    });
                }
                globs.extend(compile_glob(&place, glob.pattern())?);
            }
            sensitive.push(Sensitive {
                hit: SensitiveHit {
                    group: s.id.clone(),
                    checks: s.checks.clone(),
                    extra_review: s.extra_review.clone(),
                },
                applies_to: s.applies_to,
                globs,
            });
        }

        let mut write_allow = Vec::new();
        for glob in &policy.path_access.write_allow {
            write_allow.extend(compile_glob("path_access.write_allow", glob.pattern())?);
        }

        let mut requirements = Vec::new();
        for name in &policy.protected_paths.default_change_requires {
            let requirement =
                ChangeRequirement::parse(name).ok_or_else(|| BuildError::UnknownValue {
                    key: "protected_paths.default_change_requires",
                    found: name.clone(),
                })?;
            requirements.push(requirement);
        }
        if requirements.is_empty() {
            return Err(BuildError::Contradiction(
                "protected_paths.default_change_requires is empty, so a protected path could be changed with no evidence".to_owned(),
            ));
        }

        Ok(Self {
            groups,
            sensitive,
            write_allow,
            requirements,
            max_files_changed: usize::try_from(policy.path_access.max_files_changed_per_task)
                .unwrap_or(usize::MAX),
        })
    }

    /// The requirements a protected change needs.
    #[must_use]
    pub fn change_requirements(&self) -> &[ChangeRequirement] {
        &self.requirements
    }

    /// Compiles the files a task owns. Each entry is a glob in the policy dialect.
    ///
    /// # Errors
    /// A [`BuildError`] when an entry does not compile or is not ASCII.
    pub fn write_scope<S: AsRef<str>>(&self, owned_files: &[S]) -> Result<WriteScope, BuildError> {
        let mut owned = Vec::new();
        for glob in owned_files {
            owned.extend(compile_glob("task owned files", glob.as_ref())?);
        }
        Ok(WriteScope { owned })
    }

    fn hits(&self, repo: RepoKind, key: &str) -> Vec<&Group> {
        self.groups
            .iter()
            .filter(|g| applies(g.applies_to, repo))
            .filter(|g| {
                g.includes.iter().any(|m| m.is_match(key))
                    && !g.reincludes.iter().any(|m| m.is_match(key))
            })
            .collect()
    }

    /// The most restrictive mode that applies to the path and the group it comes from, or `None`
    /// for a path no group names.
    #[must_use]
    pub fn classify(
        &self,
        repo: RepoKind,
        path: &NormalizedPath,
    ) -> Option<(ProtectionMode, &str)> {
        self.hits(repo, path.key())
            .into_iter()
            .max_by_key(|g| mode_strictness(g.mode))
            .map(|g| (g.mode, g.id.as_str()))
    }

    fn sensitive_hits(&self, repo: RepoKind, key: &str) -> Vec<SensitiveHit> {
        self.sensitive
            .iter()
            .filter(|s| s.applies_to.is_none_or(|a| applies(a, repo)))
            .filter(|s| s.globs.iter().any(|m| m.is_match(key)))
            .map(|s| s.hit.clone())
            .collect()
    }

    /// Decides one operation on one path.
    ///
    /// The answer is a function of the text, the operation, the repository kind, the task scope
    /// and the change evidence. A path that cannot be normalized is refused whatever the
    /// operation. A hidden path is refused for every operation and no evidence lifts it.
    #[must_use]
    pub fn check(
        &self,
        repo: RepoKind,
        path: &str,
        op: Operation,
        scope: Option<&WriteScope>,
        evidence: &ChangeEvidence<'_>,
    ) -> PathVerdict {
        match normalize(path) {
            Ok(normalized) => self.check_normalized(repo, &normalized, op, scope, evidence),
            Err(refusal) => PathVerdict::Denied(PathDenial {
                reason: PathDenialReason::Unnormalizable(refusal),
                rule: RuleRef::new("matching", refusal_rule(refusal)),
                missing: Vec::new(),
            }),
        }
    }

    /// Like [`check`](Self::check) for a path that is already normalized.
    #[must_use]
    pub fn check_normalized(
        &self,
        repo: RepoKind,
        path: &NormalizedPath,
        op: Operation,
        scope: Option<&WriteScope>,
        evidence: &ChangeEvidence<'_>,
    ) -> PathVerdict {
        let key = path.key();
        let hits = self.hits(repo, key);

        if let Some(hidden) = hits.iter().find(|g| g.mode == ProtectionMode::Hidden) {
            return deny(PathDenialReason::Hidden, &hidden.id, Vec::new());
        }

        let refusing: Vec<&&Group> = hits.iter().filter(|g| !mode_allows(g.mode, op)).collect();
        let mut exception_for = Vec::new();
        if let Some(strictest) = refusing.iter().max_by_key(|g| mode_strictness(g.mode)) {
            let missing: Vec<ChangeRequirement> = self
                .requirements
                .iter()
                .copied()
                .filter(|r| !evidence.holds(*r))
                .collect();
            if !missing.is_empty() {
                return deny(denial_reason(strictest.mode), &strictest.id, missing);
            }
            exception_for = refusing
                .iter()
                .map(|g| RuleRef::new("protected_paths.groups", g.id.clone()))
                .collect();
        }

        if !matches!(op, Operation::Read) {
            if !self.write_allow.iter().any(|m| m.is_match(key)) {
                return PathVerdict::Denied(PathDenial {
                    reason: PathDenialReason::OutsideWriteAllow,
                    rule: RuleRef::new("path_access", "write_allow"),
                    missing: Vec::new(),
                });
            }
            if let Some(scope) = scope
                && !scope.owned.iter().any(|m| m.is_match(key))
            {
                return PathVerdict::Denied(PathDenial {
                    reason: PathDenialReason::OutsideTaskScope,
                    rule: RuleRef::new("path_access", "write_scope_source"),
                    missing: Vec::new(),
                });
            }
        }

        PathVerdict::Allowed(PathAllowance {
            sensitive: self.sensitive_hits(repo, key),
            exception_for,
        })
    }

    /// Decides where a symbolic link may point.
    ///
    /// The link is at `link_path` and points at `target`, which must be relative. The target is
    /// resolved lexically from the link's directory, and must stay inside the workspace and must
    /// not land on a hidden path or the git directory. Following further links on disk is the
    /// workspace audit's job; this is the check that can be made on the text alone.
    #[must_use]
    pub fn check_symlink(&self, repo: RepoKind, link_path: &str, target: &str) -> PathVerdict {
        let escapes = || {
            PathVerdict::Denied(PathDenial {
                reason: PathDenialReason::SymlinkEscapes,
                rule: RuleRef::new("matching", "symlinks"),
                missing: Vec::new(),
            })
        };
        let link = match normalize(link_path) {
            Ok(link) => link,
            Err(refusal) => {
                return PathVerdict::Denied(PathDenial {
                    reason: PathDenialReason::Unnormalizable(refusal),
                    rule: RuleRef::new("matching", refusal_rule(refusal)),
                    missing: Vec::new(),
                });
            }
        };
        if target.is_empty()
            || target.len() > MAX_PATH_BYTES
            || target.starts_with('/')
            || target.contains('\\')
            || target.chars().any(char::is_control)
        {
            return escapes();
        }
        let mut resolved: Vec<String> =
            link.key_components().map(str::to_owned).collect::<Vec<_>>();
        resolved.pop(); // the directory that holds the link
        for raw in target.split('/') {
            if raw.is_empty() || raw == "." {
                continue;
            }
            let squashed = squash(raw);
            if squashed == ".." {
                if resolved.pop().is_none() {
                    return escapes();
                }
                continue;
            }
            if squashed.contains(['/', '\\', ':'])
                || squashed.chars().any(char::is_control)
                || has_percent_escape(&squashed)
                || squashed.chars().all(|c| c == '.' || c == ' ')
            {
                return escapes();
            }
            let key = component_key(&squashed);
            if key == ".git" {
                return PathVerdict::Denied(PathDenial {
                    reason: PathDenialReason::SymlinkIntoProtected,
                    rule: RuleRef::new("matching", "reject_dot_git_components"),
                    missing: Vec::new(),
                });
            }
            if resolved.len() >= MAX_COMPONENTS {
                return escapes();
            }
            resolved.push(key);
        }
        let joined = resolved.join("/");
        if let Some(hidden) = self
            .hits(repo, &joined)
            .into_iter()
            .find(|g| g.mode == ProtectionMode::Hidden)
        {
            return PathVerdict::Denied(PathDenial {
                reason: PathDenialReason::SymlinkIntoProtected,
                rule: RuleRef::new("protected_paths.groups", hidden.id.clone()),
                missing: Vec::new(),
            });
        }
        PathVerdict::Allowed(PathAllowance::default())
    }

    /// Decides a whole trusted tree diff.
    ///
    /// Every entry is decided; the diff is allowed only if all of them are. A rename is decided
    /// as a rename-from on the old path and an add on the new path. A copy is decided as a read of
    /// the source and an add at the destination. A mode or type change is a modification. A
    /// gitlink is always refused. More entries than `max_files_changed_per_task` is refused
    /// without looking at them.
    #[must_use]
    pub fn check_diff(
        &self,
        repo: RepoKind,
        entries: &[DiffEntry],
        scope: Option<&WriteScope>,
        evidence: &ChangeEvidence<'_>,
    ) -> DiffVerdict {
        if entries.len() > self.max_files_changed {
            return DiffVerdict::Blocked {
                denials: vec![PathDenied {
                    path: String::new(),
                    denial: PathDenial {
                        reason: PathDenialReason::TooManyFiles,
                        rule: RuleRef::new("path_access", "max_files_changed_per_task"),
                        missing: Vec::new(),
                    },
                }],
            };
        }
        let mut denials = Vec::new();
        let mut sensitive: BTreeSet<SensitiveHit> = BTreeSet::new();
        let mut exceptions: BTreeSet<RuleRef> = BTreeSet::new();
        let mut record = |path: &str, verdict: PathVerdict| match verdict {
            PathVerdict::Allowed(allowance) => {
                sensitive.extend(allowance.sensitive);
                exceptions.extend(allowance.exception_for);
            }
            PathVerdict::Denied(denial) => denials.push(PathDenied {
                path: truncate(path),
                denial,
            }),
        };
        for entry in entries {
            match entry {
                DiffEntry::Added { path } => {
                    record(
                        path,
                        self.check(repo, path, Operation::Add, scope, evidence),
                    );
                }
                DiffEntry::Modified {
                    path,
                    gained_lines_only,
                } => record(
                    path,
                    self.check(
                        repo,
                        path,
                        Operation::Modify {
                            gained_lines_only: *gained_lines_only,
                        },
                        scope,
                        evidence,
                    ),
                ),
                DiffEntry::Deleted { path } => record(
                    path,
                    self.check(repo, path, Operation::Delete, scope, evidence),
                ),
                DiffEntry::Renamed { from, to } => {
                    record(
                        from,
                        self.check(repo, from, Operation::RenameFrom, scope, evidence),
                    );
                    record(to, self.check(repo, to, Operation::Add, scope, evidence));
                }
                DiffEntry::Copied { from, to } => {
                    record(
                        from,
                        self.check(repo, from, Operation::Read, None, evidence),
                    );
                    record(to, self.check(repo, to, Operation::Add, scope, evidence));
                }
                DiffEntry::ModeChanged { path } => record(
                    path,
                    self.check(repo, path, Operation::ModeChange, scope, evidence),
                ),
                DiffEntry::TypeChanged { path } => record(
                    path,
                    self.check(repo, path, Operation::TypeChange, scope, evidence),
                ),
                DiffEntry::Symlink { path, target } => {
                    record(
                        path,
                        self.check(repo, path, Operation::Add, scope, evidence),
                    );
                    record(path, self.check_symlink(repo, path, target));
                }
                DiffEntry::Gitlink { path } => record(
                    path,
                    PathVerdict::Denied(PathDenial {
                        reason: PathDenialReason::Gitlink,
                        rule: RuleRef::new("matching", "reject_gitlinks"),
                        missing: Vec::new(),
                    }),
                ),
            }
        }
        if denials.is_empty() {
            DiffVerdict::Allowed {
                sensitive: sensitive.into_iter().collect(),
                exception_for: exceptions.into_iter().collect(),
            }
        } else {
            DiffVerdict::Blocked { denials }
        }
    }
}

fn deny(reason: PathDenialReason, group: &str, missing: Vec<ChangeRequirement>) -> PathVerdict {
    PathVerdict::Denied(PathDenial {
        reason,
        rule: RuleRef::new("protected_paths.groups", group),
        missing,
    })
}

fn refusal_rule(refusal: PathRefusal) -> &'static str {
    match refusal {
        PathRefusal::ParentComponent => "reject_dotdot",
        PathRefusal::Absolute => "reject_absolute",
        PathRefusal::Backslash | PathRefusal::ControlCharacter => "reject_nul_and_backslash",
        PathRefusal::GitDirectory => "reject_dot_git_components",
        PathRefusal::TooLong | PathRefusal::ComponentTooLong | PathRefusal::TooDeep => {
            "workspace_audit"
        }
        PathRefusal::Empty
        | PathRefusal::PercentEncoded
        | PathRefusal::Colon
        | PathRefusal::DotLike
        | PathRefusal::SeparatorLookalike => "normalization",
    }
}
