//! The project's rules for agents: the template the factory installs, how the installed file is
//! read and rendered, and the decision to propose it (ADR 0026, `docs/architecture/project-rules.md`).
//!
//! Everything here is pure: no clock, no file, no network. The same inputs always give the same
//! bytes and the same decision.
//!
//! # The installed file
//!
//! ```text
//! <!-- factory-rules begin version=N -->
//! ... the template, byte for byte ...
//! <!-- factory-rules end -->
//! ... the project's section, which the factory never changes ...
//! ```
//!
//! Text before the opening marker is kept as well, so a heading a person put above the factory's
//! section survives an update. Line breaks are `\n`; a file read with `\r\n` line breaks is
//! compared without them, so a checkout that converted the line breaks is not taken for an edit.
//!
//! # Versions
//!
//! [`TEMPLATE_VERSION`] is a whole number from 1. A test pins the SHA-256 digest of the template
//! ([`TEMPLATE_SHA256`]): a change to one byte of the template fails it until the version is
//! raised and the digest updated in the same change.

use crate::values::Sha256Digest;

/// The rules text, as the factory ships it. The file is `onboarding/project-rules/AGENTS.md`.
pub const TEMPLATE: &str = include_str!("../../../onboarding/project-rules/AGENTS.md");

/// The version of [`TEMPLATE`]. Raise it with every change to the text.
pub const TEMPLATE_VERSION: u32 = 1;

/// The SHA-256 digest of [`TEMPLATE`], 64 lowercase hexadecimal characters. A test compares it
/// with the text, so the text cannot change under the same version.
pub const TEMPLATE_SHA256: &str =
    "183b516faf8e6602208bf126c8e5d27af2a7596815a32e2a88503f9a88a711b2";

/// The file the rules live in, at the root of the repository.
pub const RULES_FILE: &str = "AGENTS.md";

/// The most bytes of the rules file the factory reads or gives to an agent: 64 KiB.
pub const MAX_RULES_BYTES: usize = 65_536;

/// The start of the opening marker. The version and [`MARKER_CLOSE`] follow it.
pub const BEGIN_PREFIX: &str = "<!-- factory-rules begin version=";

/// The end of the opening marker.
const MARKER_CLOSE: &str = " -->";

/// The closing marker, a line of its own.
pub const END_MARKER: &str = "<!-- factory-rules end -->";

/// The project's section of a new file.
pub const DEFAULT_PROJECT_SECTION: &str = "\n## Rules of this project\n\nAdd the rules that belong to this project below this heading. The factory keeps everything\nafter the line `<!-- factory-rules end -->` when it updates its own rules above.\n";

/// The skeleton of `docs/` that the rules ask for: the path in the target repository and the text.
/// A file is proposed only when the default branch does not have it.
pub const SKELETON: [(&str, &str); 6] = [
    (
        "docs/README.md",
        include_str!("../../../onboarding/project-rules/docs/README.md"),
    ),
    (
        "docs/specifications/README.md",
        include_str!("../../../onboarding/project-rules/docs/specifications/README.md"),
    ),
    (
        "docs/architecture/README.md",
        include_str!("../../../onboarding/project-rules/docs/architecture/README.md"),
    ),
    (
        "docs/adr/README.md",
        include_str!("../../../onboarding/project-rules/docs/adr/README.md"),
    ),
    (
        "docs/guides/README.md",
        include_str!("../../../onboarding/project-rules/docs/guides/README.md"),
    ),
    (
        "docs/reference/README.md",
        include_str!("../../../onboarding/project-rules/docs/reference/README.md"),
    ),
];

/// A rules text and its version. [`Template::current`] is the one the factory ships; tests build
/// others to reach the "older" and "newer" cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Template<'a> {
    /// The text, ending with `\n`.
    pub text: &'a str,
    /// The version, from 1.
    pub version: u32,
}

impl Template<'static> {
    /// The template the factory ships.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            text: TEMPLATE,
            version: TEMPLATE_VERSION,
        }
    }
}

impl Template<'_> {
    /// The factory's section: the opening marker, the text and the closing marker, ending with
    /// `\n`.
    #[must_use]
    pub fn managed_block(&self) -> String {
        let mut block = String::with_capacity(self.text.len() + 80);
        block.push_str(&begin_marker(self.version));
        block.push('\n');
        block.push_str(self.text);
        if !self.text.ends_with('\n') {
            block.push('\n');
        }
        block.push_str(END_MARKER);
        block.push('\n');
        block
    }
}

/// The opening marker for `version`.
#[must_use]
pub fn begin_marker(version: u32) -> String {
    format!("{BEGIN_PREFIX}{version}{MARKER_CLOSE}")
}

/// The rules file as it was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFound<'a> {
    /// No such file.
    Missing,
    /// Larger than [`MAX_RULES_BYTES`]; its bytes were not read.
    TooLarge,
    /// The bytes of the file.
    Bytes(&'a [u8]),
}

/// Why an installed file cannot be managed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// Larger than [`MAX_RULES_BYTES`].
    TooLarge,
    /// An opening marker without a closing one, two of either, a closing marker first, or a
    /// version that is not a whole number from 1 written without leading zeros.
    MalformedMarkers,
}

impl Unreadable {
    /// A short word for logs and audit records.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotUtf8 => "not_utf8",
            Self::TooLarge => "too_large",
            Self::MalformedMarkers => "malformed_markers",
        }
    }
}

/// The installed file, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Installed {
    /// No file.
    Missing,
    /// A file without the factory's markers: all of it is the project's.
    WithoutMarkers {
        /// The whole text.
        text: String,
    },
    /// A file with the factory's section.
    Managed {
        /// The text before the opening marker, kept as it is.
        prefix: String,
        /// The version in the opening marker.
        version: u32,
        /// The text between the markers, line breaks made `\n`.
        managed: String,
        /// Everything after the closing marker's line break, kept as it is.
        project: String,
    },
    /// A file the factory cannot manage.
    Unreadable(Unreadable),
}

/// Reads the installed file.
#[must_use]
pub fn read_installed(found: FileFound<'_>) -> Installed {
    let bytes = match found {
        FileFound::Missing => return Installed::Missing,
        FileFound::TooLarge => return Installed::Unreadable(Unreadable::TooLarge),
        FileFound::Bytes(bytes) => bytes,
    };
    if bytes.len() > MAX_RULES_BYTES {
        return Installed::Unreadable(Unreadable::TooLarge);
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Installed::Unreadable(Unreadable::NotUtf8);
    };
    parse(text)
}

/// The byte offset of each line start, and the line without its line break.
fn lines_with_offsets(text: &str) -> impl Iterator<Item = (usize, &str, usize)> {
    let mut start = 0_usize;
    text.split_inclusive('\n').map(move |line| {
        let at = start;
        start = start.saturating_add(line.len());
        let bare = line.trim_end_matches('\n').trim_end_matches('\r');
        (at, bare, start)
    })
}

/// A version written as a whole number from 1, without a sign or leading zeros.
fn parse_version(text: &str) -> Option<u32> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok()
}

fn parse(text: &str) -> Installed {
    let mut begins = Vec::new();
    let mut ends = Vec::new();
    for (at, line, next) in lines_with_offsets(text) {
        if line.starts_with(BEGIN_PREFIX) || line.starts_with("<!-- factory-rules begin") {
            begins.push((at, line, next));
        } else if line.trim() == END_MARKER || line.starts_with("<!-- factory-rules end") {
            ends.push((at, line, next));
        }
    }
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Installed::WithoutMarkers {
            text: text.to_owned(),
        },
        ([(begin_at, begin_line, managed_start)], [(end_at, end_line, project_start)])
            if begin_at < end_at && *end_line == END_MARKER =>
        {
            let version = begin_line
                .strip_prefix(BEGIN_PREFIX)
                .and_then(|rest| rest.strip_suffix(MARKER_CLOSE))
                .and_then(parse_version);
            let (Some(version), Some(prefix), Some(managed), Some(project)) = (
                version,
                text.get(..*begin_at),
                text.get(*managed_start..*end_at),
                text.get(*project_start..),
            ) else {
                return Installed::Unreadable(Unreadable::MalformedMarkers);
            };
            Installed::Managed {
                prefix: prefix.to_owned(),
                version,
                managed: managed.replace("\r\n", "\n"),
                project: project.to_owned(),
            }
        }
        _ => Installed::Unreadable(Unreadable::MalformedMarkers),
    }
}

/// Where the installed file stands against a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesState {
    /// No file.
    Missing,
    /// A file without the factory's markers.
    WithoutMarkers,
    /// The factory's section is of an older version.
    Older {
        /// The installed version.
        installed: u32,
    },
    /// The same version, and the factory's section is the template.
    Current,
    /// The same version, and the factory's section differs from the template: a person changed
    /// it, and the change was merged.
    EditedByHand,
    /// A newer version than the template: a newer factory installed it.
    Newer {
        /// The installed version.
        installed: u32,
    },
    /// A file the factory cannot manage.
    Unreadable(Unreadable),
}

impl RulesState {
    /// True when the template should be proposed (if no pull request stands in the way).
    #[must_use]
    pub const fn wants_proposal(self) -> bool {
        matches!(
            self,
            Self::Missing | Self::WithoutMarkers | Self::Older { .. }
        )
    }
}

/// Classifies an installed file against a template.
#[must_use]
pub fn classify(installed: &Installed, template: Template<'_>) -> RulesState {
    match installed {
        Installed::Missing => RulesState::Missing,
        Installed::WithoutMarkers { .. } => RulesState::WithoutMarkers,
        Installed::Unreadable(why) => RulesState::Unreadable(*why),
        Installed::Managed {
            version, managed, ..
        } => match (*version).cmp(&template.version) {
            std::cmp::Ordering::Less => RulesState::Older {
                installed: *version,
            },
            std::cmp::Ordering::Greater => RulesState::Newer {
                installed: *version,
            },
            std::cmp::Ordering::Equal => {
                if *managed == template.text.replace("\r\n", "\n") {
                    RulesState::Current
                } else {
                    RulesState::EditedByHand
                }
            }
        },
    }
}

/// Renders the file to propose: the factory's section of `template`, with what the project had
/// kept. `None` for a file the factory cannot manage.
///
/// * No file: the factory's section and [`DEFAULT_PROJECT_SECTION`].
/// * A file without markers: the factory's section, an empty line, then the whole old text,
///   ending with exactly one `\n`.
/// * A managed file: the text before the opening marker, the factory's section, and the project's
///   section byte for byte.
#[must_use]
pub fn render(installed: &Installed, template: Template<'_>) -> Option<String> {
    let block = template.managed_block();
    match installed {
        Installed::Missing => Some(format!("{block}{DEFAULT_PROJECT_SECTION}")),
        Installed::WithoutMarkers { text } => {
            let kept = text.trim_end_matches(['\n', '\r']);
            if kept.trim().is_empty() {
                Some(format!("{block}{DEFAULT_PROJECT_SECTION}"))
            } else {
                Some(format!("{block}\n{kept}\n"))
            }
        }
        Installed::Managed {
            prefix, project, ..
        } => Some(format!("{prefix}{block}{project}")),
        Installed::Unreadable(_) => None,
    }
}

/// The factory's own pull request on the rules branch, as the decision needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proposal {
    /// None was ever opened.
    None,
    /// Open, with the version of its marker (`None` when it has none).
    Open(Option<u32>),
    /// Merged.
    Merged(Option<u32>),
    /// Closed without a merge.
    Closed(Option<u32>),
}

/// Why nothing is proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NothingBecause {
    /// The installed file is the template.
    UpToDate,
    /// A person changed the factory's section, and the change was merged.
    EditedByHand,
    /// A newer factory installed or proposed a newer version.
    NewerFactory,
    /// The installed file cannot be managed.
    Unreadable(Unreadable),
    /// An open pull request already proposes this version.
    AlreadyProposed,
    /// A person closed the pull request of this version without merging it.
    Declined,
    /// The pull request of this version was merged, and the default branch no longer has it: a
    /// person took it out again.
    Reverted,
}

impl NothingBecause {
    /// A short word for logs and audit records.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UpToDate => "up_to_date",
            Self::EditedByHand => "edited_by_hand",
            Self::NewerFactory => "newer_factory",
            Self::Unreadable(why) => why.code(),
            Self::AlreadyProposed => "already_proposed",
            Self::Declined => "declined",
            Self::Reverted => "reverted",
        }
    }
}

/// What to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Open a pull request, or update the open one.
    Propose,
    /// Do nothing.
    Nothing(NothingBecause),
}

/// The decision, from the state of the default branch and the factory's latest pull request.
/// The table is in `docs/architecture/project-rules.md`, section "The decision".
#[must_use]
pub fn decide(state: RulesState, proposal: Proposal, current: u32) -> Decision {
    match state {
        RulesState::Current => return Decision::Nothing(NothingBecause::UpToDate),
        RulesState::EditedByHand => return Decision::Nothing(NothingBecause::EditedByHand),
        RulesState::Newer { .. } => return Decision::Nothing(NothingBecause::NewerFactory),
        RulesState::Unreadable(why) => return Decision::Nothing(NothingBecause::Unreadable(why)),
        RulesState::Missing | RulesState::WithoutMarkers | RulesState::Older { .. } => {}
    }
    let (version, same) = match proposal {
        Proposal::None => return Decision::Propose,
        Proposal::Open(version) => (version, NothingBecause::AlreadyProposed),
        Proposal::Merged(version) => (version, NothingBecause::Reverted),
        Proposal::Closed(version) => (version, NothingBecause::Declined),
    };
    match version.map(|v| v.cmp(&current)) {
        Some(std::cmp::Ordering::Equal) => Decision::Nothing(same),
        Some(std::cmp::Ordering::Greater) => Decision::Nothing(NothingBecause::NewerFactory),
        Some(std::cmp::Ordering::Less) | None => Decision::Propose,
    }
}

/// Where the text an agent gets came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The repository's file, as it is.
    Repository,
    /// The repository's file had no factory section: the factory's section, then the file.
    RepositoryWithFactoryRules,
    /// The factory's built-in copy.
    FactoryDefault,
}

impl Origin {
    /// The word the repository map records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::RepositoryWithFactoryRules => "repository_with_factory_rules",
            Self::FactoryDefault => "built_in",
        }
    }
}

/// The rules an agent gets, and where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRules {
    /// The text.
    pub text: String,
    /// Where it came from.
    pub origin: Origin,
    /// Why the built-in copy was used for a file that is there: too large or not UTF-8.
    pub fallback: Option<Unreadable>,
}

/// The rules an agent gets from the file found at the job's base commit (table in
/// `docs/architecture/project-rules.md`, "How the agents read the rules").
#[must_use]
pub fn rules_for_agents(found: FileFound<'_>, template: Template<'_>) -> AgentRules {
    let built_in = |fallback| AgentRules {
        text: format!("{}{DEFAULT_PROJECT_SECTION}", template.managed_block()),
        origin: Origin::FactoryDefault,
        fallback,
    };
    match read_installed(found) {
        Installed::Missing => built_in(None),
        Installed::Unreadable(why @ (Unreadable::TooLarge | Unreadable::NotUtf8)) => {
            built_in(Some(why))
        }
        installed @ Installed::WithoutMarkers { .. } => match render(&installed, template) {
            Some(text) => AgentRules {
                text,
                origin: Origin::RepositoryWithFactoryRules,
                fallback: None,
            },
            None => built_in(None),
        },
        // A managed file of any version, and one whose markers are malformed, is what the people
        // of the project merged: it applies as it is.
        Installed::Managed { .. } | Installed::Unreadable(Unreadable::MalformedMarkers) => {
            match found {
                FileFound::Bytes(bytes) => AgentRules {
                    text: String::from_utf8_lossy(bytes).into_owned(),
                    origin: Origin::Repository,
                    fallback: None,
                },
                FileFound::Missing | FileFound::TooLarge => built_in(None),
            }
        }
    }
}

/// The title and the body of the rules pull request. A closed template: no text of the
/// repository, of an issue or of a model is in it. The version marker is not part of the body;
/// the adapter adds it after its text checks.
#[must_use]
pub fn pull_request_text(state: RulesState, version: u32, skeleton: &[&str]) -> (String, String) {
    let title = match state {
        RulesState::Older { .. } => {
            format!("Update the rules for agents in AGENTS.md to version {version}")
        }
        _ => format!("Install the rules for agents in AGENTS.md (version {version})"),
    };
    let what = match state {
        RulesState::Missing => "This pull request creates `AGENTS.md`, the rules that every agent of the software factory follows in this project.".to_owned(),
        RulesState::WithoutMarkers => "This pull request adds the software factory's rules for agents at the top of `AGENTS.md`. The text the file had is kept, whole, after the factory's part.".to_owned(),
        RulesState::Older { installed } => format!("This pull request replaces the factory's part of `AGENTS.md`, version {installed}, with version {version}. Everything after the line `<!-- factory-rules end -->` is kept byte for byte."),
        _ => "This pull request installs the software factory's rules for agents in `AGENTS.md`.".to_owned(),
    };
    let mut body = String::new();
    body.push_str(&what);
    body.push_str("\n\n");
    if !skeleton.is_empty() {
        body.push_str("It also adds the index files of the `docs/` folder that the rules ask for and that this repository does not have yet:\n\n");
        for path in skeleton {
            body.push_str("- `");
            body.push_str(path);
            body.push_str("`\n");
        }
        body.push('\n');
    }
    body.push_str("The part between `<!-- factory-rules begin version=N -->` and `<!-- factory-rules end -->` is the factory's, and a later release replaces it with another pull request like this one. Everything after the end line is this project's: write the project's own rules there.\n\n");
    body.push_str("Until this pull request is merged, the factory's agents follow the factory's built-in copy of these rules. The factory never merges it. Review it, mark it ready and merge it, or close it to decline this version: the factory does not propose the same version again.\n");
    (title, body)
}

/// The SHA-256 digest of a text, as 64 lowercase hexadecimal characters.
#[must_use]
pub fn digest_hex(text: &str) -> String {
    Sha256Digest::of(text.as_bytes()).hex().to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const TEXT: &str = "# Rules\n\nBe good.\n";

    fn template(version: u32) -> Template<'static> {
        Template {
            text: TEXT,
            version,
        }
    }

    fn found(text: &str) -> Installed {
        read_installed(FileFound::Bytes(text.as_bytes()))
    }

    #[test]
    fn the_template_cannot_change_under_the_same_version() {
        assert_eq!(
            digest_hex(TEMPLATE),
            TEMPLATE_SHA256,
            "the template changed: raise TEMPLATE_VERSION and update TEMPLATE_SHA256 together"
        );
        const { assert!(TEMPLATE_VERSION >= 1) };
        assert!(TEMPLATE.ends_with('\n'));
        assert!(!TEMPLATE.contains("factory-rules begin"));
        assert!(!TEMPLATE.contains("factory-rules end"));
        assert!(TEMPLATE.len() + DEFAULT_PROJECT_SECTION.len() + 100 < MAX_RULES_BYTES);
    }

    #[test]
    fn the_shipped_template_keeps_the_five_rules_and_no_factory_command() {
        for heading in [
            "## Finishing the work",
            "## Making decisions",
            "## Documentation comes first",
            "## Code quality",
            "## Testing while implementing a task",
        ] {
            assert!(TEMPLATE.contains(heading), "{heading}");
        }
        for factory_only in ["cargo nextest", "scripts/ci.sh", "--workspace", "<crate>"] {
            assert!(!TEMPLATE.contains(factory_only), "{factory_only}");
        }
    }

    #[test]
    fn the_skeleton_is_six_index_files_under_docs() {
        for (path, text) in SKELETON {
            assert!(
                path.starts_with("docs/") && path.ends_with("/README.md")
                    || path == "docs/README.md"
            );
            assert!(text.starts_with("# "), "{path}");
        }
    }

    #[test]
    fn a_new_file_is_the_block_and_the_default_project_section_in_stable_bytes() {
        let first = render(&Installed::Missing, template(3)).unwrap();
        let again = render(&Installed::Missing, template(3)).unwrap();
        assert_eq!(first, again);
        assert_eq!(
            first,
            format!(
                "<!-- factory-rules begin version=3 -->\n{TEXT}<!-- factory-rules end -->\n{DEFAULT_PROJECT_SECTION}"
            )
        );
        assert!(first.ends_with(".\n") && !first.ends_with("\n\n"));
        assert!(!first.contains('\r'));
    }

    #[test]
    fn a_rendered_file_reads_back_as_current() {
        let rendered = render(&Installed::Missing, template(3)).unwrap();
        let read = found(&rendered);
        assert_eq!(classify(&read, template(3)), RulesState::Current);
        let Installed::Managed {
            version, project, ..
        } = read
        else {
            panic!("managed")
        };
        assert_eq!(version, 3);
        assert_eq!(project, DEFAULT_PROJECT_SECTION);
    }

    #[test]
    fn an_update_keeps_the_project_section_and_the_prefix_byte_for_byte() {
        let project = "\n## Ours\n\n- Money is in cents.  \r\n- No trailing newline";
        let old = format!(
            "Heading kept\n<!-- factory-rules begin version=2 -->\nold rules\n<!-- factory-rules end -->\n{project}"
        );
        let read = found(&old);
        assert_eq!(
            classify(&read, template(3)),
            RulesState::Older { installed: 2 }
        );
        let rendered = render(&read, template(3)).unwrap();
        assert_eq!(
            rendered,
            format!("Heading kept\n{}{project}", template(3).managed_block())
        );
        // Rendering what was rendered changes nothing.
        assert_eq!(render(&found(&rendered), template(3)).unwrap(), rendered);
        assert_eq!(
            classify(&found(&rendered), template(3)),
            RulesState::Current
        );
    }

    #[test]
    fn a_file_without_markers_is_kept_whole_after_the_factory_section() {
        let theirs = "# Our agents\n\nUse tabs.\n\n\n";
        let read = found(theirs);
        assert_eq!(classify(&read, template(1)), RulesState::WithoutMarkers);
        let rendered = render(&read, template(1)).unwrap();
        assert_eq!(
            rendered,
            format!(
                "{}\n# Our agents\n\nUse tabs.\n",
                template(1).managed_block()
            )
        );
        assert_eq!(
            classify(&found(&rendered), template(1)),
            RulesState::Current
        );
        // An empty file gets the default project section.
        assert_eq!(
            render(&found("\n"), template(1)).unwrap(),
            render(&Installed::Missing, template(1)).unwrap()
        );
    }

    #[test]
    fn line_breaks_converted_by_a_checkout_are_not_an_edit() {
        let rendered = render(&Installed::Missing, template(1))
            .unwrap()
            .replace('\n', "\r\n");
        assert_eq!(
            classify(&found(&rendered), template(1)),
            RulesState::Current
        );
    }

    #[test]
    fn versions_compare_as_numbers() {
        let at = |v: u32| {
            found(&format!(
                "<!-- factory-rules begin version={v} -->\n{TEXT}<!-- factory-rules end -->\n"
            ))
        };
        assert_eq!(classify(&at(1), template(1)), RulesState::Current);
        assert_eq!(
            classify(&at(1), template(2)),
            RulesState::Older { installed: 1 }
        );
        assert_eq!(
            classify(&at(9), template(10)),
            RulesState::Older { installed: 9 }
        );
        assert_eq!(
            classify(&at(10), template(9)),
            RulesState::Newer { installed: 10 }
        );
        assert_eq!(
            classify(&at(u32::MAX), template(u32::MAX)),
            RulesState::Current
        );
        let edited =
            found("<!-- factory-rules begin version=1 -->\nchanged\n<!-- factory-rules end -->\n");
        assert_eq!(classify(&edited, template(1)), RulesState::EditedByHand);
    }

    #[test]
    fn malformed_markers_are_unreadable() {
        let bad = [
            "<!-- factory-rules begin version=1 -->\nno end\n",
            "<!-- factory-rules end -->\n<!-- factory-rules begin version=1 -->\n",
            "<!-- factory-rules begin version=1 -->\n<!-- factory-rules begin version=1 -->\n<!-- factory-rules end -->\n",
            "<!-- factory-rules begin version=0 -->\nx\n<!-- factory-rules end -->\n",
            "<!-- factory-rules begin version=01 -->\nx\n<!-- factory-rules end -->\n",
            "<!-- factory-rules begin version=-1 -->\nx\n<!-- factory-rules end -->\n",
            "<!-- factory-rules begin version=1.5 -->\nx\n<!-- factory-rules end -->\n",
            "<!-- factory-rules begin version=4294967296 -->\nx\n<!-- factory-rules end -->\n",
            "<!-- factory-rules begin version= -->\nx\n<!-- factory-rules end -->\n",
            "<!-- factory-rules begin -->\nx\n<!-- factory-rules end -->\n",
            "<!-- factory-rules begin version=1 -->\nx\n<!-- factory-rules end --> trailing\n",
        ];
        for text in bad {
            assert_eq!(
                found(text),
                Installed::Unreadable(Unreadable::MalformedMarkers),
                "{text}"
            );
            assert_eq!(render(&found(text), template(1)), None);
        }
    }

    #[test]
    fn size_and_encoding_limits() {
        let at_limit = "a".repeat(MAX_RULES_BYTES);
        assert!(matches!(found(&at_limit), Installed::WithoutMarkers { .. }));
        let over = "a".repeat(MAX_RULES_BYTES + 1);
        assert_eq!(found(&over), Installed::Unreadable(Unreadable::TooLarge));
        assert_eq!(
            read_installed(FileFound::TooLarge),
            Installed::Unreadable(Unreadable::TooLarge)
        );
        assert_eq!(
            read_installed(FileFound::Bytes(&[0xff, 0xfe])),
            Installed::Unreadable(Unreadable::NotUtf8)
        );
        assert_eq!(read_installed(FileFound::Missing), Installed::Missing);
        assert!(matches!(found(""), Installed::WithoutMarkers { .. }));
    }

    #[test]
    fn the_decision_follows_the_table() {
        use Decision::{Nothing, Propose};
        use NothingBecause as N;
        let current = 3;
        for state in [
            RulesState::Missing,
            RulesState::WithoutMarkers,
            RulesState::Older { installed: 2 },
        ] {
            assert_eq!(decide(state, Proposal::None, current), Propose);
            assert_eq!(decide(state, Proposal::Open(None), current), Propose);
            assert_eq!(decide(state, Proposal::Open(Some(2)), current), Propose);
            assert_eq!(
                decide(state, Proposal::Open(Some(3)), current),
                Nothing(N::AlreadyProposed)
            );
            assert_eq!(
                decide(state, Proposal::Open(Some(4)), current),
                Nothing(N::NewerFactory)
            );
            assert_eq!(
                decide(state, Proposal::Closed(Some(3)), current),
                Nothing(N::Declined)
            );
            assert_eq!(decide(state, Proposal::Closed(Some(2)), current), Propose);
            assert_eq!(decide(state, Proposal::Closed(None), current), Propose);
            assert_eq!(
                decide(state, Proposal::Merged(Some(3)), current),
                Nothing(N::Reverted)
            );
            assert_eq!(decide(state, Proposal::Merged(Some(1)), current), Propose);
            assert_eq!(
                decide(state, Proposal::Merged(Some(9)), current),
                Nothing(N::NewerFactory)
            );
        }
        for proposal in [
            Proposal::None,
            Proposal::Open(Some(2)),
            Proposal::Closed(None),
        ] {
            assert_eq!(
                decide(RulesState::Current, proposal, current),
                Nothing(N::UpToDate)
            );
            assert_eq!(
                decide(RulesState::EditedByHand, proposal, current),
                Nothing(N::EditedByHand)
            );
            assert_eq!(
                decide(RulesState::Newer { installed: 4 }, proposal, current),
                Nothing(N::NewerFactory)
            );
            assert_eq!(
                decide(
                    RulesState::Unreadable(Unreadable::MalformedMarkers),
                    proposal,
                    current
                ),
                Nothing(N::Unreadable(Unreadable::MalformedMarkers))
            );
        }
    }

    #[test]
    fn agents_get_the_file_or_the_built_in_copy() {
        let t = template(2);
        let built_in = format!("{}{DEFAULT_PROJECT_SECTION}", t.managed_block());

        let missing = rules_for_agents(FileFound::Missing, t);
        assert_eq!(missing.origin, Origin::FactoryDefault);
        assert_eq!(missing.text, built_in);
        assert_eq!(missing.fallback, None);

        let large = rules_for_agents(FileFound::TooLarge, t);
        assert_eq!(
            (large.origin, large.fallback),
            (Origin::FactoryDefault, Some(Unreadable::TooLarge))
        );
        assert_eq!(large.text, built_in);
        let over = "a".repeat(MAX_RULES_BYTES + 1);
        assert_eq!(
            rules_for_agents(FileFound::Bytes(over.as_bytes()), t).fallback,
            Some(Unreadable::TooLarge)
        );

        let binary = rules_for_agents(FileFound::Bytes(&[0xc3, 0x28]), t);
        assert_eq!(
            (binary.origin, binary.fallback),
            (Origin::FactoryDefault, Some(Unreadable::NotUtf8))
        );

        let theirs = rules_for_agents(FileFound::Bytes(b"Use tabs.\n"), t);
        assert_eq!(theirs.origin, Origin::RepositoryWithFactoryRules);
        assert_eq!(theirs.text, format!("{}\nUse tabs.\n", t.managed_block()));

        let older =
            "<!-- factory-rules begin version=1 -->\nold\n<!-- factory-rules end -->\nours\n";
        let managed = rules_for_agents(FileFound::Bytes(older.as_bytes()), t);
        assert_eq!(managed.origin, Origin::Repository);
        assert_eq!(
            managed.text, older,
            "an approved older version applies as installed"
        );

        let broken = "<!-- factory-rules begin version=1 -->\nno end\n";
        let kept = rules_for_agents(FileFound::Bytes(broken.as_bytes()), t);
        assert_eq!(
            (kept.origin, kept.text.as_str()),
            (Origin::Repository, broken)
        );
    }

    #[test]
    fn the_pull_request_text_is_closed_and_names_the_version_and_the_skeleton() {
        let (title, body) =
            pull_request_text(RulesState::Older { installed: 1 }, 2, &["docs/README.md"]);
        assert_eq!(
            title,
            "Update the rules for agents in AGENTS.md to version 2"
        );
        assert!(body.contains("version 1, with version 2"));
        assert!(body.contains("- `docs/README.md`"));
        assert!(body.contains("never merges"));
        let (title, body) = pull_request_text(RulesState::Missing, 1, &[]);
        assert_eq!(
            title,
            "Install the rules for agents in AGENTS.md (version 1)"
        );
        assert!(!body.contains("index files"));
        assert!(title.len() <= 256 && body.len() < 4000);
    }
}
