//! `schemas/project-manifest.schema.json`: the project-local `.factory/project.yaml`.
//!
//! It names the domain tags, the sandbox image, the gate commands, the protected paths, the
//! pinned Spec Kit version and the required documents. The validation stage reads it from the
//! protected base branch, never from the builder's branch, so a builder cannot weaken its own
//! gates. The manifest protects itself: `.factory/**` must be a protected path.
//!
//! This type is stricter than the schema in one place: a gate command may not start a shell,
//! whichever way the shell is spelled (see [`names_a_shell`]).

use serde::{Deserialize, Serialize};

use super::common::SchemaVersion;
use super::{Violations, contract};
use std::sync::LazyLock;

use regex::Regex;

use crate::error::ValueError;
use crate::macros::{string_enum, string_traits};
use crate::patterns;
use crate::values::{Bounded, HumanText, HumanTitle, NonEmptyString, NonEmptyVec, Slug, UniqueVec};

/// The protected path that keeps the manifest from being edited by the builder.
pub const SELF_PROTECTING_PATH: &str = ".factory/**";

/// Programs that are shells. A gate command is an argument vector, never a shell string.
const SHELLS: [&str; 8] = [
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "cmd",
    "powershell",
    "pwsh",
];

static WORKDIR_SHAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(patterns::WORKDIR).expect("a schema pattern is a valid regex"));
static GATE_CWD_SHAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(patterns::GATE_CWD).expect("a schema pattern is a valid regex"));

/// True when a path has a `..` segment, which can leave the directory it is meant to stay in.
fn climbs(path: &str) -> bool {
    path.split('/').any(|segment| segment == "..")
}

/// An absolute working directory inside the sandbox, such as `/workspace`.
///
/// The schema pattern allows `..` segments, so `/workspace/../etc` passes it. This type does not.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Workdir(String);

impl Workdir {
    /// Checks the pattern and refuses `..` segments.
    ///
    /// # Errors
    /// Returns a [`ValueError`] when the path is not an absolute path without `..`.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        const WHAT: &str = "working directory";
        if !WORKDIR_SHAPE.is_match(text) {
            return Err(ValueError::new(
                WHAT,
                text,
                "use an absolute path such as /workspace, with letters, digits, dots, underscores, hyphens and slashes only",
            ));
        }
        if climbs(text) {
            return Err(ValueError::new(
                WHAT,
                text,
                "use a path with no `..` segment, which could leave the intended directory",
            ));
        }
        Ok(Self(text.to_owned()))
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_traits!(Workdir);

/// A working directory for a gate command, relative to the repository. May be empty, which means
/// the repository root.
///
/// The schema pattern allows a leading slash and `..` segments, so `/etc` and `../outside` pass
/// it. This type refuses both, because a gate must run inside the repository it checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GateCwd(String);

impl GateCwd {
    /// Checks the pattern, refuses a leading slash and refuses `..` segments.
    ///
    /// # Errors
    /// Returns a [`ValueError`] when the path is not a relative path without `..`.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        const WHAT: &str = "gate working directory";
        if !GATE_CWD_SHAPE.is_match(text) {
            return Err(ValueError::new(
                WHAT,
                text,
                "use a relative path with letters, digits, dots, underscores, hyphens and slashes only",
            ));
        }
        if text.starts_with('/') {
            return Err(ValueError::new(
                WHAT,
                text,
                "a gate working directory is relative to the repository, so it cannot start with a slash",
            ));
        }
        if climbs(text) {
            return Err(ValueError::new(
                WHAT,
                text,
                "use a path with no `..` segment, which could leave the repository",
            ));
        }
        Ok(Self(text.to_owned()))
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_traits!(GateCwd);

/// The gate whose command is a test run. Only this gate may declare a test report.
pub const TEST_GATE_ID: &str = "unit-tests";

string_enum! {
    /// A format in which a test command reports its results. The set is closed: the factory
    /// reads only these.
    pub enum TestReportFormat("test report format") {
        /// What the Rust test harness prints (`cargo test`). Read from the two output streams
        /// of the command. This is the format of a gate that declares none.
        Libtest = "libtest",
        /// The JUnit XML report that pytest (`--junitxml`), jest-junit, go-junit-report, Maven
        /// Surefire, Gradle and cargo-nextest write.
        JunitXml = "junit-xml",
        /// The Test Anything Protocol, version 13 or 14.
        Tap = "tap",
    }
}

/// Where a test command writes its report: a file path relative to the output directory of the
/// verify sandbox (`/out`), which is the only directory that the test command can write to and
/// that the factory reads back. The checkout itself is mounted read-only there.
///
/// The schema pattern allows a leading slash and `..` segments. This type refuses both, and a
/// trailing slash, because the report must be one file inside the output directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReportPath(String);

impl ReportPath {
    /// Checks the pattern and refuses an empty path, a leading or trailing slash and `..`.
    ///
    /// # Errors
    /// Returns a [`ValueError`] when the path is not a relative file path without `..`.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        const WHAT: &str = "test report path";
        if text.is_empty() || !GATE_CWD_SHAPE.is_match(text) {
            return Err(ValueError::new(
                WHAT,
                text,
                "use a relative file path with letters, digits, dots, underscores, hyphens and slashes only",
            ));
        }
        if text.starts_with('/') {
            return Err(ValueError::new(
                WHAT,
                text,
                "a test report path is relative to the output directory of the sandbox, so it cannot start with a slash",
            ));
        }
        if climbs(text)
            || text
                .split('/')
                .any(|segment| segment.is_empty() || segment == ".")
        {
            return Err(ValueError::new(
                WHAT,
                text,
                "use a path with no `..`, `.` or empty segment, which could leave the output directory or name a directory",
            ));
        }
        Ok(Self(text.to_owned()))
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_traits!(ReportPath);

/// How the result of a test gate is read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestReportSpec {
    /// The format of the report.
    pub format: TestReportFormat,
    /// The report file, relative to the output directory of the sandbox. Without a path the
    /// report is read from the standard output of the command. `libtest` takes no path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<ReportPath>,
}

/// True when `program` is a shell: one of the names the schema lists, written with or without a
/// directory, in any letter case, with or without `.exe`.
///
/// The schema compares the first argument with the eight names as written. `/bin/sh`, `BASH`
/// and `bash.exe` would slip past that comparison and start a shell all the same.
#[must_use]
pub fn names_a_shell(program: &str) -> bool {
    let file_name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = file_name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    SHELLS.contains(&stem)
}

/// What the project is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// The project's machine name.
    pub name: Slug,
    /// A plain-English title.
    pub title: HumanTitle,
    /// Matched against the domain capability profiles.
    pub domain_tags: UniqueVec<Slug, 1>,
    /// The default branch.
    pub default_branch: NonEmptyString,
}

/// The sandbox the project's gates run in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    /// A logical image name. The digest comes from the factory's image registry file, not from
    /// the repository.
    pub image: Slug,
    /// The working directory.
    pub workdir: Workdir,
}

/// One gate command.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateCommandSpec {
    /// The gate.
    pub id: Slug,
    /// A plain-English title.
    pub title: HumanTitle,
    /// The executable and its arguments. A shell as the first element is not allowed.
    pub argv: NonEmptyVec<String>,
    /// The working directory, relative to the repository.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<GateCwd>,
    /// Seconds before the command is stopped, 1 to 7200.
    pub timeout_seconds: Bounded<1, 7200>,
    /// Whether the gate must pass.
    pub mandatory: bool,
    /// How the test results are read. Only the `unit-tests` gate may say. A gate that does not
    /// say is read as `libtest`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_report: Option<TestReportSpec>,
}

/// The pinned Spec Kit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecToolPin {
    /// The pinned `specify` version, for example `1.1.2`.
    pub cli_version: NonEmptyString,
    /// The integration.
    pub integration: NonEmptyString,
    /// Whether the factory may run `specify init` in this repository.
    pub may_initialize: bool,
}

/// A document the project must have.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredDocument {
    /// The path.
    pub path: NonEmptyString,
    /// What it is for.
    pub purpose: HumanText,
}

string_enum! {
    /// A readability rule that only warns, which a repository may switch off. A rule that blocks
    /// is not in this list, so a manifest cannot name one.
    pub enum ReadabilityRule("readability rule") {
        /// A title starts with a type tag and a colon, such as `feat(auth):` or `URGENT:`. Many
        /// teams write conventional-commit titles by habit, and the tag does not make the title
        /// unclear (ADR 0009 item 19).
        TitleTypeTag = "title-type-tag",
    }
}

/// The project's documentation rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationRules {
    /// Documents that must exist.
    pub required_documents: Vec<RequiredDocument>,
    /// The changelog.
    pub changelog_path: NonEmptyString,
    /// Readability rules that this repository switches off. Only rules that warn can be listed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_readability_rules: Option<UniqueVec<ReadabilityRule>>,
}

contract! {
    "project-manifest";
    /// The project-local configuration a repository keeps in `.factory/project.yaml`.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
    pub struct ProjectManifest {
        /// Always 1.
        pub schema_version: SchemaVersion,
        /// What the project is.
        pub project: Project,
        /// The sandbox.
        pub sandbox: SandboxSpec,
        /// The gate commands. At least one is mandatory.
        pub gates: NonEmptyVec<GateCommandSpec>,
        /// Paths a builder may not change. Must include `.factory/**`.
        pub protected_paths: UniqueVec<NonEmptyString, 1>,
        /// The pinned Spec Kit.
        pub spec_kit: SpecToolPin,
        /// Documentation rules.
        pub documentation: DocumentationRules,
    }
}

impl ProjectManifest {
    fn check(&self, found: &mut Violations) {
        found.require(
            self.gates.iter().any(|gate| gate.mandatory),
            "gates",
            "at least one gate must be mandatory",
        );
        for (index, gate) in self.gates.iter().enumerate() {
            let starts_a_shell = gate
                .argv
                .first()
                .is_some_and(|program| names_a_shell(program));
            found.require(
                !starts_a_shell,
                format!("gates[{index}].argv"),
                "a gate command must not start a shell; list the program and its arguments directly",
            );
            if let Some(report) = &gate.test_report {
                found.require(
                    gate.id.as_str() == TEST_GATE_ID,
                    format!("gates[{index}].test_report"),
                    "only the gate `unit-tests` reads a test report; remove `test_report` from this gate",
                );
                found.require(
                    report.format != TestReportFormat::Libtest || report.path.is_none(),
                    format!("gates[{index}].test_report.path"),
                    "the libtest format is read from the output of the command and takes no report path",
                );
            }
        }
        found.require(
            self.protected_paths
                .iter()
                .any(|path| path.as_str() == SELF_PROTECTING_PATH),
            "protected_paths",
            "the manifest must protect itself, so `.factory/**` must be a protected path",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{ReportPath, names_a_shell};

    #[test]
    fn a_report_path_is_a_relative_file_path_that_cannot_leave_the_output_directory() {
        for good in ["report.xml", "reports/junit.xml", "a/b/c.tap", "..hidden"] {
            assert!(ReportPath::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "/out/report.xml",
            "../report.xml",
            "reports/../../x",
            "reports/",
            "a//b",
            "./report.xml",
            "report xml",
            "report.xml\n",
            "~/report.xml",
        ] {
            assert!(ReportPath::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn shells_are_found_however_they_are_spelled() {
        for shell in [
            "sh",
            "bash",
            "zsh",
            "fish",
            "dash",
            "cmd",
            "powershell",
            "pwsh",
        ] {
            assert!(names_a_shell(shell), "{shell}");
        }
        for spelled in [
            "/bin/sh",
            "/usr/bin/bash",
            "BASH",
            "Bash.EXE",
            "C:\\Windows\\System32\\cmd.exe",
            "./sh",
        ] {
            assert!(names_a_shell(spelled), "{spelled}");
        }
    }

    #[test]
    fn ordinary_programs_are_not_shells() {
        for program in [
            "cargo",
            "npm",
            "/usr/bin/git",
            "shellcheck",
            "bashful",
            "sh-tool",
            "python3",
            "",
        ] {
            assert!(!names_a_shell(program), "{program}");
        }
    }
}
