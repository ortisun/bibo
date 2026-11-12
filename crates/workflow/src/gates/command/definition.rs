//! Gate definitions as data, read from a trusted place.
//!
//! A gate is an argument vector, a working directory and a time limit. The set of gates of a
//! project is the `gates` list of its project manifest, and the validation stage reads that
//! manifest from the **base commit** (the protected default branch), never from the builder's
//! commit. This module turns the typed manifest into [`CommandGate`] values and never sees a
//! file of the builder.
//!
//! Every argument vector passes through the command policy for the `verify` profile first. A
//! vector that the policy denies, or that needs a person, is [`Resolved::Refused`] and the gate
//! is `BLOCKED` (a gate that cannot be run as written is not a gate that passed). The vector that
//! runs is the policy's own: the declared one with the forced arguments inserted.
//!
//! The hash of the resolved set is recorded in every gate report (`definition_sha256`) and in the
//! evidence binding, so evidence made from one set of definitions does not count for another.

use std::time::Duration;

use factory_domain::contracts::ProjectManifest;
use factory_domain::contracts::gate_report::DefinitionSource;
use factory_domain::contracts::project_manifest::{TestReportFormat, TestReportSpec};
use factory_domain::policy::SandboxProfileKind;
use factory_domain::policy::commands::{CommandPolicy, CommandVerdict};
use factory_domain::values::{GitSha, HumanTitle, Sha256Digest, Slug};
use factory_ports::paths::RepoPath;
use factory_ports::sandbox::OUT_TARGET;

use super::outcomes::ReportKind;

/// Where the project manifest lives in the repository. The path is protected, so the builder
/// cannot change it, and it is read at the base commit in any case.
pub const MANIFEST_PATH: &str = ".factory/project.yaml";

/// The same manifest written as JSON.
pub const MANIFEST_JSON_PATH: &str = ".factory/project.json";

/// The identifiers of the gates that the validation stage knows by name.
pub mod gate_id {
    /// The formatter check.
    pub const FORMAT: &str = "format";
    /// The linter.
    pub const LINT: &str = "lint";
    /// The build.
    pub const BUILD: &str = "build";
    /// The tests.
    pub const UNIT_TESTS: &str = "unit-tests";
    /// No protected path changed (host side).
    pub const PROTECTED_PATHS: &str = "protected-paths-unchanged";
    /// Existing tests were not removed, weakened or skipped.
    pub const TEST_PROTECTION: &str = "test-file-protection";
    /// The change holds no secret (host side).
    pub const SECRET_SCAN: &str = "secret-scan";
    /// Every requirement of the frozen specification has a covering test result.
    pub const ACCEPTANCE: &str = "acceptance-evidence";
    /// The evidence is about this commit, this policy and this image.
    pub const EVIDENCE_BINDING: &str = "evidence-binding";
}

/// What a command gate is for. It decides how its output is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The formatter check.
    Format,
    /// The linter.
    Lint,
    /// The build.
    Build,
    /// The tests: the output must show that tests ran, and it is compared with the baseline.
    Tests,
    /// Any other gate of the manifest: it passes on exit code 0 and nothing else.
    Other,
}

impl Role {
    /// The role of the gate with this identifier.
    #[must_use]
    pub fn of(id: &str) -> Self {
        match id {
            gate_id::FORMAT => Self::Format,
            gate_id::LINT => Self::Lint,
            gate_id::BUILD => Self::Build,
            gate_id::UNIT_TESTS => Self::Tests,
            _ => Self::Other,
        }
    }

    /// True when a pass must show that tests ran.
    #[must_use]
    pub const fn expects_tests(self) -> bool {
        matches!(self, Self::Tests)
    }
}

/// Where the results of a test gate are read from, as the project manifest declares it
/// (`test_report`). A gate that declares nothing is [`TestReport::Libtest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestReport {
    /// The output of the Rust test harness, on the two streams of the command.
    Libtest,
    /// A report of this kind on the standard output of the command. Nothing else may be on it.
    Stdout(ReportKind),
    /// A report of this kind in a file that the command writes in the output directory of the
    /// sandbox. The path is relative to that directory.
    File(ReportKind, String),
}

impl TestReport {
    fn of(role: Role, spec: Option<&TestReportSpec>) -> Self {
        let Some(spec) = spec.filter(|_| role.expects_tests()) else {
            return Self::Libtest;
        };
        let kind = match spec.format {
            TestReportFormat::Libtest => return Self::Libtest,
            TestReportFormat::JunitXml => ReportKind::JunitXml,
            TestReportFormat::Tap => ReportKind::Tap,
        };
        match &spec.path {
            Some(path) => Self::File(kind, path.as_str().to_owned()),
            None => Self::Stdout(kind),
        }
    }
}

/// One gate that can run: a command in the verify image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandGate {
    /// The gate.
    pub id: Slug,
    /// What a person reads.
    pub title: HumanTitle,
    /// How its output is read.
    pub role: Role,
    /// The vector as the manifest wrote it.
    pub declared: Vec<String>,
    /// The vector that runs: the declared one with the forced arguments of the policy.
    pub argv: Vec<String>,
    /// The directory to run in, relative to the workspace. `None` is the workspace root.
    pub cwd: Option<RepoPath>,
    /// How long the command may run.
    pub timeout: Duration,
    /// Where the test results are read from. Always [`TestReport::Libtest`] for a gate that is
    /// not the test gate.
    pub report: TestReport,
}

impl CommandGate {
    /// The command that reads the test report file back, run by the supervisor in the same
    /// sandbox after the test command ended. `None` when the gate reads no file.
    ///
    /// The file is in the output directory of the sandbox (`/out`), because the checkout is
    /// mounted read-only in the verify sandbox. The path was checked when the manifest was read:
    /// it is relative and has no `..`, so the vector cannot name a file outside that directory.
    /// The output of this command is cut at the same size limit as any other, and a report that
    /// is cut is never accepted.
    #[must_use]
    pub fn report_command(&self) -> Option<Vec<String>> {
        match &self.report {
            TestReport::File(_, path) => {
                Some(vec!["cat".to_owned(), format!("{OUT_TARGET}/{path}")])
            }
            TestReport::Libtest | TestReport::Stdout(_) => None,
        }
    }

    /// The commands that report the version of each tool the gate needs, run before the gate.
    /// A probe that cannot run means the tool is absent and the gate is `BLOCKED`.
    ///
    /// `cargo` brings `rustc` with it, and `cargo fmt` and `cargo clippy` are separate
    /// components that the image may not hold, so they are probed on their own.
    #[must_use]
    pub fn probes(&self) -> Vec<Vec<String>> {
        let program = self.argv.first().map_or("", String::as_str);
        if program.is_empty() {
            return Vec::new();
        }
        let mut probes = vec![vec![program.to_owned(), "--version".to_owned()]];
        if program == "cargo" {
            probes.push(vec!["rustc".to_owned(), "--version".to_owned()]);
            if let Some(sub @ ("fmt" | "clippy")) = self.argv.get(1).map(String::as_str) {
                probes.push(vec![
                    "cargo".to_owned(),
                    sub.to_owned(),
                    "--version".to_owned(),
                ]);
            }
        }
        probes
    }
}

/// Why a gate of the manifest cannot run. The set is closed and holds no text of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The command policy denies the vector. The rule is the one the policy names.
    Denied {
        /// The policy rule, such as `forbidden_command_classes:shell_interpreters`.
        rule: String,
    },
    /// The command policy asks for a person before the vector may run.
    NeedsPerson,
    /// The working directory is not a path inside the repository.
    BadWorkingDirectory,
}

/// A gate of the manifest after the policy has looked at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// The gate can run.
    Ready(CommandGate),
    /// The gate cannot run as written. It is reported `BLOCKED`.
    Refused {
        /// The gate.
        id: Slug,
        /// What a person reads.
        title: HumanTitle,
        /// Why.
        why: Refusal,
    },
}

impl Resolved {
    /// The gate's identifier.
    #[must_use]
    pub fn id(&self) -> &Slug {
        match self {
            Self::Ready(gate) => &gate.id,
            Self::Refused { id, .. } => id,
        }
    }
}

/// The gates of one project, resolved from the manifest at the base commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedGates {
    commit: GitSha,
    hash: Sha256Digest,
    entries: Vec<Resolved>,
}

impl TrustedGates {
    /// Resolves the gates of `manifest`, which was read at `commit` of the protected branch.
    #[must_use]
    pub fn resolve(manifest: &ProjectManifest, commit: GitSha, commands: &CommandPolicy) -> Self {
        let entries: Vec<Resolved> = manifest
            .gates
            .iter()
            .map(|spec| {
                let declared: Vec<String> = spec.argv.as_slice().to_vec();
                let cwd = match spec.cwd.as_ref().map(|dir| dir.as_str()) {
                    None | Some("") => Ok(None),
                    Some(dir) => RepoPath::new(dir).map(Some),
                };
                let (Ok(cwd), verdict) = (
                    cwd,
                    commands.evaluate(&declared, SandboxProfileKind::Verify),
                ) else {
                    return Resolved::Refused {
                        id: spec.id.clone(),
                        title: spec.title.clone(),
                        why: Refusal::BadWorkingDirectory,
                    };
                };
                match verdict {
                    CommandVerdict::Allowed(allowed) => Resolved::Ready(CommandGate {
                        id: spec.id.clone(),
                        title: spec.title.clone(),
                        role: Role::of(spec.id.as_str()),
                        report: TestReport::of(
                            Role::of(spec.id.as_str()),
                            spec.test_report.as_ref(),
                        ),
                        argv: effective_argv(&declared, allowed.argv),
                        declared,
                        cwd,
                        timeout: Duration::from_secs(spec.timeout_seconds.get().unsigned_abs()),
                    }),
                    CommandVerdict::RequireHuman { .. } => Resolved::Refused {
                        id: spec.id.clone(),
                        title: spec.title.clone(),
                        why: Refusal::NeedsPerson,
                    },
                    CommandVerdict::Denied(denial) => Resolved::Refused {
                        id: spec.id.clone(),
                        title: spec.title.clone(),
                        why: Refusal::Denied {
                            rule: denial.rule.to_string(),
                        },
                    },
                }
            })
            .collect();
        let hash = hash_of(&entries);
        Self {
            commit,
            hash,
            entries,
        }
    }

    /// Where the definitions came from: always the protected base branch.
    #[must_use]
    pub const fn source(&self) -> DefinitionSource {
        DefinitionSource::ProtectedBaseBranch
    }

    /// The base commit the manifest was read at.
    #[must_use]
    pub fn commit(&self) -> &GitSha {
        &self.commit
    }

    /// The hash of the resolved set.
    #[must_use]
    pub fn hash(&self) -> &Sha256Digest {
        &self.hash
    }

    /// Every gate, in the order of the manifest.
    #[must_use]
    pub fn entries(&self) -> &[Resolved] {
        &self.entries
    }

    /// The gate with this identifier.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&Resolved> {
        self.entries.iter().find(|entry| entry.id().as_str() == id)
    }
}

/// The vector the policy allowed, except for `cargo fmt`.
///
/// The policy forces `--offline --locked` into every `cargo` call of the verify profile, and
/// `cargo fmt` refuses both ("unexpected argument '--offline' found", exit code 2, observed in
/// the pinned verify image). The formatter reads no dependency, so the declared vector is the
/// one that runs. The policy still had to allow it.
fn effective_argv(declared: &[String], allowed: Vec<String>) -> Vec<String> {
    let is_cargo_fmt = declared.first().map(String::as_str) == Some("cargo")
        && declared.get(1).map(String::as_str) == Some("fmt");
    if is_cargo_fmt {
        declared.to_vec()
    } else {
        allowed
    }
}

/// A hash over everything that decides what runs and how the result is read: the identifier,
/// the declared and the effective vector, the directory and the time limit of each gate, and the
/// test report of a gate that declares one, in manifest order. A gate that reads the default
/// (libtest) adds nothing, so the hash of a manifest written before test reports existed is
/// unchanged.
fn hash_of(entries: &[Resolved]) -> Sha256Digest {
    let listed: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| match entry {
            Resolved::Ready(gate) => {
                let mut one = serde_json::json!({
                    "id": gate.id.as_str(),
                    "declared": gate.declared,
                    "argv": gate.argv,
                    "cwd": gate.cwd.as_ref().map(RepoPath::as_str),
                    "timeout_seconds": gate.timeout.as_secs(),
                });
                match &gate.report {
                    TestReport::Libtest => {}
                    TestReport::Stdout(kind) => {
                        one["test_report"] = serde_json::json!({ "format": kind.as_str() });
                    }
                    TestReport::File(kind, path) => {
                        one["test_report"] =
                            serde_json::json!({ "format": kind.as_str(), "path": path });
                    }
                }
                one
            }
            Resolved::Refused { id, why, .. } => serde_json::json!({
                "id": id.as_str(),
                "refused": format!("{why:?}"),
            }),
        })
        .collect();
    Sha256Digest::of(serde_json::Value::Array(listed).to_string().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(argv: &[&str]) -> CommandGate {
        CommandGate {
            id: Slug::parse("lint").expect("a slug"),
            title: HumanTitle::parse("Lint the code").expect("a title"),
            role: Role::Lint,
            declared: argv.iter().map(|a| (*a).to_owned()).collect(),
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            cwd: None,
            timeout: Duration::from_secs(60),
            report: TestReport::Libtest,
        }
    }

    #[test]
    fn the_role_of_a_gate_comes_from_its_identifier() {
        assert_eq!(Role::of("format"), Role::Format);
        assert_eq!(Role::of("lint"), Role::Lint);
        assert_eq!(Role::of("build"), Role::Build);
        assert_eq!(Role::of("unit-tests"), Role::Tests);
        assert_eq!(Role::of("anything-else"), Role::Other);
        assert!(Role::Tests.expects_tests());
        assert!(!Role::Build.expects_tests());
    }

    #[test]
    fn a_cargo_gate_probes_cargo_and_rustc_and_its_component() {
        let probes = gate(&["cargo", "clippy", "--all-targets"]).probes();
        assert_eq!(
            probes,
            vec![
                vec!["cargo", "--version"],
                vec!["rustc", "--version"],
                vec!["cargo", "clippy", "--version"],
            ]
        );
        let probes = gate(&["cargo", "test"]).probes();
        assert_eq!(probes.len(), 2);
        let probes = gate(&["npm", "test"]).probes();
        assert_eq!(probes, vec![vec!["npm", "--version"]]);
    }

    /// The gates of a manifest whose test gate declares this `test_report`.
    fn resolved(test_report: Option<serde_json::Value>) -> TrustedGates {
        let mut tests = serde_json::json!({
            "id": "unit-tests", "title": "Run the tests", "argv": ["pytest"],
            "timeout_seconds": 60, "mandatory": true
        });
        if let Some(report) = test_report {
            tests["test_report"] = report;
        }
        let manifest: ProjectManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "project": { "name": "wc", "title": "Word count tool", "domain_tags": ["general-software"], "default_branch": "main" },
            "sandbox": { "image": "python-fixture", "workdir": "/workspace" },
            "gates": [tests],
            "protected_paths": [".factory/**"],
            "spec_kit": { "cli_version": "1.1.2", "integration": "claude", "may_initialize": true },
            "documentation": { "required_documents": [], "changelog_path": "CHANGELOG.md" }
        }))
        .expect("a manifest");
        let security: factory_domain::policy::SecurityPolicy = serde_json::from_str(include_str!(
            "../../../../domain/tests/fixtures/policy/security.json"
        ))
        .expect("the security policy fixture");
        let commands = CommandPolicy::from_policy(&security).expect("a command policy");
        let commit = GitSha::parse(&"a".repeat(40)).expect("a commit");
        TrustedGates::resolve(&manifest, commit, &commands)
    }

    fn test_gate(gates: &TrustedGates) -> &CommandGate {
        match gates.find("unit-tests") {
            Some(Resolved::Ready(gate)) => gate,
            other => panic!("the test gate is not ready: {other:?}"),
        }
    }

    #[test]
    fn a_gate_that_declares_no_test_report_reads_libtest_and_keeps_its_hash() {
        let plain = resolved(None);
        assert_eq!(test_gate(&plain).report, TestReport::Libtest);
        assert_eq!(test_gate(&plain).report_command(), None);
        let explicit = resolved(Some(serde_json::json!({ "format": "libtest" })));
        assert_eq!(test_gate(&explicit).report, TestReport::Libtest);
        assert_eq!(
            plain.hash(),
            explicit.hash(),
            "naming the default changes nothing that runs or is read"
        );
    }

    #[test]
    fn a_declared_test_report_decides_what_is_read_and_enters_the_hash() {
        let plain = resolved(None);
        let file = resolved(Some(
            serde_json::json!({ "format": "junit-xml", "path": "reports/junit.xml" }),
        ));
        assert_eq!(
            test_gate(&file).report,
            TestReport::File(ReportKind::JunitXml, "reports/junit.xml".to_owned())
        );
        assert_eq!(
            test_gate(&file).report_command(),
            Some(vec!["cat".to_owned(), "/out/reports/junit.xml".to_owned()])
        );
        let stdout = resolved(Some(serde_json::json!({ "format": "tap" })));
        assert_eq!(
            test_gate(&stdout).report,
            TestReport::Stdout(ReportKind::Tap)
        );
        assert_eq!(test_gate(&stdout).report_command(), None);
        let other_path = resolved(Some(
            serde_json::json!({ "format": "junit-xml", "path": "other.xml" }),
        ));
        let hashes: std::collections::BTreeSet<String> = [&plain, &file, &stdout, &other_path]
            .iter()
            .map(|gates| gates.hash().to_string())
            .collect();
        assert_eq!(hashes.len(), 4, "each way of reading has its own hash");
    }

    #[test]
    fn the_formatter_keeps_its_declared_vector() {
        let declared: Vec<String> = ["cargo", "fmt", "--check"].map(String::from).to_vec();
        let forced: Vec<String> = ["cargo", "fmt", "--offline", "--locked", "--check"]
            .map(String::from)
            .to_vec();
        assert_eq!(effective_argv(&declared, forced.clone()), declared);
        let test: Vec<String> = ["cargo", "test"].map(String::from).to_vec();
        assert_eq!(effective_argv(&test, forced.clone()), forced);
    }
}
