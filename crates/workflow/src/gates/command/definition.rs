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
use factory_domain::policy::SandboxProfileKind;
use factory_domain::policy::commands::{CommandPolicy, CommandVerdict};
use factory_domain::values::{GitSha, HumanTitle, Sha256Digest, Slug};
use factory_ports::paths::RepoPath;

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
}

impl CommandGate {
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

/// A hash over everything that decides what runs: the identifier, the declared and the effective
/// vector, the directory and the time limit of each gate, in manifest order.
fn hash_of(entries: &[Resolved]) -> Sha256Digest {
    let listed: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| match entry {
            Resolved::Ready(gate) => serde_json::json!({
                "id": gate.id.as_str(),
                "declared": gate.declared,
                "argv": gate.argv,
                "cwd": gate.cwd.as_ref().map(RepoPath::as_str),
                "timeout_seconds": gate.timeout.as_secs(),
            }),
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
