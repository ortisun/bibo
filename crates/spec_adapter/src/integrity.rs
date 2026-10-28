//! The integrity of the installation, checked on the host over committed bytes.
//!
//! A modified skill changes what the agent does, so the stage runs only on an installation that is
//! exactly the pinned one. The checks here read the bytes of the files the host read from a commit
//! (a [`FileView`]), never the sandbox and never the agent's report.
//!
//! | Check | Fails with |
//! |---|---|
//! | Recorded versions (`init-options.json`, `integration.json`, each manifest) equal the pinned version | `VersionMismatch` |
//! | Spec Kit is installed at all | `ToolMissing` |
//! | Every installed file hashes to the pinned value | `IntegrityNotOk` |
//! | No extensions file | `ExtensionsPresent` |
//! | `specify integration status --json` reports `ok`, when its output is given | `IntegrityNotOk` |
//!
//! `init` is never run on an initialised repository: [`decide_setup`] is the only place that can
//! make an `init` command, and it cannot make one when the project is already initialised.

use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::paths::{Finding, RepoPath};
use factory_ports::spec::{SpecError, SpecFile};
use serde_json::Value;

use crate::invocation::{Host, PINNED_VERSION};
use crate::pinned::{CLAUDE_SKILLS, CODEX_SKILLS_PREFIX, PinnedFile, SHARED_FILES};

/// The recorded options of the installation.
pub const INIT_OPTIONS: &str = ".specify/init-options.json";
/// The recorded integration, with the invocation separator.
pub const INTEGRATION: &str = ".specify/integration.json";
/// The hooks file. It must not exist.
pub const EXTENSIONS: &str = ".specify/extensions.yml";

/// Paths and globs the host reads from a commit even when the run did not change them, so that
/// the integrity of the installation is judged on the committed bytes. The list of expected files
/// of a run starts from these.
pub const PROBE_GLOBS: [&str; 5] = [
    ".specify/extensions.yml",
    ".specify/extensions/**",
    "specs/*/plan.md",
    "specs/*/tasks.md",
    "specs/*/contracts/**",
];

/// Read access to the files the host handed over.
#[derive(Debug, Clone, Copy)]
pub struct FileView<'a> {
    files: &'a [SpecFile],
}

impl<'a> FileView<'a> {
    /// A view over the files of a set.
    #[must_use]
    pub const fn new(files: &'a [SpecFile]) -> Self {
        Self { files }
    }

    /// The bytes of a file, when the host handed it over.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&'a [u8]> {
        self.files
            .iter()
            .find(|file| file.path.as_str() == path)
            .map(|file| file.bytes.as_slice())
    }

    /// Every path the host handed over.
    pub fn paths(&self) -> impl Iterator<Item = &'a RepoPath> + use<'a> {
        self.files.iter().map(|file| &file.path)
    }
}

fn finding(rule: &str, path: &str) -> Finding {
    Finding {
        rule: Slug::parse(rule).expect("the rule names are slugs"),
        path: RepoPath::new(path).ok(),
        line: None,
    }
}

fn json_text(bytes: &[u8], pointer: &str) -> Option<String> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    value.pointer(pointer)?.as_str().map(str::to_owned)
}

/// The files the host reads to judge an installation on `host`: the configuration, the manifests,
/// and every file the pinned manifests list.
#[must_use]
pub fn installation_paths(host: Host) -> Vec<&'static str> {
    let mut paths = vec![
        INIT_OPTIONS,
        INTEGRATION,
        match host {
            Host::ClaudeCode => ".specify/integrations/claude.manifest.json",
            Host::Codex => ".specify/integrations/codex.manifest.json",
        },
        ".specify/integrations/speckit.manifest.json",
    ];
    paths.extend(skill_table(host).iter().map(|file| file.path));
    paths.extend(SHARED_FILES.iter().map(|file| file.path));
    paths
}

fn skill_table(host: Host) -> &'static [PinnedFile] {
    match host {
        Host::ClaudeCode => &CLAUDE_SKILLS,
        Host::Codex => &CODEX_SKILLS_PREFIX,
    }
}

fn matches_pin(pin: &PinnedFile, bytes: &[u8]) -> bool {
    let digest = Sha256Digest::of(bytes);
    digest.hex().starts_with(pin.sha256)
}

/// Checks the installation.
///
/// # Errors
/// * [`SpecError::ToolMissing`] when there is no `init-options.json`.
/// * [`SpecError::VersionMismatch`] when any recorded version differs from the pinned one.
/// * [`SpecError::ExtensionsPresent`] when the hooks file exists.
/// * [`SpecError::IntegrityNotOk`] with one finding for each pinned file that is missing or whose
///   bytes differ.
pub fn check_installation(view: &FileView<'_>, host: Host) -> Result<(), SpecError> {
    let options = view.get(INIT_OPTIONS).ok_or(SpecError::ToolMissing)?;
    let manifest = match host {
        Host::ClaudeCode => ".specify/integrations/claude.manifest.json",
        Host::Codex => ".specify/integrations/codex.manifest.json",
    };
    let recorded = [
        json_text(options, "/speckit_version"),
        view.get(INTEGRATION)
            .and_then(|bytes| json_text(bytes, "/version")),
        view.get(manifest)
            .and_then(|bytes| json_text(bytes, "/version")),
        view.get(".specify/integrations/speckit.manifest.json")
            .and_then(|bytes| json_text(bytes, "/version")),
    ];
    for found in recorded {
        match found {
            Some(version) if version == PINNED_VERSION => {}
            Some(version) => {
                return Err(SpecError::VersionMismatch {
                    expected: PINNED_VERSION.to_owned(),
                    found: version,
                });
            }
            None => {
                return Err(SpecError::IntegrityNotOk(vec![finding(
                    "recorded-version-missing",
                    INTEGRATION,
                )]));
            }
        }
    }
    if view.get(EXTENSIONS).is_some()
        || view
            .paths()
            .any(|p| p.as_str().starts_with(".specify/extensions/"))
    {
        return Err(SpecError::ExtensionsPresent);
    }
    let mut findings = Vec::new();
    for pin in skill_table(host).iter().chain(SHARED_FILES.iter()) {
        match view.get(pin.path) {
            None => findings.push(finding("managed-file-missing", pin.path)),
            Some(bytes) if !matches_pin(pin, bytes) => {
                findings.push(finding("managed-file-modified", pin.path));
            }
            Some(_) => {}
        }
    }
    if findings.is_empty() {
        Ok(())
    } else {
        Err(SpecError::IntegrityNotOk(findings))
    }
}

/// Checks the output of `specify integration status --json`, when the host has it.
///
/// # Errors
/// [`SpecError::IntegrityNotOk`] for any status but `ok`, for modified or missing managed files,
/// and for output that is not the JSON this version writes.
pub fn check_status_json(bytes: &[u8]) -> Result<(), SpecError> {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Err(SpecError::IntegrityNotOk(vec![finding(
            "status-unreadable",
            INTEGRATION,
        )]));
    };
    let count = |key: &str| value.get(key).and_then(Value::as_u64);
    let ok = value.get("status").and_then(Value::as_str) == Some("ok")
        && count("modified_managed_files") == Some(0)
        && count("missing_managed_files") == Some(0);
    if ok {
        return Ok(());
    }
    let mut findings: Vec<Finding> = value
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| f.get("code").and_then(Value::as_str))
        .filter_map(|code| Slug::parse(code).ok())
        .map(|rule| Finding {
            rule,
            path: None,
            line: None,
        })
        .collect();
    if findings.is_empty() {
        findings.push(finding("status-not-ok", INTEGRATION));
    }
    Err(SpecError::IntegrityNotOk(findings))
}

/// The command that sets Spec Kit up in a repository that has none. It cannot be made for a
/// repository that already has `.specify/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitCommand {
    host: Host,
}

impl InitCommand {
    /// The argument vector. `--integration` is always explicit: without it a non-interactive run
    /// silently picks another host.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        [
            "specify",
            "init",
            "--here",
            "--force",
            "--non-interactive",
            "--integration",
            self.host.key(),
        ]
        .map(str::to_owned)
        .to_vec()
    }
}

/// What to do about the installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setup {
    /// The project is initialised. Nothing runs, whatever policy says.
    Ready,
    /// The project has no installation and policy authorizes setting one up.
    Init(InitCommand),
    /// The project has no installation and policy does not authorize setting one up. The stage is
    /// blocked.
    NotAuthorized,
}

/// Decides the setup. `initialised` is whether the committed tree holds the Spec Kit directory.
/// `authorized` is the policy's answer to "may the control plane set Spec Kit up here".
#[must_use]
pub fn decide_setup(initialised: bool, authorized: bool, host: Host) -> Setup {
    if initialised {
        Setup::Ready
    } else if authorized {
        Setup::Init(InitCommand { host })
    } else {
        Setup::NotAuthorized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_never_made_for_an_initialised_project() {
        for authorized in [false, true] {
            assert_eq!(
                decide_setup(true, authorized, Host::ClaudeCode),
                Setup::Ready
            );
        }
        assert_eq!(
            decide_setup(false, false, Host::ClaudeCode),
            Setup::NotAuthorized
        );
        let Setup::Init(command) = decide_setup(false, true, Host::Codex) else {
            panic!("an authorized setup of an empty project makes the command");
        };
        let argv = command.argv();
        assert_eq!(&argv[..2], ["specify", "init"]);
        assert_eq!(&argv[argv.len() - 2..], ["--integration", "codex"]);
    }

    #[test]
    fn a_status_other_than_ok_is_refused() {
        let ok = br#"{"status":"ok","modified_managed_files":0,"missing_managed_files":0,"findings":[]}"#;
        assert!(check_status_json(ok).is_ok());
        let warning = br#"{"status":"warning","modified_managed_files":1,"missing_managed_files":0,"findings":[{"code":"managed-files-modified"}]}"#;
        let Err(SpecError::IntegrityNotOk(found)) = check_status_json(warning) else {
            panic!("a warning blocks");
        };
        assert_eq!(found[0].rule.as_str(), "managed-files-modified");
        assert!(check_status_json(b"garbled").is_err());
    }
}
