//! What the checks of this gate report.
//!
//! A [`Finding`] is a short, fixed-shape record: the name of the check, how serious it is, a
//! sentence, and the path of the file it is about. The sentence is built from validated fields
//! (a package name, a version, a host) and never repeats the text of a dependency file.

/// How a finding counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The change breaks a rule. The gate fails.
    Violation,
    /// Something a person should look at. It does not fail the gate.
    Warning,
}

/// The identifiers of the checks. Each is a slug that appears in the gate report.
pub mod check {
    /// A dependency file could not be read.
    pub const UNREADABLE: &str = "unreadable-dependency-file";
    /// A lockfile of the base commit is gone.
    pub const LOCKFILE_REMOVED: &str = "lockfile-removed";
    /// The project has dependencies and no lockfile.
    pub const LOCKFILE_MISSING: &str = "lockfile-missing";
    /// The manifest names a dependency that the lockfile does not hold.
    pub const LOCKFILE_STALE: &str = "lockfile-out-of-date";
    /// The lockfile changed and no manifest did.
    pub const LOCKFILE_ONLY: &str = "lockfile-only-edit";
    /// A package comes from a source the policy does not allow, or its source changed. This is the
    /// semantic check `registry_or_source_changed` of `gate_integrity.semantic_checks`.
    pub const SOURCE: &str = "registry_or_source_changed";
    /// A dependency declared by git.
    pub const GIT: &str = "git-dependency";
    /// A dependency declared by path.
    pub const PATH: &str = "path-dependency";
    /// A dependency declared with another registry.
    pub const ALTERNATE_REGISTRY: &str = "alternate-registry-dependency";
    /// A lockfile package without a source that no manifest of the project explains.
    pub const PATH_UNEXPLAINED: &str = "path-package-unexplained";
    /// `[patch]` or `[replace]` was added or changed.
    pub const PATCH: &str = "patch-or-replace";
    /// The build configuration points cargo at another registry or changes how it is reached.
    pub const REGISTRY_REDIRECT: &str = "registry-redirect";
    /// The build configuration names a program to run, an environment to set, or a key that is
    /// not on the list of harmless ones.
    pub const BUILD_CONFIG: &str = "build-config-changed";
    /// A package archive has another checksum for the same version.
    pub const CHECKSUM_CHANGED: &str = "checksum-changed";
    /// A registry package has no usable checksum.
    pub const CHECKSUM_MISSING: &str = "checksum-missing";
    /// A package moved to an older version.
    pub const DOWNGRADE: &str = "version-downgrade";
    /// A package version could not be ordered.
    pub const UNORDERED: &str = "unordered-version";
    /// A transitive package carries the name of an internal package, or a registry package has
    /// the name and version of a member of the project.
    pub const CONFUSION: &str = "dependency-confusion";
    /// A reference in the lockfile names more than one package, so it does not say which one the
    /// project depends on. Cargo never writes such a lockfile.
    pub const REFERENCE_AMBIGUOUS: &str = "lockfile-reference-ambiguous";
    /// A reference in the lockfile names no package. `cargo fetch --locked` refuses such a file.
    pub const REFERENCE_DANGLING: &str = "lockfile-reference-dangling";
    /// A new dependency request is not a valid request.
    pub const INVALID_REQUEST: &str = "invalid-dependency-request";
    /// A change brings more new direct dependencies than a person can decide on.
    pub const TOO_MANY_NEW: &str = "too-many-new-dependencies";
    /// A license outside the owner-approved list.
    pub const LICENSE: &str = "license-not-allowed";
    /// A package name one edit from a popular name, below a package a person approved.
    pub const SUSPECT_NAME: &str = "typosquat-suspect";
    /// A build script or a procedural macro came into the graph.
    pub const BUILD_CODE: &str = "build-code-added";
    /// A lockfile update with no change to the manifest.
    pub const UPDATE_ONLY: &str = "lockfile-update-only";
}

/// One thing a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The check, one of [`check`].
    pub check: &'static str,
    /// How it counts.
    pub severity: Severity,
    /// A sentence for a person.
    pub message: String,
    /// The file it is about.
    pub path: Option<String>,
}

impl Finding {
    /// A finding that fails the gate.
    #[must_use]
    pub fn violation(check: &'static str, path: Option<&str>, message: String) -> Self {
        Self {
            check,
            severity: Severity::Violation,
            message,
            path: path.map(str::to_owned),
        }
    }

    /// A finding that does not fail the gate.
    #[must_use]
    pub fn warning(check: &'static str, path: Option<&str>, message: String) -> Self {
        Self {
            check,
            severity: Severity::Warning,
            message,
            path: path.map(str::to_owned),
        }
    }

    /// True when the finding fails the gate.
    #[must_use]
    pub fn is_violation(&self) -> bool {
        self.severity == Severity::Violation
    }
}
