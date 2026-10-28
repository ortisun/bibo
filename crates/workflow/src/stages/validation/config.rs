//! What the composition root hands the validation stage.
//!
//! The stage reads no file and no environment variable. The policy engine, the path rules, the
//! redactor, the verify image and its limits come in here, built by the program that loads the
//! policy files and the image registry. Nothing in this value comes from the repository under
//! work.

use std::collections::BTreeSet;
use std::sync::Arc;

use factory_domain::contracts::{Contract, ProjectManifest};
use factory_domain::policy::PolicyEngine;
use factory_domain::redaction::Redactor;
use factory_ports::paths::{PathRules, RepoGlob};
use factory_ports::sandbox::{CacheMount, FixedEnv, Hardening, ImageDigest, SandboxLimits};

/// The manifest bytes could not be turned into a project manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the project manifest could not be read")]
pub struct ManifestRejected;

/// Turns the bytes of the project manifest, read from the protected base commit, into the typed
/// manifest.
///
/// The manifest may be YAML or JSON. The YAML reader and the schema engine live in the
/// `contracts` crate, which this crate may not depend on, so the program that composes the stage
/// passes the loader of `contracts` here. [`JsonManifestReader`] reads JSON only.
pub trait ManifestReader: Send + Sync {
    /// Reads and validates the manifest.
    ///
    /// # Errors
    /// [`ManifestRejected`] for anything that is not a valid manifest. The error carries no text
    /// of the file.
    fn read(&self, bytes: &[u8]) -> Result<ProjectManifest, ManifestRejected>;
}

/// A reader for a manifest written as JSON.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonManifestReader;

impl ManifestReader for JsonManifestReader {
    fn read(&self, bytes: &[u8]) -> Result<ProjectManifest, ManifestRejected> {
        let text = std::str::from_utf8(bytes).map_err(|_| ManifestRejected)?;
        ProjectManifest::from_json_str(text).map_err(|_| ManifestRejected)
    }
}

/// The verify sandbox, apart from the workspace it mounts.
#[derive(Debug, Clone)]
pub struct VerifySandbox {
    /// The image, pinned by digest. It comes from the factory's image registry file.
    pub image: ImageDigest,
    /// Resource limits, within the policy maximum for the `verify` profile.
    pub limits: SandboxLimits,
    /// The environment the supervisor sets, from its fixed list.
    pub env: FixedEnv,
    /// The security settings of the container.
    pub hardening: Hardening,
    /// The read-only caches to mount.
    pub caches: Vec<CacheMount>,
    /// The CPU architecture of the image, as the gate report records it.
    pub arch: String,
}

/// The bounds on what the stage reads and keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// The largest file version read for the host-side gates.
    pub max_file_bytes: u64,
    /// The largest patch read.
    pub max_patch_bytes: u64,
    /// The largest manifest read.
    pub max_manifest_bytes: u64,
    /// How much of each stream of a command the supervisor keeps.
    pub max_output_bytes: u64,
    /// How long a version probe may run.
    pub probe_timeout_seconds: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_file_bytes: 1024 * 1024,
            max_patch_bytes: 5 * 1024 * 1024,
            max_manifest_bytes: 256 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
            probe_timeout_seconds: 30,
        }
    }
}

/// Everything the validation stage is built from.
#[derive(Clone)]
pub struct ValidationConfig {
    /// The evaluators of the security and approval policies.
    pub policy: Arc<PolicyEngine>,
    /// The path rules the workspace adapter classifies paths with.
    pub path_rules: PathRules,
    /// The held-out test globs (`evaluation_holdouts`), present in the verify workspace only.
    pub holdouts: Vec<RepoGlob>,
    /// The one redactor of the factory.
    pub redactor: Arc<Redactor>,
    /// The verify sandbox.
    pub sandbox: VerifySandbox,
    /// Reads the project manifest.
    pub manifest: Arc<dyn ManifestReader>,
    /// The central flaky registry: test identifiers that may be re-run once after a failure
    /// (`gate_integrity.flaky_tests`). A test that is not listed is never re-run.
    pub flaky_registry: BTreeSet<String>,
    /// Bounds.
    pub bounds: Bounds,
}

impl std::fmt::Debug for ValidationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationConfig")
            .field("sandbox", &self.sandbox.image)
            .field("holdouts", &self.holdouts.len())
            .finish_non_exhaustive()
    }
}
