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
use factory_domain::policy::dependency::RunWhen;
use factory_domain::redaction::Redactor;
use factory_ports::paths::{PathRules, RepoGlob};
use factory_ports::sandbox::{CacheMount, FixedEnv, Hardening, ImageDigest, SandboxLimits};

use crate::gates::supply_chain::approval::RecordedApprovals;
use crate::gates::supply_chain::facts::{AdvisoryDatabase, RegistryMetadata};
use crate::gates::supply_chain::licenses::LicensePolicy;
use crate::gates::supply_chain::names::PopularNames;
use crate::gates::supply_chain::run::{
    Bounds as SupplyBounds, DEFAULT_ADVISORY_DB_MAX_AGE_DAYS, FetchSandbox, SbomRule,
};

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

/// When the dependency and supply chain gates run. The policy says which
/// (`supply_chain.dependency_gates.run_when`); the stage runs them whenever the policy or this
/// setting says `Always`, so a configuration may tighten the rule and never loosen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunSupplyChain {
    /// On every change. The four reports are made from the dependency files of both commits even
    /// when the change touches none.
    Always,
    /// Only when the change touches a dependency file (a lockfile, a manifest, a build
    /// configuration, the configuration of a scanner, a build script). Otherwise the four reports
    /// say that nothing applies, and no file is read and no container is made.
    WhenDependencyFilesChange,
}

/// How much of the object store the dependency gates read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyReadLimits {
    /// The most paths of one commit that are listed. A listing as long as this is taken for a cut
    /// listing, and a cut listing is not a project with fewer files: the gates are blocked.
    pub max_paths: usize,
    /// The most dependency files read from one commit.
    pub max_files: usize,
    /// The largest dependency file read.
    pub max_file_bytes: u64,
    /// The most bytes of dependency files read from one commit.
    pub max_total_bytes: u64,
}

impl Default for DependencyReadLimits {
    fn default() -> Self {
        Self {
            max_paths: 50_000,
            max_files: 2_000,
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024,
        }
    }
}

/// What the dependency gates are configured with. Nothing in it comes from the repository.
#[derive(Clone)]
pub struct SupplyChainSettings {
    /// When the gates run.
    pub run: RunSupplyChain,
    /// The `fetch_deps` sandbox. The `verify` sandbox is the stage's own.
    pub fetch: FetchSandbox,
    /// The license rule, equal to `deny.toml`.
    pub licenses: LicensePolicy,
    /// The popular names to measure the distance to.
    pub popular: PopularNames,
    /// The names of the organization's internal packages. The members of the project at the base
    /// commit are added by the gate.
    pub internal_names: Vec<String>,
    /// The SBOM rule: required for a release or a high-risk job, never a constant.
    pub sbom: SbomRule,
    /// The most whole days old the advisory database may be. The policy has the last word: the
    /// stage uses the lower of this and `supply_chain.advisory_database.max_age_days`, so a
    /// configuration may lower the limit and never raise it.
    pub advisory_db_max_age_days: u64,
    /// Bounds on what the gate runs.
    pub bounds: SupplyBounds,
    /// Bounds on what the gate reads.
    pub limits: DependencyReadLimits,
}

impl SupplyChainSettings {
    /// The settings a stage built from policy starts from: the age of the advisory database and
    /// the rule for when the gates run are the policy's (`supply_chain.advisory_database` and
    /// `supply_chain.dependency_gates`), and the limits are the defaults. The configuration seam
    /// stays: a field may be changed afterwards, and the stage still takes the stricter of the
    /// field and the policy.
    #[must_use]
    pub fn from_policy(
        policy: &PolicyEngine,
        fetch: FetchSandbox,
        licenses: LicensePolicy,
        popular: PopularNames,
        sbom: SbomRule,
    ) -> Self {
        Self {
            run: match policy.dependency.run_when() {
                RunWhen::DependencyFilesChange => RunSupplyChain::WhenDependencyFilesChange,
                RunWhen::Always => RunSupplyChain::Always,
            },
            advisory_db_max_age_days: policy.dependency.advisory_database_max_age_days(),
            ..Self::new(fetch, licenses, popular, sbom)
        }
    }

    /// The settings with the default limits, a database age of
    /// [`DEFAULT_ADVISORY_DB_MAX_AGE_DAYS`] and the gates run only for a change that touches a
    /// dependency file. This does not read the policy; the stage still applies the policy's
    /// limit and rule on top ([`from_policy`](Self::from_policy) starts from them).
    #[must_use]
    pub fn new(
        fetch: FetchSandbox,
        licenses: LicensePolicy,
        popular: PopularNames,
        sbom: SbomRule,
    ) -> Self {
        Self {
            run: RunSupplyChain::WhenDependencyFilesChange,
            fetch,
            licenses,
            popular,
            internal_names: Vec::new(),
            sbom,
            advisory_db_max_age_days: DEFAULT_ADVISORY_DB_MAX_AGE_DAYS,
            bounds: SupplyBounds::default(),
            limits: DependencyReadLimits::default(),
        }
    }
}

/// What the composition root hands the dependency gates: their settings and the three sources the
/// gates cannot read from the repository.
#[derive(Clone)]
pub struct SupplyChainSeams {
    /// The settings.
    pub settings: SupplyChainSettings,
    /// The decisions recorded for a job, loaded by tenant and job from the ledger.
    pub approvals: Arc<dyn RecordedApprovals>,
    /// The facts about a package the registry knows. A source that knows nothing returns the
    /// default record, which the policy reads as the worst answer.
    pub registry: Arc<dyn RegistryMetadata>,
    /// The date of the advisory database the audit reads. A database of unknown age blocks.
    pub advisory_db: Arc<dyn AdvisoryDatabase>,
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
    /// The dependency and supply chain gates. The stage always makes their four reports.
    pub supply_chain: SupplyChainSeams,
}

impl std::fmt::Debug for ValidationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationConfig")
            .field("sandbox", &self.sandbox.image)
            .field("holdouts", &self.holdouts.len())
            .finish_non_exhaustive()
    }
}
