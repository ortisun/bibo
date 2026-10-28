//! Start-up checks that need no database: the policy, and the catalog of sandbox images.
//!
//! A process that fails one of these does not start. Each check returns a typed error that names
//! what is wrong, and a [`CheckResult`] for the health report, so the same fact reaches the
//! operator whether it stopped the process or is shown by the readiness endpoint.
//!
//! * [`load_policy`] reads `policies/security.yaml` and `policies/approval.yaml` **only** from the
//!   protected configuration checkout (never from a job workspace or a target repository, which
//!   `ProtectedPolicySource` refuses), checks them, builds the policy engine and hashes the pair.
//!   The hash goes into `EngineConfig::policy_hash` and so into every ledger entry.
//! * [`check_image_catalog`] reads `images.json`, requires every profile to resolve to an image
//!   that is pinned by digest and `ready`, and refuses the egress sidecar while it is a skeleton.
//!   The Docker daemon is not asked: this is the static half, and the sandbox adapter does the
//!   dynamic half (the image must be present on the host) when it creates a container.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use factory_contracts::policy::{PolicyError, PolicyLoader, ProtectedPolicySource};
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::approval::ApprovalPolicy;
use factory_domain::policy::security::SecurityPolicy;
use factory_domain::values::Sha256Digest;
use factory_ports::sandbox::SandboxProfile;
use factory_sandbox::container::images::ImageCatalog;

use crate::health::{CheckResult, CheckStatus};

/// The policies as loaded, with everything built from them.
#[derive(Debug, Clone)]
pub struct LoadedPolicies {
    /// `policies/security.yaml`.
    pub security: Arc<SecurityPolicy>,
    /// `policies/approval.yaml`.
    pub approval: Arc<ApprovalPolicy>,
    /// The evaluators built from both.
    pub engine: Arc<PolicyEngine>,
    /// The hash of the two documents together, as recorded in the ledger.
    pub hash: Sha256Digest,
    /// Where they were read from.
    pub source: PathBuf,
}

/// Why start-up stops.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartupFailure {
    /// A policy file is missing, unsafe or does not pass its own checks.
    #[error("the policy cannot be loaded: {0}")]
    Policy(String),
    /// The evaluators cannot be built from the policy.
    #[error("the policy engine cannot be built: {0}")]
    PolicyEngine(String),
    /// The image catalog is unusable.
    #[error("the sandbox image catalog is unusable: {0}")]
    Images(String),
    /// A port is a fake the profile refuses.
    #[error(transparent)]
    Ports(#[from] crate::registry::RegistryRefused),
    /// The store refused to start.
    #[error("the store cannot start: {0}")]
    Store(String),
    /// A kind of secret the policy requires has no value.
    #[error("the policy requires a registered secret of kind {0}, and none is configured")]
    SecretKindMissing(&'static str),
    /// Anything else that stops the process, with a plain reason.
    #[error("{0}")]
    Other(String),
}

impl From<PolicyError> for StartupFailure {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error.to_string())
    }
}

/// Loads, checks, builds and hashes the policy.
///
/// `untrusted_roots` are the directories where job workspaces and target repositories live. A
/// checkout inside one of them is refused.
///
/// # Errors
/// [`StartupFailure::Policy`] or [`StartupFailure::PolicyEngine`].
pub fn load_policy(
    checkout: &Path,
    untrusted_roots: &[&Path],
) -> Result<LoadedPolicies, StartupFailure> {
    let source = ProtectedPolicySource::protected_default_branch(checkout, untrusted_roots)?;
    let security = PolicyLoader::load_security(&source)?;
    let approval = PolicyLoader::load_approval(&source)?;
    let engine = PolicyEngine::new(&security.document, &approval.document)
        .map_err(|error| StartupFailure::PolicyEngine(error.to_string()))?;
    let hash = Sha256Digest::of(
        format!("{}\n{}", security.hash.as_str(), approval.hash.as_str()).as_bytes(),
    );
    Ok(LoadedPolicies {
        security: Arc::new(security.document),
        approval: Arc::new(approval.document),
        engine: Arc::new(engine),
        hash,
        source: source.root().to_path_buf(),
    })
}

/// The result of reading the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogReport {
    /// The platforms checked.
    pub platforms: Vec<String>,
}

/// Checks the catalog for one platform, or for every platform in it when `platform` is `None`.
///
/// Every profile (`agent`, `fetch_deps`, `verify`) must resolve to a pinned, ready image, and the
/// egress sidecar must be ready.
///
/// # Errors
/// [`StartupFailure::Images`].
pub fn check_image_catalog(
    json: &str,
    platform: Option<&str>,
) -> Result<CatalogReport, StartupFailure> {
    let platforms: Vec<String> = match platform {
        Some(one) => vec![one.to_owned()],
        None => serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .and_then(|root| {
                root.get("platforms")
                    .and_then(serde_json::Value::as_object)
                    .map(|map| map.keys().cloned().collect())
            })
            .ok_or_else(|| StartupFailure::Images("the catalog is not readable".to_owned()))?,
    };
    if platforms.is_empty() {
        return Err(StartupFailure::Images(
            "the catalog lists no platform".to_owned(),
        ));
    }
    for platform in &platforms {
        let catalog = ImageCatalog::from_json(json, platform)
            .map_err(|error| StartupFailure::Images(format!("{platform}: {error}")))?;
        for profile in [
            SandboxProfile::Agent,
            SandboxProfile::FetchDeps,
            SandboxProfile::Verify,
        ] {
            let reference = catalog.reference_for(profile).ok_or_else(|| {
                StartupFailure::Images(format!("{platform}: no image for {}", profile.as_str()))
            })?;
            catalog
                .check_spec_image(profile, reference)
                .map_err(|error| {
                    StartupFailure::Images(format!("{platform}: {}: {error}", profile.as_str()))
                })?;
        }
        catalog
            .sidecar()
            .map_err(|error| StartupFailure::Images(format!("{platform}: sidecar: {error}")))?;
    }
    Ok(CatalogReport { platforms })
}

/// The health-report line for a check that passed or failed.
#[must_use]
pub fn result_of<T, E: std::fmt::Display>(name: &str, outcome: &Result<T, E>) -> CheckResult {
    match outcome {
        Ok(_) => CheckResult::pass(name, "ok"),
        Err(error) => CheckResult {
            name: name.to_owned(),
            status: CheckStatus::Fail,
            detail: error.to_string(),
        },
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// The repository root, two levels above this package.
    pub fn repository_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// The security policy of the repository, loaded the way a binary loads it.
    pub fn repository_security_policy() -> SecurityPolicy {
        let root = repository_root();
        let loaded = load_policy(&root, &[]).expect("the repository policy loads");
        (*loaded.security).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::repository_root;
    use super::*;

    #[test]
    fn the_repository_policy_loads_and_hashes_the_same_way_twice() {
        let first = load_policy(&repository_root(), &[]).expect("loads");
        let second = load_policy(&repository_root(), &[]).expect("loads");
        assert_eq!(first.hash, second.hash);
        assert!(first.hash.as_str().starts_with("sha256:"));
    }

    #[test]
    fn a_missing_checkout_is_refused_with_no_default_policy() {
        let refusal =
            load_policy(Path::new("/nonexistent/factory/protected"), &[]).expect_err("no checkout");
        assert!(matches!(refusal, StartupFailure::Policy(_)));
    }

    #[test]
    fn a_checkout_inside_a_job_workspace_is_refused() {
        let root = repository_root();
        let inside = root.join("policies");
        // The checkout lies inside the "workspace" root, so it is untrusted.
        let refusal = load_policy(&root.join("policies"), &[&root]).expect_err("untrusted");
        assert!(refusal.to_string().contains("job workspace"), "{refusal}");
        let _ = inside;
    }

    #[test]
    fn the_repository_catalog_is_pinned_and_has_no_skeleton() {
        let json =
            std::fs::read_to_string(repository_root().join("infra/sandbox-images/images.json"))
                .expect("the catalog exists");
        let report = check_image_catalog(&json, None).expect("every platform passes");
        assert!(!report.platforms.is_empty());
    }

    #[test]
    fn a_skeleton_sidecar_stops_start_up() {
        let json =
            std::fs::read_to_string(repository_root().join("infra/sandbox-images/images.json"))
                .expect("the catalog exists")
                .replace("\"status\": \"ready\"", "\"status\": \"skeleton\"");
        let refusal = check_image_catalog(&json, None).expect_err("not ready");
        assert!(matches!(refusal, StartupFailure::Images(_)), "{refusal}");
    }

    #[test]
    fn an_unknown_platform_is_refused() {
        let json =
            std::fs::read_to_string(repository_root().join("infra/sandbox-images/images.json"))
                .expect("the catalog exists");
        assert!(check_image_catalog(&json, Some("linux/riscv64")).is_err());
    }
}
