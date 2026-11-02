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
use factory_domain::policy::issue_workflow::{IssueWorkflowPolicy, StatusLabels};
use factory_domain::policy::routing::ModelRoutingPolicy;
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

/// The issue workflow policy as loaded: the label of each job state, checked.
#[derive(Debug, Clone)]
pub struct LoadedIssueWorkflow {
    /// The whole policy.
    pub policy: Arc<IssueWorkflowPolicy>,
    /// The `factory: <state>` label of each job state. The only source of a status label.
    pub labels: Arc<StatusLabels>,
    /// The hash of the file, as the loader reports it.
    pub hash: String,
}

/// Loads `policies/issue-workflow.yaml` from the protected checkout. A missing, unsafe or broken
/// file stops the start of a worker that writes the status of jobs on issues: a worker with no
/// label for a job state would have nothing safe to write.
///
/// # Errors
/// [`StartupFailure::Policy`].
pub fn load_issue_workflow(
    checkout: &Path,
    untrusted_roots: &[&Path],
) -> Result<LoadedIssueWorkflow, StartupFailure> {
    let source = ProtectedPolicySource::protected_default_branch(checkout, untrusted_roots)?;
    let loaded = PolicyLoader::load_issue_workflow(&source)?;
    let labels = loaded.document.status_labels().map_err(|problems| {
        StartupFailure::Policy(problems.first().map_or_else(
            || "the issue workflow policy is unsound".to_owned(),
            |p| format!("{}: {}", p.path, p.message),
        ))
    })?;
    Ok(LoadedIssueWorkflow {
        policy: Arc::new(loaded.document),
        labels: Arc::new(labels),
        hash: loaded.hash.as_str().to_owned(),
    })
}

/// What the issue status step needs from the policies, checked as a whole.
#[derive(Debug, Clone)]
pub struct LoadedStatusPolicy {
    /// The `factory: <state>` label of each job state. The only source of a status label.
    pub labels: Arc<StatusLabels>,
    /// What the approval policy says about writing a status label (`write_status_label`).
    pub permission: crate::issue_status::StatusPermission,
    /// The hash written on every record of the step: the hash of the security and approval
    /// policies with the hash of `policies/issue-workflow.yaml` bound in (finding STS-6), so that a
    /// record says which label map was in force.
    pub policy_hash: Sha256Digest,
}

/// Why the status step cannot use the policies: a plain sentence for the log, the health report
/// and the audit record. It never holds the text of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPolicyRefused(pub String);

impl std::fmt::Display for StatusPolicyRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Binds the hash of the issue workflow policy into the hash of the policies in force. The other
/// policies are bound the same way in [`load_policy`].
#[must_use]
pub fn bind_issue_workflow_hash(base: &Sha256Digest, workflow_hash: &str) -> Sha256Digest {
    Sha256Digest::of(format!("{}\n{workflow_hash}", base.as_str()).as_bytes())
}

/// Loads and checks everything the status step needs. A policy that is missing, unsound, or
/// contradicted by the approval policy gives a refusal, and the worker then starts the step in its
/// **off** state: it writes nothing, it says so, and it does not stop (finding STS-7). The labels
/// show state and decide nothing, so a fault here never costs a job.
///
/// # Errors
/// [`StatusPolicyRefused`] when `policies/issue-workflow.yaml` cannot be loaded, when its trigger
/// label is not the one the engine acts on (`intake.trigger_label` of the approval policy), or
/// when the approval policy does not let the step write a status label.
pub fn load_status_policy(
    checkout: &Path,
    untrusted_roots: &[&Path],
    approval: &ApprovalPolicy,
    base_hash: &Sha256Digest,
) -> Result<LoadedStatusPolicy, StatusPolicyRefused> {
    let loaded = load_issue_workflow(checkout, untrusted_roots).map_err(|error| {
        StatusPolicyRefused(format!(
            "policies/issue-workflow.yaml cannot be used: {error}"
        ))
    })?;
    if loaded.policy.trigger.label != approval.intake.trigger_label {
        return Err(StatusPolicyRefused(
            "the trigger label of policies/issue-workflow.yaml is not the one of intake.trigger_label in policies/approval.yaml"
                .to_owned(),
        ));
    }
    let permission = crate::issue_status::StatusPermission::from_policy(approval)
        .map_err(|why| StatusPolicyRefused(why.to_owned()))?;
    Ok(LoadedStatusPolicy {
        labels: loaded.labels,
        permission,
        policy_hash: bind_issue_workflow_hash(base_hash, &loaded.hash),
    })
}

/// The routing policy as loaded.
#[derive(Debug, Clone)]
pub struct LoadedRouting {
    /// `policies/model_routing.yaml`, checked against its own rules and against the security policy.
    pub policy: Arc<ModelRoutingPolicy>,
    /// The hash of the file, as the loader reports it.
    pub hash: String,
}

/// Loads `policies/model_routing.yaml` from the protected checkout and checks it against the
/// security policy. A missing, unsafe or broken file stops the start: a worker with no routing
/// policy has no model to route to and no price to meter with.
///
/// # Errors
/// [`StartupFailure::Policy`].
pub fn load_routing(
    checkout: &Path,
    untrusted_roots: &[&Path],
    security: &SecurityPolicy,
) -> Result<LoadedRouting, StartupFailure> {
    let source = ProtectedPolicySource::protected_default_branch(checkout, untrusted_roots)?;
    let loaded = PolicyLoader::load_model_routing(&source, security)?;
    Ok(LoadedRouting {
        policy: Arc::new(loaded.document),
        hash: loaded.hash.as_str().to_owned(),
    })
}

/// Refuses a routing policy that still waits for a person, in the production profile.
///
/// Every price and every ceiling of the file is marked as waiting for the project owner while the
/// status is `designed` or a price is `unchecked` (`ModelRoutingPolicy::unconfirmed`). The typed
/// view says a production run starts only when nothing waits. The other profiles start, and the
/// log says what is unconfirmed.
///
/// # Errors
/// [`StartupFailure::Policy`] in the production profile.
pub fn confirm_routing(
    profile: crate::profile::Profile,
    routing: &LoadedRouting,
) -> Result<(), StartupFailure> {
    let waiting = routing.policy.unconfirmed();
    if waiting.is_empty() {
        return Ok(());
    }
    if profile == crate::profile::Profile::Production {
        return Err(StartupFailure::Policy(format!(
            "policies/model_routing.yaml still waits for the project owner: {}",
            waiting.join("; ")
        )));
    }
    tracing::warn!(
        unconfirmed = waiting.len(),
        "the routing policy still waits for the project owner; a production start would refuse it"
    );
    Ok(())
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
