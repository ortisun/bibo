//! What the delivery stage reads from the stage runs before it.
//!
//! Every input is a typed document that an earlier stage stored, read back from the artifact
//! store by the hash the stage contract recorded. Nothing is taken from an agent's report or from
//! the text of a transcript. A document that is missing, does not parse or breaks its own
//! contract blocks the stage: a pull request is not opened from a guess.
//!
//! # Deliverables of the stages this stage builds on
//!
//! | Stage | Deliverable | Defined by |
//! |---|---|---|
//! | `IMPLEMENTATION` | `implementation-result` | the implementation package |
//! | `VALIDATION` | `validation-evidence` | the validation package |
//! | `REVIEW` | `review-verdict` | the review package |
//! | `SPECIFICATION` | `specification-contract` | the specification package |
//! | `TASK_PLANNING` | `task-plan` | the implementation package reads it by this name |
//! | `ARCHITECTURE` | `architecture-design` | the implementation package reads it by this name |
//! | `DOCUMENTING` | `documentation-plan` | **this package proposes the name** |
//! | `DOCUMENTATION_REVIEW` | `documentation-gate-report`, `documentation-review` | **this package proposes the names** |
//!
//! The documentation stages are not merged yet. The three names in bold are this package's
//! reading of what they will produce, and the documentation packages must confirm them or this
//! file changes. Until then a job cannot reach delivery with real documentation stages, and the
//! delivery stage blocks (`DependencyUnavailable`) instead of inventing a documentation
//! reference.

use factory_domain::contracts::{
    ArtifactRef, Contract, GateReport, ReviewVerdict, SpecificationContract, StageContract, TaskDag,
};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::{GitSha, Sha256Digest};
use factory_domain::vocabulary::StageKind;
use factory_ports::artifact::ArtifactStore;
use factory_ports::paths::CommitSha;
use serde_json::Value;

use crate::handlers::UpstreamRun;
use crate::stages::validation::Binding;

/// The implementation stage's deliverable that names the commits.
pub const IMPLEMENTATION_RESULT: &str = "implementation-result";
/// The validation stage's deliverable: the gate reports and the evidence binding.
pub const VALIDATION_EVIDENCE: &str = "validation-evidence";
/// The review stage's deliverable.
pub const REVIEW_VERDICT: &str = "review-verdict";
/// The specification stage's deliverable.
pub const SPECIFICATION_CONTRACT: &str = "specification-contract";
/// The task planning stage's deliverable.
pub const TASK_PLAN: &str = "task-plan";
/// The architecture stage's deliverable.
pub const ARCHITECTURE: &str = "architecture-design";
/// The documenting stage's plan.
pub const DOCUMENTATION_PLAN: &str = "documentation-plan";
/// The documentation gate's report.
pub const DOCUMENTATION_GATE: &str = "documentation-gate-report";
/// The documentation reviewer's verdict.
pub const DOCUMENTATION_REVIEW: &str = "documentation-review";
/// The hash of the policy bundle, named as an input of the contract.
pub const POLICY_INPUT: &str = "policy-bundle";

/// Which stage produces each input, in the order the contract lists them.
pub const SOURCES: [(StageKind, &str); 9] = [
    (StageKind::Implementation, IMPLEMENTATION_RESULT),
    (StageKind::Validation, VALIDATION_EVIDENCE),
    (StageKind::Review, REVIEW_VERDICT),
    (StageKind::Specification, SPECIFICATION_CONTRACT),
    (StageKind::TaskPlanning, TASK_PLAN),
    (StageKind::Architecture, ARCHITECTURE),
    (StageKind::Documenting, DOCUMENTATION_PLAN),
    (StageKind::DocumentationReview, DOCUMENTATION_GATE),
    (StageKind::DocumentationReview, DOCUMENTATION_REVIEW),
];

/// The newest passed run of `kind` that produced a deliverable called `name`.
#[must_use]
pub fn upstream_output<'a>(
    upstream: &'a [UpstreamRun],
    kind: StageKind,
    name: &str,
) -> Option<(&'a UpstreamRun, &'a ArtifactRef)> {
    upstream
        .iter()
        .rev()
        .filter(|run| run.kind == kind && run.status == StageRunStatus::Passed)
        .find_map(|run| {
            run.outputs
                .iter()
                .find(|output| output.name.as_str() == name)
                .map(|output| (run, &output.artifact))
        })
}

/// The artifact the contract named as the input `name`.
#[must_use]
pub fn contract_input(contract: &StageContract, name: &str) -> Option<ArtifactRef> {
    contract
        .inputs
        .iter()
        .find(|input| input.name.as_str() == name)
        .map(|input| input.artifact.clone())
}

/// Why the dossier could not be read. The set is closed and carries no document text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DossierError {
    /// The contract does not name an input, or the store does not hold it.
    #[error("an input of the delivery stage is missing")]
    Missing,
    /// An input does not parse or breaks the rules of its contract.
    #[error("an input of the delivery stage is not a valid document")]
    Invalid,
    /// The review verdict is not `PASS`, or a gate report is `FAILED`. Delivery follows work that
    /// passed.
    #[error("the evidence does not allow a delivery")]
    NotDeliverable,
}

/// The two commits of the implementation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The protected branch tip the change is relative to.
    pub base: CommitSha,
    /// The commit to deliver.
    pub head: CommitSha,
}

/// The validation evidence: the binding and the reports.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationDossier {
    /// What the reports are bound to.
    pub binding: Binding,
    /// One report for each gate.
    pub reports: Vec<GateReport>,
    /// The hash of the stored document.
    pub sha256: Sha256Digest,
}

/// Everything the delivery stage reads, parsed.
#[derive(Debug, Clone)]
pub struct Dossier {
    /// The commits.
    pub candidate: Candidate,
    /// The hash of the implementation result.
    pub implementation_sha256: Sha256Digest,
    /// The frozen specification.
    pub specification: SpecificationContract,
    /// Its hash.
    pub specification_sha256: Sha256Digest,
    /// The task plan.
    pub plan: TaskDag,
    /// Its hash.
    pub plan_sha256: Sha256Digest,
    /// The hash of the architecture design.
    pub architecture_sha256: Sha256Digest,
    /// The gate reports and the binding.
    pub validation: ValidationDossier,
    /// The independent review.
    pub review: ReviewVerdict,
    /// Its hash.
    pub review_sha256: Sha256Digest,
    /// The hash of the documentation plan.
    pub documentation_plan_sha256: Sha256Digest,
    /// The hash of the documentation gate report.
    pub documentation_gate_sha256: Sha256Digest,
    /// The hash of the documentation review.
    pub documentation_review_sha256: Sha256Digest,
}

async fn bytes(
    artifacts: &dyn ArtifactStore,
    scope: &TenantScope,
    contract: &StageContract,
    name: &str,
) -> Result<(Vec<u8>, ArtifactRef), DossierError> {
    let reference = contract_input(contract, name).ok_or(DossierError::Missing)?;
    let bytes = artifacts
        .get(scope, &reference)
        .await
        .map_err(|_| DossierError::Missing)?;
    // The store verifies the hash it returns, and the contract recorded it. Check again: a store
    // that returned other bytes would otherwise put them into a pull request.
    if Sha256Digest::of(&bytes) != reference.sha256 {
        return Err(DossierError::Invalid);
    }
    Ok((bytes, reference))
}

fn sha_only(reference: &ArtifactRef) -> Sha256Digest {
    reference.sha256.clone()
}

/// Reads the two commits from the implementation result.
#[must_use]
pub fn parse_candidate(bytes: &[u8]) -> Option<Candidate> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let field = |name: &str| value.get(name).and_then(Value::as_str);
    Some(Candidate {
        base: CommitSha::parse(field("base_commit")?).ok()?,
        head: CommitSha::parse(field("head_commit")?).ok()?,
    })
}

fn parse_validation(bytes: &[u8], sha256: Sha256Digest) -> Option<ValidationDossier> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let binding = Binding::from_json(value.get("binding")?)?;
    let mut reports = Vec::new();
    for item in value.get("reports")?.as_array()? {
        reports.push(GateReport::from_json_value(item.clone()).ok()?);
    }
    if reports.is_empty() {
        return None;
    }
    Some(ValidationDossier {
        binding,
        reports,
        sha256,
    })
}

/// Reads every input named by the contract.
///
/// # Errors
/// [`DossierError`]. A document that does not validate is `Invalid`; a review that is not `PASS`
/// or a gate report that is `FAILED` is `NotDeliverable`.
pub async fn read(
    artifacts: &dyn ArtifactStore,
    scope: &TenantScope,
    contract: &StageContract,
) -> Result<Dossier, DossierError> {
    let (result, result_ref) = bytes(artifacts, scope, contract, IMPLEMENTATION_RESULT).await?;
    let candidate = parse_candidate(&result).ok_or(DossierError::Invalid)?;

    let (evidence, evidence_ref) = bytes(artifacts, scope, contract, VALIDATION_EVIDENCE).await?;
    let validation =
        parse_validation(&evidence, sha_only(&evidence_ref)).ok_or(DossierError::Invalid)?;

    let (verdict, verdict_ref) = bytes(artifacts, scope, contract, REVIEW_VERDICT).await?;
    let review = ReviewVerdict::from_json_str(
        std::str::from_utf8(&verdict).map_err(|_| DossierError::Invalid)?,
    )
    .map_err(|_| DossierError::Invalid)?;
    review.validate().map_err(|_| DossierError::Invalid)?;

    let (spec, spec_ref) = bytes(artifacts, scope, contract, SPECIFICATION_CONTRACT).await?;
    let specification = SpecificationContract::from_json_str(
        std::str::from_utf8(&spec).map_err(|_| DossierError::Invalid)?,
    )
    .map_err(|_| DossierError::Invalid)?;

    let (plan, plan_ref) = bytes(artifacts, scope, contract, TASK_PLAN).await?;
    let plan =
        TaskDag::from_json_str(std::str::from_utf8(&plan).map_err(|_| DossierError::Invalid)?)
            .map_err(|_| DossierError::Invalid)?;

    let (_, architecture_ref) = bytes(artifacts, scope, contract, ARCHITECTURE).await?;
    let (_, documentation_plan) = bytes(artifacts, scope, contract, DOCUMENTATION_PLAN).await?;
    let (_, documentation_gate) = bytes(artifacts, scope, contract, DOCUMENTATION_GATE).await?;
    let (_, documentation_review) = bytes(artifacts, scope, contract, DOCUMENTATION_REVIEW).await?;

    Ok(Dossier {
        candidate,
        implementation_sha256: sha_only(&result_ref),
        specification,
        specification_sha256: sha_only(&spec_ref),
        plan,
        plan_sha256: sha_only(&plan_ref),
        architecture_sha256: sha_only(&architecture_ref),
        validation,
        review,
        review_sha256: sha_only(&verdict_ref),
        documentation_plan_sha256: sha_only(&documentation_plan),
        documentation_gate_sha256: sha_only(&documentation_gate),
        documentation_review_sha256: sha_only(&documentation_review),
    })
}

/// The commit as the git object id the manifest and the approval binding use.
#[must_use]
pub fn git_sha(commit: &CommitSha) -> Option<GitSha> {
    GitSha::parse(commit.as_str()).ok()
}
