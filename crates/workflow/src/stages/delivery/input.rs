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
//! | `DOCUMENTING` | `documentation-plan`, `documentation-result` | `stages::documenting::input` |
//! | `DOCUMENTATION_REVIEW` | `documentation-gate-report`, `documentation-review` | `stages::documenting::input` |
//!
//! # Which commit is delivered
//!
//! The implementation result names the **code head**. The gates ran on it, so the evidence
//! binding stays on it. The `DOCUMENTING` stage commits the documents on top of the code head and
//! names that commit in `documentation-result` (`head_commit`) together with the code head it was
//! written for (`code_head`). The commit that is pushed, opened as the pull request and shown to
//! the person is [`Dossier::pushed_head`]: the documentation commit, or the code head when the
//! stage committed nothing. A documentation result or plan written for other commits than the
//! implementation result is stale and is refused, not delivered.

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

use super::documentation_gate::{DocumentationGate, Expected, GateProblem};
use crate::gates::docs::plan::DocPlan;
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
/// What the documenting stage did: the commit it made on top of the code head, if any.
pub const DOCUMENTATION_RESULT: &str = "documentation-result";
/// The documentation gate's report.
pub const DOCUMENTATION_GATE: &str = "documentation-gate-report";
/// The documentation reviewer's verdict.
pub const DOCUMENTATION_REVIEW: &str = "documentation-review";
/// The hash of the policy bundle, named as an input of the contract.
pub const POLICY_INPUT: &str = "policy-bundle";

/// Which stage produces each input, in the order the contract lists them.
pub const SOURCES: [(StageKind, &str); 10] = [
    (StageKind::Implementation, IMPLEMENTATION_RESULT),
    (StageKind::Validation, VALIDATION_EVIDENCE),
    (StageKind::Review, REVIEW_VERDICT),
    (StageKind::Specification, SPECIFICATION_CONTRACT),
    (StageKind::TaskPlanning, TASK_PLAN),
    (StageKind::Architecture, ARCHITECTURE),
    (StageKind::Documenting, DOCUMENTATION_PLAN),
    (StageKind::Documenting, DOCUMENTATION_RESULT),
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
    /// The review verdict is not `PASS`, a gate report is `FAILED`, or the documentation stage
    /// reports a refusal. Delivery follows work that passed.
    #[error("the evidence does not allow a delivery")]
    NotDeliverable,
    /// The documentation was written for other commits than the implementation result names, or
    /// the reports of the documentation gate were made for other commits or another plan than the
    /// ones that are delivered. Nothing changed in the world: the documents disagree, and no one
    /// waives that.
    #[error("the documentation was written for other commits than the implementation result")]
    Stale,
}

/// The two commits of the implementation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The protected branch tip the change is relative to.
    pub base: CommitSha,
    /// The code head: the commit the gates ran on. The documentation commit, if there is one, sits
    /// on top of it.
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
    /// The commits of the implementation result.
    pub candidate: Candidate,
    /// The commit that is pushed and that the pull request points at: the documentation commit,
    /// or the code head when the documenting stage committed nothing.
    pub pushed_head: CommitSha,
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

/// Reads `documentation-result` and returns the commit to deliver.
///
/// The result and the plan must both be about the commits of the implementation result. A result
/// that names the code head as its own head committed nothing, and then the code head is
/// delivered. One that names another commit is a documentation commit, and it must come from a
/// writer that ran, changed something, and was not told by its plan that nothing needed writing.
///
/// # Errors
/// [`DossierError::Invalid`] for a document that is not a result or contradicts itself or its plan,
/// [`DossierError::Stale`] for documents about other commits, and
/// [`DossierError::NotDeliverable`] for a result that records a refusal of the audit, a path outside
/// the writer's scope or a claim that cites a file that does not exist.
pub fn parse_documentation(
    bytes: &[u8],
    candidate: &Candidate,
    plan: &DocPlan,
) -> Result<CommitSha, DossierError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| DossierError::Invalid)?;
    let text = |name: &str| value.get(name).and_then(Value::as_str);
    if text("kind") != Some(DOCUMENTATION_RESULT) {
        return Err(DossierError::Invalid);
    }
    let commit = |name: &str| {
        text(name)
            .and_then(|found| CommitSha::parse(found).ok())
            .ok_or(DossierError::Invalid)
    };
    let (base, code_head, head) = (
        commit("base_commit")?,
        commit("code_head")?,
        commit("head_commit")?,
    );
    let list = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_array)
            .ok_or(DossierError::Invalid)
    };
    let refused = match value.get("refusal") {
        Some(Value::Null) => false,
        Some(Value::Object(_)) => true,
        _ => return Err(DossierError::Invalid),
    };
    let (out_of_scope, unresolved, changes) = (
        list("out_of_scope")?,
        list("unresolved_claims")?,
        list("changes")?,
    );

    if base != candidate.base
        || code_head != candidate.head
        || plan.binding.base_commit != candidate.base.as_str()
        || plan.binding.code_head != candidate.head.as_str()
    {
        return Err(DossierError::Stale);
    }
    if refused || !out_of_scope.is_empty() || !unresolved.is_empty() {
        return Err(DossierError::NotDeliverable);
    }
    if head == candidate.head {
        return Ok(head);
    }
    let writer_ran = value.get("writer_ran").and_then(Value::as_bool) == Some(true);
    if !writer_ran || changes.is_empty() || plan.not_applicable.is_some() {
        return Err(DossierError::Invalid);
    }
    Ok(head)
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
    let (plan_bytes, documentation_plan) =
        bytes(artifacts, scope, contract, DOCUMENTATION_PLAN).await?;
    let documentation_plan_document = serde_json::from_slice::<Value>(&plan_bytes)
        .ok()
        .and_then(|value| DocPlan::from_json(&value).ok())
        .ok_or(DossierError::Invalid)?;
    let (documentation_result, _) = bytes(artifacts, scope, contract, DOCUMENTATION_RESULT).await?;
    let pushed_head = parse_documentation(
        &documentation_result,
        &candidate,
        &documentation_plan_document,
    )?;
    // The gate report is read, not only hashed: a report made for other commits or another plan
    // than the ones that are delivered is stale, whatever its hash.
    let (gate_bytes, documentation_gate) =
        bytes(artifacts, scope, contract, DOCUMENTATION_GATE).await?;
    DocumentationGate::from_bytes(&gate_bytes)
        .map_err(|_| DossierError::Invalid)?
        .check(&Expected {
            base_commit: &candidate.base,
            code_head: &candidate.head,
            documentation_head: &pushed_head,
            plan_sha256: &documentation_plan.sha256,
        })
        .map_err(|problem| match problem {
            GateProblem::Invalid => DossierError::Invalid,
            GateProblem::Stale(_) => DossierError::Stale,
        })?;
    let (_, documentation_review) = bytes(artifacts, scope, contract, DOCUMENTATION_REVIEW).await?;

    Ok(Dossier {
        candidate,
        pushed_head,
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
