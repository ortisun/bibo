//! The evidence manifest: the summary that rides with the draft pull request.
//!
//! It is built from typed evidence only: the stored gate reports, the stored review verdict, the
//! hashes of the stored specification, plan and documentation checks, the verified head of the
//! ledger and the risk tier that the policy engine computed. Nothing in it is read from an
//! agent's account.
//!
//! # Honesty
//!
//! A manifest that hides a gap is worse than none. [`build`] therefore writes, in `limitations`,
//! one sentence for **every gate that did not run** (no report, a gate that does not apply, a gate
//! that was blocked and then decided by a person) and one for **every adapter that was not real**.
//! It also says that the pull request is a draft that a person must review, mark ready and merge.
//! `PRODUCTION_READY` is listed as not attained, because the factory does not deploy.
//!
//! A gate that `FAILED` cannot be in a manifest, and a `BLOCKED` gate can only be there with the
//! ledger entry that records the person's decision about it. Either of those is a refusal, not a
//! manifest.

use std::collections::BTreeSet;

use factory_domain::contracts::evidence_manifest::{
    AdapterKind, AdapterUse, Assurance, Attained, ChangeSummary, DeliveredGateOutcome,
    DocumentationRefs, GateEntry, HashRef, LedgerHead, ManifestMetadata, ManifestRisk, NotAttained,
    PlanRef, RepositoryName, RepositoryRef, RequiredApproval, ReviewEntry, SpecificationRef,
};
use factory_domain::contracts::{Contract, EvidenceManifest, SchemaVersion};
use factory_domain::ids::ManifestId;
use factory_domain::policy::risk::RiskAssessment;
use factory_domain::values::{
    Bounded, HumanText, HumanTitle, NonEmptyString, NonEmptyVec, NonNegativeInt, PositiveInt,
    Sha256Digest, Slug, Timestamp, UniqueVec,
};
use factory_domain::vocabulary::{
    AssuranceLevel, ExecutionMode, Fidelity, GateOutcome, ReviewerRole, RiskTier, Verdict,
};
use factory_ports::paths::RepoRef;

use super::input::Dossier;
use super::seams::LedgerState;
use crate::handlers::RunIdentity;

/// The size of the change, measured from the patch the job's object store exported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeFacts {
    /// The hash of the patch.
    pub diff_sha256: Sha256Digest,
    /// Files changed.
    pub files_changed: u64,
    /// Lines added.
    pub insertions: u64,
    /// Lines removed.
    pub deletions: u64,
}

/// An adapter that took part, as the stage saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterReport {
    /// A short name such as `sandbox`.
    pub name: &'static str,
    /// What kind of adapter.
    pub kind: AdapterKind,
    /// What its `fidelity()` said.
    pub fidelity: Fidelity,
}

/// Everything the manifest is built from.
#[derive(Debug, Clone)]
pub struct ManifestInputs<'a> {
    /// The stored evidence.
    pub dossier: &'a Dossier,
    /// The stage run.
    pub identity: &'a RunIdentity,
    /// Production or test.
    pub mode: ExecutionMode,
    /// When the manifest is made.
    pub now: Timestamp,
    /// The new manifest's id.
    pub manifest_id: ManifestId,
    /// The repository.
    pub repo: &'a RepoRef,
    /// The size of the change.
    pub change: ChangeFacts,
    /// The verified ledger.
    pub ledger: &'a LedgerState,
    /// The tier the policy computed.
    pub risk: &'a RiskAssessment,
    /// The adapters that took part.
    pub adapters: Vec<AdapterReport>,
    /// The gates the validation stage always reports.
    pub expected_gates: &'a [&'a str],
    /// The title of the manifest. It is the cleaned title of the pull request
    /// ([`safe_title`](super::pr::safe_title)), never the raw title of the specification, so a
    /// secret or markup in that title is not stored with the evidence.
    pub title: String,
}

/// Why no manifest can be made. The set is closed and carries no document text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// A gate failed, or was blocked and no person decided about it.
    #[error("a gate has not cleared")]
    GateNotCleared(Slug),
    /// The review verdict is not `PASS`.
    #[error("the review did not pass")]
    ReviewNotPass,
    /// A value does not fit the limits of the manifest.
    #[error("a value does not fit the manifest")]
    Value,
    /// The finished manifest breaks a rule of its contract.
    #[error("the manifest breaks a rule of its contract")]
    Contract,
}

impl From<factory_domain::error::ValueError> for ManifestError {
    fn from(_: factory_domain::error::ValueError) -> Self {
        Self::Value
    }
}

/// The score the manifest shows for a tier. The policy defines tiers and no scores, so the score
/// is a fixed, monotonic presentation of the tier and carries no more information than it.
#[must_use]
pub const fn score_of(tier: RiskTier) -> i64 {
    match tier {
        RiskTier::Low => 10,
        RiskTier::Medium => 35,
        RiskTier::High => 65,
        RiskTier::Critical => 90,
    }
}

fn int(value: u64) -> Result<NonNegativeInt, ManifestError> {
    Ok(NonNegativeInt::new(
        i64::try_from(value).map_err(|_| ManifestError::Value)?,
    )?)
}

fn positive(value: u64) -> Result<PositiveInt, ManifestError> {
    Ok(PositiveInt::new(
        i64::try_from(value).map_err(|_| ManifestError::Value)?,
    )?)
}

fn text(sentence: &str) -> Result<HumanText, ManifestError> {
    Ok(HumanText::parse(sentence)?)
}

fn not_attained_reason(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::ProductionReady => {
            "The factory does not deploy or release, so nothing was verified in production."
        }
        AssuranceLevel::VerifiedOnDevice => {
            "No device run was part of this job, so nothing was verified on a device."
        }
        AssuranceLevel::VerifiedInSimulator => {
            "No simulator run was part of this job, so nothing was verified in a simulator."
        }
        AssuranceLevel::PaperValidated => {
            "No paper trading run was part of this job, so nothing was validated on paper."
        }
        _ => "The ledger holds no entry that supports this level for the job.",
    }
}

fn adapter_use(report: &AdapterReport) -> Result<AdapterUse, ManifestError> {
    Ok(AdapterUse {
        name: Slug::parse(report.name)?,
        kind: report.kind,
        fidelity: report.fidelity,
        // The ports do not report a version, so the manifest says so instead of inventing one.
        version: NonEmptyString::parse("not reported by the port")?,
    })
}

fn kind_label(kind: AdapterKind) -> &'static str {
    match kind {
        AdapterKind::AgentRuntime => "agent runtime",
        AdapterKind::Sandbox => "sandbox",
        AdapterKind::ChangeHost => "code host",
        AdapterKind::ArtifactStore => "artifact store",
        AdapterKind::Store => "database",
        AdapterKind::SpecificationProvider => "specification provider",
    }
}

fn approvals_required(tier: RiskTier) -> Result<UniqueVec<RequiredApproval, 1>, ManifestError> {
    let roles = if tier == RiskTier::Critical {
        vec![RequiredApproval::SecurityApprover]
    } else {
        vec![RequiredApproval::Approver]
    };
    Ok(UniqueVec::new(roles)?)
}

/// Builds the manifest and checks it against the rules of its contract.
///
/// # Errors
/// [`ManifestError`]: a gate that has not cleared, a review that is not `PASS`, a value that does
/// not fit, or a manifest that breaks its contract.
pub fn build(i: &ManifestInputs<'_>) -> Result<EvidenceManifest, ManifestError> {
    let dossier = i.dossier;
    let mut limitations: Vec<String> = Vec::new();

    let mut gate_entries = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for report in &dossier.validation.reports {
        let id = &report.metadata.gate_id;
        seen.insert(id.as_str());
        let sha = report.evidence_hash.clone();
        let (outcome, disposition) = match report.outcome {
            GateOutcome::Passed => (DeliveredGateOutcome::Passed, None),
            GateOutcome::NotApplicable => {
                limitations.push(format!(
                    "The gate {} does not apply to this change, so it did not run.",
                    id.as_str()
                ));
                (DeliveredGateOutcome::NotApplicable, None)
            }
            GateOutcome::Blocked => {
                let entry = i
                    .ledger
                    .dispositions
                    .iter()
                    .find(|(gate, _)| gate == id)
                    .map(|(_, entry)| *entry)
                    .ok_or_else(|| ManifestError::GateNotCleared(id.clone()))?;
                limitations.push(format!(
                    "The gate {} could not run. A person recorded a decision about it, and no result exists.",
                    id.as_str()
                ));
                (DeliveredGateOutcome::Blocked, Some(entry))
            }
            GateOutcome::Failed => return Err(ManifestError::GateNotCleared(id.clone())),
        };
        gate_entries.push(GateEntry {
            gate_id: id.clone(),
            outcome,
            sha256: sha,
            disposition_ledger_entry_id: disposition,
        });
    }
    for expected in i.expected_gates {
        if !seen.contains(expected) {
            limitations.push(format!(
                "The gate {expected} has no report, so it did not run."
            ));
        }
    }

    if dossier.review.verdict != Verdict::Pass {
        return Err(ManifestError::ReviewNotPass);
    }
    let reviewer: ReviewerRole = dossier.review.metadata.reviewer.role;

    for adapter in &i.adapters {
        if adapter.fidelity == Fidelity::Fake {
            limitations.push(format!(
                "The {} ({}) was a stand-in, not the real system.",
                kind_label(adapter.kind),
                adapter.name
            ));
        }
    }
    limitations.push(
        "The pull request is a draft. A person reviews it, marks it ready and merges it on the code host; the factory does neither."
            .to_owned(),
    );
    limitations.push(
        "Checks ran in a sandbox. Nothing was verified on a device, in a simulator, on paper trading or in production."
            .to_owned(),
    );

    let attained: Vec<Attained> = i
        .ledger
        .attained
        .iter()
        .map(|(level, entry)| Attained {
            level: *level,
            ledger_entry_id: *entry,
        })
        .collect();
    let not_attained: Vec<NotAttained> = [
        AssuranceLevel::Specified,
        AssuranceLevel::Implemented,
        AssuranceLevel::VerifiedInSandbox,
        AssuranceLevel::VerifiedInSimulator,
        AssuranceLevel::VerifiedOnDevice,
        AssuranceLevel::PaperValidated,
        AssuranceLevel::ProductionReady,
    ]
    .into_iter()
    .filter(|level| !i.ledger.attained.iter().any(|(held, _)| held == level))
    .map(|level| {
        Ok(NotAttained {
            level,
            reason: text(not_attained_reason(level))?,
        })
    })
    .collect::<Result<_, ManifestError>>()?;

    let spec = &dossier.specification;
    let plan = &dossier.plan;
    let title = HumanTitle::parse(&i.title)?;
    let summary = text(&format!(
        "This change implements version {} of the frozen specification. {} gate report(s) are attached and an independent review passed.",
        spec.metadata.spec_version.get(),
        dossier.validation.reports.len()
    ))?;

    let manifest = EvidenceManifest {
        schema_version: SchemaVersion,
        metadata: ManifestMetadata {
            manifest_id: i.manifest_id,
            job_id: i.identity.job,
            tenant_id: i.identity.tenant,
            generated_at: i.now,
            execution_mode: i.mode,
            repository: RepositoryRef {
                full_name: RepositoryName::parse(&i.repo.to_string())?,
                base_commit: factory_domain::values::GitSha::parse(
                    dossier.candidate.base.as_str(),
                )?,
                head_commit: factory_domain::values::GitSha::parse(
                    dossier.candidate.head.as_str(),
                )?,
            },
        },
        title,
        summary,
        ledger: LedgerHead {
            entry_count: positive(i.ledger.entry_count)?,
            head_sequence: positive(i.ledger.head_sequence)?,
            head_hash: i.ledger.head_hash.clone(),
            chain_verified_at: i.ledger.chain_verified_at,
        },
        specification: SpecificationRef {
            spec_id: spec.metadata.spec_id,
            spec_version: spec.metadata.spec_version,
            sha256: dossier.specification_sha256.clone(),
        },
        architecture: HashRef {
            sha256: dossier.architecture_sha256.clone(),
        },
        plan: PlanRef {
            plan_id: plan.metadata.plan_id,
            plan_version: plan.metadata.plan_version,
            sha256: dossier.plan_sha256.clone(),
        },
        change: ChangeSummary {
            diff_sha256: i.change.diff_sha256.clone(),
            files_changed: int(i.change.files_changed)?,
            insertions: int(i.change.insertions)?,
            deletions: int(i.change.deletions)?,
        },
        gate_reports: NonEmptyVec::new(gate_entries)?,
        reviews: NonEmptyVec::new(vec![ReviewEntry {
            role: reviewer,
            verdict: factory_domain::contracts::common::PassVerdict,
            sha256: dossier.review_sha256.clone(),
        }])?,
        documentation: DocumentationRefs {
            plan_sha256: dossier.documentation_plan_sha256.clone(),
            gate_report_sha256: dossier.documentation_gate_sha256.clone(),
            review_sha256: dossier.documentation_review_sha256.clone(),
        },
        assurance: Assurance {
            attained: UniqueVec::new(attained)?,
            not_attained,
        },
        adapters: NonEmptyVec::new(
            i.adapters
                .iter()
                .map(adapter_use)
                .collect::<Result<Vec<_>, _>>()?,
        )?,
        risk: ManifestRisk {
            tier: i.risk.tier,
            score: Bounded::new(score_of(i.risk.tier))?,
            rationale: text(&risk_rationale(i.risk))?,
        },
        approvals_required: approvals_required(i.risk.tier)?,
        limitations: NonEmptyVec::new(
            limitations
                .iter()
                .map(|line| text(line))
                .collect::<Result<Vec<_>, _>>()?,
        )?,
    };
    manifest.validate().map_err(|_| ManifestError::Contract)?;
    Ok(manifest)
}

fn risk_rationale(risk: &RiskAssessment) -> String {
    if risk.unclassified {
        return "No risk criterion matched the change, so the policy treats it as high risk."
            .to_owned();
    }
    format!(
        "The policy computed the tier {} from these facts of the change: {}.",
        risk.tier.as_str(),
        risk.matched.join(", ")
    )
}

/// The hash of the manifest as stored: the SHA-256 of its JSON form.
///
/// # Errors
/// [`ManifestError::Contract`] when the manifest cannot be written as JSON.
pub fn hash_of(manifest: &EvidenceManifest) -> Result<Sha256Digest, ManifestError> {
    let value = manifest
        .to_json_value()
        .map_err(|_| ManifestError::Contract)?;
    Ok(Sha256Digest::of(value.to_string().as_bytes()))
}
