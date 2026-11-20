//! The delivery stage handler.
//!
//! `execute` checks that the evidence still describes the world, builds the manifest and the text
//! of the pull request from stored documents, pushes the factory branch, opens a **draft** pull
//! request, and publishes the gate results as check runs. `evaluate` reads the pull request back
//! and checks the stored manifest and text. Neither says that the stage passed.
//!
//! # What this stage never does
//!
//! It has no way to merge, to mark a pull request ready for review, or to deploy: the
//! `ChangeHost` port has no such method, and `cargo xtask check-architecture` bans the names.
//! A pull request that is not a draft after the stage ran is a failed gate.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::evidence_manifest::AdapterKind;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{Contract, StageContract};
use factory_domain::ids::ManifestId;
use factory_domain::policy::PolicyEngine;
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType, Slug};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::githost::{ChangeHost, GitHostError, GitScope};
use factory_ports::registry::ContractKind;
use factory_ports::workspace::WorkspaceError;
use serde_json::{Value, json};

use super::binding;
use super::checks::{review_check, validation_check};
use super::contract::{MANIFEST, RESULT, resolve};
use super::design_recheck::DesignRecheck;
use super::input::{self, DossierError, POLICY_INPUT, contract_input};
use super::manifest::{self, AdapterReport, ChangeFacts, ManifestError, ManifestInputs};
use super::pr::{self, PrFacts};
use super::publish;
use super::risk;
use super::seams::{DeliverySources, EvidenceDrift, SeamError};
use crate::gates::framework::GateDecision;
use crate::gates::readability::{Artifact, ReadabilityGate, Severity};
use crate::gates::scope::hardening::PatchSignals;
use crate::handlers::{
    ContractContext, GateContext, OutputDocument, StageContext, StageError, StageHandler,
    StageOutput,
};
use crate::stages::validation::GATES as VALIDATION_GATES;

/// What the delivery stage is built from by the composition root.
#[derive(Clone)]
pub struct DeliveryConfig {
    /// The policy engine: the risk tier is computed here.
    pub policy: Arc<PolicyEngine>,
    /// Finds secrets in the text before it is sent.
    pub redactor: Arc<Redactor>,
    /// The commit of the factory's own gate definitions, recorded in the stage's gate reports.
    pub definition_commit: GitSha,
    /// The readability gate for the title and the body.
    pub readability: ReadabilityGate,
    /// The largest patch the stage reads to count the change, in bytes.
    pub max_patch_bytes: u64,
}

impl std::fmt::Debug for DeliveryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeliveryConfig { .. }")
    }
}

/// The ports and seams the delivery stage uses besides the engine's.
#[derive(Clone)]
pub struct DeliveryDeps {
    /// Pushes through `JobRepo`, opens the draft pull request, publishes check runs.
    pub host: Arc<dyn ChangeHost>,
    /// Facts from the store and the repository configuration.
    pub sources: Arc<dyn DeliverySources>,
    /// Tells the engine that a bound value changed.
    pub drift: Arc<dyn EvidenceDrift>,
    /// Checks the design of the issue again right before the pull request is opened (DG-8).
    pub recheck: DesignRecheck,
}

/// The delivery stage.
#[derive(Clone)]
pub struct DeliveryHandler {
    pub(super) config: Arc<DeliveryConfig>,
    pub(super) deps: DeliveryDeps,
}

impl std::fmt::Debug for DeliveryHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeliveryHandler { .. }")
    }
}

impl DeliveryHandler {
    /// A handler built from the composition root's configuration.
    #[must_use]
    pub fn new(config: Arc<DeliveryConfig>, deps: DeliveryDeps) -> Self {
        Self { config, deps }
    }
}

pub(crate) fn dossier_error(error: DossierError) -> StageError {
    match error {
        DossierError::Missing => StageError::Blocked(BlockedCode::DependencyUnavailable),
        DossierError::Invalid => StageError::InvalidOutput,
        DossierError::NotDeliverable | DossierError::Stale => StageError::PolicyDenied,
    }
}

pub(crate) fn seam_error(error: SeamError) -> StageError {
    match error {
        SeamError::NotFound => StageError::Blocked(BlockedCode::DependencyUnavailable),
        SeamError::Unavailable => StageError::Tool,
    }
}

/// How a failure of the code host is classified. A refusal of a credential or of the text is a
/// policy matter and is never retried; an outage is.
pub(crate) fn host_error(error: &GitHostError) -> StageError {
    match error {
        GitHostError::Unavailable | GitHostError::RateLimited { .. } => StageError::Provider,
        GitHostError::Unauthorized
        | GitHostError::Forbidden
        | GitHostError::BranchNotAllowed
        | GitHostError::UnsafeText => StageError::PolicyDenied,
        GitHostError::NotFound | GitHostError::Conflict | GitHostError::Rejected(_) => {
            StageError::Tool
        }
    }
}

pub(crate) fn workspace_error(error: &WorkspaceError) -> StageError {
    match error {
        WorkspaceError::Cancelled => StageError::Cancelled,
        WorkspaceError::NonFastForward
        | WorkspaceError::BranchNotAllowed
        | WorkspaceError::Unauthorized
        | WorkspaceError::NotMadeHere => StageError::PolicyDenied,
        _ => StageError::Tool,
    }
}

fn media_json() -> Result<MediaType, StageError> {
    MediaType::parse("application/json").map_err(|_| StageError::Internal)
}

pub(crate) fn slug(text: &str) -> Result<Slug, StageError> {
    Slug::parse(text).map_err(|_| StageError::Internal)
}

pub(crate) fn fidelity_of(parts: &[Fidelity]) -> Fidelity {
    if parts.contains(&Fidelity::Fake) {
        Fidelity::Fake
    } else {
        Fidelity::Real
    }
}

#[async_trait]
impl StageHandler for DeliveryHandler {
    fn fidelity(&self) -> Fidelity {
        fidelity_of(&[
            self.deps.host.fidelity(),
            self.deps.sources.fidelity(),
            self.deps.recheck.fidelity(),
        ])
    }

    fn kind(&self) -> StageKind {
        StageKind::Delivery
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        resolve(ctx)
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let ports = ctx.ports;
        let identity = ctx.identity;
        let scope = TenantScope::new(identity.tenant);
        let dossier = input::read(ports.artifacts, &scope, ctx.contract)
            .await
            .map_err(dossier_error)?;
        let target = self
            .deps
            .sources
            .target(&identity)
            .await
            .map_err(seam_error)?;
        let git = GitScope {
            tenant: identity.tenant,
            job: identity.job,
            stage: StageKind::Delivery,
            repo: target.repo.clone(),
        };

        // 1. The evidence must still describe the world. The base is resolved again here, before
        //    anything is pushed (ADR 0010). The gates ran on the code head, so the binding is
        //    compared with the code head and not with the documentation commit on top of it.
        let live_base = self
            .deps
            .host
            .resolve_branch(&git, &target.base)
            .await
            .map_err(|e| host_error(&e))?;
        let current = self
            .deps
            .sources
            .current_values(&identity, &dossier.candidate.base)
            .await
            .map_err(seam_error)?;
        let policy_hash = contract_input(ctx.contract, POLICY_INPUT)
            .ok_or(StageError::Blocked(BlockedCode::PolicyUnresolvable))?
            .sha256;
        let differences = binding::differences(
            &dossier.validation.binding,
            &binding::Now {
                live_base: &live_base,
                current: &current,
                policy_hash: &policy_hash,
                head: &dossier.candidate.head,
                implementation_sha256: &dossier.implementation_sha256,
            },
        )
        .ok_or(StageError::Internal)?;
        if !differences.is_empty() {
            return self.binding_failed(&identity, &differences).await;
        }

        // 2. The change, measured on the host from the job's object store: everything the pull
        //    request will hold, from the base to the pushed head.
        let repo = ports
            .workspaces
            .repo(identity.job)
            .await
            .map_err(|e| workspace_error(&e))?;
        let export = repo
            .export_patch(
                &dossier.candidate.base,
                &dossier.pushed_head,
                self.config.max_patch_bytes,
                ctx.cancel,
            )
            .await
            .map_err(|e| workspace_error(&e))?;
        let patch = ports
            .artifacts
            .get(&scope, &export.patch)
            .await
            .map_err(|_| StageError::Blocked(BlockedCode::DependencyUnavailable))?;
        let (insertions, deletions) = count_lines(&patch);
        let change = ChangeFacts {
            diff_sha256: export.patch.sha256.clone(),
            files_changed: export.changes.len() as u64,
            insertions,
            deletions,
        };

        // 3. The manifest, from typed evidence.
        let ledger = self
            .deps
            .sources
            .ledger(&identity)
            .await
            .map_err(seam_error)?;
        // The tier is the highest of what the job and the design show and what the diff shows,
        // and the intake classifier's claim can raise it (AUT-10).
        let measured = risk::assess_with_patch(
            &self.config.policy,
            &target.risk,
            target.agent_claim,
            &export.changes,
            &PatchSignals::of(&patch),
        );
        let risk = measured.assessment.clone();
        let manifest = manifest::build(&ManifestInputs {
            dossier: &dossier,
            identity: &identity,
            mode: ctx.mode,
            now: ports.clock.now(),
            manifest_id: ManifestId::from_uuid(ports.ids.new_uuid()),
            repo: &target.repo,
            change: change.clone(),
            ledger: &ledger,
            risk: &risk,
            adapters: vec![
                adapter(
                    "agent-runtime",
                    AdapterKind::AgentRuntime,
                    ports.runtime.fidelity(),
                ),
                adapter("sandbox", AdapterKind::Sandbox, ports.sandbox.fidelity()),
                adapter(
                    "change-host",
                    AdapterKind::ChangeHost,
                    self.deps.host.fidelity(),
                ),
                adapter(
                    "artifact-store",
                    AdapterKind::ArtifactStore,
                    ports.artifacts.fidelity(),
                ),
                adapter("store", AdapterKind::Store, self.deps.sources.fidelity()),
            ],
            expected_gates: &VALIDATION_GATES.map(|(gate, _)| gate),
            same_family_reviews: same_family_reviews(ports.artifacts, &scope, ctx.upstream).await,
            title: pr::safe_title(
                dossier.specification.title.as_str(),
                target.issue.number,
                &self.config.redactor,
            )
            .0,
        })
        .map_err(|e| match e {
            ManifestError::GateNotCleared(_) | ManifestError::ReviewNotPass => {
                StageError::PolicyDenied
            }
            ManifestError::Value | ManifestError::Contract => StageError::InvalidOutput,
        })?;
        let manifest_hash = manifest::hash_of(&manifest).map_err(|_| StageError::Internal)?;

        // 4. The text, from the manifest and the dossier. A text that is refused stops the stage
        //    before the host is touched. The title follows the project's git conventions, read at
        //    the base the job worked from.
        let conventions = crate::conventions::load(ctx, &dossier.candidate.base).await?;
        let text = pr::compose(
            &PrFacts {
                dossier: &dossier,
                manifest: &manifest,
                manifest_hash: &manifest_hash,
                target: &target,
                risk: &risk,
                change: &change,
                conventions: conventions.as_ref(),
            },
            &self.config.redactor,
        );
        let tree = self
            .deps
            .sources
            .tree_of(&identity, &dossier.pushed_head)
            .await
            .map_err(seam_error)?;

        // `head_commit` is the commit the pull request points at, which is what the approval
        // binds to. `code_head` is the commit the gates ran on, which the evidence binds to.
        let mut result = json!({
            "kind": RESULT,
            "delivered": false,
            "repository": target.repo.to_string(),
            "base_branch": target.base.as_str(),
            "head_branch": target.head.as_str(),
            "base_commit": dossier.candidate.base.as_str(),
            "head_commit": dossier.pushed_head.as_str(),
            "code_head": dossier.candidate.head.as_str(),
            "tree": tree.as_str(),
            "manifest_sha256": manifest_hash.as_str(),
            "spec_version": dossier.specification.metadata.spec_version.get(),
            "issue": target.issue.number,
            "risk": measured.reported().to_json(),
        });
        let documents = |result: Value| -> Result<StageOutput, StageError> {
            Ok(StageOutput {
                documents: vec![
                    OutputDocument {
                        name: slug(MANIFEST)?,
                        contract: Some((ContractKind::EvidenceManifest, 1)),
                        media_type: media_json()?,
                        value: manifest.to_json_value().map_err(|_| StageError::Internal)?,
                    },
                    OutputDocument {
                        name: slug(RESULT)?,
                        contract: None,
                        media_type: media_json()?,
                        value: result,
                    },
                ],
                ..StageOutput::default()
            })
        };
        let Ok(text) = text else {
            return documents(result);
        };
        if self.blocks(&text) {
            result["title"] = json!(text.title);
            result["body"] = json!(text.body);
            return documents(result);
        }

        // 5. The design is checked again, right before the first effect (DG-8). An approval that
        //    was taken back while the job ran, a second design label, or a code host that cannot
        //    be read stops the stage here: nothing is pushed and no pull request is opened.
        self.deps.recheck.check(ctx, &git, &target.issue).await?;

        // 6. Effects. Each is safe to repeat.
        let published = publish::deliver(
            self.deps.host.as_ref(),
            &*repo,
            &git,
            &target,
            &dossier,
            &text,
            identity.stage_run,
            ctx.cancel,
        )
        .await?;
        let checks = [
            validation_check(
                &dossier.pushed_head,
                &dossier.candidate.head,
                &published.external_id,
                &dossier.validation.reports,
            ),
            review_check(
                &dossier.pushed_head,
                &dossier.candidate.head,
                &published.external_id,
                dossier.review.verdict,
                dossier.review.findings.len(),
            ),
        ];
        let mut check_log = Vec::new();
        for request in checks.into_iter().flatten() {
            let name = request.name.as_str().to_owned();
            let status = format!("{:?}", request.status);
            let made = self
                .deps
                .host
                .publish_check(&git, request)
                .await
                .map_err(|e| host_error(&e))?;
            check_log.push(json!({ "name": name, "id": made.id, "status": status }));
        }
        result["delivered"] = json!(true);
        result["pull_request"] = json!(published.number);
        result["title"] = json!(text.title);
        result["body"] = json!(text.body);
        result["check_runs"] = json!(check_log);
        documents(result)
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        self.verify(ctx).await
    }
}

impl DeliveryHandler {
    /// True when the readability gate has a finding that blocks.
    fn blocks(&self, text: &pr::PrText) -> bool {
        self.config
            .readability
            .findings(&[Artifact::pull_request(&text.title, &text.body)])
            .map_or(true, |findings| {
                findings
                    .iter()
                    .any(|finding| finding.severity == Severity::Block)
            })
    }

    /// A bound value changed: the engine supersedes the runs that depend on the evidence, and this
    /// attempt, which the engine cancels with them, stops.
    async fn binding_failed(
        &self,
        identity: &crate::handlers::RunIdentity,
        differences: &[&'static str],
    ) -> Result<StageOutput, StageError> {
        if binding::is_drift(differences) {
            self.deps
                .drift
                .binding_changed(identity.tenant, identity.job)
                .await
                .map_err(seam_error)?;
            return Err(StageError::Cancelled);
        }
        // The evidence is about another commit or another implementation. Nothing changed in the
        // world; the documents disagree with each other, and no one waives that.
        Err(StageError::PolicyDenied)
    }
}

fn adapter(name: &'static str, kind: AdapterKind, fidelity: Fidelity) -> AdapterReport {
    AdapterReport {
        name,
        kind,
        fidelity,
    }
}

/// Lines added and removed in a unified diff, not counting the file headers.
fn count_lines(patch: &[u8]) -> (u64, u64) {
    let text = String::from_utf8_lossy(patch);
    let mut added = 0u64;
    let mut removed = 0u64;
    for line in text.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            added += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            removed += 1;
        }
    }
    (added, removed)
}

/// The reviews of the job that another model of the author's own family made, read from the
/// records the code review and the documentation review stored next to their verdicts. A record
/// that cannot be read says nothing here; the verdicts themselves are read and checked by the
/// dossier.
async fn same_family_reviews(
    artifacts: &dyn factory_ports::artifact::ArtifactStore,
    scope: &TenantScope,
    upstream: &[crate::handlers::UpstreamRun],
) -> Vec<(
    &'static str,
    crate::stages::review::independence::SameFamilyReview,
)> {
    let mut found = Vec::new();
    for (review, kind, name) in [
        (
            "code review",
            StageKind::Review,
            crate::stages::review::RECORD,
        ),
        (
            "documentation review",
            StageKind::DocumentationReview,
            crate::stages::documenting::DOCUMENTATION_REVIEW_RECORD,
        ),
    ] {
        let Some((_, stored)) = super::input::upstream_output(upstream, kind, name) else {
            continue;
        };
        let Ok(bytes) = artifacts.get(scope, stored).await else {
            continue;
        };
        if let Some(same) = crate::stages::review::independence::same_family_review(&bytes) {
            found.push((review, same));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_counted_without_the_file_headers() {
        let patch = b"--- a/x\n+++ b/x\n-old\n+new\n+newer\n context\n";
        assert_eq!(count_lines(patch), (2, 1));
    }

    #[test]
    fn a_failure_of_the_host_is_classified_by_what_to_do_next() {
        assert_eq!(host_error(&GitHostError::Unavailable), StageError::Provider);
        assert_eq!(
            host_error(&GitHostError::UnsafeText),
            StageError::PolicyDenied
        );
        assert_eq!(
            host_error(&GitHostError::Unauthorized),
            StageError::PolicyDenied
        );
        assert_eq!(host_error(&GitHostError::Conflict), StageError::Tool);
    }
}
