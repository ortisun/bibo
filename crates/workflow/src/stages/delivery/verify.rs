//! `evaluate` of the delivery stage: three gates over what the stage stored and what the code host
//! now says.
//!
//! | Gate | Answers |
//! |---|---|
//! | `delivery-pull-request` | Does the pull request exist, is it open and a draft, and does it point at the delivered commit on the factory branch? A pull request that is not a draft is a violation of policy, not a failure to retry |
//! | `delivery-manifest` | Does the stored manifest follow its contract, and is its hash the one in the stored body? |
//! | `readability-gate` | Do the stored title and body follow the readability rules? |
//!
//! Nothing here reads a report the stage wrote about itself. The pull request is read from the
//! code host, the manifest and the text from the artifact store by the hash the engine recorded.

use factory_domain::contracts::{Contract, EvidenceManifest, GateReport};
use factory_domain::ids::GateReportId;
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::githost::{GitScope, PullRequestLifecycle, PullRequestRef};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use serde_json::Value;

use super::contract::{MANIFEST, MANIFEST_GATE, PULL_REQUEST_GATE, RESULT};
use super::handler::{DeliveryHandler, fidelity_of, host_error};
use super::manifest;
use crate::gates::framework::GateDecision;
use crate::gates::readability::{
    Artifact, GATE_ID as READABILITY_GATE, ReportContext as ReadabilityContext, ReviewerPolicy,
};
use crate::handlers::{GateContext, StageError};
use crate::stages::intake::common::{
    Executor, GateDefinition, GateFacts, GateSubject, gate_report,
};
use factory_domain::contracts::gate_report::{BlockedCode, DefinitionSource};

const PULL_REQUEST_TEXT: &str = "delivery-pull-request 1.0.0: the pull request exists on the code host, is open, is a draft, is on the factory branch and points at the delivered commit.";
const MANIFEST_TEXT: &str = "delivery-manifest 1.0.0: the stored evidence manifest follows its contract, it cites the commit the pull request was opened from, and its hash is the one written in the pull request body.";

/// What `execute` stored about the delivery.
struct Stored {
    delivered: bool,
    repository: String,
    head_branch: String,
    head_commit: String,
    manifest_sha256: String,
    pull_request: Option<u64>,
    title: Option<String>,
    body: Option<String>,
}

fn read_result(value: &Value) -> Option<Stored> {
    let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    Some(Stored {
        delivered: value.get("delivered").and_then(Value::as_bool)?,
        repository: text("repository")?,
        head_branch: text("head_branch")?,
        head_commit: text("head_commit")?,
        manifest_sha256: text("manifest_sha256")?,
        pull_request: value.get("pull_request").and_then(Value::as_u64),
        title: text("title"),
        body: text("body"),
    })
}

impl DeliveryHandler {
    pub(super) async fn verify(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let ports = ctx.ports;
        let scope = TenantScope::new(ctx.identity.tenant);
        let unavailable = || StageError::Blocked(BlockedCode::DependencyUnavailable);
        let stored = |name: &str| {
            ctx.outputs
                .iter()
                .find(|output| output.name.as_str() == name)
                .map(|output| output.artifact.clone())
        };
        let result_ref = stored(RESULT).ok_or(StageError::InvalidOutput)?;
        let manifest_ref = stored(MANIFEST).ok_or(StageError::InvalidOutput)?;
        let result_bytes = ports
            .artifacts
            .get(&scope, &result_ref)
            .await
            .map_err(|_| unavailable())?;
        let manifest_bytes = ports
            .artifacts
            .get(&scope, &manifest_ref)
            .await
            .map_err(|_| unavailable())?;
        let result: Stored = serde_json::from_slice::<Value>(&result_bytes)
            .ok()
            .as_ref()
            .and_then(read_result)
            .ok_or(StageError::InvalidOutput)?;

        let fidelity = match fidelity_of(&[
            self.deps.host.fidelity(),
            self.deps.sources.fidelity(),
            ports.artifacts.fidelity(),
        ]) {
            Fidelity::Fake => "fake",
            Fidelity::Real => "real",
        };
        let now = ports.clock.now();
        let subject = || GateSubject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
            report_id: GateReportId::from_uuid(ports.ids.new_uuid()),
            started_at: now,
            finished_at: ports.clock.now(),
        };
        let definition = |id: &'static str, text: &'static str| GateDefinition {
            id,
            version: "1.0.0",
            text,
            commit: self.config.definition_commit.clone(),
        };
        let report = |id: &'static str,
                      text: &'static str,
                      title: &str,
                      failures: Vec<(String, String)>,
                      evidence: Vec<String>|
         -> Result<GateReport, StageError> {
            let passed = failures.is_empty();
            gate_report(
                &subject(),
                &GateFacts {
                    definition: definition(id, text),
                    outcome: if passed { "PASSED" } else { "FAILED" },
                    title: title.to_owned(),
                    reason: if passed {
                        "Every check of the gate held.".to_owned()
                    } else {
                        failures
                            .iter()
                            .map(|(_, message)| message.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    },
                    failures,
                    blocked: None,
                    fidelity,
                    executor: Executor::InProcess,
                    commands: Vec::new(),
                    tools: vec![("factory-delivery".to_owned(), "1.0.0".to_owned())],
                    evidence,
                },
            )
        };

        // The manifest.
        let mut manifest_failures: Vec<(String, String)> = Vec::new();
        let parsed = std::str::from_utf8(&manifest_bytes)
            .ok()
            .and_then(|text| EvidenceManifest::from_json_str(text).ok());
        match &parsed {
            None => manifest_failures.push((
                "manifest-invalid".to_owned(),
                "The stored manifest does not follow the evidence manifest contract.".to_owned(),
            )),
            Some(parsed) => {
                if parsed.validate().is_err() {
                    manifest_failures.push((
                        "manifest-invalid".to_owned(),
                        "The stored manifest breaks a rule of the evidence manifest contract."
                            .to_owned(),
                    ));
                }
                // The manifest and the pull request must name the same head: the commit that was
                // pushed, which is the documentation commit when there is one.
                if parsed.metadata.repository.head_commit.as_str() != result.head_commit {
                    manifest_failures.push((
                        "manifest-head-differs".to_owned(),
                        "The stored manifest cites another commit than the one the pull request was opened from."
                            .to_owned(),
                    ));
                }
                let recomputed = manifest::hash_of(parsed).ok();
                if recomputed.as_ref().map(Sha256Digest::as_str)
                    != Some(result.manifest_sha256.as_str())
                {
                    manifest_failures.push((
                        "manifest-hash-differs".to_owned(),
                        "The hash of the stored manifest is not the hash the delivery recorded."
                            .to_owned(),
                    ));
                }
                if let Some(body) = &result.body
                    && !body.contains(&result.manifest_sha256_hex())
                {
                    manifest_failures.push((
                        "body-lacks-manifest-hash".to_owned(),
                        "The text of the pull request does not carry the hash of the manifest."
                            .to_owned(),
                    ));
                }
            }
        }
        let manifest_report = report(
            MANIFEST_GATE,
            MANIFEST_TEXT,
            "Evidence manifest",
            manifest_failures,
            vec![format!("manifest={}", result.manifest_sha256)],
        )?;

        // The pull request, read back from the code host.
        let mut pr_failures: Vec<(String, String)> = Vec::new();
        let mut violation = false;
        match (result.delivered, result.pull_request) {
            (true, Some(number)) => {
                let repo =
                    RepoRef::parse(&result.repository).map_err(|_| StageError::InvalidOutput)?;
                let head =
                    BranchName::new(&result.head_branch).map_err(|_| StageError::InvalidOutput)?;
                let head_commit =
                    CommitSha::parse(&result.head_commit).map_err(|_| StageError::InvalidOutput)?;
                let git = GitScope {
                    tenant: ctx.identity.tenant,
                    job: ctx.identity.job,
                    stage: StageKind::Delivery,
                    repo: repo.clone(),
                };
                match self
                    .deps
                    .host
                    .pull_request_state(&git, &PullRequestRef { repo, number })
                    .await
                {
                    Ok(state) => {
                        if state.lifecycle != PullRequestLifecycle::Open {
                            pr_failures.push((
                                "pull-request-not-open".to_owned(),
                                "The pull request is not open.".to_owned(),
                            ));
                        }
                        if !state.draft {
                            violation = true;
                            pr_failures.push((
                                "pull-request-not-draft".to_owned(),
                                "The pull request is not a draft. The factory opens drafts only, and a person marks a pull request ready."
                                    .to_owned(),
                            ));
                        }
                        if state.head != head || state.head_sha != head_commit {
                            violation = true;
                            pr_failures.push((
                                "pull-request-at-another-commit".to_owned(),
                                "The pull request does not point at the delivered commit on the factory branch."
                                    .to_owned(),
                            ));
                        }
                    }
                    Err(error) => {
                        if matches!(host_error(&error), StageError::Provider) {
                            return Err(StageError::Provider);
                        }
                        pr_failures.push((
                            "pull-request-missing".to_owned(),
                            "The code host has no such pull request.".to_owned(),
                        ));
                    }
                }
            }
            _ => pr_failures.push((
                "no-pull-request".to_owned(),
                "No pull request was opened, because the text of it did not pass the checks."
                    .to_owned(),
            )),
        }
        let pr_report = report(
            PULL_REQUEST_GATE,
            PULL_REQUEST_TEXT,
            "Draft pull request",
            pr_failures,
            vec![
                format!("head={}", result.head_commit),
                format!("delivered={}", result.delivered),
            ],
        )?;

        // The readability gate, over the stored text.
        let readability = match (&result.title, &result.body) {
            (Some(title), Some(body)) => self
                .config
                .readability
                .evaluate(
                    &[Artifact::pull_request(title, body)],
                    &ReadabilityContext {
                        gate_report_id: GateReportId::from_uuid(ports.ids.new_uuid()),
                        job_id: ctx.identity.job,
                        stage_run_id: ctx.identity.stage_run,
                        attempt_id: Some(ctx.attempt),
                        execution_mode: ctx.mode,
                        definition_source: DefinitionSource::CentralConfig,
                        definition_commit: self.config.definition_commit.clone(),
                        started_at: now,
                        finished_at: ports.clock.now(),
                        reviewer: ReviewerPolicy::Optional,
                    },
                )
                .map_err(|_| StageError::Internal)?,
            _ => report(
                READABILITY_GATE,
                "readability-gate 1.0.0 (delivery): the text of the pull request could not be written from the evidence.",
                "Pull request text",
                vec![(
                    "text-refused".to_owned(),
                    "The text of the pull request was refused: it held a secret, markup or a link that is not allowed."
                        .to_owned(),
                )],
                vec!["text=refused".to_owned()],
            )?,
        };

        Ok(GateDecision {
            reports: vec![pr_report, manifest_report, readability],
            policy_violation: violation,
            ..GateDecision::default()
        })
    }
}

impl Stored {
    /// The hash as it is written in the body: 64 lowercase hex characters, with no prefix.
    fn manifest_sha256_hex(&self) -> String {
        self.manifest_sha256
            .strip_prefix("sha256:")
            .unwrap_or(&self.manifest_sha256)
            .to_owned()
    }
}
