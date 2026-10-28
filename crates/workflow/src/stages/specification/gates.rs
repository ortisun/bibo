//! `evaluate` of the specification stage: the rules of the gate, run again over what the stage
//! stored, and one report for each gate.
//!
//! Nothing here reads what the writer said. The contract and the evidence are the stage's own
//! artifacts, the files are re-read from the commit and hashed by the host, the transcripts are
//! read from the artifact store, and the approval is asked of the engine's record again.

use std::collections::BTreeMap;

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::specification_contract::SpecStatus;
use factory_domain::contracts::{ArtifactRef, Contract, GateReport, SpecificationContract};
use factory_domain::ids::GateReportId;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_domain::vocabulary::Fidelity;
use factory_ports::paths::{CommitSha, RepoGlob, RepoPath};
use factory_ports::workspace::{ReadView, WorkspaceError};

use super::evidence::Evidence;
use super::handler::SpecificationHandler;
use super::input::{EVIDENCE, SPECIFICATION_CONTRACT};
use super::judge::{JudgeInput, Judged, judge};
use crate::gates::framework::GateDecision;
use crate::gates::spec;
use crate::gates::spec::checklist::parse_waivers;
use crate::handlers::{GateContext, StageError};
use crate::stages::intake::common::{
    Executor, GateDefinition, GateFacts, GateSubject, gate_report,
};

const LIST_LIMIT: usize = 200;

pub(super) async fn evaluate(
    h: &SpecificationHandler,
    ctx: &GateContext<'_>,
) -> Result<GateDecision, StageError> {
    let ports = ctx.ports;
    let scope = TenantScope::new(ctx.identity.tenant);
    let unavailable = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let stored = |name: &str| {
        ctx.outputs
            .iter()
            .find(|output| output.name.as_str() == name)
            .map(|output| output.artifact.clone())
    };
    let evidence_ref = stored(EVIDENCE).ok_or(StageError::InvalidOutput)?;
    let evidence_bytes = ports
        .artifacts
        .get(&scope, &evidence_ref)
        .await
        .map_err(|_| unavailable())?;
    let evidence = serde_json::from_slice(&evidence_bytes)
        .ok()
        .and_then(|value| Evidence::from_json(&value))
        .ok_or(StageError::InvalidOutput)?;
    let contract = match stored(SPECIFICATION_CONTRACT) {
        Some(reference) => {
            let bytes = ports
                .artifacts
                .get(&scope, &reference)
                .await
                .map_err(|_| unavailable())?;
            Some(
                SpecificationContract::from_json_str(&String::from_utf8_lossy(&bytes))
                    .map_err(|_| StageError::InvalidOutput)?,
            )
        }
        None => None,
    };

    // The answers of people: their waivers.
    let mut waivers = Vec::new();
    for answer in ctx.human_inputs {
        let bytes = ports
            .artifacts
            .get(&scope, answer)
            .await
            .map_err(|_| unavailable())?;
        waivers.extend(parse_waivers(&String::from_utf8_lossy(&bytes)));
    }

    // The transcripts, by hash.
    let mut transcripts = Vec::new();
    for hash in &evidence.transcripts {
        let reference = ArtifactRef {
            sha256: Sha256Digest::parse(hash).map_err(|_| StageError::InvalidOutput)?,
            media_type: MediaType::parse("text/plain").map_err(|_| StageError::Internal)?,
            size_bytes: None,
        };
        transcripts.push(
            ports
                .artifacts
                .get(&scope, &reference)
                .await
                .map_err(|_| unavailable())?,
        );
    }

    // The files, read again from the commit and hashed by the host.
    let mut committed: BTreeMap<String, Sha256Digest> = BTreeMap::new();
    let mut listed: Vec<String> = Vec::new();
    if let (Some(head), Some(found)) = (&evidence.head_commit, &contract) {
        let head = CommitSha::parse(head).map_err(|_| StageError::InvalidOutput)?;
        let repo = ports
            .workspaces
            .repo(ctx.identity.job)
            .await
            .map_err(|_| unavailable())?;
        for artifact in found.provenance.artifacts.as_slice() {
            let Ok(path) = RepoPath::new(artifact.path.as_str()) else {
                continue;
            };
            match repo
                .read_file_at(&head, &path, h.config.max_file_bytes, ReadView::Trusted)
                .await
            {
                Ok(bytes) => {
                    committed.insert(path.as_str().to_owned(), Sha256Digest::of(&bytes));
                }
                Err(WorkspaceError::PathNotFound(_)) => {}
                Err(WorkspaceError::Cancelled) => return Err(StageError::Cancelled),
                Err(_) => return Err(unavailable()),
            }
        }
        if let Ok(glob) = RepoGlob::new(&format!("{}/**", evidence.feature_directory)) {
            listed = repo
                .list_at(&head, &glob, LIST_LIMIT, ReadView::Trusted)
                .await
                .map_err(|_| unavailable())?
                .into_iter()
                .map(|p| p.as_str().to_owned())
                .collect();
        }
    }
    let recorded: Vec<&str> = contract
        .as_ref()
        .map(|c| {
            c.provenance
                .artifacts
                .as_slice()
                .iter()
                .map(|a| a.path.as_str())
                .collect()
        })
        .unwrap_or_default();
    let unlisted: Vec<String> = listed
        .into_iter()
        .filter(|path| !recorded.contains(&path.as_str()))
        .collect();

    // An approved contract carries the approval the engine recorded, or it is refused.
    let approval_recorded = match (&contract, &evidence.draft_sha256) {
        (Some(c), Some(draft)) if c.metadata.status == SpecStatus::Approved => {
            let draft = Sha256Digest::parse(draft).map_err(|_| StageError::InvalidOutput)?;
            let recorded = h
                .approvals
                .approval(&ctx.identity, &draft)
                .await
                .map_err(|_| unavailable())?;
            let carried = c.metadata.approved_by.as_ref();
            Some(match (recorded, carried) {
                (Some(r), Some(c)) => {
                    r.principal == c.principal_id && r.role == c.role && r.basis == c.basis
                }
                _ => false,
            })
        }
        _ => None,
    };

    let judged = judge(&JudgeInput {
        contract: contract.as_ref(),
        evidence: &evidence,
        waivers: &waivers,
        limits: &h.config.limits,
        profile: &h.profile,
        transcripts: &transcripts,
        committed: &committed,
        unlisted: &unlisted,
        approval_recorded,
        writer: h.config.writer.as_str(),
    });
    let fidelity = if [
        ports.workspaces.fidelity(),
        ports.sandbox.fidelity(),
        ports.runtime.fidelity(),
        ports.artifacts.fidelity(),
    ]
    .contains(&Fidelity::Fake)
        || evidence.fake
    {
        "fake"
    } else {
        "real"
    };
    let mut reports: Vec<GateReport> = Vec::with_capacity(judged.len());
    for gate in &judged {
        reports.push(report_of(h, ctx, gate, fidelity, &evidence)?);
    }
    let profile_violated = judged
        .iter()
        .any(|gate| gate.id == spec::STAGE_PROFILE && !gate.findings.is_empty());
    Ok(GateDecision {
        reports,
        review: None,
        human_gate: false,
        // A violation of the stage profile is a violation of policy: the stage run is blocked, the
        // output is discarded and nobody is asked to override it.
        policy_violation: profile_violated,
        assurance: Vec::new(),
    })
}

fn report_of(
    h: &SpecificationHandler,
    ctx: &GateContext<'_>,
    gate: &Judged,
    fidelity: &'static str,
    evidence: &Evidence,
) -> Result<GateReport, StageError> {
    let ports = ctx.ports;
    let now = ports.clock.now();
    let failures: Vec<(String, String)> = gate
        .findings
        .iter()
        .map(|f| (f.code.to_owned(), f.message.clone()))
        .collect();
    let outcome = if gate.blocked.is_some() {
        "BLOCKED"
    } else if failures.is_empty() {
        "PASSED"
    } else {
        "FAILED"
    };
    let mut lines = vec![format!("gate={}", gate.id)];
    lines.push(format!("base={}", evidence.base_commit));
    if let Some(head) = &evidence.head_commit {
        lines.push(format!("head={head}"));
    }
    lines.extend(gate.findings.iter().map(|f| format!("finding={}", f.code)));
    gate_report(
        &GateSubject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
            report_id: GateReportId::from_uuid(ports.ids.new_uuid()),
            started_at: now,
            finished_at: ports.clock.now(),
        },
        &GateFacts {
            definition: GateDefinition {
                id: gate.id,
                version: "1.0.0",
                text: gate.text,
                commit: h.config.definition_commit.clone(),
            },
            outcome,
            title: gate.title.to_owned(),
            reason: if failures.is_empty() {
                "The gate found nothing wrong.".to_owned()
            } else {
                format!("The gate found {} problem(s).", failures.len())
            },
            failures,
            blocked: gate.blocked.clone(),
            fidelity,
            executor: Executor::InProcess,
            commands: Vec::new(),
            tools: vec![("factory-specification".to_owned(), "1.0.0".to_owned())],
            evidence: lines,
        },
    )
}
