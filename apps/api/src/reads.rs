//! What a person reads before they decide: the specification draft they approve, the gate reports
//! of the evidence, and the stored documents behind both.
//!
//! * `GET /v1/jobs/{job_id}/specification-draft` gives the commit that holds the draft, the head of
//!   the ledger and the facts of the approval window, so that a person can write `head=` and
//!   `evidence=` of an `approve` for what they read and not for what someone told them. The commit
//!   is the one the worker compares with (`StoreSpecDrafts`, the seam the hook reads).
//! * `GET /v1/jobs/{job_id}/gate-reports` lists every gate report the engine wrote into the ledger
//!   of the job, with the gate, the outcome, the block code and the hash of the report.
//! * `GET /v1/jobs/{job_id}/artifacts/{sha256}` downloads one stored document of the job.
//!
//! # Who may read
//!
//! Any designation of the tenant, as for the status and the timeline, and only on a repository the
//! caller's allowlist entry reaches (API-1). Two layers keep a tenant out of another's documents,
//! and each is checked on its own in the tests: row-level security in the database (the
//! transaction is opened for the caller's tenant, so another tenant's job, links and index rows are
//! not visible) and the application's own scope (the artifact must be linked to a stage run of the
//! job in the path, and the artifact store answers only for a hash the tenant's index names).
//!
//! # What a download is
//!
//! The text of a document is untrusted: it may hold anything an agent or a person wrote. It is
//! served under one of two content types the API fixes (`text/plain; charset=utf-8` for documents
//! the stages store as text or JSON, `application/octet-stream` for the rest), always with
//! `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`, and never larger than
//! [`MAX_DOWNLOAD_BYTES`]. A larger document is `413`, not a cut one.

use factory_composition::specs::{DRAFT_ROLE_PREFIX, StoreSpecDrafts};
use factory_domain::contracts::evidence_ledger_entry::Evidence;
use factory_domain::contracts::{Contract as _, GateReport};
use factory_domain::ids::{JobId, StageRunId};
use factory_domain::state::StageRunStatus;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::StageKind;
use factory_ports::artifact::ArtifactError;
use factory_ports::store::{ArtifactDirection, StoreError};
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::specification::seams::SpecDrafts;
use serde_json::{Value, json};

use crate::answers::{Answer, ApiError, Download, Reply};
use crate::auth::{Caller, require_repository};
use crate::jobs::parse_id;
use crate::state::ApiState;

/// The largest document a download serves, in bytes.
pub const MAX_DOWNLOAD_BYTES: u64 = 4 * 1024 * 1024;

/// The most gate reports one listing reads.
pub const MAX_REPORTS: usize = 200;

/// The ledger is read in pages of this many entries, at most [`MAX_LEDGER_PAGES`] of them.
const LEDGER_PAGE: u32 = 500;
const MAX_LEDGER_PAGES: u32 = 10;

/// True when a document of `size` bytes may be served.
fn size_ok(size: i64) -> bool {
    u64::try_from(size).is_ok_and(|size| size <= MAX_DOWNLOAD_BYTES)
}

/// The query of `GET /v1/jobs/{job_id}/specification-draft`: `stage_run_id` (a UUID), and nothing
/// else.
fn draft_query(query: Option<&str>) -> Result<Option<StageRunId>, ApiError> {
    let mut found = None;
    for pair in query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        match pair.split_once('=') {
            Some(("stage_run_id", value)) if found.is_none() => {
                found = Some(
                    parse_id(value, StageRunId::parse)
                        .ok_or(ApiError::BadRequest("stage_run_id"))?,
                );
            }
            _ => return Err(ApiError::BadRequest("query")),
        }
    }
    Ok(found)
}

/// The number of a draft link role (`spec-draft-<n>`), or `None` for any other role.
fn draft_number(role: &str) -> Option<u32> {
    let digits = role.strip_prefix(DRAFT_ROLE_PREFIX)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// `GET /v1/jobs/{job_id}/specification-draft`.
#[allow(clippy::too_many_lines)]
pub async fn specification_draft(
    state: &ApiState,
    caller: &Caller,
    job_id: &str,
    query: Option<&str>,
) -> Answer {
    caller.require_listed()?;
    let job_id = parse_id(job_id, JobId::parse).ok_or(ApiError::NotFound)?;
    let wanted = draft_query(query)?;
    let artifacts = state
        .ports
        .artifacts
        .as_ref()
        .ok_or(ApiError::Unavailable)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let read = async {
        let job = tx.get_job(job_id).await?;
        let repository = tx.get_repository(job.value.repository).await?;
        let runs = tx.list_stage_runs(job_id).await?;
        let run = runs
            .iter()
            .filter(|run| {
                run.value.kind == StageKind::Specification
                    && wanted.is_none_or(|named| named == run.value.id)
            })
            .max_by_key(|run| run.value.run_number)
            .map(|run| run.value.clone());
        let Some(run) = run else {
            return Ok::<_, StoreError>(None);
        };
        let links = tx.list_stage_run_artifacts(run.id).await?;
        let newest = links
            .iter()
            .filter(|link| link.direction == ArtifactDirection::Output)
            .filter_map(|link| draft_number(link.role.as_str()).map(|number| (number, link)))
            .max_by_key(|(number, _)| *number)
            .map(|(number, link)| (number, link.sha256.clone()));
        let saved_at = match &newest {
            Some((_, sha256)) => Some(tx.get_artifact_index(sha256).await?.created_at),
            None => None,
        };
        let head = tx.ledger_head(job_id).await?;
        Ok(Some((
            job.value,
            repository.value.full_name,
            run,
            newest,
            saved_at,
            head,
        )))
    }
    .await;
    let _ = tx.rollback().await;
    let Some((job, repository, run, newest, saved_at, head)) = read? else {
        return Err(ApiError::NotFound);
    };
    require_repository(state, caller, &repository)?;

    // The commit is read through the seam the worker's hook reads it through, so the person sees
    // the value the hook will compare their `head` with.
    let draft = match &newest {
        Some(_) => {
            let identity = RunIdentity {
                tenant: caller.tenant,
                job: job_id,
                correlation: job.correlation_id,
                stage_run: run.id,
                kind: StageKind::Specification,
            };
            StoreSpecDrafts::new(
                std::sync::Arc::clone(&state.ports.store),
                std::sync::Arc::clone(artifacts),
            )
            .load(&identity)
            .await
            .map_err(|_| ApiError::Unavailable)?
        }
        None => None,
    };
    let window_hours = state.policies.approval.approval_binding.expires_after_hours;
    Ok(Reply::ok(json!({
        "job_id": job_id.as_text(),
        "stage_run_id": run.id.as_text(),
        "status": run.status.to_string(),
        "run_number": run.run_number,
        "draft": match (&newest, &draft, &saved_at) {
            (Some((number, sha256)), Some(record), Some(at)) => json!({
                "number": number,
                "commit": record.commit.as_str(),
                "feature_directory": record.feature_directory,
                "artifact_sha256": sha256.as_str(),
                "saved_at": at.as_text(),
            }),
            _ => Value::Null,
        },
        "ledger_head": head.as_ref().map(|head| json!({
            "sequence": head.sequence,
            "hash": head.hash.as_str(),
        })),
        "approval": {
            "window_hours": window_hours,
            "approvable": run.status == StageRunStatus::WaitingForHuman && draft.is_some(),
            "head": draft.as_ref().map(|record| record.commit.as_str().to_owned()),
            "evidence": head.as_ref().map(|head| head.hash.as_str().to_owned()),
        },
    })))
}

/// One gate report of the ledger, before it is read.
struct Cited {
    stage_run: StageRunId,
    recorded_at: String,
    sha256: Sha256Digest,
}

/// `GET /v1/jobs/{job_id}/gate-reports`.
pub async fn gate_reports(state: &ApiState, caller: &Caller, job_id: &str) -> Answer {
    caller.require_listed()?;
    let job_id = parse_id(job_id, JobId::parse).ok_or(ApiError::NotFound)?;
    let artifacts = state
        .ports
        .artifacts
        .as_ref()
        .ok_or(ApiError::Unavailable)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let read = async {
        let job = tx.get_job(job_id).await?;
        let repository = tx.get_repository(job.value.repository).await?;
        let runs = tx.list_stage_runs(job_id).await?;
        let mut cited: Vec<Cited> = Vec::new();
        let mut from = 1_u64;
        for _ in 0..MAX_LEDGER_PAGES {
            let page = tx.read_ledger(job_id, from, LEDGER_PAGE).await?;
            let count = page.len();
            for entry in &page {
                for evidence in &entry.evidence {
                    if let Evidence::Test(test) = evidence
                        && !cited
                            .iter()
                            .any(|held| held.sha256 == test.gate_report_sha256)
                    {
                        cited.push(Cited {
                            stage_run: entry.metadata.stage_run_id,
                            recorded_at: entry.metadata.recorded_at.as_text(),
                            sha256: test.gate_report_sha256.clone(),
                        });
                    }
                }
            }
            match page.last() {
                Some(last) if count == LEDGER_PAGE as usize => {
                    from = u64::try_from(last.metadata.sequence.get())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                }
                _ => break,
            }
        }
        let truncated = cited.len() > MAX_REPORTS;
        cited.truncate(MAX_REPORTS);
        let mut references = Vec::with_capacity(cited.len());
        for held in &cited {
            references.push(tx.get_artifact_index(&held.sha256).await.ok());
        }
        Ok::<_, StoreError>((
            repository.value.full_name,
            runs,
            cited,
            references,
            truncated,
        ))
    }
    .await;
    let _ = tx.rollback().await;
    let (repository, runs, cited, references, truncated) = read?;
    require_repository(state, caller, &repository)?;

    let scope = caller.scope();
    let mut reports = Vec::with_capacity(cited.len());
    for (held, reference) in cited.iter().zip(references) {
        let stage = runs
            .iter()
            .find(|run| run.value.id == held.stage_run)
            .map_or("unknown", |run| run.value.kind.as_str());
        let parsed = match reference {
            Some(entry)
                if entry
                    .artifact
                    .size_bytes
                    .is_none_or(|size| size_ok(size.get())) =>
            {
                match artifacts.get(&scope, &entry.artifact).await {
                    Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
                        .ok()
                        .and_then(|value| GateReport::from_json_value(value).ok()),
                    Err(_) => None,
                }
            }
            _ => None,
        };
        reports.push(match parsed {
            Some(report) => json!({
                "stage_run_id": held.stage_run.as_text(),
                "stage": stage,
                "gate": report.metadata.gate_id.as_str(),
                "title": report.title.as_str(),
                "outcome": report.outcome.as_str(),
                "code": report.blocked_reason.as_ref().map(|reason| reason.code.as_str().to_owned()),
                "reason": report.reason.as_str(),
                "report_sha256": held.sha256.as_str(),
                "recorded_at": held.recorded_at,
                "readable": true,
            }),
            None => json!({
                "stage_run_id": held.stage_run.as_text(),
                "stage": stage,
                "gate": Value::Null,
                "title": Value::Null,
                "outcome": Value::Null,
                "code": Value::Null,
                "reason": Value::Null,
                "report_sha256": held.sha256.as_str(),
                "recorded_at": held.recorded_at,
                "readable": false,
            }),
        });
    }
    Ok(Reply::ok(json!({
        "job_id": job_id.as_text(),
        "reports": reports,
        "truncated": truncated,
    })))
}

/// The content type a document is served under: text for what the stages store as text or JSON,
/// and opaque bytes for everything else. It is never the type the document claims for itself.
fn served_as(media_type: &str) -> (&'static str, &'static str) {
    let media = media_type.split(';').next().unwrap_or("").trim();
    if media.eq_ignore_ascii_case("application/json")
        || media.to_ascii_lowercase().starts_with("text/")
    {
        ("text/plain; charset=utf-8", "txt")
    } else {
        ("application/octet-stream", "bin")
    }
}

/// `GET /v1/jobs/{job_id}/artifacts/{sha256}`.
pub async fn artifact(state: &ApiState, caller: &Caller, job_id: &str, sha256: &str) -> Answer {
    caller.require_listed()?;
    let job_id = parse_id(job_id, JobId::parse).ok_or(ApiError::NotFound)?;
    // A hash is 64 lower case hexadecimal digits. Anything else names nothing.
    let hash = (sha256.len() == 64
        && sha256
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    .then(|| Sha256Digest::parse(&format!("sha256:{sha256}")).ok())
    .flatten()
    .ok_or(ApiError::NotFound)?;
    let artifacts = state
        .ports
        .artifacts
        .as_ref()
        .ok_or(ApiError::Unavailable)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let read = async {
        let job = tx.get_job(job_id).await?;
        let repository = tx.get_repository(job.value.repository).await?;
        // The application's own scope. The tenant's index row says whether the tenant holds the
        // document at all (the row-level rule of the database is applied to this read, and the
        // store applies it again when it reads the bytes). The document belongs to *this job* if
        // the index says the job's stage run stored it, or if a stage run of the job is linked to
        // it, as input or as output. A second job of the same tenant has neither, and is refused.
        let entry = match tx.get_artifact_index(&hash).await {
            Ok(entry) => Some(entry),
            Err(StoreError::NotFound) => None,
            Err(other) => return Err(other),
        };
        let entry = match entry {
            Some(entry)
                if entry
                    .origin
                    .is_some_and(|(origin_job, _)| origin_job == job_id) =>
            {
                Some(entry)
            }
            Some(entry) => {
                let mut linked = false;
                for run in tx.list_stage_runs(job_id).await? {
                    if tx
                        .list_stage_run_artifacts(run.value.id)
                        .await?
                        .iter()
                        .any(|link| link.sha256 == hash)
                    {
                        linked = true;
                        break;
                    }
                }
                linked.then_some(entry)
            }
            None => None,
        };
        Ok::<_, StoreError>((repository.value.full_name, entry))
    }
    .await;
    let _ = tx.rollback().await;
    let (repository, entry) = read?;
    require_repository(state, caller, &repository)?;
    let entry = entry.ok_or(ApiError::NotFound)?;
    if entry
        .artifact
        .size_bytes
        .is_some_and(|size| !size_ok(size.get()))
    {
        return Err(ApiError::PayloadTooLarge);
    }
    let bytes = artifacts
        .get(&caller.scope(), &entry.artifact)
        .await
        .map_err(|error| match error {
            ArtifactError::NotFound => ApiError::NotFound,
            _ => ApiError::Unavailable,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_DOWNLOAD_BYTES {
        return Err(ApiError::PayloadTooLarge);
    }
    let (content_type, extension) = served_as(entry.artifact.media_type.as_str());
    Ok(Reply::download(Download {
        bytes,
        content_type,
        file_name: format!("{}.{extension}", &hash.hex()[..16]),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_of_the_draft_takes_one_stage_run_and_nothing_else() {
        assert_eq!(draft_query(None), Ok(None));
        assert!(
            draft_query(Some("stage_run_id=0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b"))
                .expect("fine")
                .is_some()
        );
        for bad in [
            "stage_run_id=x",
            "stage_run_id=",
            "head=abc",
            "stage_run_id=0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b&stage_run_id=0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b",
            "stage_run_id",
        ] {
            assert!(draft_query(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_a_numbered_draft_role_is_a_draft() {
        assert_eq!(draft_number("spec-draft-3"), Some(3));
        for other in [
            "spec-draft-",
            "spec-draft-x",
            "spec-draft-1a",
            "specification-contract.a1",
        ] {
            assert_eq!(draft_number(other), None, "{other}");
        }
    }

    #[test]
    fn a_document_is_served_as_text_or_as_bytes_and_never_as_a_page() {
        for (media, served) in [
            ("text/plain", "text/plain; charset=utf-8"),
            ("text/html", "text/plain; charset=utf-8"),
            ("TEXT/markdown; charset=utf-8", "text/plain; charset=utf-8"),
            ("application/json", "text/plain; charset=utf-8"),
            ("image/svg+xml", "application/octet-stream"),
            ("application/xhtml+xml", "application/octet-stream"),
            ("application/octet-stream", "application/octet-stream"),
            ("", "application/octet-stream"),
        ] {
            assert_eq!(served_as(media).0, served, "{media}");
        }
    }
}
