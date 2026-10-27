//! Approver decisions (FR-029, FR-031).
//!
//! The approver is read from the principal, not from the caller: the insert selects the GitHub
//! user id and the kind from the `principals` row, and only an active human of the tenant is
//! selected. The database repeats the rule with a composite key to `(tenant, principal, 'human',
//! GitHub user id)`. The expiry is `now()` plus the validity the caller asked for, so the caller's
//! clock is never written.

use async_trait::async_trait;
use diesel::sql_types::{BigInt, Integer, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{ApprovalId, JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::values::GitSha;
use factory_ports::store::{
    Approval, ApprovalBinding, ApprovalChannel, ApprovalDecision, ApprovalInvalidation,
    ApprovalOps, ConstraintRule, Inserted, NewApproval, StoreError, Version, Versioned,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Table, exists};
use super::conv::{
    corrupt, digest_from_column, from_column, git_sha_from_column, micros, slug_from_column,
    unsigned_from_column,
};
use super::error::database;
use super::tx::{PgTx, call};

const COLUMNS: &str = "id, job_id, stage_run_id, decision, approver_principal_id, \
    approver_github_user_id, approver_designation, allowlist_version_hash, pr_head_sha, tree_hash, \
    base_sha, evidence_manifest_hash, spec_version, policy_hash, reason, channel, created_at, \
    expires_at, invalidated_at, invalidation_reason";

#[derive(QueryableByName)]
struct ApprovalRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    stage_run_id: Uuid,
    #[diesel(sql_type = Text)]
    decision: String,
    #[diesel(sql_type = SqlUuid)]
    approver_principal_id: Uuid,
    #[diesel(sql_type = BigInt)]
    approver_github_user_id: i64,
    #[diesel(sql_type = Text)]
    approver_designation: String,
    #[diesel(sql_type = Text)]
    allowlist_version_hash: String,
    #[diesel(sql_type = Nullable<Text>)]
    pr_head_sha: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    tree_hash: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    base_sha: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    evidence_manifest_hash: Option<String>,
    #[diesel(sql_type = Nullable<Integer>)]
    spec_version: Option<i32>,
    #[diesel(sql_type = Text)]
    policy_hash: String,
    #[diesel(sql_type = Text)]
    reason: String,
    #[diesel(sql_type = Text)]
    channel: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
    #[diesel(sql_type = Timestamptz)]
    expires_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    invalidated_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    invalidation_reason: Option<String>,
}

const fn decision_name(decision: ApprovalDecision) -> &'static str {
    match decision {
        ApprovalDecision::Approve => "approve",
        ApprovalDecision::Reject => "reject",
        ApprovalDecision::Rework => "rework",
        ApprovalDecision::Pause => "pause",
        ApprovalDecision::Cancel => "cancel",
    }
}

fn decision_from_column(name: &str) -> Result<ApprovalDecision, StoreError> {
    Ok(match name {
        "approve" => ApprovalDecision::Approve,
        "reject" => ApprovalDecision::Reject,
        "rework" => ApprovalDecision::Rework,
        "pause" => ApprovalDecision::Pause,
        "cancel" => ApprovalDecision::Cancel,
        _ => return Err(corrupt("approval decision")),
    })
}

const fn channel_name(channel: ApprovalChannel) -> &'static str {
    match channel {
        ApprovalChannel::Dashboard => "dashboard",
        ApprovalChannel::Cli => "cli",
        ApprovalChannel::GithubComment => "github_comment",
    }
}

fn channel_from_column(name: &str) -> Result<ApprovalChannel, StoreError> {
    Ok(match name {
        "dashboard" => ApprovalChannel::Dashboard,
        "cli" => ApprovalChannel::Cli,
        "github_comment" => ApprovalChannel::GithubComment,
        _ => return Err(corrupt("approval channel")),
    })
}

const fn invalidation_name(reason: ApprovalInvalidation) -> &'static str {
    match reason {
        ApprovalInvalidation::NewCommit => "new_commit",
        ApprovalInvalidation::BaseMoved => "base_moved",
        ApprovalInvalidation::PolicyChange => "policy_change",
        ApprovalInvalidation::ImageChange => "image_change",
        ApprovalInvalidation::SpecRevision => "spec_revision",
    }
}

fn invalidation_from_column(name: &str) -> Result<ApprovalInvalidation, StoreError> {
    Ok(match name {
        "new_commit" => ApprovalInvalidation::NewCommit,
        "base_moved" => ApprovalInvalidation::BaseMoved,
        "policy_change" => ApprovalInvalidation::PolicyChange,
        "image_change" => ApprovalInvalidation::ImageChange,
        "spec_revision" => ApprovalInvalidation::SpecRevision,
        _ => return Err(corrupt("invalidation reason")),
    })
}

fn approval_from_row(row: ApprovalRow) -> Result<Approval, StoreError> {
    let sha = |value: &Option<String>| -> Result<Option<GitSha>, StoreError> {
        value.as_deref().map(git_sha_from_column).transpose()
    };
    let binding = match (
        sha(&row.pr_head_sha)?,
        sha(&row.tree_hash)?,
        sha(&row.base_sha)?,
        row.evidence_manifest_hash.as_deref(),
        row.spec_version,
    ) {
        (Some(pr_head), Some(tree), Some(base), Some(manifest), Some(spec)) => {
            Some(ApprovalBinding {
                pr_head,
                tree,
                base,
                evidence_manifest: digest_from_column(manifest)?,
                spec_version: u32::try_from(spec).map_err(|_| corrupt("spec version"))?,
            })
        }
        _ => None,
    };
    let invalidated = match (row.invalidated_at, row.invalidation_reason.as_deref()) {
        (Some(at), Some(reason)) => Some((from_column(at), invalidation_from_column(reason)?)),
        _ => None,
    };
    Ok(Approval {
        id: ApprovalId::from_uuid(row.id),
        job: JobId::from_uuid(row.job_id),
        stage_run: StageRunId::from_uuid(row.stage_run_id),
        decision: decision_from_column(&row.decision)?,
        approver: PrincipalId::from_uuid(row.approver_principal_id),
        approver_github_user_id: unsigned_from_column(row.approver_github_user_id, "approver")?,
        designation: slug_from_column(&row.approver_designation)?,
        binding,
        reason: row.reason,
        channel: channel_from_column(&row.channel)?,
        created_at: from_column(row.created_at),
        expires_at: from_column(row.expires_at),
        invalidated,
    })
}

/// True when the stored approval is the one offered. The times are not compared.
fn same_approval(stored: &ApprovalRow, new: &NewApproval) -> bool {
    let binding = new.binding.as_ref();
    stored.job_id == new.job.as_uuid()
        && stored.stage_run_id == new.stage_run.as_uuid()
        && stored.decision == decision_name(new.decision)
        && stored.approver_principal_id == new.approver.as_uuid()
        && stored.approver_designation == new.designation.as_str()
        && stored.allowlist_version_hash == new.allowlist_version.as_str()
        && stored.policy_hash == new.policy_hash.as_str()
        && stored.reason == new.reason
        && stored.channel == channel_name(new.channel)
        && stored.pr_head_sha.as_deref() == binding.map(|b| b.pr_head.as_str())
        && stored.tree_hash.as_deref() == binding.map(|b| b.tree.as_str())
        && stored.base_sha.as_deref() == binding.map(|b| b.base.as_str())
        && stored.evidence_manifest_hash.as_deref() == binding.map(|b| b.evidence_manifest.as_str())
        && stored.spec_version == binding.and_then(|b| i32::try_from(b.spec_version).ok())
}

async fn require_job(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
    operation: &'static str,
) -> Result<(), StoreError> {
    if exists(connection, Table::Jobs, tenant, job.as_uuid(), operation).await? {
        Ok(())
    } else {
        Err(StoreError::NotFound)
    }
}

async fn record(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewApproval,
) -> Result<Inserted<Approval>, StoreError> {
    let operation = "record_approval";
    // An approve decision is bound to what the approver saw. The database repeats the rule; this
    // keeps the refusal from aborting the transaction.
    if new.decision == ApprovalDecision::Approve && new.binding.is_none() {
        return Err(StoreError::Constraint(ConstraintRule::TextBounds));
    }
    let binding = new.binding.as_ref();
    let spec = binding
        .map(|b| i32::try_from(b.spec_version))
        .transpose()
        .map_err(|_| StoreError::Constraint(ConstraintRule::TextBounds))?;
    let inserted = sql_query(format!(
        "INSERT INTO approvals (tenant_id, id, job_id, stage_run_id, decision, \
                approver_principal_id, approver_github_user_id, approver_designation, \
                allowlist_version_hash, policy_hash, reason, channel, expires_at, pr_head_sha, \
                tree_hash, base_sha, evidence_manifest_hash, spec_version) \
         SELECT p.tenant_id, $2, $3, $4, $5, p.id, p.github_user_id, $6, $7, $8, $9, $10, \
                now() + $11 * interval '1 microsecond', $12, $13, $14, $15, $16 \
           FROM principals p \
          WHERE p.tenant_id = $1 AND p.id = $17 AND p.kind = 'human' AND p.disabled_at IS NULL \
         ON CONFLICT DO NOTHING RETURNING {COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id.as_uuid())
    .bind::<SqlUuid, _>(new.job.as_uuid())
    .bind::<SqlUuid, _>(new.stage_run.as_uuid())
    .bind::<Text, _>(decision_name(new.decision))
    .bind::<Text, _>(new.designation.as_str())
    .bind::<Text, _>(new.allowlist_version.as_str())
    .bind::<Text, _>(new.policy_hash.as_str())
    .bind::<Text, _>(new.reason.as_str())
    .bind::<Text, _>(channel_name(new.channel))
    .bind::<BigInt, _>(micros(new.valid_for))
    .bind::<Nullable<Text>, _>(binding.map(|b| b.pr_head.as_str().to_owned()))
    .bind::<Nullable<Text>, _>(binding.map(|b| b.tree.as_str().to_owned()))
    .bind::<Nullable<Text>, _>(binding.map(|b| b.base.as_str().to_owned()))
    .bind::<Nullable<Text>, _>(binding.map(|b| b.evidence_manifest.as_str().to_owned()))
    .bind::<Nullable<Integer>, _>(spec)
    .bind::<SqlUuid, _>(new.approver.as_uuid())
    .get_result::<ApprovalRow>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?;
    if let Some(row) = inserted {
        return Ok(Inserted {
            row: Versioned {
                value: approval_from_row(row)?,
                version: Version::FIRST,
            },
            created: true,
        });
    }
    // No row: a replay, a reuse of the id, a second decision for the same head, or an approver
    // who is not an active human of the tenant.
    let stored = sql_query(format!(
        "SELECT {COLUMNS} FROM approvals WHERE tenant_id = $1 AND id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id.as_uuid())
    .get_result::<ApprovalRow>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?;
    match stored {
        Some(row) if same_approval(&row, &new) => Ok(Inserted {
            row: Versioned {
                value: approval_from_row(row)?,
                version: Version::FIRST,
            },
            created: false,
        }),
        Some(_) => Err(StoreError::Constraint(
            ConstraintRule::IdReusedWithDifferentContent,
        )),
        None => {
            // The approver is the reason when no other decision of theirs holds the head.
            let approver_ok = sql_query(
                "SELECT 1::bigint AS n FROM principals \
                  WHERE tenant_id = $1 AND id = $2 AND kind = 'human' AND disabled_at IS NULL",
            )
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<SqlUuid, _>(new.approver.as_uuid())
            .execute(connection)
            .await
            .map_err(|error| database(operation, &error))?;
            if approver_ok == 0 {
                Err(StoreError::NotFound)
            } else {
                Err(StoreError::Constraint(
                    ConstraintRule::IdReusedWithDifferentContent,
                ))
            }
        }
    }
}

async fn list(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
) -> Result<Vec<Approval>, StoreError> {
    let rows = sql_query(format!(
        "SELECT {COLUMNS} FROM approvals WHERE tenant_id = $1 AND job_id = $2 \
          ORDER BY created_at, id"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .load::<ApprovalRow>(connection)
    .await
    .map_err(|error| database("list_approvals", &error))?;
    if rows.is_empty() {
        require_job(connection, tenant, job, "list_approvals").await?;
    }
    rows.into_iter().map(approval_from_row).collect()
}

async fn valid(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
    head: &GitSha,
) -> Result<Vec<Approval>, StoreError> {
    let rows = sql_query(format!(
        "SELECT {COLUMNS} FROM approvals \
          WHERE tenant_id = $1 AND job_id = $2 AND decision = 'approve' AND pr_head_sha = $3 \
            AND invalidated_at IS NULL AND expires_at > now() \
          ORDER BY created_at, id"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .bind::<Text, _>(head.as_str())
    .load::<ApprovalRow>(connection)
    .await
    .map_err(|error| database("valid_approvals", &error))?;
    if rows.is_empty() {
        require_job(connection, tenant, job, "valid_approvals").await?;
    }
    rows.into_iter().map(approval_from_row).collect()
}

async fn invalidate(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
    reason: ApprovalInvalidation,
) -> Result<u32, StoreError> {
    require_job(connection, tenant, job, "invalidate_approvals").await?;
    let changed = sql_query(
        "UPDATE approvals SET invalidated_at = now(), invalidation_reason = $3 \
          WHERE tenant_id = $1 AND job_id = $2 AND invalidated_at IS NULL AND expires_at > now()",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .bind::<Text, _>(invalidation_name(reason))
    .execute(connection)
    .await
    .map_err(|error| database("invalidate_approvals", &error))?;
    u32::try_from(changed).map_err(|_| corrupt("row count"))
}

#[async_trait]
impl ApprovalOps for PgTx {
    async fn record_approval(
        &mut self,
        new: NewApproval,
    ) -> Result<Inserted<Approval>, StoreError> {
        call!(self, connection, tenant => record(connection, tenant, new))
    }

    async fn list_approvals(&mut self, job: JobId) -> Result<Vec<Approval>, StoreError> {
        call!(self, connection, tenant => list(connection, tenant, job))
    }

    async fn valid_approvals(
        &mut self,
        job: JobId,
        head: &GitSha,
    ) -> Result<Vec<Approval>, StoreError> {
        call!(self, connection, tenant => valid(connection, tenant, job, head))
    }

    async fn invalidate_approvals(
        &mut self,
        job: JobId,
        reason: ApprovalInvalidation,
    ) -> Result<u32, StoreError> {
        call!(self, connection, tenant => invalidate(connection, tenant, job, reason))
    }
}
