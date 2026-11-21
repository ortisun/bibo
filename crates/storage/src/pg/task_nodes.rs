//! Task nodes, their dependency edges, and the artifacts a stage run consumed and produced.
//!
//! # The graph
//!
//! `insert_task_graph` makes every node and every edge of a plan in one transaction: the nodes in
//! one statement, the edges in a second. The code checks the keys and the edges before it writes
//! (a repeated key, an edge to an unknown key, a cycle), so a refusal leaves the transaction
//! usable. The database enforces the same rules (`task_nodes_*_task_key_key`,
//! `task_node_dependencies_acyclic`) as the last line. The stage run is locked first, so two
//! writers of one plan take turns and the second one finds the first one's nodes.
//!
//! # The fence
//!
//! A move that starts, finishes or abandons a node (`T02` to `T05`) carries the fence of the
//! attempt that works on it. The statement requires that attempt to be live, held by that worker,
//! at that epoch. The lease need not be unexpired: only `heartbeat` asks for that.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use diesel::sql_types::{
    Array, BigInt, Bool, Nullable, SmallInt, Text, Timestamptz, Uuid as SqlUuid,
};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{AttemptId, JobId, StageRunId, TaskNodeId, TenantId};
use factory_domain::state::{Status, TaskNodeStatus};
use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::store::{
    AppliedTransition, ArtifactDirection, ConstraintRule, Fence, NewTaskGraph, StageArtifactOps,
    StageRunArtifact, StoreError, TaskNode, TaskNodeEffects, TaskNodeOps, Version, Versioned,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Table, exists, no_row_changed};
use super::conv::{
    corrupt, digest_from_column, epoch_to_column, from_column, git_sha_from_column,
    slug_from_column, status_from_column, version_from_column,
};
use super::error::database;
use super::tx::{PgTx, call};

fn id_reused() -> StoreError {
    StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)
}

const COLUMNS: &str = "tenant_id, id, job_id, stage_run_id, task_key, plan_sha256, status, version, \
    retry_count, current_attempt_id, commit_sha, created_at";

#[derive(QueryableByName)]
struct NodeRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    stage_run_id: Uuid,
    #[diesel(sql_type = Text)]
    task_key: String,
    #[diesel(sql_type = Text)]
    plan_sha256: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = SmallInt)]
    retry_count: i16,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    current_attempt_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    commit_sha: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
}

fn node_from_row(row: NodeRow) -> Result<Versioned<TaskNode>, StoreError> {
    Ok(Versioned {
        value: TaskNode {
            id: TaskNodeId::from_uuid(row.id),
            tenant_id: TenantId::from_uuid(row.tenant_id),
            job_id: JobId::from_uuid(row.job_id),
            stage_run_id: StageRunId::from_uuid(row.stage_run_id),
            key: slug_from_column(&row.task_key)?,
            plan_sha256: digest_from_column(&row.plan_sha256)?,
            status: status_from_column::<TaskNodeStatus>(&row.status)?,
            retry_count: u32::try_from(row.retry_count).map_err(|_| corrupt("retry count"))?,
            current_attempt: row.current_attempt_id.map(AttemptId::from_uuid),
            commit: row
                .commit_sha
                .as_deref()
                .map(git_sha_from_column)
                .transpose()?,
            created_at: from_column(row.created_at),
        },
        version: version_from_column(row.version)?,
    })
}

#[derive(QueryableByName)]
struct JobOfRun {
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    n: i64,
}

/// True when the edges `(node, depends_on)` between the keys contain a cycle (Kahn's algorithm).
fn has_cycle(keys: &BTreeSet<&str>, edges: &[(&str, &str)]) -> bool {
    let mut waiting: BTreeMap<&str, usize> = keys.iter().map(|key| (*key, 0)).collect();
    for (node, _) in edges {
        *waiting.entry(node).or_insert(0) += 1;
    }
    let mut ready: Vec<&str> = waiting
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(key, _)| *key)
        .collect();
    let mut removed = 0;
    while let Some(done) = ready.pop() {
        removed += 1;
        for (node, depends_on) in edges {
            if *depends_on == done
                && let Some(count) = waiting.get_mut(node)
            {
                *count -= 1;
                if *count == 0 {
                    ready.push(node);
                }
            }
        }
    }
    removed != waiting.len()
}

async fn nodes_of(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    stage_run: StageRunId,
    operation: &'static str,
) -> Result<Vec<Versioned<TaskNode>>, StoreError> {
    sql_query(format!(
        "SELECT {COLUMNS} FROM task_nodes WHERE tenant_id = $1 AND stage_run_id = $2 \
          ORDER BY task_key"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(stage_run.as_uuid())
    .load::<NodeRow>(connection)
    .await
    .map_err(|error| database(operation, &error))?
    .into_iter()
    .map(node_from_row)
    .collect()
}

async fn require_run(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    stage_run: StageRunId,
    operation: &'static str,
) -> Result<(), StoreError> {
    if exists(
        connection,
        Table::StageRuns,
        tenant,
        stage_run.as_uuid(),
        operation,
    )
    .await?
    {
        Ok(())
    } else {
        Err(StoreError::NotFound)
    }
}

async fn insert_task_graph(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    graph: NewTaskGraph,
) -> Result<Vec<Versioned<TaskNode>>, StoreError> {
    let operation = "insert_task_graph";
    // The stage run is locked, so two writers of one plan take turns.
    let job = sql_query(
        "SELECT job_id FROM stage_runs WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(graph.stage_run.as_uuid())
    .get_result::<JobOfRun>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?
    .ok_or(StoreError::NotFound)?
    .job_id;
    // A repeat: the same plan gives back the nodes it made, another plan is refused.
    let stored = nodes_of(connection, tenant, graph.stage_run, operation).await?;
    if let Some(first) = stored.as_slice().first() {
        return if first.value.plan_sha256 == graph.plan_sha256 {
            Ok(stored)
        } else {
            Err(id_reused())
        };
    }

    // The keys, the ids and the edges are checked before anything is written.
    let mut keys = BTreeMap::new();
    for node in &graph.nodes {
        if keys.insert(node.key.as_str(), node.id).is_some() {
            return Err(StoreError::Constraint(ConstraintRule::DuplicateTaskKey));
        }
    }
    let mut edges: Vec<(&str, &str)> = Vec::new();
    for node in &graph.nodes {
        for dependency in &node.depends_on {
            if !keys.contains_key(dependency.as_str()) {
                return Err(StoreError::NotFound);
            }
            edges.push((node.key.as_str(), dependency.as_str()));
        }
    }
    let key_set: BTreeSet<&str> = keys.keys().copied().collect();
    if has_cycle(&key_set, &edges) {
        return Err(StoreError::Constraint(ConstraintRule::DependencyCycle));
    }
    let ids: Vec<Uuid> = graph.nodes.iter().map(|node| node.id.as_uuid()).collect();
    let taken = sql_query(
        "SELECT count(*) AS n FROM task_nodes WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<Array<SqlUuid>, _>(ids.clone())
    .get_result::<Count>(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    if taken.n > 0 {
        return Err(id_reused());
    }

    // The nodes, in one statement, then the edges, in a second.
    let names: Vec<String> = graph
        .nodes
        .iter()
        .map(|node| node.key.as_str().to_owned())
        .collect();
    sql_query(
        "INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256) \
         SELECT $1, n.id, $2, $3, n.task_key, $4 FROM unnest($5::uuid[], $6::text[]) AS n(id, task_key)",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job)
    .bind::<SqlUuid, _>(graph.stage_run.as_uuid())
    .bind::<Text, _>(graph.plan_sha256.as_str())
    .bind::<Array<SqlUuid>, _>(ids)
    .bind::<Array<Text>, _>(names)
    .execute(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    if !edges.is_empty() {
        let from: Vec<Uuid> = edges
            .iter()
            .filter_map(|(node, _)| keys.get(node).map(|id| id.as_uuid()))
            .collect();
        let to: Vec<Uuid> = edges
            .iter()
            .filter_map(|(_, dependency)| keys.get(dependency).map(|id| id.as_uuid()))
            .collect();
        sql_query(
            "INSERT INTO task_node_dependencies (tenant_id, stage_run_id, task_node_id, \
                    depends_on_task_node_id) \
             SELECT $1, $2, e.node, e.depends_on FROM unnest($3::uuid[], $4::uuid[]) AS e(node, depends_on)",
        )
        .bind::<SqlUuid, _>(tenant.as_uuid())
        .bind::<SqlUuid, _>(graph.stage_run.as_uuid())
        .bind::<Array<SqlUuid>, _>(from)
        .bind::<Array<SqlUuid>, _>(to)
        .execute(connection)
        .await
        .map_err(|error| database(operation, &error))?;
    }
    nodes_of(connection, tenant, graph.stage_run, operation).await
}

#[derive(QueryableByName)]
struct Edge {
    #[diesel(sql_type = SqlUuid)]
    task_node_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    depends_on_task_node_id: Uuid,
}

async fn dependencies(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    stage_run: StageRunId,
) -> Result<Vec<(TaskNodeId, TaskNodeId)>, StoreError> {
    require_run(connection, tenant, stage_run, "task_dependencies").await?;
    let edges = sql_query(
        "SELECT d.task_node_id, d.depends_on_task_node_id \
           FROM task_nodes n \
           JOIN task_node_dependencies d ON d.tenant_id = n.tenant_id AND d.task_node_id = n.id \
          WHERE n.tenant_id = $1 AND n.stage_run_id = $2 \
          ORDER BY n.task_key, d.depends_on_task_node_id",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(stage_run.as_uuid())
    .load::<Edge>(connection)
    .await
    .map_err(|error| database("task_dependencies", &error))?;
    Ok(edges
        .into_iter()
        .map(|edge| {
            (
                TaskNodeId::from_uuid(edge.task_node_id),
                TaskNodeId::from_uuid(edge.depends_on_task_node_id),
            )
        })
        .collect())
}

#[derive(QueryableByName)]
struct NodeState {
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
}

#[derive(QueryableByName)]
struct NewVersion {
    #[diesel(sql_type = BigInt)]
    version: i64,
}

#[derive(QueryableByName)]
struct Found {
    #[diesel(sql_type = Bool)]
    found: bool,
}

/// Whether the fence names a live attempt held by that worker at that epoch.
pub(super) async fn fence_is_current(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    fence: &Fence,
) -> Result<bool, StoreError> {
    sql_query(
        "SELECT EXISTS (SELECT 1 FROM attempts \
                         WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND lease_epoch = $4 \
                           AND status IN ('STARTING', 'RUNNING', 'CANCELLING')) AS found",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(fence.attempt.as_uuid())
    .bind::<Text, _>(fence.worker.as_str())
    .bind::<BigInt, _>(epoch_to_column(fence.epoch))
    .get_result::<Found>(connection)
    .await
    .map(|row| row.found)
    .map_err(|error| database("transition_task_node", &error))
}

/// The transitions that start, finish or abandon a node, and carry the fence of its attempt.
fn needs_fence(transition_id: &str) -> bool {
    matches!(transition_id, "T02" | "T03" | "T04" | "T05")
}

/// The record that rides on a move: the attempt on `T02`, the commit on `T03`, neither elsewhere.
fn check_effects(transition_id: &str, effects: &TaskNodeEffects) -> Result<(), StoreError> {
    let wants_attempt = transition_id == "T02";
    let wants_commit = transition_id == "T03";
    if effects.attempt.is_some() == wants_attempt && effects.commit.is_some() == wants_commit {
        Ok(())
    } else {
        Err(StoreError::Constraint(ConstraintRule::AttemptEndRule))
    }
}

async fn transition(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: TaskNodeId,
    expected: Version,
    by: Option<Fence>,
    t: AppliedTransition<TaskNodeStatus>,
    effects: TaskNodeEffects,
) -> Result<Version, StoreError> {
    let operation = "transition_task_node";
    let transition_id = t.transition_id();
    let fenced = needs_fence(transition_id);
    let from = t.from_status().to_string();
    let rule = check_effects(transition_id, &effects).err();
    if (fenced && by.is_none()) || rule.is_some() {
        return Err(refusal(
            connection,
            tenant,
            id,
            expected,
            &from,
            fenced,
            by.as_ref(),
            rule,
        )
        .await?);
    }
    let to = t.to_status();
    let fence = by.as_ref();
    let updated = sql_query(
        "UPDATE task_nodes t SET status = $4, version = t.version + 1, \
                current_attempt_id = CASE $5 WHEN 'T02' THEN $6::uuid \
                    WHEN 'T03' THEN NULL WHEN 'T04' THEN NULL WHEN 'T05' THEN NULL \
                    ELSE t.current_attempt_id END, \
                commit_sha = CASE WHEN $5 = 'T03' THEN $7 ELSE t.commit_sha END, \
                retry_count = t.retry_count + CASE WHEN $5 = 'T06' THEN 1 ELSE 0 END, \
                finished_at = CASE WHEN $8 THEN coalesce(t.finished_at, now()) ELSE t.finished_at END \
          WHERE t.tenant_id = $1 AND t.id = $2 AND t.version = $3 AND t.status = $9 \
            AND ($10 IS FALSE OR EXISTS (SELECT 1 FROM attempts a \
                    WHERE a.tenant_id = t.tenant_id AND a.id = $11::uuid AND a.lease_owner = $12 \
                      AND a.lease_epoch = $13 \
                      AND a.status IN ('STARTING', 'RUNNING', 'CANCELLING'))) \
          RETURNING t.version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<Text, _>(to.to_string())
    .bind::<Text, _>(transition_id)
    .bind::<Nullable<SqlUuid>, _>(effects.attempt.map(|attempt| attempt.as_uuid()))
    .bind::<Nullable<Text>, _>(effects.commit.as_ref().map(|sha| sha.as_str().to_owned()))
    .bind::<Bool, _>(to.is_terminal())
    .bind::<Text, _>(from.clone())
    .bind::<Bool, _>(fenced)
    .bind::<Nullable<SqlUuid>, _>(fence.map(|fence| fence.attempt.as_uuid()))
    .bind::<Nullable<Text>, _>(fence.map(|fence| fence.worker.as_str().to_owned()))
    .bind::<Nullable<BigInt>, _>(fence.map(|fence| epoch_to_column(fence.epoch)))
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(refusal(
            connection,
            tenant,
            id,
            expected,
            &from,
            fenced,
            by.as_ref(),
            None,
        )
        .await?),
    }
}

/// Why a move changed no row, in the order the port lists them: no such node, the node moved,
/// the status is not the one the move starts from, the fence is not current, the record breaks
/// the rule of the move.
#[allow(clippy::too_many_arguments)]
async fn refusal(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: TaskNodeId,
    expected: Version,
    from: &str,
    fenced: bool,
    by: Option<&Fence>,
    rule: Option<StoreError>,
) -> Result<StoreError, StoreError> {
    let state =
        sql_query("SELECT status, version FROM task_nodes WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<SqlUuid, _>(id.as_uuid())
            .get_result::<NodeState>(connection)
            .await
            .optional()
            .map_err(|error| database("transition_task_node", &error))?;
    let Some(state) = state else {
        return Ok(StoreError::NotFound);
    };
    if state.version != expected.get() || state.status != from {
        return Ok(StoreError::Conflict);
    }
    if fenced {
        match by {
            Some(fence) if fence_is_current(connection, tenant, fence).await? => {}
            _ => return Ok(StoreError::LeaseFenced),
        }
    }
    match rule {
        Some(rule) => Ok(rule),
        // Nothing explains it, so the row moved between the update and this read.
        None => {
            no_row_changed(
                connection,
                Table::TaskNodes,
                tenant,
                id.as_uuid(),
                "transition_task_node",
            )
            .await
        }
    }
}

#[async_trait]
impl TaskNodeOps for PgTx {
    async fn insert_task_graph(
        &mut self,
        graph: NewTaskGraph,
    ) -> Result<Vec<Versioned<TaskNode>>, StoreError> {
        call!(self, connection, tenant => insert_task_graph(connection, tenant, graph))
    }

    async fn get_task_node(&mut self, id: TaskNodeId) -> Result<Versioned<TaskNode>, StoreError> {
        call!(self, connection, tenant => async {
            sql_query(format!("SELECT {COLUMNS} FROM task_nodes WHERE tenant_id = $1 AND id = $2"))
                .bind::<SqlUuid, _>(tenant.as_uuid())
                .bind::<SqlUuid, _>(id.as_uuid())
                .get_result::<NodeRow>(connection)
                .await
                .optional()
                .map_err(|error| database("get_task_node", &error))?
                .map(node_from_row)
                .transpose()?
                .ok_or(StoreError::NotFound)
        })
    }

    async fn list_task_nodes(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<Versioned<TaskNode>>, StoreError> {
        call!(self, connection, tenant => async {
            require_run(connection, tenant, stage_run, "list_task_nodes").await?;
            nodes_of(connection, tenant, stage_run, "list_task_nodes").await
        })
    }

    async fn task_dependencies(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<(TaskNodeId, TaskNodeId)>, StoreError> {
        call!(self, connection, tenant => dependencies(connection, tenant, stage_run))
    }

    async fn transition_task_node(
        &mut self,
        id: TaskNodeId,
        expected: Version,
        by: Option<Fence>,
        t: AppliedTransition<TaskNodeStatus>,
        effects: TaskNodeEffects,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => {
            transition(connection, tenant, id, expected, by, t, effects)
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Artifacts of a stage run
// ---------------------------------------------------------------------------------------------

const fn direction_name(direction: ArtifactDirection) -> &'static str {
    match direction {
        ArtifactDirection::Input => "input",
        ArtifactDirection::Output => "output",
    }
}

fn direction_from_column(name: &str) -> Result<ArtifactDirection, StoreError> {
    match name {
        "input" => Ok(ArtifactDirection::Input),
        "output" => Ok(ArtifactDirection::Output),
        _ => Err(corrupt("artifact direction")),
    }
}

#[derive(QueryableByName)]
struct LinkRow {
    #[diesel(sql_type = SqlUuid)]
    stage_run_id: Uuid,
    #[diesel(sql_type = Text)]
    direction: String,
    #[diesel(sql_type = Text)]
    role: String,
    #[diesel(sql_type = Text)]
    content_sha256: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
}

#[derive(QueryableByName)]
struct HashRow {
    #[diesel(sql_type = Text)]
    content_sha256: String,
}

#[derive(QueryableByName)]
struct RunRow {
    #[diesel(sql_type = SqlUuid)]
    stage_run_id: Uuid,
}

async fn link(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    stage_run: StageRunId,
    direction: ArtifactDirection,
    role: Slug,
    sha256: Sha256Digest,
) -> Result<(), StoreError> {
    let operation = "link_stage_run_artifact";
    require_run(connection, tenant, stage_run, operation).await?;
    // The artifact must be one the tenant has indexed (the composite key to `artifacts`).
    let indexed = sql_query(
        "SELECT EXISTS (SELECT 1 FROM artifacts WHERE tenant_id = $1 AND content_sha256 = $2) AS found",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<Text, _>(sha256.as_str())
    .get_result::<Found>(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    if !indexed.found {
        return Err(StoreError::NotFound);
    }
    let inserted = sql_query(
        "INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, \
                content_sha256) \
         SELECT s.tenant_id, s.job_id, s.id, $3, $4, $5 FROM stage_runs s \
          WHERE s.tenant_id = $1 AND s.id = $2 \
         ON CONFLICT (tenant_id, stage_run_id, direction, role) DO NOTHING RETURNING stage_run_id",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(stage_run.as_uuid())
    .bind::<Text, _>(direction_name(direction))
    .bind::<Text, _>(role.as_str())
    .bind::<Text, _>(sha256.as_str())
    .get_result::<RunRow>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?;
    if inserted.is_some() {
        return Ok(());
    }
    // The role was linked already: the same artifact is a replay, another one is a reuse.
    let stored = sql_query(
        "SELECT content_sha256 FROM stage_run_artifacts \
          WHERE tenant_id = $1 AND stage_run_id = $2 AND direction = $3 AND role = $4",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(stage_run.as_uuid())
    .bind::<Text, _>(direction_name(direction))
    .bind::<Text, _>(role.as_str())
    .get_result::<HashRow>(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    if stored.content_sha256 == sha256.as_str() {
        Ok(())
    } else {
        Err(id_reused())
    }
}

#[async_trait]
impl StageArtifactOps for PgTx {
    async fn link_stage_run_artifact(
        &mut self,
        stage_run: StageRunId,
        direction: ArtifactDirection,
        role: Slug,
        sha256: Sha256Digest,
    ) -> Result<(), StoreError> {
        call!(self, connection, tenant => {
            link(connection, tenant, stage_run, direction, role, sha256)
        })
    }

    async fn list_stage_run_artifacts(
        &mut self,
        stage_run: StageRunId,
    ) -> Result<Vec<StageRunArtifact>, StoreError> {
        call!(self, connection, tenant => async {
            require_run(connection, tenant, stage_run, "list_stage_run_artifacts").await?;
            sql_query(
                "SELECT stage_run_id, direction, role, content_sha256, created_at \
                   FROM stage_run_artifacts WHERE tenant_id = $1 AND stage_run_id = $2 \
                  ORDER BY created_at, direction, role",
            )
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<SqlUuid, _>(stage_run.as_uuid())
            .load::<LinkRow>(connection)
            .await
            .map_err(|error| database("list_stage_run_artifacts", &error))?
            .into_iter()
            .map(|row| {
                Ok(StageRunArtifact {
                    stage_run: StageRunId::from_uuid(row.stage_run_id),
                    direction: direction_from_column(&row.direction)?,
                    role: slug_from_column(&row.role)?,
                    sha256: digest_from_column(&row.content_sha256)?,
                    created_at: from_column(row.created_at),
                })
            })
            .collect()
        })
    }

    async fn stage_runs_consuming(
        &mut self,
        job: JobId,
        sha256: &Sha256Digest,
    ) -> Result<Vec<StageRunId>, StoreError> {
        call!(self, connection, tenant => async {
            sql_query(
                "SELECT stage_run_id FROM stage_run_artifacts \
                  WHERE tenant_id = $1 AND job_id = $2 AND content_sha256 = $3 \
                    AND direction = 'input' ORDER BY created_at, stage_run_id",
            )
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<SqlUuid, _>(job.as_uuid())
            .bind::<Text, _>(sha256.as_str())
            .load::<RunRow>(connection)
            .await
            .map_err(|error| database("stage_runs_consuming", &error))
            .map(|rows| {
                rows.into_iter()
                    .map(|row| StageRunId::from_uuid(row.stage_run_id))
                    .collect()
            })
        })
    }
}
