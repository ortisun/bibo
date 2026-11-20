-- ports v1.1 (ADR 0014, decision 2): the listings that replace the engine's payload bookkeeping.
--
-- Every listing of the revised Store was planned on 10,000 generated rows with row-level security on
-- (docs/database/query-plans.md, section "Listings and the other operations of ports v1.1"). All but one use an
-- index that already exists. This migration adds the one that does not:
--
--   list_jobs with a repository filter, newest first, keyset page. Without an index the planner reads every job of
--   the tenant (jobs_open_idx / the tenant prefix of a unique key), keeps the ones of the repository and sorts them:
--   the cost grows with the tenant's whole history and not with the page. The index below serves the filter, the
--   order and the keyset condition from one range of one index. It also serves the foreign key from jobs to
--   repositories, which had no index of its own.
--
-- jobs_listing_idx (tenant_id, created_at DESC, id DESC) already serves the unfiltered listing and a status filter;
-- jobs_open_idx serves a filter on open statuses.
--
-- Nothing else is added: the edges of a task graph are read through their nodes (task_nodes already has the unique
-- key (tenant_id, stage_run_id, id) and the edges have a primary key that starts with (tenant_id, task_node_id)),
-- so an index on task_node_dependencies (tenant_id, stage_run_id) would be written for every edge and read by no plan.
--
-- A plain CREATE INDEX blocks writes to jobs while it builds. Do not run this on a busy table without
-- CREATE INDEX CONCURRENTLY in a migration of its own (docs/database/migration-safety.md); today jobs is small.

SET LOCAL lock_timeout = '5s';

CREATE INDEX jobs_repository_listing_idx ON jobs (tenant_id, repository_id, created_at DESC, id DESC);
COMMENT ON INDEX jobs_repository_listing_idx IS
  'list_jobs filtered by repository, newest first, keyset (created_at, id). Also the index behind the foreign key to repositories.';
