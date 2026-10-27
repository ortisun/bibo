//! The PostgreSQL implementation of the [`Store`](factory_ports::store::Store) port.
//!
//! Read [`store`] first: it explains the pools, the logins and the start-up checks. The tenant
//! transaction is in [`tx`], the system scope in [`system`]. The other modules are one aggregate
//! each. `docs/database/for-the-storage-crate.md` is the specification of the SQL.
//!
//! # Where the current `Store` port and the migrations disagree
//!
//! The architecture review (`docs/reviews/architecture-foundation-review.md`, F-01, F-02, F-06)
//! found that the `Store` write model cannot persist what the migrations require. The port is
//! being revised, so this crate does not invent port methods. Each method of the current port is
//! in one of three states. **Clean** means it maps to the columns and constraints as they are.
//! **Provisional** means it works only through a stopgap value that the port cannot carry; the
//! stopgap is named in the module and is to be deleted when the port carries the value.
//! **Blocked** means it returns a closed `Constraint` error and says why.
//!
//! | Method | State | What it conflicts with |
//! |---|---|---|
//! | `begin`, `begin_system`, `schema_version`, `fidelity` | clean | `SchemaVersion` is 32 bits, Diesel's version is 14 digits, so the number is the count of applied migrations |
//! | `get_job`, `transition_job` | clean | `Job` cannot return `repository_id`, `execution_mode`, `autonomy_level`, `pipeline_scope` |
//! | `insert_job` | provisional | `jobs.repository_id`, `execution_mode`, `autonomy_level`, `pipeline_scope` are `NOT NULL` (`NewJob` has none); taken from the tenant's oldest enabled repository and `JobDefaults` |
//! | `insert_stage_run` | provisional | `stage_runs.run_number` is `NOT NULL` (`NewStageRun` has none); computed as the highest of the job and kind plus one |
//! | `get_stage_run` | provisional | `StageRun.lease` has no column on `stage_runs`; read from the newest attempt at the current epoch (`attempts.lease_owner`, `lease_expires_at`, `last_heartbeat_at`) |
//! | `transition_stage_run` | provisional for `S02`, `S08`, `S14`, `S18` and `S03` | CHECK `stage_runs_passed_has_outcome`, `stage_runs_skipped_has_outcome` need `gate_outcome` (set from the transition id); trigger `stage_runs_lease_epoch_moves_with_claim` needs `lease_epoch + 1` with `READY` to `RUNNING`; `gate_report_sha256` and `stage_contract_sha256` cannot be set |
//! | `claim_ready` | provisional, differs from the port | the port leaves the run `READY` and raises its epoch; the trigger above lets the epoch move only with `READY` to `RUNNING`, and the lease owner and expiry exist only on `attempts`. This is the DBA recipe: find as the system login, then in a tenant transaction `RUNNING`, `lease_epoch + 1` and the attempt row |
//! | `expired_leases` | clean | |
//! | `insert_attempt` | blocked as a creator | `attempts.deadline_at`, `lease_owner`, `lease_expires_at` (CHECK `attempts_active_has_lease`) are required and `NewAttempt` has none; the claim creates the attempt, and this call only registers it |
//! | `get_attempt`, `heartbeat` | clean | a heartbeat keeps the length of the lease, because the port gives no ttl |
//! | `transition_attempt` | provisional for `A02`, `A05`, `A08`; blocked for `A04` | CHECK `attempts_failed_has_class` (`failure_class`), `attempts_cancelling_has_teardown` (`teardown_deadline_at`), `attempts_succeeded_has_output` (`output_sha256`, refused) |
//! | `insert_task_node` | blocked | `task_nodes.stage_run_id` and `plan_sha256` (key to `artifacts`) are `NOT NULL`; `NewTaskNode` has neither |
//! | `get_task_node`, `transition_task_node` | clean | |
//! | `append_ledger_entry`, `ledger_head`, `read_ledger` | clean | an append raises the job's version by one (the head move meets trigger `bump_guard`); `ledger_entries` has a key to `stage_runs` |
//! | `enqueue_event`, `read_events` | clean | the database is stricter than the port: CHECK `outbox_aggregate_has_reached_version` (deferred) refuses an event for a version the aggregate has not reached |
//! | `record_audit` | provisional | `audit_events.subject`, `decision`, `reason` are `NOT NULL` (`AuditEvent` has none; stored as `job:<id>`, `record`, `recorded by the store`); `job_id` is nullable in the table and required by the port; `created_at` is the database's |
//! | `read_audit` | clean | |
//! | `index_artifact` | clean when the size is known | `artifacts.size_bytes` is `NOT NULL`, `ArtifactRef.size_bytes` is optional (stored as 0) |
//! | `get_artifact_index` | clean | |
//! | `insert_principal`, `get_principal` | provisional | `principals.kind` is `NOT NULL` and CHECK `principals_check` ties `human` to `github_user_id`; the port has only `external_ref` (a number becomes a human, other text a service) |
//!
//! Not started, because the port has no method for them (F-02): `original_requests`,
//! `webhook_deliveries`, `approvals`, `stage_run_artifacts`, `task_node_dependencies`, `inbox`,
//! listings of a job's stage runs and attempts, timers (`stage_runs.not_before`, due work), and
//! the two lookups as port methods (they are methods of `PgStore`).

mod artifact_index;
mod attempts;
mod audit;
mod cas;
mod config;
mod conv;
mod error;
mod jobs;
mod ledger;
mod lookup;
mod outbox;
mod pool;
mod principals;
mod readiness;
mod stage_runs;
mod store;
mod system;
mod task_nodes;
mod tx;

pub use config::{
    AttemptTimings, AutonomyLevel, DatabaseUrl, JobDefaults, PgStoreConfig, PoolSettings,
    TenantLogin,
};
pub use error::{RoleProblem, StartupError};
pub use lookup::{ResolvedRepository, ResolvedToken};
pub use pool::PgPool;
pub use store::PgStore;
