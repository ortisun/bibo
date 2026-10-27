//! The PostgreSQL implementation of the [`Store`](factory_ports::store::Store) port.
//!
//! Read [`store`] first: it explains the pools, the logins and the start-up checks. The tenant
//! transaction is in [`tx`], the system scope in [`system`]. The other modules are one aggregate
//! each. `docs/database/for-the-storage-crate.md` is the specification of the SQL.
//!
//! # Pending adaptation to ports v1.1
//!
//! The `Store` port was revised to v1.1 (`docs/architecture/ports-v1.1.md`): a two-step claim with
//! the lease on the attempt, a read-only `SystemTx`, idempotent inserts, listings and due-work
//! queries, a new audit shape and a commit witness. Every table module of this directory was
//! written against the old write model, so none of them maps to the new traits. The package
//! `s1-ports-revision` made only the mechanical edits that let the workspace build:
//!
//! * `begin`, `begin_system`, `resolve_token`, `resolve_installation`, `record_platform_audit`
//!   and `committed` return the closed error `StoreError::Unavailable`.
//! * `schema_version`, `fidelity`, the pools, the role checks and the schema checks are kept and
//!   work as before.
//! * The modules named below stay in the tree and are not compiled (`#[cfg(any())]`). The
//!   Postgres adaptation package re-enables each one against the new traits, using
//!   `docs/database/for-the-storage-crate.md` for the SQL. Their tests are not compiled either;
//!   see the notice at the top of each file in `tests/`.

#[cfg(any())]
mod artifact_index;
#[cfg(any())]
mod attempts;
#[cfg(any())]
mod audit;
#[cfg(any())]
mod cas;
mod config;
#[cfg(any())]
mod conv;
mod error;
#[cfg(any())]
mod jobs;
#[cfg(any())]
mod ledger;
#[cfg(any())]
mod lookup;
#[cfg(any())]
mod outbox;
mod pool;
#[cfg(any())]
mod principals;
mod readiness;
#[cfg(any())]
mod stage_runs;
mod store;
#[cfg(any())]
mod system;
#[cfg(any())]
mod task_nodes;
#[cfg(any())]
mod tx;

pub use config::{
    AttemptTimings, AutonomyLevel, DatabaseUrl, JobDefaults, PgStoreConfig, PoolSettings,
    TenantLogin,
};
pub use error::{RoleProblem, StartupError};
pub use pool::PgPool;
pub use store::PgStore;
