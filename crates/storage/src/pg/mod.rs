//! The PostgreSQL implementation of the [`Store`](factory_ports::store::Store) port.
//!
//! Read [`store`] first: it explains the pools, the logins and the start-up checks. The tenant
//! transaction is in [`tx`], the system scope in [`system`]. The other modules are one aggregate
//! each, and each holds the `impl` of its port trait for the transaction.
//! `docs/database/for-the-storage-crate.md` is the specification of the SQL.

mod approvals;
mod artifact_index;
mod attempts;
mod audit;
mod cas;
mod config;
mod conv;
mod error;
mod jobs;
mod ledger;
mod outbox;
mod pool;
mod principals;
mod readiness;
mod stage_runs;
mod store;
mod system;
mod task_nodes;
pub mod troubleshooting;
mod tx;

pub use config::{DatabaseUrl, PgStoreConfig, PoolSettings, TenantLogin};
pub use error::{RoleProblem, StartupError};
pub use pool::PgPool;
pub use store::PgStore;
