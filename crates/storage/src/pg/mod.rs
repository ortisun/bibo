//! The PostgreSQL implementation of the [`Store`](factory_ports::store::Store) port.
//!
//! Read [`store`] first: it explains the pools, the logins and the start-up checks. The tenant
//! transaction is in [`tx`], the system scope in [`system`]. The other modules are one aggregate
//! each. `docs/database/for-the-storage-crate.md` is the specification of the SQL.

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
