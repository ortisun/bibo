//! The scheduler: the claim loop, the heartbeat and the sweeper.
//!
//! These are the three ways time and concurrency act on a stage run. Work is handed out by the
//! claim, kept alive by the heartbeat, and taken back by the sweeper when the worker stops.
//! None of them keeps a timer in memory: leases, deadlines and back-offs are values compared with
//! the database clock.

mod backoff;
mod claim;
mod lease;
mod sweeper;
mod ticker;

pub use backoff::retry_delay;
pub use claim::{Claimed, ClaimedAttempt, Deferral};
pub use lease::Pulse;
pub use sweeper::Swept;
pub use ticker::Ticker;
