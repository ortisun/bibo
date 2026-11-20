//! One active troubleshooter, and the loop that runs a pass each probe period.
//!
//! Only one troubleshooter may act at a time: two would race on the day's caps and could open
//! the same issue twice. [`activate`] asks for the PostgreSQL advisory lock of
//! `factory_storage::pg::troubleshooting::TroubleshooterLock` on a connection of its own (why a
//! lock and not a lease row is in that module). A second instance gets [`Activation::Idle`], says
//! so, and waits; it asks again every probe period, so it takes over when the first one stops.
//! The active one checks that it still holds the lock before every pass and stops acting when
//! it does not.

use std::time::Duration;

use factory_composition::system::Shutdown;
use factory_ports::clock::CancelSignal as _;
use factory_storage::pg::DatabaseUrl;
use factory_storage::pg::troubleshooting::TroubleshooterLock;

use crate::troubleshooter::{PassOptions, PassReport, Troubleshooter};

/// Whether this instance may act.
#[derive(Debug)]
pub enum Activation {
    /// It holds the lock.
    Active(Box<TroubleshooterLock>),
    /// Another instance holds it.
    Idle,
}

/// Asks for the lock once.
///
/// # Errors
/// The database cannot be reached.
pub async fn activate(url: &DatabaseUrl) -> Result<Activation, String> {
    match TroubleshooterLock::try_acquire(url).await {
        Ok(Some(lock)) => Ok(Activation::Active(Box::new(lock))),
        Ok(None) => Ok(Activation::Idle),
        Err(error) => Err(format!(
            "the database cannot be reached for the troubleshooter's lock: {error}"
        )),
    }
}

/// Runs a pass every `period` until `shutdown` is raised, while holding the lock. Each report is
/// handed to `on_pass`. When the lock is lost, the loop goes back to waiting for it.
pub async fn run_loop(
    troubleshooter: &Troubleshooter,
    url: &DatabaseUrl,
    period: Duration,
    mut options: PassOptions,
    shutdown: &Shutdown,
    on_pass: &(dyn Fn(&Result<PassReport, String>) + Send + Sync),
) {
    let mut lock: Option<TroubleshooterLock> = None;
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        if let Some(held) = lock.as_mut()
            && !held.still_held().await
        {
            tracing::warn!(
                "the troubleshooter lost its lock; it stops acting until it holds it again"
            );
            lock = None;
        }
        if lock.is_none() {
            match activate(url).await {
                Ok(Activation::Active(held)) => {
                    tracing::info!("this troubleshooter is the active one");
                    lock = Some(*held);
                }
                Ok(Activation::Idle) => {
                    tracing::info!("another troubleshooter is active; this one idles");
                }
                Err(error) => tracing::warn!("{error}"),
            }
        }
        if lock.is_some() {
            let report = troubleshooter
                .pass(options)
                .await
                .map_err(|error| error.to_string());
            on_pass(&report);
            options.sweep_now = false;
        }
        tokio::select! {
            () = tokio::time::sleep(period) => {}
            () = shutdown.cancelled() => break,
        }
    }
    if let Some(held) = lock {
        held.release().await;
    }
}
