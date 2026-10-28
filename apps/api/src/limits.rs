//! Rate limits, and the bounded queue of audit events for deliveries that belong to no tenant.
//!
//! * [`RateLimiter`] counts requests in fixed one-minute windows, by source address or by
//!   installation. The address is the TCP peer: the API never reads `X-Forwarded-For`, `Forwarded`
//!   or `X-Real-IP`, so a client cannot choose the key it is counted under. (A deployment behind a
//!   proxy counts the proxy's address until a trusted-proxy setting exists; the README says so.)
//! * [`PlatformAudit`] carries the events of a webhook that failed its checks to a task that
//!   writes them. The request that failed touches no database (NT-WH-01): it puts an event in a
//!   bounded queue and returns. The task writes at most a fixed number a minute and drops the
//!   rest, so a flood of forged deliveries cannot become a flood of audit rows (NT-WH-10).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use factory_domain::ids::{AuditEventId, CorrelationId};
use factory_domain::scope::PlatformScope;
use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::clock::IdGenerator;
use factory_ports::store::{AuditAction, AuditActor, AuditDecision, NewAuditEvent, Store};
use tokio::sync::mpsc;

/// What a count is kept for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    /// A source address.
    Ip(IpAddr),
    /// A GitHub installation.
    Installation(u64),
}

#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    count: u32,
}

const WINDOW: Duration = Duration::from_secs(60);
const PRUNE_ABOVE: usize = 50_000;

/// Fixed-window counters.
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<Key, Window>>,
}

impl RateLimiter {
    /// An empty limiter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts one request for `key` at `now` and says whether it is within `limit` for the
    /// current window.
    pub fn allow(&self, key: Key, limit: u32, now: Instant) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() > PRUNE_ABOVE {
            windows.retain(|_, window| now.duration_since(window.started) < WINDOW);
        }
        let window = windows.entry(key).or_insert(Window {
            started: now,
            count: 0,
        });
        if now.duration_since(window.started) >= WINDOW {
            *window = Window {
                started: now,
                count: 0,
            };
        }
        window.count = window.count.saturating_add(1);
        window.count <= limit
    }
}

/// One event for the platform audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformEvent {
    /// The action, such as `webhook.rejected`.
    pub action: &'static str,
    /// What it concerned: a delivery id that passed the shape check, or `none`.
    pub subject: String,
    /// A fixed sentence. It never says which of several checks failed.
    pub reason: &'static str,
}

/// The sending end of the queue.
#[derive(Debug, Clone)]
pub struct PlatformAudit {
    sender: mpsc::Sender<PlatformEvent>,
}

impl PlatformAudit {
    /// A queue of `capacity` events and its receiving end.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<PlatformEvent>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (Self { sender }, receiver)
    }

    /// Queues an event. Never waits and never touches the database; false when the queue is full.
    pub fn report(&self, event: PlatformEvent) -> bool {
        self.sender.try_send(event).is_ok()
    }
}

/// Writes the queued events, at most `per_minute` in each minute. The rest are dropped and counted
/// in one log line. Ends when every sender is gone.
pub async fn write_platform_audit(
    mut events: mpsc::Receiver<PlatformEvent>,
    store: Arc<dyn Store>,
    ids: Arc<dyn IdGenerator>,
    policy_hash: Sha256Digest,
    per_minute: u32,
) {
    let mut minute_started = Instant::now();
    let mut written = 0_u32;
    let mut dropped = 0_u32;
    while let Some(event) = events.recv().await {
        if minute_started.elapsed() >= WINDOW {
            if dropped > 0 {
                tracing::warn!(
                    dropped,
                    "platform audit events were dropped in the last minute"
                );
            }
            (minute_started, written, dropped) = (Instant::now(), 0, 0);
        }
        if written >= per_minute {
            dropped = dropped.saturating_add(1);
            continue;
        }
        written += 1;
        let (Ok(action), Ok(actor)) = (AuditAction::new(event.action), Slug::parse("webhook"))
        else {
            continue;
        };
        let record = NewAuditEvent {
            id: AuditEventId::from_uuid(ids.new_uuid()),
            actor: AuditActor::Anonymous(actor),
            action,
            subject: event.subject,
            decision: AuditDecision::Deny,
            reason: event.reason.to_owned(),
            policy_hash: policy_hash.clone(),
            job: None,
            stage_run: None,
            correlation_id: CorrelationId::from_uuid(ids.new_uuid()),
        };
        if let Err(error) = store
            .record_platform_audit(PlatformScope::receiver(), record)
            .await
        {
            tracing::warn!(error = %error, "a platform audit event could not be written");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_counts_up_to_the_limit_and_then_refuses() {
        let limiter = RateLimiter::new();
        let key = Key::Installation(7);
        let start = Instant::now();
        assert!(limiter.allow(key, 2, start));
        assert!(limiter.allow(key, 2, start));
        assert!(!limiter.allow(key, 2, start));
        // Another key has its own count.
        assert!(limiter.allow(Key::Installation(8), 2, start));
    }

    #[test]
    fn a_new_window_starts_the_count_again() {
        let limiter = RateLimiter::new();
        let key = Key::Ip(IpAddr::from([127, 0, 0, 1]));
        let start = Instant::now();
        assert!(limiter.allow(key, 1, start));
        assert!(!limiter.allow(key, 1, start));
        assert!(limiter.allow(key, 1, start + WINDOW));
    }

    #[tokio::test]
    async fn the_queue_never_waits_and_refuses_when_full() {
        let (queue, _receiver) = PlatformAudit::channel(1);
        let event = PlatformEvent {
            action: "webhook.rejected",
            subject: "none".to_owned(),
            reason: "the delivery did not pass its checks",
        };
        assert!(queue.report(event.clone()));
        assert!(!queue.report(event));
    }
}
