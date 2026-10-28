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
use std::net::{IpAddr, Ipv6Addr};
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
    /// A source address, as [`source_of`] groups it.
    Ip(IpAddr),
    /// A GitHub installation.
    Installation(u64),
    /// Every source that arrived while the table was full: they share one count.
    Overflow,
}

/// The address a source is counted under, for requests and for open connections.
///
/// * An IPv4 address is itself.
/// * An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, how a dual-stack listener reports an IPv4 peer)
///   is the IPv4 address, so one client is not two sources.
/// * Any other IPv6 address is its /64, the smallest block a provider hands to one subscriber: a
///   client that holds a prefix has 2^64 addresses and must not get a count for each (API-9).
#[must_use]
pub fn source_of(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
            || {
                let [a, b, c, d, ..] = v6.segments();
                IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
            },
            IpAddr::V4,
        ),
    }
}

#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    count: u32,
}

const WINDOW: Duration = Duration::from_secs(60);
const PRUNE_ABOVE: usize = 50_000;
/// The most distinct sources counted at once. Past it, new sources share [`Key::Overflow`].
const MAX_KEYS: usize = 100_000;

/// Fixed-window counters.
#[derive(Debug)]
pub struct RateLimiter {
    windows: Mutex<HashMap<Key, Window>>,
    max_keys: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_capacity(MAX_KEYS)
    }
}

impl RateLimiter {
    /// An empty limiter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty limiter that counts at most `max_keys` sources at once.
    #[must_use]
    pub fn with_capacity(max_keys: usize) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max_keys,
        }
    }

    /// Counts one request for `key` at `now` and says whether it is within `limit` for the
    /// current window. A source address is counted under [`source_of`] it. When the table is full
    /// of live windows a source it has not seen is counted with every other such source, so the
    /// table cannot be grown without bound and the newcomers are limited together.
    pub fn allow(&self, key: Key, limit: u32, now: Instant) -> bool {
        let key = match key {
            Key::Ip(address) => Key::Ip(source_of(address)),
            other => other,
        };
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() > PRUNE_ABOVE.min(self.max_keys) {
            windows.retain(|_, window| now.duration_since(window.started) < WINDOW);
        }
        let key = if windows.len() >= self.max_keys && !windows.contains_key(&key) {
            Key::Overflow
        } else {
            key
        };
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
    use std::net::Ipv4Addr;

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

    #[test]
    fn an_ipv6_source_is_its_64_bit_prefix_and_a_mapped_address_is_the_ipv4_one() {
        let in_prefix = |last: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, last));
        assert_eq!(source_of(in_prefix(1)), source_of(in_prefix(65_535)));
        assert_ne!(
            source_of(in_prefix(1)),
            source_of(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1))),
            "another /64 is another source"
        );
        let plain = IpAddr::from([192, 0, 2, 7]);
        assert_eq!(source_of(plain), plain);
        assert_eq!(
            source_of(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped())),
            plain
        );
        // The two spellings of one client share a count.
        let limiter = RateLimiter::new();
        let now = Instant::now();
        assert!(limiter.allow(Key::Ip(plain), 1, now));
        assert!(!limiter.allow(
            Key::Ip(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped())),
            1,
            now
        ));
    }

    #[test]
    fn a_full_table_does_not_grow_and_the_newcomers_share_one_count() {
        let limiter = RateLimiter::with_capacity(3);
        let now = Instant::now();
        for last in 1..=3_u8 {
            assert!(limiter.allow(Key::Ip(IpAddr::from([10, 0, 0, last])), 1, now));
        }
        // Three sources fill the table. Two more are new: they share the overflow count of 1.
        assert!(limiter.allow(Key::Ip(IpAddr::from([10, 0, 0, 4])), 1, now));
        assert!(!limiter.allow(Key::Ip(IpAddr::from([10, 0, 0, 5])), 1, now));
        // A source that was counted keeps its own count.
        assert!(!limiter.allow(Key::Ip(IpAddr::from([10, 0, 0, 1])), 1, now));
        let size = limiter.windows.lock().expect("lock").len();
        assert_eq!(size, 4, "three sources and the overflow entry");
        // A minute later the old windows are pruned and a new source is counted on its own.
        assert!(limiter.allow(Key::Ip(IpAddr::from([10, 0, 0, 6])), 1, now + WINDOW));
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
