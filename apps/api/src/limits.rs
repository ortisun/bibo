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

/// The action of the row that says how many events of one kind were not written in a window.
pub const AUDIT_DROPPED: &str = "webhook.audit_dropped";

/// How many platform audit events of each kind are written in a window, and how many are left out.
///
/// Each kind has its own budget (API-7). With one budget for every kind, an unauthenticated flood of
/// forged deliveries (`webhook.rejected`) used the whole minute and a genuine delivery for an
/// unregistered installation (`webhook.unbound`), which NT-AUTHZ-08 says is audited, was dropped
/// without a trace. Left-out events are counted, and when the window ends one row per kind says
/// how many, so a flood is visible in the audit log and not only in a log line.
#[derive(Debug)]
pub struct AuditBudget {
    per_kind: u32,
    window: Duration,
    started: Instant,
    kinds: HashMap<&'static str, (u32, u32)>,
}

/// Events of one kind that a window left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Left {
    /// The action of the events.
    pub action: &'static str,
    /// How many.
    pub count: u32,
}

impl AuditBudget {
    /// A budget of `per_kind` events of each kind in each `window`, the first window starting at `now`.
    #[must_use]
    pub fn new(per_kind: u32, window: Duration, now: Instant) -> Self {
        Self {
            per_kind,
            window,
            started: now,
            kinds: HashMap::new(),
        }
    }

    /// When the current window ends.
    #[must_use]
    pub fn ends_at(&self) -> Instant {
        self.started + self.window
    }

    /// Ends the window if it is over, and says what it left out. The next window starts at `now`.
    pub fn roll(&mut self, now: Instant) -> Vec<Left> {
        if now.duration_since(self.started) < self.window {
            return Vec::new();
        }
        self.started = now;
        let mut left: Vec<Left> = self
            .kinds
            .drain()
            .filter(|(_, (_, dropped))| *dropped > 0)
            .map(|(action, (_, count))| Left { action, count })
            .collect();
        left.sort_by_key(|each| each.action);
        left
    }

    /// Asks for a place for one event of this kind: true when it is to be written.
    pub fn admit(&mut self, action: &'static str) -> bool {
        let (written, dropped) = self.kinds.entry(action).or_insert((0, 0));
        if *written >= self.per_kind {
            *dropped = dropped.saturating_add(1);
            return false;
        }
        *written += 1;
        true
    }
}

/// Writes the queued events, at most `per_minute` of each kind in each minute. The rest are counted,
/// and one row per kind says how many at the end of the minute. Ends when every sender is gone.
pub async fn write_platform_audit(
    mut events: mpsc::Receiver<PlatformEvent>,
    store: Arc<dyn Store>,
    ids: Arc<dyn IdGenerator>,
    policy_hash: Sha256Digest,
    per_minute: u32,
) {
    let mut budget = AuditBudget::new(per_minute, WINDOW, Instant::now());
    let write = |event: PlatformEvent| {
        let store = Arc::clone(&store);
        let ids = Arc::clone(&ids);
        let policy_hash = policy_hash.clone();
        async move {
            let (Ok(action), Ok(actor)) = (AuditAction::new(event.action), Slug::parse("webhook"))
            else {
                return;
            };
            let record = NewAuditEvent {
                id: AuditEventId::from_uuid(ids.new_uuid()),
                actor: AuditActor::Anonymous(actor),
                action,
                subject: event.subject,
                decision: AuditDecision::Deny,
                reason: event.reason.to_owned(),
                policy_hash,
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
    };
    loop {
        // Wake at the end of the window even when nothing arrives, so the row that counts the
        // events left out is written in the minute after the flood and not at the next event.
        let next = tokio::time::timeout_at(budget.ends_at().into(), events.recv()).await;
        let event = match next {
            Ok(Some(event)) => Some(event),
            Ok(None) => break,
            Err(_elapsed) => None,
        };
        for each in budget.roll(Instant::now()) {
            // The kind is one of a closed set of fixed words and is in the row that follows.
            tracing::warn!(
                dropped = each.count,
                "platform audit events were left out in the last minute"
            );
            write(PlatformEvent {
                action: AUDIT_DROPPED,
                subject: format!("{} x{}", each.action, each.count),
                reason: "Events of this kind arrived faster than the audit log takes them; the count is in the subject.",
            })
            .await;
        }
        if let Some(event) = event
            && budget.admit(event.action)
        {
            write(event).await;
        }
    }
}

/// The decision refusals of one person that are written as rows in a window. Past it they are
/// counted (API-8).
pub const REFUSAL_ROWS_PER_WINDOW: u32 = 5;
const MAX_REFUSAL_PRINCIPALS: usize = 10_000;

/// What the audit log does with one refused decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Write the usual `decision.denied` row. When `carried` is not zero the last window left that
    /// many refusals of this person out: write the row that says so too.
    Record {
        /// The refusals the window before left out.
        carried: u32,
    },
    /// The first refusal past the share: write one row that says the rest are counted, not written.
    Suppress,
    /// Write nothing; the refusal is counted.
    Count,
}

#[derive(Debug, Clone, Copy)]
struct RefusalWindow {
    started: Instant,
    rows: u32,
    left_out: u32,
}

/// Counts the refused decisions of each person, so a token holder with no designation cannot grow
/// the tenant's hash-chained audit log by one row per request (API-8). A person gets
/// [`REFUSAL_ROWS_PER_WINDOW`] rows a minute, then one row that says the rest are counted, and the
/// count is written in the first row of the next window.
#[derive(Debug, Default)]
pub struct RefusalBudget {
    windows: Mutex<HashMap<factory_domain::ids::PrincipalId, RefusalWindow>>,
}

impl RefusalBudget {
    /// An empty budget.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decides what to write for a refusal of `principal` at `now`.
    pub fn admit(&self, principal: factory_domain::ids::PrincipalId, now: Instant) -> Refusal {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if windows.len() > MAX_REFUSAL_PRINCIPALS {
            windows.retain(|_, window| {
                now.duration_since(window.started) < WINDOW || window.left_out > 0
            });
        }
        let fresh = RefusalWindow {
            started: now,
            rows: 0,
            left_out: 0,
        };
        let window = windows.entry(principal).or_insert(fresh);
        let mut carried = 0;
        if now.duration_since(window.started) >= WINDOW {
            carried = window.left_out;
            *window = fresh;
        }
        if window.rows < REFUSAL_ROWS_PER_WINDOW {
            window.rows += 1;
            return Refusal::Record { carried };
        }
        window.left_out = window.left_out.saturating_add(1);
        if window.left_out == 1 {
            Refusal::Suppress
        } else {
            Refusal::Count
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

    #[test]
    fn each_kind_of_audit_event_has_its_own_budget_and_the_left_out_are_counted() {
        let start = Instant::now();
        let mut budget = AuditBudget::new(2, WINDOW, start);
        // A flood of one kind uses its own budget and nobody else's.
        let admitted = (0..70).filter(|_| budget.admit("webhook.rejected")).count();
        assert_eq!(admitted, 2);
        assert!(
            budget.admit("webhook.unbound"),
            "another kind still has its budget"
        );
        assert!(budget.admit("webhook.unbound"));
        assert!(!budget.admit("webhook.unbound"));
        // Nothing is said before the window ends.
        assert!(budget.roll(start + WINDOW / 2).is_empty());
        // When it ends, one entry per kind that left events out, with the count.
        assert_eq!(
            budget.roll(start + WINDOW),
            vec![
                Left {
                    action: "webhook.rejected",
                    count: 68
                },
                Left {
                    action: "webhook.unbound",
                    count: 1
                },
            ]
        );
        // The next window starts clean, and a window with nothing left out says nothing.
        assert!(budget.admit("webhook.rejected"));
        assert!(budget.roll(start + WINDOW * 2).is_empty());
        assert_eq!(budget.ends_at(), start + WINDOW * 2 + WINDOW);
    }

    #[test]
    fn a_person_gets_a_few_refusal_rows_then_one_note_then_a_count() {
        let budget = RefusalBudget::new();
        let person = factory_domain::ids::PrincipalId::from_uuid(uuid::Uuid::from_u128(1));
        let other = factory_domain::ids::PrincipalId::from_uuid(uuid::Uuid::from_u128(2));
        let start = Instant::now();
        let plan: Vec<Refusal> = (0..60).map(|_| budget.admit(person, start)).collect();
        let rows = plan
            .iter()
            .filter(|each| matches!(each, Refusal::Record { .. }))
            .count();
        let notes = plan
            .iter()
            .filter(|each| **each == Refusal::Suppress)
            .count();
        let counted = plan.iter().filter(|each| **each == Refusal::Count).count();
        assert_eq!((rows, notes, counted), (5, 1, 54));
        assert_eq!(
            plan[5],
            Refusal::Suppress,
            "the note comes first after the share"
        );
        // Another person is not touched by the first one's flood.
        assert_eq!(budget.admit(other, start), Refusal::Record { carried: 0 });
        // The next window opens with a row, and says how many the last one left out (55 = 1 + 54).
        assert_eq!(
            budget.admit(person, start + WINDOW),
            Refusal::Record { carried: 55 }
        );
        assert_eq!(
            budget.admit(person, start + WINDOW + Duration::from_secs(1)),
            Refusal::Record { carried: 0 },
            "and says it once"
        );
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
