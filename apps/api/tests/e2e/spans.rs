//! A `tracing` subscriber that keeps the spans and events the composed pipeline emits, so that
//! assertion A11 reads what the engine actually emitted.
//!
//! It is the same idea as the capture of the harness's scripted wiring, with one difference that
//! the composed pipeline needs: the stack of entered spans is kept per thread, because the engine
//! runs on a multi-threaded runtime and a future enters its span on whichever thread polls it.
//!
//! It must be the global subscriber of the process, and it must be installed before
//! `support::captured()` is first called (that function tries to install its own and gives up
//! quietly when one is already there). `install` does this once.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

const CORRELATION: &str = "factory.correlation_id";

thread_local! {
    static STACK: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug, Clone, Default)]
struct SpanData {
    name: String,
    parent: Option<u64>,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct EventData {
    target: String,
    parent: Option<u64>,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct State {
    next: u64,
    spans: HashMap<u64, SpanData>,
    events: Vec<EventData>,
}

/// The subscriber. The handle is cloned out to read what it captured.
#[derive(Debug, Clone, Default)]
pub struct Capture {
    state: Arc<Mutex<State>>,
}

struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
}

/// A span the engine opened.
#[derive(Debug, Clone)]
pub struct SpanRecord {
    pub id: u64,
    pub parent: Option<u64>,
    pub name: String,
    pub stage_run_id: Option<String>,
    pub attempt_id: Option<String>,
}

/// A log line or event of a factory crate, with the correlation id it carried.
#[derive(Debug, Clone)]
pub struct LineRecord {
    pub label: String,
    pub correlation_id: Option<String>,
    /// Whether the line was written inside one of the job's spans ([`JOB_SPANS`]), or carries the
    /// correlation id in its own fields. A line written outside any job, such as the token sweep
    /// of the worker loop, has no correlation id by design (`docs/observability/conventions.md`,
    /// section 7), and assertion A11 does not ask it for one.
    pub in_job: bool,
}

/// The spans of a job: the ones whose required attributes hold `factory.correlation_id` (the span
/// table of `docs/observability/conventions.md`). The harness keeps the same list
/// (`tests/end_to_end/src/evidence.rs`, `JOB_SPANS`).
pub const JOB_SPANS: [&str; 6] = [
    "factory.job",
    "factory.stage_run",
    "factory.attempt",
    "factory.agent",
    "factory.tool_call",
    "factory.gate",
];

/// Installs the capture as the global subscriber, once, and returns the handle.
pub fn install() -> &'static Capture {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = Capture::default();
        let _ = tracing::subscriber::set_global_default(capture.clone());
        // The canary sweeps of the other tests read `support::captured()`. Calling it now, after
        // ours is installed, makes it a no-op that returns its own empty list.
        let _ = crate::support::captured();
        capture
    })
}

impl Capture {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many events were captured so far. A mark for [`Capture::lines_since`].
    pub fn mark(&self) -> usize {
        self.lock().events.len()
    }

    /// Every `factory.*` span captured so far.
    pub fn spans(&self) -> Vec<SpanRecord> {
        let state = self.lock();
        let mut ids: Vec<&u64> = state.spans.keys().collect();
        ids.sort();
        ids.into_iter()
            .filter_map(|id| {
                let span = &state.spans[id];
                span.name.starts_with("factory.").then(|| SpanRecord {
                    id: *id,
                    parent: span.parent,
                    name: span.name.clone(),
                    stage_run_id: span.fields.get("factory.stage_run_id").cloned(),
                    attempt_id: span.fields.get("factory.attempt_id").cloned(),
                })
            })
            .collect()
    }

    /// The events of the factory's own crates captured after `mark`, each with the correlation id
    /// of its own fields or of the nearest span above it. Events of third-party crates (the
    /// database driver, the HTTP stack) are not factory log lines and are left out.
    pub fn lines_since(&self, mark: usize) -> Vec<LineRecord> {
        let state = self.lock();
        state
            .events
            .iter()
            .enumerate()
            .skip(mark)
            .filter(|(_, event)| event.target.starts_with("factory"))
            // A metric (`gauge.factory_queue_depth`, a counter, a histogram) measures the whole
            // queue and not one job, so it has no correlation id to carry and is not a log line.
            .filter(|(_, event)| {
                !event.fields.keys().any(|name| {
                    name.starts_with("gauge.")
                        || name.starts_with("counter.")
                        || name.starts_with("histogram.")
                        || name.starts_with("monotonic_counter.")
                })
            })
            .map(|(index, event)| {
                let mut correlation = event.fields.get(CORRELATION).cloned();
                let mut in_job = correlation.is_some();
                let mut cursor = event.parent;
                while let Some(id) = cursor {
                    let span = state.spans.get(&id);
                    if correlation.is_none() {
                        correlation = span.and_then(|s| s.fields.get(CORRELATION).cloned());
                    }
                    in_job |= span.is_some_and(|s| JOB_SPANS.contains(&s.name.as_str()));
                    cursor = span.and_then(|s| s.parent);
                }
                let label = event
                    .fields
                    .get("message")
                    .cloned()
                    .or_else(|| event.fields.keys().next().cloned())
                    .unwrap_or_else(|| "event".to_owned());
                LineRecord {
                    label: format!("event {} ({}: {label})", index + 1, event.target),
                    correlation_id: correlation.map(|text| text.trim_matches('"').to_owned()),
                    in_job,
                }
            })
            .collect()
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let mut fields = Fields(BTreeMap::new());
        attributes.record(&mut fields);
        let mut state = self.lock();
        state.next += 1;
        let id = state.next;
        let parent = if attributes.is_root() {
            None
        } else if let Some(explicit) = attributes.parent() {
            Some(explicit.into_u64())
        } else {
            STACK.with(|stack| stack.borrow().last().copied())
        };
        state.spans.insert(
            id,
            SpanData {
                name: attributes.metadata().name().to_owned(),
                parent,
                fields: fields
                    .0
                    .into_iter()
                    .map(|(k, v)| (k, v.trim_matches('"').to_owned()))
                    .collect(),
            },
        );
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut fields = Fields(BTreeMap::new());
        values.record(&mut fields);
        if let Some(data) = self.lock().spans.get_mut(&span.into_u64()) {
            data.fields.extend(
                fields
                    .0
                    .into_iter()
                    .map(|(k, v)| (k, v.trim_matches('"').to_owned())),
            );
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        let mut state = self.lock();
        let parent = if event.is_root() {
            None
        } else if let Some(explicit) = event.parent() {
            Some(explicit.into_u64())
        } else {
            STACK.with(|stack| stack.borrow().last().copied())
        };
        state.events.push(EventData {
            target: event.metadata().target().to_owned(),
            parent,
            fields: fields
                .0
                .into_iter()
                .map(|(k, v)| (k, v.trim_matches('"').to_owned()))
                .collect(),
        });
    }

    fn enter(&self, span: &Id) {
        STACK.with(|stack| stack.borrow_mut().push(span.into_u64()));
    }

    fn exit(&self, span: &Id) {
        STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(position) = stack.iter().rposition(|id| *id == span.into_u64()) {
                stack.remove(position);
            }
        });
    }
}
