//! A `tracing` subscriber that keeps the spans and events the engine emits, so assertion A11 reads
//! what the engine actually emitted and not what the harness thinks it should have.
//!
//! The engine opens a `factory.stage_run` span, a `factory.attempt` span under it and a
//! `factory.gate` span, and logs events. The scripted wiring plays the worker loop: it opens a
//! `factory.job` span around the work, as the composition root's worker does
//! (`s1-apps-composition`). The subscriber records every span with its parent and fields, and
//! every event with the span it happened in.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use crate::evidence::{Correlated, JOB_SPANS, Span};

const CORRELATION: &str = "factory.correlation_id";

#[derive(Debug, Clone, Default)]
struct SpanData {
    name: String,
    parent: Option<u64>,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct EventData {
    parent: Option<u64>,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct State {
    next: u64,
    spans: HashMap<u64, SpanData>,
    stack: Vec<u64>,
    events: Vec<EventData>,
}

/// The subscriber. Clone it to read what it captured after the run.
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

impl Capture {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("the capture lock is never poisoned")
    }

    /// How many events were captured so far. Use it as a mark for [`Capture::logs_since`].
    #[must_use]
    pub fn mark(&self) -> usize {
        self.lock().events.len()
    }

    /// Every `factory.*` span captured, with its parent.
    #[must_use]
    pub fn spans(&self) -> Vec<Span> {
        let state = self.lock();
        let mut ids: Vec<&u64> = state.spans.keys().collect();
        ids.sort();
        ids.into_iter()
            .filter_map(|id| {
                let span = &state.spans[id];
                span.name.starts_with("factory.").then(|| Span {
                    id: id.to_string(),
                    parent_id: span.parent.map(|p| p.to_string()),
                    name: span.name.clone(),
                    stage_run_id: span.fields.get("factory.stage_run_id").cloned(),
                    attempt_id: span.fields.get("factory.attempt_id").cloned(),
                })
            })
            .collect()
    }

    /// The events captured after `mark`, each with the correlation id of its own fields or of the
    /// nearest span above it. An event outside every span has none.
    #[must_use]
    pub fn logs_since(&self, mark: usize) -> Vec<Correlated> {
        let state = self.lock();
        state
            .events
            .iter()
            .enumerate()
            .skip(mark)
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
                Correlated {
                    source: "log".to_owned(),
                    label: format!("event {} ({label})", index + 1),
                    correlation_id: correlation,
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
            state.stack.last().copied()
        };
        state.spans.insert(
            id,
            SpanData {
                name: attributes.metadata().name().to_owned(),
                parent,
                fields: fields.0,
            },
        );
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut fields = Fields(BTreeMap::new());
        values.record(&mut fields);
        if let Some(data) = self.lock().spans.get_mut(&span.into_u64()) {
            data.fields.extend(fields.0);
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
            state.stack.last().copied()
        };
        state.events.push(EventData {
            parent,
            fields: fields.0,
        });
    }

    fn enter(&self, span: &Id) {
        self.lock().stack.push(span.into_u64());
    }

    fn exit(&self, span: &Id) {
        let mut state = self.lock();
        if let Some(position) = state.stack.iter().rposition(|id| *id == span.into_u64()) {
            state.stack.remove(position);
        }
    }
}
