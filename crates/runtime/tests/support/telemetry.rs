//! Reading what the adapters say to `tracing`: a `Subscriber` that remembers every span and event.
//!
//! The runtime crate may depend on `tracing` and on no other telemetry crate (ADR 0013), so the
//! tests read the spans and events with a small subscriber of their own, as the workflow crate's
//! tests do (`crates/workflow/tests/telemetry_support`). The values are kept in the type `tracing`
//! delivered them in, because the conventions page asks for integers as `i64`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// A field value as `tracing` delivered it.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    I64(i64),
    U64(u64),
    Bool(bool),
    F64(f64),
}

impl Value {
    /// The value as text, whatever its kind.
    pub fn text(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::I64(n) => n.to_string(),
            Value::U64(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::F64(n) => n.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpanRecord {
    pub id: u64,
    pub name: String,
    pub parent: Option<u64>,
    /// The fields given at creation and the ones recorded afterwards.
    pub fields: BTreeMap<String, Value>,
}

impl SpanRecord {
    pub fn text(&self, key: &str) -> Option<String> {
        self.fields.get(key).map(Value::text)
    }
}

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub fields: BTreeMap<String, Value>,
}

impl EventRecord {
    pub fn message(&self) -> String {
        self.fields
            .get("message")
            .map(Value::text)
            .unwrap_or_default()
    }

    /// Every value of the event as text, the message included.
    pub fn all_text(&self) -> String {
        self.fields
            .iter()
            .map(|(name, value)| format!("{name}={}", value.text()))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Default)]
struct State {
    spans: Vec<SpanRecord>,
    events: Vec<EventRecord>,
    entered: Vec<u64>,
}

/// A `Subscriber` that remembers every span and event. Cheap to clone; the clones share state.
#[derive(Clone, Default)]
pub struct Recorder {
    state: Arc<Mutex<State>>,
    next_id: Arc<AtomicU64>,
}

#[derive(Default)]
struct Fields {
    values: BTreeMap<String, Value>,
}

impl Visit for Fields {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.values
            .insert(field.name().to_owned(), Value::I64(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.values
            .insert(field.name().to_owned(), Value::U64(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.values
            .insert(field.name().to_owned(), Value::Bool(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.values
            .insert(field.name().to_owned(), Value::F64(value));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.values
            .insert(field.name().to_owned(), Value::Str(value.to_owned()));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.values
            .insert(field.name().to_owned(), Value::Str(format!("{value:?}")));
    }
}

impl Recorder {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Makes this recorder the subscriber of the current thread until the guard is dropped. A
    /// `#[tokio::test]` runs on one thread, so the adapter's futures report here.
    #[must_use = "the recorder is the subscriber only while the guard lives"]
    pub fn install(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(self.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn spans(&self) -> Vec<SpanRecord> {
        self.lock().spans.clone()
    }

    pub fn events(&self) -> Vec<EventRecord> {
        self.lock().events.clone()
    }

    /// The spans with this name, in the order they were opened.
    pub fn spans_named(&self, name: &str) -> Vec<SpanRecord> {
        self.spans()
            .into_iter()
            .filter(|span| span.name == name)
            .collect()
    }
}

impl Subscriber for Recorder {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut state = self.lock();
        let parent = if attributes.is_root() {
            None
        } else if let Some(explicit) = attributes.parent() {
            Some(explicit.into_u64())
        } else {
            state.entered.last().copied()
        };
        let mut fields = Fields::default();
        attributes.record(&mut fields);
        state.spans.push(SpanRecord {
            id,
            name: attributes.metadata().name().to_owned(),
            parent,
            fields: fields.values,
        });
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut fields = Fields::default();
        values.record(&mut fields);
        let mut state = self.lock();
        if let Some(record) = state.spans.iter_mut().find(|s| s.id == span.into_u64()) {
            record.fields.extend(fields.values);
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.lock().events.push(EventRecord {
            fields: fields.values,
        });
    }

    fn enter(&self, span: &Id) {
        self.lock().entered.push(span.into_u64());
    }

    fn exit(&self, span: &Id) {
        let mut state = self.lock();
        if let Some(at) = state.entered.iter().rposition(|id| *id == span.into_u64()) {
            state.entered.remove(at);
        }
    }
}
