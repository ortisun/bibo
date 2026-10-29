//! Reading what the engine says to `tracing`, and the conventions page it must agree with.
//!
//! `workflow` may depend on `tracing` and on no other telemetry crate (ADR 0013), so these tests
//! cannot use the OpenTelemetry pipeline of `factory-observability`. They record the spans and
//! events the engine creates with a small `Subscriber` of their own and compare them with the
//! tables of `docs/observability/conventions.md`. The tests in `crates/composition/tests` cover the
//! other half: that the same spans become one OpenTelemetry trace.
//!
//! Each test file includes this module with `mod telemetry_support;` and uses the parts it needs.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

// ---- What was recorded -------------------------------------------------------------------

/// A field value as `tracing` delivered it. The kinds are kept apart because the conventions page
/// asks for integers as `i64`: `tracing-opentelemetry` turns an unsigned field into a string.
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
    /// The span this one was created under: the explicit parent, or the span entered at the time.
    pub parent: Option<u64>,
    /// The fields given at creation and the ones recorded afterwards.
    pub fields: BTreeMap<String, Value>,
    /// The names of the fields that were declared but never given a value.
    pub declared_only: Vec<String>,
}

impl SpanRecord {
    pub fn text(&self, key: &str) -> Option<String> {
        self.fields.get(key).map(Value::text)
    }
}

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub level: Level,
    pub target: String,
    pub parent: Option<u64>,
    pub fields: BTreeMap<String, Value>,
}

impl EventRecord {
    pub fn message(&self) -> String {
        self.fields
            .get("message")
            .map(Value::text)
            .unwrap_or_default()
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
    /// `#[tokio::test]` runs on one thread, so the engine's futures report here.
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

    /// Forgets what was recorded so far.
    pub fn clear(&self) {
        let mut state = self.lock();
        state.spans.clear();
        state.events.clear();
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
        let declared_only = attributes
            .metadata()
            .fields()
            .iter()
            .map(|field| field.name().to_owned())
            .filter(|name| !fields.values.contains_key(name))
            .collect();
        state.spans.push(SpanRecord {
            id,
            name: attributes.metadata().name().to_owned(),
            parent,
            fields: fields.values,
            declared_only,
        });
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut fields = Fields::default();
        values.record(&mut fields);
        let mut state = self.lock();
        if let Some(record) = state.spans.iter_mut().find(|s| s.id == span.into_u64()) {
            for (name, value) in fields.values {
                record.declared_only.retain(|declared| declared != &name);
                record.fields.insert(name, value);
            }
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let mut state = self.lock();
        let parent = if event.is_root() {
            None
        } else if let Some(explicit) = event.parent() {
            Some(explicit.into_u64())
        } else {
            state.entered.last().copied()
        };
        state.events.push(EventRecord {
            level: *event.metadata().level(),
            target: event.metadata().target().to_owned(),
            parent,
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

// ---- The conventions page ----------------------------------------------------------------

/// The conventions page the tables are read from.
pub const CONVENTIONS: &str = include_str!("../../../../docs/observability/conventions.md");

/// The rows of the table between `<!-- table:NAME -->` and `<!-- /table:NAME -->`, header and
/// separator removed. Each cell is trimmed and loses the backticks around it.
pub fn table(name: &str) -> Vec<Vec<String>> {
    let begin = format!("<!-- table:{name} -->");
    let end = format!("<!-- /table:{name} -->");
    let start = CONVENTIONS
        .find(&begin)
        .unwrap_or_else(|| panic!("the conventions page has no marker {begin}"));
    let stop = CONVENTIONS
        .find(&end)
        .unwrap_or_else(|| panic!("the conventions page has no marker {end}"));
    CONVENTIONS[start + begin.len()..stop]
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .skip(2)
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_owned())
                .collect()
        })
        .collect()
}

/// The names in a cell such as "`a`, `b`".
pub fn names_in(cell: &str) -> Vec<String> {
    cell.split(',')
        .map(|part| part.trim().trim_matches('`').to_owned())
        .filter(|part| !part.is_empty() && part != "none")
        .collect()
}

/// The span names of the conventions page, with the attributes each must carry when it ends.
pub fn required_attributes() -> BTreeMap<String, Vec<String>> {
    table("spans")
        .into_iter()
        .map(|row| (row[0].clone(), names_in(&row[1])))
        .collect()
}

/// The attribute keys the conventions page allows on a span, by span name.
pub fn allowed_attributes(span: &str) -> Vec<String> {
    table("attributes")
        .into_iter()
        .filter(|row| names_in(&row[3]).iter().any(|name| name == span))
        .map(|row| row[0].clone())
        .collect()
}

/// The outcome values of the conventions page.
pub fn outcome_values() -> Vec<String> {
    table("outcomes")
        .into_iter()
        .map(|row| row[0].clone())
        .collect()
}

/// What a span lacks to meet the conventions page, as sentences. Empty when it meets them: the
/// name is in the span table, every required attribute has a value, and every field it carries is
/// allowed on a span of that name.
pub fn shape_problems(span: &SpanRecord) -> Vec<String> {
    let required = required_attributes();
    let Some(needed) = required.get(&span.name) else {
        return vec![format!(
            "{} is not a span name on the conventions page",
            span.name
        )];
    };
    let mut problems = Vec::new();
    for key in needed {
        match span.fields.get(key) {
            None => problems.push(format!("{} lacks {key}", span.name)),
            Some(value) if value.text().is_empty() => {
                problems.push(format!("{} has an empty {key}", span.name));
            }
            Some(_) => {}
        }
    }
    let allowed = allowed_attributes(&span.name);
    for key in span.fields.keys() {
        if !allowed.contains(key) {
            problems.push(format!(
                "{} carries {key}, which the page does not allow on it",
                span.name
            ));
        }
    }
    problems
}
