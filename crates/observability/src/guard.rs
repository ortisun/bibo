//! The last stop before a span leaves the process.
//!
//! [`AttributeGuard`] makes three promises about every span handed to an exporter:
//!
//! 1. Only attribute keys on the allowlist in [`crate::names`] survive. Anything else is dropped
//!    and counted. This is what keeps a prompt, an issue body or a request header out of a trace
//!    even when a call site records one by mistake.
//! 2. Every string that remains has its secrets removed by a [`Scrub`], and is cut to
//!    [`MAX_ATTRIBUTE_VALUE_BYTES`]. Scrubbing runs first, so a secret that straddles the cut is
//!    removed whole.
//! 3. If the scrubber fails, the value is replaced and the original is never passed on.
//!
//! The guard also blanks the description of an error status. That text is free-form and tends to
//! hold paths, query text and other internals. The error class travels as an attribute instead.
//!
//! [`RedactingSpanExporter`] applies the guard to each batch and then calls the real exporter.

use crate::metrics::{RedactionKind, record_redaction};
use crate::names::{self, MAX_ATTRIBUTE_VALUE_BYTES};
use crate::redact::{Scrub, ScrubError};
use opentelemetry::trace::{Event, Link, Status};
use opentelemetry::{Array, KeyValue, StringValue, Value};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Appended to a value that was cut.
pub const TRUNCATION_MARKER: &str = "[TRUNCATED]";

/// Replaces a value when the scrubber could not run.
pub const SCRUBBER_UNAVAILABLE: &str = "[REDACTED:scrubber_unavailable]";

/// How many different dropped keys are reported in the diagnostic log. The counter keeps counting.
const MAX_REPORTED_DROPPED_KEYS: usize = 64;

/// Counts of what the guard did. Safe to read from any thread.
#[derive(Debug, Default)]
pub struct GuardStats {
    redacted_values: AtomicU64,
    truncated_values: AtomicU64,
    dropped_attributes: AtomicU64,
    scrub_failures: AtomicU64,
}

/// A point-in-time copy of [`GuardStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuardSnapshot {
    /// Strings in which at least one secret was replaced.
    pub redacted_values: u64,
    /// Strings that were cut to the length limit.
    pub truncated_values: u64,
    /// Attributes dropped because their key is not on the allowlist, or their type is unknown.
    pub dropped_attributes: u64,
    /// Strings replaced because the scrubber failed.
    pub scrub_failures: u64,
}

impl GuardStats {
    pub fn snapshot(&self) -> GuardSnapshot {
        GuardSnapshot {
            redacted_values: self.redacted_values.load(Ordering::Relaxed),
            truncated_values: self.truncated_values.load(Ordering::Relaxed),
            dropped_attributes: self.dropped_attributes.load(Ordering::Relaxed),
            scrub_failures: self.scrub_failures.load(Ordering::Relaxed),
        }
    }

    // Each count below also adds one to `factory_redactions_total`, with the kind and nothing else
    // (`metrics::record_redaction`). The count and the metric are raised in the same place, so
    // they cannot drift apart, and the metric never sees the text or the key of the value.

    /// A secret was replaced in a string.
    fn redacted(&self) {
        self.redacted_values.fetch_add(1, Ordering::Relaxed);
        record_redaction(RedactionKind::Redacted);
    }

    /// A string was cut to the length limit.
    fn truncated(&self) {
        self.truncated_values.fetch_add(1, Ordering::Relaxed);
        record_redaction(RedactionKind::Truncated);
    }

    /// An attribute was not passed on: its key is not allowed or its type is unknown.
    fn dropped(&self) {
        self.dropped_attributes.fetch_add(1, Ordering::Relaxed);
        record_redaction(RedactionKind::Dropped);
    }

    /// The scrubber failed and the original value was replaced. The metric counts it as dropped,
    /// because the original is not passed on; `scrub_failures` keeps it apart for a reader of the
    /// statistics.
    fn scrub_failed(&self) {
        self.scrub_failures.fetch_add(1, Ordering::Relaxed);
        record_redaction(RedactionKind::Dropped);
    }
}

/// Applies the allowlist, the scrubber and the length limit. See the module documentation.
#[derive(Debug, Clone)]
pub struct AttributeGuard {
    scrubber: Arc<dyn Scrub>,
    stats: Arc<GuardStats>,
    max_value_bytes: usize,
    reported_keys: Arc<Mutex<BTreeSet<String>>>,
}

impl AttributeGuard {
    pub fn new(scrubber: Arc<dyn Scrub>) -> Self {
        Self {
            scrubber,
            stats: Arc::new(GuardStats::default()),
            max_value_bytes: MAX_ATTRIBUTE_VALUE_BYTES,
            reported_keys: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    /// Change the length limit. The default is [`MAX_ATTRIBUTE_VALUE_BYTES`].
    pub fn with_max_value_bytes(mut self, max: usize) -> Self {
        self.max_value_bytes = max;
        self
    }

    pub fn stats(&self) -> Arc<GuardStats> {
        Arc::clone(&self.stats)
    }

    /// Return the span with every promise of the module documentation applied.
    pub fn sanitize(&self, mut span: SpanData) -> SpanData {
        span.name = match self.clean(span.name.as_ref()) {
            Cow::Borrowed(_) => span.name,
            Cow::Owned(cleaned) => Cow::Owned(cleaned),
        };
        let attributes = std::mem::take(&mut span.attributes);
        let (kept, dropped) = self.clean_attributes(attributes, names::is_allowed_attribute);
        span.attributes = kept;
        span.dropped_attributes_count = span.dropped_attributes_count.saturating_add(dropped);

        span.events.events = std::mem::take(&mut span.events.events)
            .into_iter()
            .map(|event| self.clean_event(event))
            .collect();
        span.links.links = std::mem::take(&mut span.links.links)
            .into_iter()
            .map(|link| self.clean_link(link))
            .collect();

        if let Status::Error { .. } = span.status {
            span.status = Status::error("");
        }
        span
    }

    fn clean_event(&self, mut event: Event) -> Event {
        event.name = match self.clean(event.name.as_ref()) {
            Cow::Borrowed(_) => event.name,
            Cow::Owned(cleaned) => Cow::Owned(cleaned),
        };
        let (kept, dropped) = self.clean_attributes(
            std::mem::take(&mut event.attributes),
            names::is_allowed_event_attribute,
        );
        event.attributes = kept;
        event.dropped_attributes_count = event.dropped_attributes_count.saturating_add(dropped);
        event
    }

    fn clean_link(&self, mut link: Link) -> Link {
        let (kept, dropped) = self.clean_attributes(
            std::mem::take(&mut link.attributes),
            names::is_allowed_attribute,
        );
        link.attributes = kept;
        link.dropped_attributes_count = link.dropped_attributes_count.saturating_add(dropped);
        link
    }

    fn clean_attributes(
        &self,
        attributes: Vec<KeyValue>,
        is_allowed: fn(&str) -> bool,
    ) -> (Vec<KeyValue>, u32) {
        let mut kept = Vec::with_capacity(attributes.len());
        let mut dropped = 0u32;
        for KeyValue { key, value, .. } in attributes {
            if !is_allowed(key.as_str()) {
                self.note_dropped(key.as_str());
                dropped += 1;
                continue;
            }
            match self.clean_value(value) {
                Some(value) => kept.push(KeyValue::new(key, value)),
                None => {
                    self.note_dropped(key.as_str());
                    dropped += 1;
                }
            }
        }
        (kept, dropped)
    }

    /// `None` means the value has a type this guard does not know, so it cannot be vouched for.
    fn clean_value(&self, value: Value) -> Option<Value> {
        match value {
            Value::String(text) => Some(Value::String(self.clean_string_value(text))),
            Value::Array(Array::String(items)) => Some(Value::Array(Array::String(
                items
                    .into_iter()
                    .map(|item| self.clean_string_value(item))
                    .collect(),
            ))),
            Value::Bool(_)
            | Value::I64(_)
            | Value::F64(_)
            | Value::Array(Array::Bool(_) | Array::I64(_) | Array::F64(_)) => Some(value),
            _ => None,
        }
    }

    fn clean_string_value(&self, text: StringValue) -> StringValue {
        match self.clean(text.as_str()) {
            Cow::Borrowed(_) => text,
            Cow::Owned(cleaned) => StringValue::from(cleaned),
        }
    }

    /// Scrub, then cut. Returns the input itself when nothing changed.
    fn clean<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let scrubbed = match self.scrubber.scrub(text) {
            Ok(Cow::Borrowed(same)) => Cow::Borrowed(same),
            Ok(Cow::Owned(changed)) => {
                if changed != text {
                    self.stats.redacted();
                }
                Cow::Owned(changed)
            }
            Err(ScrubError::Unavailable) => {
                self.stats.scrub_failed();
                // Owned on purpose: callers read `Borrowed` as "the input is unchanged".
                return Cow::Owned(SCRUBBER_UNAVAILABLE.to_string());
            }
        };
        if scrubbed.len() <= self.max_value_bytes {
            return scrubbed;
        }
        self.stats.truncated();
        let mut cut = self.max_value_bytes;
        while !scrubbed.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut cut_text = String::with_capacity(cut + TRUNCATION_MARKER.len());
        cut_text.push_str(&scrubbed[..cut]);
        cut_text.push_str(TRUNCATION_MARKER);
        Cow::Owned(cut_text)
    }

    /// Count a dropped attribute and, the first time a key is seen, say so in the diagnostic log.
    /// Only the key is logged, never the value.
    fn note_dropped(&self, key: &str) {
        self.stats.dropped();
        let Ok(mut seen) = self.reported_keys.lock() else {
            return;
        };
        if seen.len() >= MAX_REPORTED_DROPPED_KEYS || !seen.insert(key.to_string()) {
            return;
        }
        let shown = self.clean(key);
        tracing::warn!(
            "telemetry attribute {shown} is not on the allowlist or has an unknown type; it was dropped"
        );
    }
}

/// Wraps a span exporter so that every batch passes through an [`AttributeGuard`] first.
#[derive(Debug)]
pub struct RedactingSpanExporter<E> {
    inner: E,
    guard: AttributeGuard,
}

impl<E> RedactingSpanExporter<E> {
    pub fn new(inner: E, guard: AttributeGuard) -> Self {
        Self { inner, guard }
    }
}

impl<E: SpanExporter> SpanExporter for RedactingSpanExporter<E> {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        let batch: Vec<SpanData> = batch
            .into_iter()
            .map(|span| self.guard.sanitize(span))
            .collect();
        self.inner.export(batch)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}
