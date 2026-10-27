//! Diagnostic logs: JSON lines that carry the job correlation id and leave the process free of
//! secrets.
//!
//! Three pieces work together:
//!
//! * [`CorrelationLayer`] watches spans for the `factory.correlation_id` field and remembers the
//!   id, once it has checked that it is a lower case UUID.
//! * [`log_layer`] writes each event as one JSON line. When an event happens inside a span that
//!   has a correlation id, or inside a child of one, the line starts with a top-level
//!   `correlation_id` field.
//! * Every line passes through a [`Scrub`] before it is written.
//!
//! Logs are diagnostic. They are not domain events: nothing may rely on them, they can be lost
//! or sampled, and they carry no state change. Domain events are the rows of the transactional
//! outbox, described in ADR 0004.

use crate::names::{self, attr};
use crate::redact::Scrub;
use std::fmt;
use std::io;
use std::sync::Arc;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::fmt::format::{
    Format, FormatEvent, FormatFields, Json, JsonFields, Writer,
};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::{FmtContext, MakeWriter};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// A job correlation id: a lower case UUID in the 8-4-4-4-12 layout, as in the domain event
/// schema.
///
/// The strict check does two jobs. It keeps a wrong value from being presented as a correlation
/// id, and it guarantees the text holds no character that needs escaping in JSON, which is what
/// makes it safe to write into a log line by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationId(String);

/// The text is not a lower case UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCorrelationId;

impl fmt::Display for InvalidCorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a correlation id must be a lower case UUID such as 0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77")
    }
}

impl std::error::Error for InvalidCorrelationId {}

impl CorrelationId {
    pub fn parse(text: &str) -> Result<Self, InvalidCorrelationId> {
        let bytes = text.as_bytes();
        let well_formed = bytes.len() == 36
            && bytes.iter().enumerate().all(|(i, &b)| match i {
                8 | 13 | 18 | 23 => b == b'-',
                _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
            });
        if well_formed {
            Ok(Self(text.to_string()))
        } else {
            Err(InvalidCorrelationId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Finds the correlation id among the fields of a span.
#[derive(Default)]
struct FindCorrelationId {
    found: Option<CorrelationId>,
}

impl Visit for FindCorrelationId {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == attr::CORRELATION_ID {
            self.found = CorrelationId::parse(value).ok();
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == attr::CORRELATION_ID {
            let text = format!("{value:?}");
            self.found = CorrelationId::parse(text.trim_matches('"')).ok();
        }
    }
}

/// Remembers the correlation id of every span that has one, so [`log_layer`] can find it.
///
/// Add it to the subscriber together with the log layer. It does not write anything itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct CorrelationLayer {
    _private: (),
}

impl CorrelationLayer {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl<S> Layer<S> for CorrelationLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut finder = FindCorrelationId::default();
        attributes.record(&mut finder);
        remember(finder, id, &ctx);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let mut finder = FindCorrelationId::default();
        values.record(&mut finder);
        remember(finder, id, &ctx);
    }
}

fn remember<S>(finder: FindCorrelationId, id: &Id, ctx: &Context<'_, S>)
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    if let (Some(correlation_id), Some(span)) = (finder.found, ctx.span(id)) {
        span.extensions_mut().replace(correlation_id);
    }
}

/// Writes JSON like the standard formatter, with `correlation_id` first when one is in scope.
struct CorrelatedJson {
    inner: Format<Json, SystemTime>,
}

impl CorrelatedJson {
    fn new() -> Self {
        Self {
            inner: tracing_subscriber::fmt::format()
                .json()
                .with_current_span(false)
                .with_span_list(false)
                .with_file(false)
                .with_line_number(false)
                .with_thread_ids(false)
                .with_thread_names(false),
        }
    }
}

impl<S, N> FormatEvent<S, N> for CorrelatedJson
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut line = String::new();
        self.inner
            .format_event(ctx, Writer::new(&mut line), event)?;

        let correlation_id = ctx.event_scope().and_then(|mut scope| {
            scope.find_map(|span| span.extensions().get::<CorrelationId>().cloned())
        });
        match (correlation_id, line.strip_prefix('{')) {
            (Some(id), Some(rest)) => {
                write!(
                    writer,
                    "{{\"{}\":\"{}\"",
                    names::CORRELATION_LOG_FIELD,
                    id.as_str()
                )?;
                if !rest.starts_with('}') {
                    writer.write_char(',')?;
                }
                writer.write_str(rest)
            }
            _ => writer.write_str(&line),
        }
    }
}

/// The log layer: JSON lines, with the correlation id when one is in scope, scrubbed before they
/// are written.
///
/// Pair it with [`CorrelationLayer`]. Without that layer no line has a correlation id.
pub fn log_layer<S, M>(make_writer: M, scrubber: Arc<dyn Scrub>) -> impl Layer<S>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    M: for<'writer> MakeWriter<'writer> + 'static,
{
    tracing_subscriber::fmt::layer()
        .event_format(CorrelatedJson::new())
        .fmt_fields(JsonFields::new())
        .with_writer(ScrubbingMakeWriter {
            inner: make_writer,
            scrubber,
        })
}

/// What is written in place of a line when the scrubber is not available.
const DROPPED_LINE: &str =
    "{\"level\":\"ERROR\",\"fields\":{\"message\":\"log line dropped: redactor unavailable\"}}\n";

struct ScrubbingMakeWriter<M> {
    inner: M,
    scrubber: Arc<dyn Scrub>,
}

impl<'a, M> MakeWriter<'a> for ScrubbingMakeWriter<M>
where
    M: MakeWriter<'a>,
{
    type Writer = ScrubbingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        ScrubbingWriter::new(self.inner.make_writer(), Arc::clone(&self.scrubber))
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        ScrubbingWriter::new(self.inner.make_writer_for(meta), Arc::clone(&self.scrubber))
    }
}

/// Collects what one event writes and passes it on, scrubbed, when the event is done.
///
/// The formatter hands over one event per writer. Scrubbing the whole event at once means a
/// secret cannot hide between two calls to `write`.
struct ScrubbingWriter<W: io::Write> {
    inner: W,
    scrubber: Arc<dyn Scrub>,
    pending: Vec<u8>,
}

impl<W: io::Write> ScrubbingWriter<W> {
    fn new(inner: W, scrubber: Arc<dyn Scrub>) -> Self {
        Self {
            inner,
            scrubber,
            pending: Vec::new(),
        }
    }

    fn emit(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        match self.scrubber.scrub(&text) {
            Ok(clean) => self.inner.write_all(clean.as_bytes()),
            Err(_) => self.inner.write_all(DROPPED_LINE.as_bytes()),
        }
    }
}

impl<W: io::Write> io::Write for ScrubbingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.inner.flush()
    }
}

impl<W: io::Write> Drop for ScrubbingWriter<W> {
    fn drop(&mut self) {
        // Nothing can be reported from a destructor. The inner writer decides what a failed write
        // means.
        let _ = self.emit();
    }
}
