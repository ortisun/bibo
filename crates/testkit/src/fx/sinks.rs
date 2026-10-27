//! FX-SINKS: one place that collects everything a job could leak into.
//!
//! The catalog's secret-leak tests (NT-SEC-01, NT-SBX-13, NT-SEC-11 and others) share one shape:
//! run a job with canaries planted, collect every place where text can end up, and sweep all of it.
//! A [`SinkCollector`] is the "collect" half. A test, or the adapter under test through a hook the
//! test installs, records text under a [`SinkKind`]. The "sweep" half is [`SinkCollector::sweep`],
//! which hands every entry to the [`Sweeper`].
//!
//! The collector holds raw bytes on purpose: a redactor that failed must be visible here. It is a
//! test double and holds only fake secrets (rule 5 of the catalog).
//!
//! Streams (standard output, standard error) are recorded chunk by chunk, so a canary cut in two
//! by a chunk boundary is found, as it would be in a real pipe.
//!
//! # What this module does not capture by itself
//!
//! The collector does not depend on `tracing`, OpenTelemetry, `async-nats`, PostgreSQL or any
//! object-store client, because the testkit may not. The test that owns such an exporter pushes
//! what it received with [`SinkCollector::record_attribute`] and the other `record_*` methods. The
//! spawn recorder and the fake GitHub server hand over their records directly (see
//! [`SinkCollector::ingest_spawns`] and [`SinkCollector::ingest_github`]).

use std::sync::{Arc, Mutex, MutexGuard};

use super::canary::{SweepReport, Sweeper};

/// A place where text can end up and where a secret must not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SinkKind {
    /// A process's standard output, kept as a stream of chunks.
    Stdout,
    /// A process's standard error, kept as a stream of chunks.
    Stderr,
    /// One log line.
    LogLine,
    /// An OpenTelemetry span or metric attribute, as `key=value`.
    TelemetryAttribute,
    /// An OpenTelemetry log record body.
    TelemetryLogRecord,
    /// A row of the audit table.
    AuditRow,
    /// A row of the outbox table.
    OutboxRow,
    /// A message on a NATS subject.
    NatsMessage,
    /// A dump of the whole database.
    DatabaseDump,
    /// A stored artifact (log, report, evidence file).
    Artifact,
    /// A request body or header the fake GitHub server received.
    GithubRequest,
    /// Pull request or issue text bound for GitHub: title, body, comment, commit message.
    PullRequestText,
    /// A prompt sent to a model, or a prompt the scripted runtime captured.
    CapturedPrompt,
    /// An HTTP response body of the API.
    ApiResponse,
    /// The environment of a process, one `NAME=value` per line.
    Environment,
    /// The arguments of a spawned process, one per line.
    ProcessArgument,
}

impl SinkKind {
    /// Every kind of sink. The sweeper's self-proof plants a canary in each of these.
    pub const ALL: [SinkKind; 16] = [
        SinkKind::Stdout,
        SinkKind::Stderr,
        SinkKind::LogLine,
        SinkKind::TelemetryAttribute,
        SinkKind::TelemetryLogRecord,
        SinkKind::AuditRow,
        SinkKind::OutboxRow,
        SinkKind::NatsMessage,
        SinkKind::DatabaseDump,
        SinkKind::Artifact,
        SinkKind::GithubRequest,
        SinkKind::PullRequestText,
        SinkKind::CapturedPrompt,
        SinkKind::ApiResponse,
        SinkKind::Environment,
        SinkKind::ProcessArgument,
    ];

    /// The name used in sink labels and reports.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SinkKind::Stdout => "stdout",
            SinkKind::Stderr => "stderr",
            SinkKind::LogLine => "log_line",
            SinkKind::TelemetryAttribute => "telemetry_attribute",
            SinkKind::TelemetryLogRecord => "telemetry_log_record",
            SinkKind::AuditRow => "audit_row",
            SinkKind::OutboxRow => "outbox_row",
            SinkKind::NatsMessage => "nats_message",
            SinkKind::DatabaseDump => "database_dump",
            SinkKind::Artifact => "artifact",
            SinkKind::GithubRequest => "github_request",
            SinkKind::PullRequestText => "pull_request_text",
            SinkKind::CapturedPrompt => "captured_prompt",
            SinkKind::ApiResponse => "api_response",
            SinkKind::Environment => "environment",
            SinkKind::ProcessArgument => "process_argument",
        }
    }
}

/// One thing collected: a stream of chunks, or a single record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkEntry {
    /// What kind of sink it came from.
    pub kind: SinkKind,
    /// Where in that kind: a process name, a table, a subject, a file name.
    pub origin: String,
    /// The bytes, in the order they arrived. A record has one chunk.
    pub chunks: Vec<Vec<u8>>,
}

impl SinkEntry {
    /// The sink label used in a sweep report: `kind:origin`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}:{}", self.kind.name(), self.origin)
    }

    /// The number of bytes held.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.chunks.iter().map(Vec::len).sum()
    }
}

/// Collects text from every sink of a test run. Cloning shares the same store, so the code under
/// test and the test hold handles to one collector.
#[derive(Debug, Clone, Default)]
pub struct SinkCollector {
    entries: Arc<Mutex<Vec<SinkEntry>>>,
}

impl SinkCollector {
    /// An empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<SinkEntry>> {
        self.entries
            .lock()
            .expect("the sink collector lock is never poisoned")
    }

    /// Records one item as its own entry.
    pub fn record(&self, kind: SinkKind, origin: &str, data: impl AsRef<[u8]>) {
        self.lock().push(SinkEntry {
            kind,
            origin: origin.to_owned(),
            chunks: vec![data.as_ref().to_vec()],
        });
    }

    /// Appends a chunk to the stream with this kind and origin, starting it when it is new.
    pub fn record_chunk(&self, kind: SinkKind, origin: &str, chunk: impl AsRef<[u8]>) {
        let mut entries = self.lock();
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.kind == kind && e.origin == origin)
        {
            entry.chunks.push(chunk.as_ref().to_vec());
        } else {
            entries.push(SinkEntry {
                kind,
                origin: origin.to_owned(),
                chunks: vec![chunk.as_ref().to_vec()],
            });
        }
    }

    /// Records a JSON document, written compactly.
    pub fn record_json(&self, kind: SinkKind, origin: &str, document: &serde_json::Value) {
        self.record(kind, origin, document.to_string());
    }

    /// Records an attribute or label as `key=value`, so a secret in the key is found as well.
    pub fn record_attribute(&self, kind: SinkKind, key: &str, value: &str) {
        self.record(kind, key, format!("{key}={value}"));
    }

    /// Records the environment of a process, one `NAME=value` per line.
    pub fn record_environment<'a>(
        &self,
        origin: &str,
        variables: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) {
        let text = variables
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("\n");
        self.record(SinkKind::Environment, origin, text);
    }

    /// Records the arguments of a process, one per line.
    pub fn record_arguments<'a>(&self, origin: &str, arguments: impl IntoIterator<Item = &'a str>) {
        let text = arguments.into_iter().collect::<Vec<_>>().join("\n");
        self.record(SinkKind::ProcessArgument, origin, text);
    }

    /// Takes the arguments and the environment of every program the spawn recorder saw, so a
    /// secret passed on a command line or in an environment variable is swept (NT-SEC-09).
    ///
    /// # Panics
    /// Panics when the recorder's log cannot be read.
    #[cfg(unix)]
    pub fn ingest_spawns(&self, recorder: &super::spawn::SpawnRecorder) {
        for record in recorder.records().expect("the spawn log can be read") {
            let origin = format!("{}#{}", record.program, record.seq);
            self.record_arguments(&origin, record.argv.iter().map(String::as_str));
            self.record_environment(
                &origin,
                record.env.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            );
        }
    }

    /// Takes every request the fake GitHub server received: the request line, the headers (the
    /// `Authorization` value is already masked by the fake) and the body. A secret the code
    /// under test sent to GitHub in a title, a comment or a branch name is swept (NT-SEC-03).
    pub fn ingest_github(&self, github: &super::github::FakeGithub) {
        for request in github.requests() {
            let origin = format!("{}#{}", request.route, request.seq);
            self.record(SinkKind::GithubRequest, &origin, request.as_text());
        }
    }

    /// A copy of everything collected, in order.
    #[must_use]
    pub fn entries(&self) -> Vec<SinkEntry> {
        self.lock().clone()
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// True when nothing was collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Searches every entry. Each stream is searched as one piece of text, whatever its chunks.
    #[must_use]
    pub fn sweep(&self, sweeper: &Sweeper) -> SweepReport {
        let entries = self.entries();
        let mut report = SweepReport::default();
        for entry in &entries {
            report.hits.extend(
                sweeper.scan_chunks(&entry.label(), entry.chunks.iter().map(Vec::as_slice)),
            );
            report.sinks_scanned += 1;
            report.bytes_scanned += entry.byte_len();
        }
        report
    }

    /// A description of what was collected, without the content: kind, origin, size and the
    /// `fidelity` label every record of the harness carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fidelity": "fake",
            "entries": self.entries().iter().map(|e| serde_json::json!({
                "fidelity": "fake",
                "kind": e.kind.name(),
                "origin": e.origin,
                "chunks": e.chunks.len(),
                "bytes": e.byte_len(),
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests;
