//! Reading back what the pipeline exports, for tests of code that sits above it.
//!
//! The in-memory exporter of the OpenTelemetry SDK lives behind that crate's `testing` feature,
//! which this crate turns on only for its own tests. The crates that wire the pipeline into a
//! service (the composition library and the programs) test the trace they produce, and they may
//! not take the SDK as a dependency of their own, so this module gives them a small exporter that
//! keeps the spans it is handed.
//!
//! Pass a [`SpanCapture`] to
//! [`build_pipeline_with_span_exporter`](crate::telemetry::build_pipeline_with_span_exporter). The
//! exporter sits behind the same attribute guard as the real one, so a test reads what would have
//! left the process. No service uses this module.

use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use std::sync::{Arc, Mutex, PoisonError};

/// A span exporter that keeps every span it receives. Cheap to clone; the clones share the store.
#[derive(Debug, Clone, Default)]
pub struct SpanCapture {
    spans: Arc<Mutex<Vec<SpanData>>>,
}

impl SpanCapture {
    pub fn new() -> Self {
        Self::default()
    }

    /// The spans exported so far, oldest first.
    pub fn spans(&self) -> Vec<SpanData> {
        self.spans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl SpanExporter for SpanCapture {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        self.spans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(batch);
        std::future::ready(Ok(()))
    }
}
