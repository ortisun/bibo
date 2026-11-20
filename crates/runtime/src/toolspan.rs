//! The `factory.tool_call` span: one tool call that an agent made, as the adapter read it from the
//! tool's event stream.
//!
//! A tool call is the least trusted thing an adapter sees. The model chose its name and its
//! arguments, the tool printed them, and the repository can steer both. So a span records only
//! what cannot carry that text:
//!
//! | Attribute | What it holds |
//! |---|---|
//! | `factory.tool_name` | one of a fixed list of words, chosen by this crate: the built-in tools of the adapter, or `unlisted` for any name the adapter does not know. It is a `&'static str`, so a name from the stream cannot reach it. |
//! | `factory.tool_args_sha256` | the SHA-256 of the arguments, 64 hex characters. The arguments are not recorded. |
//! | `factory.outcome` | `succeeded`, `failed`, `denied` or `cancelled`, from the call's result in the stream. |
//! | `factory.attempt_id` | the attempt of the request. |
//!
//! The result of the call, its output and its error text are never recorded.
//!
//! The adapter reads the stream after the tool has ended, so the span is opened and closed when the
//! stream is read. Its duration is not the duration of the call, and the spans of one run appear
//! together under the span that is current when the adapter reads the stream, which is the
//! `factory.agent` span when the engine runs the adapter.
//!
//! The span carries no `factory.correlation_id` and no `factory.job_id`, which the conventions page
//! lists as required: the request the adapter receives names the attempt and nothing else of the
//! job. The parent `factory.agent` span has both, and the spans share a trace.

use factory_ports::agent::AgentRunRequest;

/// The name for a tool the adapter does not know. A fixed word, so no name from a stream can
/// become an attribute value.
pub(crate) const UNLISTED: &str = "unlisted";

/// The most spans one run opens. A stream can hold far more calls than a run is allowed to make,
/// and the stream is written by the tool, so the number is bounded here and not by the stream.
pub(crate) const MAX_SPANS_PER_RUN: usize = 256;

/// How a tool call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The call returned a result that is not an error.
    Succeeded,
    /// The call returned an error, or the command it ran failed.
    Failed,
    /// Policy or the tool's own permission check refused the call.
    Denied,
    /// The stream ends without a result for the call: the run was cut.
    Cancelled,
}

impl Outcome {
    /// The outcome value of the conventions page.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One tool call, reduced to what a span may record. There is no way to put text in it: the name is
/// a static word, the digest is hex and the outcome is an enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolCall {
    pub(crate) name: &'static str,
    pub(crate) args_sha256: String,
    pub(crate) outcome: Outcome,
}

/// Opens and closes one `factory.tool_call` span for each call, up to [`MAX_SPANS_PER_RUN`].
pub(crate) fn emit(req: &AgentRunRequest, calls: &[ToolCall]) {
    for call in calls.iter().take(MAX_SPANS_PER_RUN) {
        let span = tracing::info_span!(
            "factory.tool_call",
            factory.attempt_id = %req.attempt,
            factory.tool_name = call.name,
            factory.tool_args_sha256 = call.args_sha256.as_str(),
            factory.outcome = call.outcome.as_str(),
        );
        drop(span);
    }
}
