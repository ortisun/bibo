//! The agent runtime as a stage handler sees it: every run is a `factory.agent` span.
//!
//! A handler never calls the adapter itself. The engine hands it [`ObservedRuntime`], which does
//! the same work and wraps [`AgentRuntime::run`] in the span of the conventions page, so every
//! stage that runs an agent gets the span without a line of code in the stage. The span hangs from
//! whatever span is current when the handler calls: the attempt, or the gate inside it.
//!
//! The span records ids, a model name, counts and a number, and nothing a model or a tool wrote:
//!
//! | Attribute | Where it comes from |
//! |---|---|
//! | `factory.agent_id` | the agent id of the request, a slug from the registry |
//! | `factory.model` | the model the router chose, from the request |
//! | `factory.outcome` | `succeeded`, `timed_out`, `cancelled` or `failed`, from the closed error set |
//! | `error.type` | a fixed word for each variant of the closed error set, set when the run failed |
//! | `factory.tokens_input`, `factory.tokens_output`, `factory.cost_usd` | the usage the adapter reported |
//!
//! The cost here is what the adapter reported for the run. The broker's meter stays the source of
//! truth for spend, and `factory_spend_usd_total` is read from it.

use async_trait::async_trait;
use factory_domain::ids::{CorrelationId, JobId};
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, ProbeError, RuntimeCapabilities,
    RuntimeId,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::SandboxSession;
use tracing::Instrument;

/// An agent runtime that opens a `factory.agent` span around each run and otherwise does what the
/// runtime it wraps does.
pub(crate) struct ObservedRuntime<'a> {
    inner: &'a dyn AgentRuntime,
    correlation: CorrelationId,
    job: JobId,
}

impl<'a> ObservedRuntime<'a> {
    /// Wraps `inner` for the runs of one job. The ids go on every span the wrapper opens.
    pub(crate) fn new(inner: &'a dyn AgentRuntime, correlation: CorrelationId, job: JobId) -> Self {
        Self {
            inner,
            correlation,
            job,
        }
    }
}

#[async_trait]
impl AgentRuntime for ObservedRuntime<'_> {
    fn id(&self) -> &RuntimeId {
        self.inner.id()
    }

    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn probe(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError> {
        self.inner.probe(session).await
    }

    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> AgentRunReport {
        let span = tracing::info_span!(
            "factory.agent",
            factory.correlation_id = %self.correlation,
            factory.job_id = %self.job,
            factory.attempt_id = %req.attempt,
            factory.agent_id = req.agent.id.as_str(),
            factory.model = req.model.model.as_str(),
            factory.outcome = tracing::field::Empty,
            factory.tokens_input = tracing::field::Empty,
            factory.tokens_output = tracing::field::Empty,
            factory.cost_usd = tracing::field::Empty,
            error.type = tracing::field::Empty,
        );
        let report = self
            .inner
            .run(session, req, cancel)
            .instrument(span.clone())
            .await;
        let (outcome, kind) = match &report.outcome {
            Ok(_) => ("succeeded", None),
            Err(error) => failure(error),
        };
        span.record("factory.outcome", outcome);
        if let Some(kind) = kind {
            span.record("error.type", kind);
        }
        // Counts are recorded as signed integers: an unsigned field arrives as a string.
        span.record(
            "factory.tokens_input",
            saturating(report.usage.input_tokens),
        );
        span.record(
            "factory.tokens_output",
            saturating(report.usage.output_tokens),
        );
        span.record("factory.cost_usd", dollars(report.usage.cost.0));
        report
    }
}

/// The outcome value and the `error.type` word for a failed run. Both are fixed words chosen by
/// the variant, so no text from the tool reaches the span. The match has no wildcard: a new
/// variant of the closed error set fails to compile here until it is given a word.
const fn failure(error: &AgentRunError) -> (&'static str, Option<&'static str>) {
    match error {
        AgentRunError::Timeout => ("timed_out", Some("timeout")),
        AgentRunError::Cancelled => ("cancelled", Some("cancelled")),
        AgentRunError::ProviderUnavailable => ("failed", Some("provider_unavailable")),
        AgentRunError::RateLimited { .. } => ("failed", Some("rate_limited")),
        AgentRunError::AuthenticationRequired => ("failed", Some("authentication_required")),
        AgentRunError::ProcessFailed(_) => ("failed", Some("process_failed")),
        AgentRunError::OutputMissing => ("failed", Some("output_missing")),
        AgentRunError::OutputTooLarge => ("failed", Some("output_too_large")),
        AgentRunError::CapabilityMissing(_) => ("failed", Some("capability_missing")),
        AgentRunError::BudgetRefused => ("failed", Some("budget_refused")),
    }
}

/// A count as the signed integer that `tracing-opentelemetry` keeps as a number.
fn saturating(count: u64) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// Millionths of a dollar as dollars.
fn dollars(micro: u64) -> f64 {
    micro as f64 / 1_000_000.0
}
