//! The contract suite for the `AgentRuntime` port (ports-v1.1): probing, the shape of a run's
//! report, the closed failure set, cancellation, the budget, output as bytes and a failed run
//! that still reports what it used.
//!
//! A run is driven by a *behavior* that the subject arranges. A fake plays the behavior from a
//! script. A real adapter gets the same behavior from a scripted fake model provider behind the
//! broker (FX-ADV-P), so the two are held to one contract.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::vocabulary::StageKind;
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, Capability, CostMicroUsd, Denial,
    ExitInfo, Usage,
};
use factory_ports::sandbox::SandboxSession;

use super::{Check, Context, Report, Waiver, check_list, ensure, ensure_eq, run_checks, skip};
use crate::clock::FakeCancel;

/// What the next call to `run` should do.
#[derive(Debug, Clone)]
pub enum Behavior {
    /// The tool finishes and prints this output, using this much.
    Finish {
        /// The final output. It need not follow any schema: the runtime must not judge it.
        output: serde_json::Value,
        /// What the run used.
        usage: Usage,
    },
    /// The tool finishes, and reports that these tool calls were denied.
    FinishWithDenials(Vec<Denial>),
    /// The tool fails in the way the error describes, after using this much.
    Fail {
        /// How it fails.
        error: AgentRunError,
        /// What the run used before it failed.
        usage: Usage,
    },
    /// The tool keeps working until it is cancelled.
    RunUntilCancelled,
}

/// What the suite needs beyond the `AgentRuntime` port itself.
#[async_trait]
pub trait AgentRuntimeSubject: Send + Sync {
    /// The runtime under test.
    fn runtime(&self) -> &dyn AgentRuntime;

    /// True when the transcript is stored. A fake indexes it for a test tenant first, as the
    /// engine does; a real adapter asks its store.
    async fn transcript_is_stored(&self, reference: &ArtifactRef) -> Result<bool, String>;

    /// A verified `agent`-profile sandbox for the run.
    async fn session(&self) -> Result<Box<dyn SandboxSession>, String>;

    /// A well-formed request for a standard (non-specification) stage.
    fn request(&self) -> AgentRunRequest;

    /// Arranges what the next call to `run` does. Returns `false` when the subject cannot.
    async fn arrange(&self, behavior: Behavior) -> bool;

    /// Makes the runtime's next probe find that `capability` is missing. Returns `false` when the
    /// subject cannot.
    async fn remove_capability(&self, capability: Capability) -> bool;
}

/// A check of the agent runtime contract.
pub type AgentCheck = Check<dyn AgentRuntimeSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: AgentRuntimeSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn AgentRuntimeSubject>
    })
    .await
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[Waiver] = &[];

/// Every check of the agent runtime contract.
#[must_use]
pub fn checks() -> Vec<AgentCheck> {
    check_list![dyn AgentRuntimeSubject;
        probing_reports_a_version_and_its_observations_and_repeats,
        a_run_returns_the_output_unjudged_with_a_stored_transcript,
        a_run_reports_what_it_used,
        denied_tool_calls_are_reported,
        every_failure_keeps_its_own_closed_variant,
        a_failed_run_still_reports_usage_and_transcript,
        output_is_bytes_and_a_oversize_output_is_a_failure,
        a_cancel_that_is_already_set_stops_the_run,
        a_cancel_during_a_run_stops_it_promptly,
        a_run_that_needs_a_missing_capability_is_refused,
        a_run_over_its_cost_limit_is_refused,
    ]
}

async fn run_once(
    subject: &dyn AgentRuntimeSubject,
    request: AgentRunRequest,
) -> Result<AgentRunReport, String> {
    let mut session = subject.session().await?;
    let cancel = FakeCancel::new();
    Ok(subject
        .runtime()
        .run(session.as_mut(), request, &cancel)
        .await)
}

async fn probing_reports_a_version_and_its_observations_and_repeats(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    let mut session = subject.session().await?;
    let first = subject
        .runtime()
        .probe(session.as_mut())
        .await
        .ctx("first probe")?;
    ensure!(
        !first.runtime_version.is_empty(),
        "a probe must report the tool's version"
    );
    ensure!(
        !first.observations.is_empty(),
        "a probe must report at least one observation"
    );
    ensure!(
        first.observations.iter().all(|o| !o.source.is_empty()),
        "every observation must say where it came from"
    );
    let second = subject
        .runtime()
        .probe(session.as_mut())
        .await
        .ctx("second probe")?;
    ensure_eq!(second, first, "a second probe of the same tool");
    Ok(())
}

async fn a_run_returns_the_output_unjudged_with_a_stored_transcript(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    // An output that follows no schema. The runtime reports its bytes; the engine judges them.
    let output = serde_json::json!("this is not an object, let alone the requested schema");
    if !subject
        .arrange(Behavior::Finish {
            output: output.clone(),
            usage: Usage::default(),
        })
        .await
    {
        skip!("this subject cannot arrange a finished run");
    }
    let report = run_once(subject, subject.request()).await?;
    let raw = report.outcome.clone().ctx("the run's output")?;
    let parsed: serde_json::Value =
        serde_json::from_slice(raw.as_bytes()).ctx("the output is JSON bytes")?;
    ensure_eq!(parsed, output, "the output the run returned");
    ensure!(
        report
            .runtime_version
            .as_deref()
            .is_some_and(|v| !v.is_empty()),
        "a run must report the version of the tool"
    );
    ensure_eq!(
        report.exit,
        Some(ExitInfo {
            code: Some(0),
            signal: None
        }),
        "how the tool ended"
    );
    let transcript = report
        .transcript
        .clone()
        .ok_or("a finished run must report its transcript")?;
    ensure!(
        subject.transcript_is_stored(&transcript).await?,
        "the transcript must be stored in the artifact store"
    );
    Ok(())
}

async fn a_run_reports_what_it_used(subject: &dyn AgentRuntimeSubject) -> Result<(), String> {
    let used = Usage {
        input_tokens: 1200,
        output_tokens: 340,
        cost: CostMicroUsd(25_000),
        requests: 3,
    };
    if !subject
        .arrange(Behavior::Finish {
            output: serde_json::json!({}),
            usage: used,
        })
        .await
    {
        skip!("this subject cannot arrange a finished run");
    }
    let report = run_once(subject, subject.request()).await?;
    ensure_eq!(report.usage, used, "the usage of the run");
    Ok(())
}

async fn denied_tool_calls_are_reported(subject: &dyn AgentRuntimeSubject) -> Result<(), String> {
    let denials = vec![Denial {
        tool: "Bash".to_owned(),
        reason: "the tool is not granted for this stage".to_owned(),
    }];
    if !subject
        .arrange(Behavior::FinishWithDenials(denials.clone()))
        .await
    {
        skip!("this subject cannot arrange denials");
    }
    let report = run_once(subject, subject.request()).await?;
    ensure_eq!(
        report.permission_denials,
        denials,
        "the denials the run reported"
    );
    Ok(())
}

async fn every_failure_keeps_its_own_closed_variant(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    let failures = [
        AgentRunError::ProviderUnavailable,
        AgentRunError::RateLimited {
            retry_after: Some(Duration::from_secs(30)),
        },
        AgentRunError::AuthenticationRequired,
        AgentRunError::Timeout,
        AgentRunError::ProcessFailed(ExitInfo {
            code: Some(2),
            signal: None,
        }),
        AgentRunError::OutputMissing,
    ];
    for failure in failures {
        if !subject
            .arrange(Behavior::Fail {
                error: failure.clone(),
                usage: Usage::default(),
            })
            .await
        {
            skip!("this subject cannot arrange the failure {failure:?}");
        }
        let report = run_once(subject, subject.request()).await?;
        ensure_eq!(
            report.outcome.err(),
            Some(failure.clone()),
            "the error of a run that failed with {failure:?}"
        );
    }
    Ok(())
}

async fn a_failed_run_still_reports_usage_and_transcript(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    let spent = Usage {
        input_tokens: 500,
        output_tokens: 80,
        cost: CostMicroUsd(12_000),
        requests: 2,
    };
    if !subject
        .arrange(Behavior::Fail {
            error: AgentRunError::Timeout,
            usage: spent,
        })
        .await
    {
        skip!("this subject cannot arrange a failing run that used something");
    }
    let report = run_once(subject, subject.request()).await?;
    ensure_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::Timeout),
        "the run failed"
    );
    ensure_eq!(
        report.usage,
        spent,
        "a failed run still reports what it used"
    );
    let transcript = report
        .transcript
        .clone()
        .ok_or("a failed run still reports its transcript")?;
    ensure!(
        subject.transcript_is_stored(&transcript).await?,
        "the transcript of a failed run must be stored"
    );
    Ok(())
}

async fn output_is_bytes_and_a_oversize_output_is_a_failure(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    let big = serde_json::json!({ "padding": "x".repeat(2048) });
    if !subject
        .arrange(Behavior::Finish {
            output: big,
            usage: Usage::default(),
        })
        .await
    {
        skip!("this subject cannot arrange a finished run");
    }
    let mut request = subject.request();
    request.max_output_bytes = 64;
    let report = run_once(subject, request).await?;
    ensure_eq!(
        report.outcome.err(),
        Some(AgentRunError::OutputTooLarge),
        "an output larger than max_output_bytes"
    );
    // An output under the limit comes back as the bytes the tool wrote.
    let small = serde_json::json!({ "ok": true });
    subject
        .arrange(Behavior::Finish {
            output: small.clone(),
            usage: Usage::default(),
        })
        .await;
    let mut request = subject.request();
    request.max_output_bytes = 64;
    let report = run_once(subject, request).await?;
    let raw = report.outcome.ctx("an output within the limit")?;
    let parsed: serde_json::Value = serde_json::from_slice(raw.as_bytes()).ctx("JSON bytes")?;
    ensure_eq!(parsed, small, "the bytes parse back to the output");
    Ok(())
}

async fn a_cancel_that_is_already_set_stops_the_run(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    if !subject.arrange(Behavior::RunUntilCancelled).await {
        skip!("this subject cannot arrange a long run");
    }
    let mut session = subject.session().await?;
    let cancel = FakeCancel::new();
    cancel.cancel();
    let report = tokio::time::timeout(
        Duration::from_secs(10),
        subject
            .runtime()
            .run(session.as_mut(), subject.request(), &cancel),
    )
    .await
    .map_err(|_| {
        "a run started with the cancel already set was still going after 10 seconds".to_owned()
    })?;
    ensure_eq!(
        report.outcome.err(),
        Some(AgentRunError::Cancelled),
        "a run started after the cancel"
    );
    Ok(())
}

async fn a_cancel_during_a_run_stops_it_promptly(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    if !subject.arrange(Behavior::RunUntilCancelled).await {
        skip!("this subject cannot arrange a long run");
    }
    let mut session = subject.session().await?;
    let cancel = FakeCancel::new();
    let request = subject.request();
    let run = tokio::time::timeout(
        Duration::from_secs(10),
        subject.runtime().run(session.as_mut(), request, &cancel),
    );
    let trigger = async {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(run, trigger);
    match outcome {
        Err(_) => Err("the run was still going 10 seconds after the cancel".to_owned()),
        Ok(report) => match report.outcome {
            Err(AgentRunError::Cancelled) => Ok(()),
            Err(other) => Err(format!(
                "a cancelled run: expected Cancelled but found {other:?}"
            )),
            Ok(_) => Err("a cancelled run returned an output".to_owned()),
        },
    }
}

async fn a_run_that_needs_a_missing_capability_is_refused(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    if !subject.remove_capability(Capability::SkillInvocation).await {
        skip!("this subject cannot remove a capability");
    }
    let mut session = subject.session().await?;
    // The specification stage needs skills. The probe now says the tool cannot invoke them.
    let probed = subject
        .runtime()
        .probe(session.as_mut())
        .await
        .ctx("probe")?;
    ensure!(
        !probed.supports(Capability::SkillInvocation),
        "the probe must report the missing capability, not guess it is there"
    );
    let mut request = subject.request();
    request.flag_set = factory_ports::agent::FlagSet::for_stage(StageKind::Specification);
    let cancel = FakeCancel::new();
    let report = subject
        .runtime()
        .run(session.as_mut(), request, &cancel)
        .await;
    ensure_eq!(
        report.outcome.err(),
        Some(AgentRunError::CapabilityMissing(
            Capability::SkillInvocation
        )),
        "a specification run on a tool that cannot invoke skills"
    );
    Ok(())
}

async fn a_run_over_its_cost_limit_is_refused(
    subject: &dyn AgentRuntimeSubject,
) -> Result<(), String> {
    let request = subject.request();
    let limit_micro = (request.limits.max_cost_usd.as_f64() * 1_000_000.0).ceil();
    let over = CostMicroUsd(limit_micro as u64 + 1_000_000);
    if !subject
        .arrange(Behavior::Finish {
            output: serde_json::json!({}),
            usage: Usage {
                cost: over,
                ..Usage::default()
            },
        })
        .await
    {
        skip!("this subject cannot arrange an expensive run");
    }
    let report = run_once(subject, request).await?;
    ensure_eq!(
        report.outcome.err(),
        Some(AgentRunError::BudgetRefused),
        "a run that spent more than its cost limit"
    );
    Ok(())
}
