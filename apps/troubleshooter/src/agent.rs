//! The agent run: a seam ([`AgentRunner`]) and the real one ([`SandboxAgentRunner`]).
//!
//! The real runner does what the worker does for a stage's agent, outside any job (ADR 0021,
//! Decision 1): a broker token for the `troubleshooter` role with the run's ceiling, the
//! troubleshooter sandbox (the agent image, an empty read-only workspace, the broker token and
//! the gateway's run token), Claude Code with [`FlagSet::Troubleshooting`] and the gateway tools,
//! then the sandbox is removed and the broker token revoked whatever happened.
//!
//! # Identifiers a run borrows from a job
//!
//! The sandbox spec, the broker token and the agent request are typed with a `JobId` and an
//! `AttemptId`, because every other agent runs in a job. A troubleshooting run has neither, so it
//! gets both derived from its run id: the first 16 bytes of `SHA-256("troubleshooter-job:" +
//! run id)` and of `SHA-256("troubleshooter-attempt:" + run id)`, with the UUID version 8 and
//! variant bits set ([`derived_ids`]). They are stable (the same run always names the same
//! sandbox), never collide with the random version 4 ids of jobs, and never enter `jobs` or
//! `attempts`: they only name containers, labels and the token. The broker request also needs a
//! stage; it gets `INTAKE`, which the broker uses as a label only, because the ceiling, the
//! models and the request caps are the troubleshooter role's (`operations_roles` of
//! `policies/model_routing.yaml`).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::redaction::RegisteringBroker;
use factory_composition::sandbox_specs::{PolicySpecs, broker_endpoint, gateway_endpoint};
use factory_domain::contracts::{AgentManifest, VersionedRef};
use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::troubleshooting::TroubleshootingRunId;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::{
    AgentRunRequest, AgentRuntime, AssembledPrompt, CostMicroUsd, FlagSet, JobTokenRef,
    JobTokenRequest, McpGateway, McpToolName, ModelBroker, ModelSelection, RequestCaps, Usage,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{McpRunTokenSecret, SandboxProvider, TeardownReason};

/// One agent run to make.
pub struct AgentJob {
    /// The run.
    pub run_id: TroubleshootingRunId,
    /// The tenant the run writes for.
    pub tenant: TenantId,
    /// The assembled prompt.
    pub prompt: AssembledPrompt,
    /// The gateway's bearer token for this run, for the sandbox's token file only.
    pub gateway_token: McpRunTokenSecret,
    /// The gateway tools the run may call.
    pub tools: Vec<McpToolName>,
    /// The most the run may spend.
    pub ceiling: CostMicroUsd,
}

impl std::fmt::Debug for AgentJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentJob")
            .field("run_id", &self.run_id)
            .field("tools", &self.tools.len())
            .field("ceiling", &self.ceiling)
            .finish_non_exhaustive()
    }
}

/// What an agent run left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentResult {
    /// The report bytes, unvalidated, or why there are none.
    pub output: Result<Vec<u8>, String>,
    /// What the run spent, as metered.
    pub usage: Usage,
}

/// Runs the troubleshooter agent once.
#[async_trait]
pub trait AgentRunner: Send + Sync {
    /// Whether this runner starts the real tool in a real sandbox.
    fn fidelity(&self) -> Fidelity;

    /// Runs the agent. Always returns: a failure is in `output`.
    async fn run(&self, job: AgentJob) -> AgentResult;
}

/// The job and attempt ids a run borrows (module notes).
#[must_use]
pub fn derived_ids(run: &TroubleshootingRunId) -> (JobId, AttemptId) {
    let uuid = |purpose: &str| {
        let digest = Sha256Digest::of(format!("{purpose}:{}", run.as_str()).as_bytes());
        let hex = &digest.as_str()["sha256:".len()..];
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap_or(0);
        }
        bytes[6] = (bytes[6] & 0x0f) | 0x80; // version 8: a custom layout
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // the RFC 9562 variant
        uuid::Uuid::from_bytes(bytes)
    };
    (
        JobId::from_uuid(uuid("troubleshooter-job")),
        AttemptId::from_uuid(uuid("troubleshooter-attempt")),
    )
}

/// A cancel signal that is never raised: the run's wall clock bounds it.
struct NotCancelled;

#[async_trait]
impl CancelSignal for NotCancelled {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn is_cancelled(&self) -> bool {
        false
    }

    async fn cancelled(&self) {
        std::future::pending::<()>().await;
    }
}

/// The real agent run: broker token, troubleshooter sandbox, Claude Code.
pub struct SandboxAgentRunner {
    /// The broker, which keeps every token's secret for the sandbox spec.
    pub broker: Arc<RegisteringBroker>,
    /// The sandbox specs from the security policy and the image catalog.
    pub specs: Arc<PolicySpecs>,
    /// The sandbox provider.
    pub sandbox: Arc<dyn SandboxProvider>,
    /// Claude Code, bound to the tenant.
    pub runtime: Arc<dyn AgentRuntime>,
    /// The troubleshooter's manifest.
    pub manifest: AgentManifest,
    /// The model the role starts with.
    pub model: ModelSelection,
    /// The role's caps on one request.
    pub per_request: Option<RequestCaps>,
    /// The most report bytes read.
    pub max_output_bytes: u64,
}

#[async_trait]
impl AgentRunner for SandboxAgentRunner {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn run(&self, job: AgentJob) -> AgentResult {
        let (job_id, attempt) = derived_ids(&job.run_id);
        let wall = Duration::from_secs(
            u64::try_from(self.manifest.resource_limits.max_wall_time_seconds.get())
                .unwrap_or(900)
                .saturating_add(60),
        );
        let failed = |why: &str| AgentResult {
            output: Err(why.to_owned()),
            usage: Usage::default(),
        };
        let token = match self
            .broker
            .issue(JobTokenRequest {
                tenant: job.tenant,
                job: job_id,
                stage: StageKind::Intake,
                cost_ceiling: job.ceiling,
                allowed_models: vec![self.model.clone()],
                ttl: wall,
                per_request: self.per_request,
            })
            .await
        {
            Ok(token) => token,
            Err(_) => return failed("the broker refused a token for the run"),
        };
        let token_ref = JobTokenRef { id: token.id };
        let outcome = self.in_sandbox(&job, job_id, attempt, token_ref).await;
        let metered = self
            .broker
            .usage(&token.id)
            .await
            .map(|usage| usage.usage)
            .unwrap_or_default();
        let _ = self.broker.revoke(&token.id).await;
        match outcome {
            Ok((output, reported)) => AgentResult {
                output,
                usage: if metered.cost >= reported.cost {
                    metered
                } else {
                    reported
                },
            },
            Err(why) => AgentResult {
                output: Err(why),
                usage: metered,
            },
        }
    }
}

type SandboxOutcome = Result<(Result<Vec<u8>, String>, Usage), String>;

impl SandboxAgentRunner {
    async fn in_sandbox(
        &self,
        job: &AgentJob,
        job_id: JobId,
        attempt: AttemptId,
        token: JobTokenRef,
    ) -> SandboxOutcome {
        let spec = self
            .specs
            .troubleshooter_spec(job_id, attempt, token, job.gateway_token.clone())
            .map_err(|_| "the troubleshooter sandbox cannot be specified".to_owned())?;
        let cancel = NotCancelled;
        let mut session = self
            .sandbox
            .create_verified(spec, &cancel)
            .await
            .map_err(|error| format!("the sandbox did not start: {error}"))?;
        let request = AgentRunRequest {
            attempt,
            agent: VersionedRef {
                id: self.manifest.id.clone(),
                version: self.manifest.version.clone(),
            },
            prompt: job.prompt.clone(),
            output_schema: self.manifest.outputs_schema.clone(),
            max_output_bytes: self.max_output_bytes,
            broker: broker_endpoint(),
            job_token: token,
            tools: self.manifest.allowed_tools.iter().cloned().collect(),
            limits: self.manifest.resource_limits.clone(),
            model: self.model.clone(),
            flag_set: FlagSet::Troubleshooting,
            mcp_gateway: Some(McpGateway {
                url: gateway_endpoint(),
                tools: job.tools.clone(),
            }),
        };
        let report = self.runtime.run(session.as_mut(), request, &cancel).await;
        let reason = if report.outcome.is_ok() {
            TeardownReason::Completed
        } else {
            TeardownReason::Failed
        };
        let _ = session.stop_and_remove(reason).await;
        let output = report
            .outcome
            .map(|raw| raw.as_bytes().to_vec())
            .map_err(|error| error.to_string());
        Ok((output, report.usage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_borrows_stable_version_8_ids_that_differ_from_each_other() {
        let run = TroubleshootingRunId::parse("tr-20261120T091500Z-0a1b2c3d").expect("an id");
        let (job, attempt) = derived_ids(&run);
        assert_eq!(derived_ids(&run), (job, attempt), "stable");
        assert_ne!(job.as_uuid(), attempt.as_uuid());
        assert_eq!(job.as_uuid().get_version_num(), 8);
        let other = TroubleshootingRunId::parse("tr-20261120T091500Z-0a1b2c3e").expect("an id");
        assert_ne!(derived_ids(&other).0, job);
    }
}
