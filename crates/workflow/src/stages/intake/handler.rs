//! The `INTAKE` stage handler.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the original request and check that its bytes still hash to the hash the store holds.
//! 2. Refuse a request that was edited and that no person has confirmed since (`S22`). The engine
//!    already holds such a run before any attempt starts; this is the second wall.
//! 3. Authorize the person who applied the label, by numeric id (`authorize`). A refusal ends the
//!    stage with `PolicyDenied`. No sandbox is made and no agent runs.
//! 4. Store the original bytes apart, under their hash.
//! 5. Assemble the prompt. The issue text goes in as untrusted data and nowhere else.
//! 6. Run the classifier in a verified sandbox, and read its answer through the schema check and
//!    through `Classification::read`. An answer that fails either is `InvalidOutput`.
//! 7. Decide the outcome (`decide`) and return the normalized request, the decision and the
//!    stored original.
//!
//! `evaluate` then reads the stored documents back and produces the evidence: whether the original
//! is still the one the request had, what the outcome was, and the readability report of the
//! title and the description.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::StageContract;
use factory_domain::ids::GateReportId;
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::RepoKind;
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::{AgentRunRequest, BrokerEndpoint, Capability, RoutingNeed};
use factory_ports::githost::{GitScope, IssueRef, IssueSource, LabelApplication};
use factory_ports::registry::VersionReq;
use factory_ports::sandbox::TeardownReason;
use serde_json::Value;

use super::authorize::{Authorization, authorize};
use super::classify::{Classification, IntakeRules, ReadProblem, decide};
use super::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec, Executor,
    GateDefinition, GateFacts, GateSubject, gate_report, stage_contract,
};
use super::normalize::{
    ClassifierRef, OriginalRef, decision_document, description_from, normalized_request, title_from,
};
use super::seams::{
    AgentOutputCheck, AgentSandboxSpecs, AllowlistSource, CapabilityProbes, FetchedRequest,
    RequestSnapshot, RequestSource, SeamError,
};
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::gates::framework::GateDecision;
use crate::gates::readability::{
    Artifact, GATE_ID as READABILITY_GATE, Options, ReadabilityGate, ReportContext, ReviewerPolicy,
};
use crate::handlers::{
    ContractContext, GateContext, NamedArtifact, SandboxReady, StageContext, StageError,
    StageHandler, StageOutput,
};
use crate::prompts::{Assembler, AssemblyRequest, ContentClass, Input, Limits, Scope, Source};

/// The gate that reports whether the original request is still the one the stage read.
pub const ORIGINAL_GATE: &str = "intake-original-preserved";
/// The gate that reports the outcome of intake.
pub const OUTCOME_GATE: &str = "intake-outcome";

const ORIGINAL_GATE_TEXT: &str = "intake-original-preserved 1.0.0: the stored original request hashes to the hash recorded for it, and the normalized request points at that hash.";
const OUTCOME_GATE_TEXT: &str = "intake-outcome 1.0.0: the request is accepted, or the stage asks one question, or the request is declined or split with a reason a person can read.";

/// The most bytes of one human answer that go into a prompt.
const ANSWER_MAX_BYTES: usize = 8 * 1024;

/// How long after the label was applied the issue may still be recorded as changed, in seconds.
/// Applying a label is itself a change to the issue, and the host stamps both in the same second or
/// the next, so the two times are not compared to the instant.
const LABEL_SKEW_SECONDS: u64 = 5;

/// What the handler is configured with. All of it comes from protected configuration.
#[derive(Debug, Clone)]
pub struct IntakeConfig {
    /// The label that asks the factory to work, such as `factory`.
    pub label: String,
    /// The agent that classifies.
    pub agent: Slug,
    /// How a classification becomes an outcome.
    pub rules: IntakeRules,
    /// The commit of the factory's gate definitions, named in every report.
    pub definition_commit: GitSha,
    /// Where the sandbox reaches the model broker.
    pub broker: BrokerEndpoint,
    /// The most bytes of final output the runtime reads.
    pub max_output_bytes: u64,
}

/// The `INTAKE` handler. See the module notes for what it does.
pub struct IntakeHandler {
    config: IntakeConfig,
    requests: Arc<dyn RequestSource>,
    issues: Arc<dyn IssueSource>,
    allowlists: Arc<dyn AllowlistSource>,
    policy: Arc<PolicyEngine>,
    redactor: Arc<Redactor>,
    schemas: Arc<dyn AgentOutputCheck>,
    sandboxes: Arc<dyn AgentSandboxSpecs>,
    probes: Arc<dyn CapabilityProbes>,
    readability: ReadabilityGate,
}

/// The collaborators of the handler, in one place so a composition root names each.
pub struct IntakeDeps {
    /// The stored original request.
    pub requests: Arc<dyn RequestSource>,
    /// The code host, read-only.
    pub issues: Arc<dyn IssueSource>,
    /// The named allowlist.
    pub allowlists: Arc<dyn AllowlistSource>,
    /// The policy evaluators.
    pub policy: Arc<PolicyEngine>,
    /// The redactor of the job.
    pub redactor: Arc<Redactor>,
    /// The check of an agent's output against its own schema.
    pub schemas: Arc<dyn AgentOutputCheck>,
    /// The sandbox spec factory.
    pub sandboxes: Arc<dyn AgentSandboxSpecs>,
    /// The runtime probes.
    pub probes: Arc<dyn CapabilityProbes>,
}

impl IntakeHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: IntakeConfig, deps: IntakeDeps) -> Self {
        Self {
            config,
            requests: deps.requests,
            issues: deps.issues,
            allowlists: deps.allowlists,
            policy: deps.policy,
            redactor: deps.redactor,
            schemas: deps.schemas,
            sandboxes: deps.sandboxes,
            probes: deps.probes,
            readability: ReadabilityGate::new(Options::new()),
        }
    }

    /// Whether the person who applied the label may ask, by numeric id, read from the code host
    /// and the allowlist now. Returns the application of the label too, for its time.
    async fn authorize_label(
        &self,
        identity: &crate::handlers::RunIdentity,
        issue: &IssueRef,
        now: Timestamp,
    ) -> Result<(Authorization, Option<LabelApplication>), StageError> {
        let allowlist = self
            .allowlists
            .current(identity.tenant)
            .await
            .map_err(|_| {
                StageError::Environment(
                    factory_domain::machines::guards::EnvironmentCause::PolicyUnloadable,
                )
            })?;
        let application = self
            .issues
            .label_application(&self.scope(identity, issue), issue, &self.config.label)
            .await
            .map_err(|_| StageError::Tool)?;
        let repository = format!("{}/{}", issue.repo.owner(), issue.repo.name());
        let decision = authorize(
            &self.policy.authority,
            &allowlist,
            identity.tenant,
            &repository,
            application
                .as_ref()
                .map(|found| (found.actor.id, found.actor.login.as_str())),
            &now,
        );
        Ok((decision, application))
    }

    fn scope(&self, ctx_identity: &crate::handlers::RunIdentity, issue: &IssueRef) -> GitScope {
        GitScope {
            tenant: ctx_identity.tenant,
            job: ctx_identity.job,
            stage: StageKind::Intake,
            repo: issue.repo.clone(),
        }
    }
}

fn seam(error: SeamError) -> StageError {
    match error {
        SeamError::Unavailable => StageError::Tool,
        SeamError::NotFound => StageError::Internal,
    }
}

fn definition(id: &'static str, text: &'static str, commit: &GitSha) -> GateDefinition {
    GateDefinition {
        id,
        version: "1.0.0",
        text,
        commit: commit.clone(),
    }
}

#[async_trait]
impl StageHandler for IntakeHandler {
    fn fidelity(&self) -> Fidelity {
        // The handler holds no state of its own, and its collaborators say what they are.
        if [
            self.requests.fidelity(),
            self.issues.fidelity(),
            self.allowlists.fidelity(),
            self.schemas.fidelity(),
        ]
        .contains(&Fidelity::Fake)
        {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }

    fn kind(&self) -> StageKind {
        StageKind::Intake
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        Some(RoutingNeed {
            stage: ctx.identity.kind,
            tier: factory_domain::contracts::agent_manifest::RecommendedTier::Standard,
            required: vec![Capability::JsonSchemaOutput],
            risk: factory_domain::vocabulary::RiskTier::Low,
            exclude: Vec::new(),
            probed: self.probes.probed(),
        })
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        // No recorded request and no issue to fetch one from, no contract: the claim is deferred
        // and nothing starts. A job that a webhook created has no text yet and names its issue
        // instead: the stage fetches the text when it runs, so the input is named by the issue.
        let (input_hash, input_description) = match self.requests.recorded(ctx.identity.job) {
            Some(recorded) => (
                recorded.sha256,
                "The request exactly as it was received, kept as untrusted text.",
            ),
            None => {
                let issue = self
                    .requests
                    .awaiting(ctx.identity.job)
                    .ok_or(StageError::Internal)?;
                (
                    Sha256Digest::of(
                        format!(
                            "github-issue:{}/{}#{}",
                            issue.repo.owner(),
                            issue.repo.name(),
                            issue.number
                        )
                        .as_bytes(),
                    ),
                    "The issue the job was created from, kept as untrusted text. The text is fetched when the stage runs and stored as revision 1; until then this input is named by the hash of the issue reference.",
                )
            }
        };
        stage_contract(&ContractSpec {
            kind: StageKind::Intake,
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            mode: ctx.mode,
            created_at: ctx.now,
            contract_id: "stage-contract.intake",
            title: "Read, authorize and classify the request",
            purpose: "Check that the person who asked may ask, keep the original text apart, and turn the request into a short plain-English request that later stages can read.",
            problem: "A request arrives as free text that anyone can edit. The factory must know who asked, must keep the original words unchanged, and must decide whether to go on, ask one question, decline or split the request, before any other stage reads it.",
            inputs: vec![ContractInput {
                name: "original-request",
                description: input_description,
                sha256: input_hash,
                media_type: "text/plain",
                source: "untrusted_external",
                produced_by: None,
                commit_sha: None,
                retrieved_at: ctx.now,
                trust: "untrusted",
            }],
            preconditions: vec![(
                "requester-authorized",
                "The person who applied the label is on the named allowlist, found by numeric id.",
                "policy_allows",
            )],
            method: (
                "Authorize by numeric id, then classify with the intake agent",
                "The allowlist decides who may ask. The agent only reads text and returns a typed classification, which the stage checks twice before it acts.",
                "Let the agent decide who may ask",
                "An agent reads text that anyone can write, so it can never be the authority on who may ask.",
            ),
            agent: (self.config.agent.as_str().to_owned(), "1.0.0"),
            granted_tools: vec!["report.submit"],
            shell: "none",
            placement: Some("sandbox"),
            deliverables: vec![
                ContractDeliverable {
                    name: "normalized-request",
                    description: "The title and description in plain English, with the kind of work, the domain tags and a risk hint.",
                    media_type: "application/json",
                    required: true,
                },
                ContractDeliverable {
                    name: "intake-decision",
                    description: "Whether the request is accepted, asks one question, is declined or is split, and why.",
                    media_type: "application/json",
                    required: true,
                },
                ContractDeliverable {
                    name: "original-request",
                    description: "The original text, stored apart and unchanged.",
                    media_type: "text/plain",
                    required: true,
                },
            ],
            criteria: vec![
                ContractCriterion {
                    id: "original-kept-unchanged",
                    description: "The original text is stored apart, and the request still has the hash it had.",
                    gate: ORIGINAL_GATE,
                },
                ContractCriterion {
                    id: "outcome-recorded",
                    description: "The outcome is one of accept, clarify, decline and split, with a reason.",
                    gate: OUTCOME_GATE,
                },
                ContractCriterion {
                    id: "plain-english",
                    description: "The title and the description pass the readability gate.",
                    gate: READABILITY_GATE,
                },
            ],
            gates: vec![ORIGINAL_GATE, OUTCOME_GATE, READABILITY_GATE],
            budget: ContractBudget {
                wall_time_seconds: 300,
                max_tokens: 20_000,
                max_cost_usd: 0.25,
                attempt_timeout_seconds: 240,
                max_attempts: 3,
            },
            rollback: "Nothing outside the job is changed. Discard the normalized request and the decision.",
            span_name: "stage.intake",
        })
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let identity = ctx.identity;
        let ports = ctx.ports;

        // 1. The original request, and its integrity. A job that a webhook created has none yet:
        // the stage fetches the issue live and stores it as revision 1.
        let snapshot = match self.requests.latest(identity.tenant, identity.job).await {
            Ok(snapshot) => snapshot,
            Err(SeamError::NotFound) => {
                match self.first_request(&identity, ports.clock.now()).await {
                    Ok((snapshot, replaced)) => {
                        // The text a person pasted into the issue may hold a secret (finding F-6
                        // of the cross-cutting security tests). It was replaced before it was
                        // stored, and the replacement is on the record.
                        if replaced > 0 {
                            ctx.note_audit(AuditAction::new(
                                AuditKind::SecretRedactedOrBlocked,
                                AuditDecision::Noted,
                            ));
                        }
                        snapshot
                    }
                    Err(StageError::PolicyDenied) => {
                        ctx.note_audit(AuditAction::new(
                            AuditKind::AuthorizationDecision,
                            AuditDecision::Denied,
                        ));
                        return Err(StageError::PolicyDenied);
                    }
                    Err(other) => return Err(other),
                }
            }
            Err(other) => return Err(seam(other)),
        };
        if Sha256Digest::of(snapshot.text.as_bytes()) != snapshot.sha256 {
            return Err(StageError::Internal);
        }

        // 2. An edited request that no person has confirmed does not reach an agent.
        if snapshot.revision > 1 && ctx.human_inputs.is_empty() {
            ctx.note_audit(AuditAction::new(
                AuditKind::AuthorizationDecision,
                AuditDecision::Denied,
            ));
            return Err(StageError::PolicyDenied);
        }

        // 3. Who asked, by numeric id.
        let now = ports.clock.now();
        let (decision, application) = self
            .authorize_label(&identity, &snapshot.issue, now)
            .await?;
        let labelled_by = application.as_ref().map(|found| &found.actor);
        if !decision.is_authorized() {
            ctx.note_audit(AuditAction::new(
                AuditKind::AuthorizationDecision,
                AuditDecision::Denied,
            ));
            return Err(StageError::PolicyDenied);
        }
        ctx.note_audit(AuditAction::new(
            AuditKind::AuthorizationDecision,
            AuditDecision::Granted,
        ));

        // 4. The original, stored apart under its hash.
        let original = ports
            .artifacts
            .put(
                snapshot.text.clone().into_bytes(),
                MediaType::parse("text/plain").map_err(|_| StageError::Internal)?,
            )
            .await
            .map_err(|_| StageError::Tool)?;
        if original.sha256 != snapshot.sha256 {
            return Err(StageError::Internal);
        }

        // 5. The prompt. The issue text is untrusted data.
        let manifest = ports
            .registry
            .manifest(&self.config.agent, &VersionReq::Any)
            .map_err(|_| StageError::Internal)?;
        let prompt = ports
            .registry
            .prompt(&manifest)
            .map_err(|_| StageError::Internal)?;
        let request_text = self.request_with_answers(ctx, &snapshot).await?;
        let assembler = Assembler::new(&self.redactor, &self.policy.paths, Limits::default());
        let assembled = assembler
            .assemble(AssemblyRequest::new(
                &manifest,
                &prompt,
                Scope::new(identity.tenant, RepoKind::Target),
                vec![
                    Input::untrusted(
                        "request",
                        ContentClass::IssueText,
                        Source::Issue {
                            number: snapshot.issue.number,
                        },
                        identity.tenant,
                        request_text.into_bytes(),
                    )
                    .fetched_at(now),
                ],
            ))
            .map_err(|_| StageError::Internal)?;

        // 6. The classifier, in a verified sandbox.
        let token = ctx.job_token.ok_or(StageError::Internal)?;
        let need = RoutingNeed {
            stage: StageKind::Intake,
            tier: factory_domain::contracts::agent_manifest::RecommendedTier::Standard,
            required: vec![Capability::JsonSchemaOutput],
            risk: factory_domain::vocabulary::RiskTier::Low,
            exclude: Vec::new(),
            probed: self.probes.probed(),
        };
        let route = ports.router.route(&need).map_err(|_| {
            StageError::Blocked(
                factory_domain::contracts::gate_report::BlockedCode::ToolUnavailable,
            )
        })?;
        let spec = self
            .sandboxes
            .agent_spec(identity.job, ctx.attempt, token)
            .map_err(|_| {
                StageError::Environment(
                    factory_domain::machines::guards::EnvironmentCause::PolicyUnloadable,
                )
            })?;
        let mut session = ports.sandbox.create_verified(spec, ctx.cancel).await?;
        let capabilities = ports.runtime.probe(&mut *session).await;
        let capabilities = match capabilities {
            Ok(found) => found,
            Err(error) => {
                let _ = session.stop_and_remove(TeardownReason::Failed).await;
                return Err(error.into());
            }
        };
        ctx.report_sandbox_ready(SandboxReady {
            posture_verified: true,
            tool_grants_recorded: true,
            probe_satisfies_stage: capabilities.supports(Capability::JsonSchemaOutput),
        });
        let request = AgentRunRequest {
            attempt: ctx.attempt,
            agent: factory_domain::contracts::VersionedRef {
                id: manifest.id.clone(),
                version: manifest.version.clone(),
            },
            prompt: assembled.to_port_prompt(),
            output_schema: manifest.outputs_schema.clone(),
            max_output_bytes: self.config.max_output_bytes,
            broker: self.config.broker.clone(),
            job_token: token,
            tools: manifest.allowed_tools.as_slice().to_vec(),
            limits: manifest.resource_limits.clone(),
            model: route.model,
            flag_set: route.flag_set,
        };
        let report = ports.runtime.run(&mut *session, request, ctx.cancel).await;
        let _ = session
            .stop_and_remove(if report.outcome.is_ok() {
                TeardownReason::Completed
            } else {
                TeardownReason::Failed
            })
            .await;
        let usage = report.usage;
        let denials = report.permission_denials.clone();
        let output = match &report.outcome {
            Ok(output) => output.clone(),
            Err(error) => {
                ctx.note_failed_run(&report);
                return Err(error.clone().into());
            }
        };

        // The answer, checked twice.
        let validated = self
            .schemas
            .check(&manifest.outputs_schema, output.as_bytes())
            .map_err(|_| StageError::InvalidOutput)?;
        let classification = Classification::read(&validated.value)
            .map_err(|_: ReadProblem| StageError::InvalidOutput)?;
        let outcome = decide(&classification, &self.config.rules)
            .map_err(|_: ReadProblem| StageError::InvalidOutput)?;

        // 7. The documents.
        let title = title_from(&classification.summary);
        let description = description_from(&classification);
        let mut normalized = normalized_request(
            &classification,
            &title,
            &description,
            &OriginalRef {
                revision: snapshot.revision,
                sha256: &snapshot.sha256,
                artifact: &original,
            },
            &ClassifierRef {
                agent: manifest.id.as_str(),
                version: manifest.version.to_string(),
                output_sha256: &validated.sha256,
            },
        );
        if let Some(map) = normalized.as_object_mut() {
            map.insert(
                "prompt_signals".into(),
                serde_json::json!(
                    assembled
                        .manifest()
                        .signals
                        .iter()
                        .map(|signal| signal.name())
                        .collect::<Vec<_>>()
                ),
            );
            map.insert(
                "authorization".into(),
                serde_json::json!({
                    "allowlist_version": match &decision {
                        Authorization::Authorized { allowlist_version, .. }
                        | Authorization::Denied { allowlist_version, .. } => allowlist_version,
                    },
                    "actor_id": labelled_by.map(|actor| actor.id),
                }),
            );
        }
        // The documents are stored here, as artifacts the contract declares. The engine indexes a
        // declared artifact for the tenant before the gate runs, so `evaluate` can read it back;
        // a document that the engine stores itself is indexed only after the gate.
        let json_type = MediaType::parse("application/json").map_err(|_| StageError::Internal)?;
        let mut stored = Vec::with_capacity(3);
        for (name, value) in [
            ("normalized-request", normalized),
            (
                "intake-decision",
                decision_document(&outcome, &snapshot.sha256),
            ),
        ] {
            let bytes = serde_json::to_vec(&value).map_err(|_| StageError::Internal)?;
            let artifact = ports
                .artifacts
                .put(bytes, json_type.clone())
                .await
                .map_err(|_| StageError::Tool)?;
            stored.push(NamedArtifact {
                name: slug(name)?,
                artifact,
            });
        }
        stored.push(NamedArtifact {
            name: slug("original-request")?,
            artifact: original,
        });
        Ok(StageOutput {
            documents: Vec::new(),
            artifacts: stored,
            usage,
            permission_denials: denials,
            needs_human: None,
        })
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let scope = TenantScope::new(ctx.identity.tenant);
        let read = |name: &str| {
            ctx.outputs
                .iter()
                .find(|output| output.name.as_str() == name)
        };
        let (Some(normalized), Some(decision), Some(original)) = (
            read("normalized-request"),
            read("intake-decision"),
            read("original-request"),
        ) else {
            return Err(StageError::InvalidOutput);
        };
        let fetch = |named: &NamedArtifact| {
            let artifacts = ctx.ports.artifacts;
            let reference = named.artifact.clone();
            async move { artifacts.get(&scope, &reference).await }
        };
        let normalized_bytes = fetch(normalized).await.map_err(|_| StageError::Tool)?;
        let decision_bytes = fetch(decision).await.map_err(|_| StageError::Tool)?;
        let original_bytes = fetch(original).await.map_err(|_| StageError::Tool)?;
        let normalized: Value =
            serde_json::from_slice(&normalized_bytes).map_err(|_| StageError::InvalidOutput)?;
        let decision: Value =
            serde_json::from_slice(&decision_bytes).map_err(|_| StageError::InvalidOutput)?;

        let now = ctx.ports.clock.now();
        let subject = |ctx: &GateContext<'_>| GateSubject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
            report_id: GateReportId::from_uuid(ctx.ports.ids.new_uuid()),
            started_at: now,
            finished_at: ctx.ports.clock.now(),
        };

        // Gate: the original is still the original.
        let recorded = normalized["original"]["sha256"]
            .as_str()
            .unwrap_or_default();
        let stored = Sha256Digest::of(&original_bytes);
        let latest = self
            .requests
            .latest(ctx.identity.tenant, ctx.identity.job)
            .await;
        let (original_outcome, original_reason, failures, blocked) = match &latest {
            Err(_) => (
                "BLOCKED",
                "The stored request could not be read, so the stage cannot show that the original text is unchanged."
                    .to_owned(),
                Vec::new(),
                Some(("dependency_unavailable", "the stored original request".to_owned())),
            ),
            Ok(latest) => {
                let mut failures = Vec::new();
                if stored.as_str() != recorded {
                    failures.push((
                        "stored-original-differs".to_owned(),
                        "The stored original text does not have the hash that the normalized request names."
                            .to_owned(),
                    ));
                }
                if latest.sha256.as_str() != recorded {
                    failures.push((
                        "request-changed".to_owned(),
                        "The request changed while the stage was running, so the normalized request describes text that is no longer the request."
                            .to_owned(),
                    ));
                }
                if failures.is_empty() {
                    (
                        "PASSED",
                        "The original text is stored apart, and its hash is the one the request still has."
                            .to_owned(),
                        failures,
                        None,
                    )
                } else {
                    (
                        "FAILED",
                        "The original text and the normalized request do not belong together."
                            .to_owned(),
                        failures,
                        None,
                    )
                }
            }
        };
        let original_report = gate_report(
            &subject(ctx),
            &GateFacts {
                definition: definition(
                    ORIGINAL_GATE,
                    ORIGINAL_GATE_TEXT,
                    &self.config.definition_commit,
                ),
                outcome: original_outcome,
                title: "The original request is kept unchanged".to_owned(),
                reason: original_reason,
                failures,
                blocked,
                fidelity: "real",
                executor: Executor::InProcess,
                commands: Vec::new(),
                tools: vec![("factory-intake".to_owned(), "1.0.0".to_owned())],
                evidence: vec![format!("stored={stored}"), format!("recorded={recorded}")],
            },
        )?;

        // Gate: the outcome.
        let word = decision["decision"].as_str().unwrap_or_default().to_owned();
        let explanation = decision["explanation"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let stops = word == "decline" || word == "split";
        let outcome_report = gate_report(
            &subject(ctx),
            &GateFacts {
                definition: definition(
                    OUTCOME_GATE,
                    OUTCOME_GATE_TEXT,
                    &self.config.definition_commit,
                ),
                outcome: if stops { "FAILED" } else { "PASSED" },
                title: match word.as_str() {
                    "accept" => "The request is accepted".to_owned(),
                    "clarify" => "The request needs one answer".to_owned(),
                    "decline" => "The request is declined".to_owned(),
                    "split" => "The request must be split".to_owned(),
                    _ => "The outcome of intake is not one the factory knows".to_owned(),
                },
                reason: if explanation.is_empty() {
                    "The decision has no explanation.".to_owned()
                } else {
                    explanation
                },
                failures: if stops {
                    vec![(
                        word.clone(),
                        "The request does not go on without an operator.".to_owned(),
                    )]
                } else {
                    Vec::new()
                },
                blocked: None,
                fidelity: "real",
                executor: Executor::InProcess,
                commands: Vec::new(),
                tools: vec![("factory-intake".to_owned(), "1.0.0".to_owned())],
                evidence: vec![format!("decision={word}")],
            },
        )?;

        // Gate: plain English.
        let title = normalized["title"].as_str().unwrap_or_default();
        let description = normalized["description"].as_str().unwrap_or_default();
        let readability = self
            .readability
            .evaluate(
                &[Artifact::request(title, description)],
                &ReportContext {
                    gate_report_id: GateReportId::from_uuid(ctx.ports.ids.new_uuid()),
                    job_id: ctx.identity.job,
                    stage_run_id: ctx.identity.stage_run,
                    attempt_id: Some(ctx.attempt),
                    execution_mode: ctx.mode,
                    definition_source:
                        factory_domain::contracts::gate_report::DefinitionSource::CentralConfig,
                    definition_commit: self.config.definition_commit.clone(),
                    started_at: now,
                    finished_at: ctx.ports.clock.now(),
                    reviewer: ReviewerPolicy::Optional,
                },
            )
            .map_err(|_| StageError::Internal)?;

        Ok(GateDecision {
            reports: vec![original_report, outcome_report, readability],
            review: None,
            human_gate: word == "clarify",
            policy_violation: stops,
            assurance: Vec::new(),
        })
    }
}

/// Title and body as one text, the way the API stores a request: the title, a blank line, the body.
/// A missing part leaves no separator.
fn request_text(title: &str, body: &str) -> String {
    match (title.is_empty(), body.is_empty()) {
        (false, false) => format!("{title}\n\n{body}"),
        (false, true) => title.to_owned(),
        (true, _) => body.to_owned(),
    }
}

fn slug(name: &str) -> Result<Slug, StageError> {
    Slug::parse(name).map_err(|_| StageError::Internal)
}

impl IntakeHandler {
    /// Fetches the issue of a job that a webhook created and stores its text as revision 1.
    ///
    /// The webhook payload is a hint and carries no text, and the API holds no credential for the
    /// code host, so this is the one place the text of such a job is read. It fails closed:
    /// a job that names no issue, an issue the host does not return, another issue than the one
    /// asked for, and an issue with no words in it all end the attempt, and nothing is stored.
    ///
    /// The snapshot is checked against the label before it is stored (AUT-11). The text of the
    /// issue is what the factory will act on, under the authority of the person who applied the
    /// label, so the label must be on the issue now, applied by a person on the allowlist (by
    /// numeric id), and the issue must not have changed since the label was applied: an author who
    /// edits the body after a requester labelled it must not have the new words acted on under the
    /// requester's name. A source that cannot say when the label was applied gives no time to
    /// compare, and the time check is then not made. Any activity on the issue after the label (a
    /// comment, another label) moves the host's "last changed" time too, so the job is refused and
    /// the requester applies the label again. That is the price of the check, and it fails closed.
    async fn first_request(
        &self,
        identity: &crate::handlers::RunIdentity,
        now: Timestamp,
    ) -> Result<(RequestSnapshot, u64), StageError> {
        let issue = self
            .requests
            .awaiting(identity.job)
            .ok_or(StageError::Internal)?;
        let fetched = self
            .issues
            .fetch_issue(&self.scope(identity, &issue), &issue)
            .await
            .map_err(|_| StageError::Tool)?;
        if fetched.reference != issue {
            return Err(StageError::Tool);
        }
        let (decision, application) = self.authorize_label(identity, &issue, now).await?;
        if !decision.is_authorized() {
            return Err(StageError::PolicyDenied);
        }
        let changed_after_label = application
            .and_then(|found| found.applied_at)
            .and_then(|applied| {
                applied.checked_add(std::time::Duration::from_secs(LABEL_SKEW_SECONDS))
            })
            .is_some_and(|limit| fetched.updated_at > limit);
        if changed_after_label {
            return Err(StageError::PolicyDenied);
        }
        let text = request_text(&fetched.title, &fetched.body);
        if text.trim().is_empty() {
            return Err(StageError::Tool);
        }
        // A secret in the issue text never reaches the store: not the column of the request, not
        // the artifact that keeps the original apart. What is kept is the text with each secret
        // replaced, and its hash is of that text (a hash of the original would let anyone who can
        // guess the rest of the sentence check a guess at the secret). A text the redactor cannot
        // judge is not kept at all.
        let (text, replaced) = {
            let redacted = self
                .redactor
                .redact_str(&text)
                .map_err(|_| StageError::Internal)?;
            (
                redacted.output.clone().into_owned(),
                redacted.report.replacements(),
            )
        };
        let snapshot = self
            .requests
            .record_first(
                identity.tenant,
                identity.job,
                FetchedRequest {
                    issue,
                    author: fetched.author.id,
                    text,
                },
            )
            .await
            .map_err(seam)?;
        Ok((snapshot, replaced))
    }

    /// The text the classifier reads: the original, and the answers people gave to the question
    /// of an earlier round, each marked. All of it goes in the one untrusted block.
    async fn request_with_answers(
        &self,
        ctx: &StageContext<'_>,
        snapshot: &RequestSnapshot,
    ) -> Result<String, StageError> {
        let mut text = snapshot.text.clone();
        let scope = TenantScope::new(ctx.identity.tenant);
        for (index, answer) in ctx.human_inputs.iter().enumerate() {
            let bytes = ctx
                .ports
                .artifacts
                .get(&scope, answer)
                .await
                .map_err(|_| StageError::Tool)?;
            let bounded = bytes
                .get(..bytes.len().min(ANSWER_MAX_BYTES))
                .unwrap_or(&bytes);
            let answer_text = String::from_utf8_lossy(bounded);
            text.push_str(&format!(
                "\n\nAnswer {} from the requester:\n{}",
                index + 1,
                answer_text
            ));
        }
        Ok(text)
    }
}
