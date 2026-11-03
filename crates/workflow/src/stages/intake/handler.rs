//! The `INTAKE` stage handler.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the original request and check that its bytes still hash to the hash the store holds.
//! 2. Refuse a request that was edited and that no person has confirmed since (`S22`). The engine
//!    already holds such a run before any attempt starts; this is the second wall.
//! 3. Authorize the person who applied the label, by numeric id (`authorize`). A refusal ends the
//!    stage with `PolicyDenied`. No sandbox is made and no agent runs.
//! 4. Judge the design (`design`): read the labels of the issue from the code host now. An issue
//!    with a design label needs `design: approved`, applied by a person who holds the approver
//!    designation. A refusal answers the person on the issue, returns the decision `decline` and
//!    stops before any sandbox is made. A rule that cannot be read blocks the stage run.
//! 5. Store the original bytes apart, under their hash.
//! 6. Assemble the prompt. The issue text goes in as untrusted data and nowhere else.
//! 7. Run the classifier in a verified sandbox, and read its answer through the schema check and
//!    through `Classification::read`. An answer that fails either is `InvalidOutput`.
//! 8. Decide the outcome (`decide`) and return the normalized request, the decision and the
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
use factory_domain::policy::authority::Allowlist;
use factory_domain::policy::issue_workflow::{DesignGate, DesignLabels};
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::{AgentRunRequest, BrokerEndpoint, RoutingNeed};
use factory_ports::githost::{GitScope, IssueRef, IssueSource, LabelApplication};
use factory_ports::registry::VersionReq;
use factory_ports::sandbox::TeardownReason;
use serde_json::Value;

use super::authorize::{Authorization, Labeller, authorize};
use super::classify::{Classification, DeclineReason, IntakeRules, Outcome, ReadProblem, decide};
use super::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec, Executor,
    GateDefinition, GateFacts, GateSubject, gate_report, stage_contract,
};
use super::design::{
    self, ARTIFACT as DESIGN_ARTIFACT, DesignDecision, GATE as DESIGN_GATE, Judging, Reply,
    ReplyStatus,
};
use super::normalize::{
    ClassifierRef, OriginalRef, decision_document, description_from, normalized_request, title_from,
};
use super::seams::{
    AgentOutputCheck, AgentSandboxSpecs, AllowlistSource, CapabilityProbes, DesignGatePolicy,
    FetchedRequest, RefusalReplies, ReplyError, RequestSnapshot, RequestSource, SeamError,
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
    design: Arc<dyn DesignGatePolicy>,
    replies: Arc<dyn RefusalReplies>,
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
    /// The design rule of the issue workflow policy, read now.
    pub design: Arc<dyn DesignGatePolicy>,
    /// Answers a person on the issue when the stage refuses it.
    pub replies: Arc<dyn RefusalReplies>,
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
            design: deps.design,
            replies: deps.replies,
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
    ) -> Result<(Authorization, Option<LabelApplication>, Allowlist), StageError> {
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
            application.as_ref().map(Labeller::of),
            &now,
        );
        Ok((decision, application, allowlist))
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
            self.design.fidelity(),
            self.replies.fidelity(),
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
            required: Vec::new(),
            risk: factory_domain::vocabulary::RiskTier::Low,
            exclude: Vec::new(),
            probed: self.probes.probed(),
            author: None,
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
                ContractDeliverable {
                    name: DESIGN_ARTIFACT,
                    description: "What the design gate found on the issue: no design label, an approved design and who approved it, or the reason the design is not approved.",
                    media_type: "application/json",
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
                    id: "design-approved-or-not-needed",
                    description: "An issue with a design label has the approved design label, applied by a person who holds the approver designation; an issue with none is not held back.",
                    gate: DESIGN_GATE,
                },
                ContractCriterion {
                    id: "plain-english",
                    description: "The title and the description pass the readability gate.",
                    gate: READABILITY_GATE,
                },
            ],
            gates: vec![ORIGINAL_GATE, OUTCOME_GATE, DESIGN_GATE, READABILITY_GATE],
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
        let (decision, application, allowlist) = self
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

        // 4. The design gate. The labels are read from the code host now, and the person who
        // applied the approved label is matched on the allowlist by numeric id. A rule that cannot
        // be read blocks the run: the stage never guesses and never falls back to a default.
        let issue_text = format!(
            "{}/{}#{}",
            snapshot.issue.repo.owner(),
            snapshot.issue.repo.name(),
            snapshot.issue.number
        );
        let (design_rule, design_decision) = match self
            .judge_design(&identity, &snapshot.issue, &allowlist, now)
            .await
        {
            Ok(judged) => judged,
            Err(DesignStop::Unjudgeable) => {
                let status = self
                    .reply(&identity, &snapshot.issue, Reply::CannotCheck, "")
                    .await
                    .ok();
                ctx.note_audit_because(
                    AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),
                    design::unjudgeable_reason(&issue_text, status),
                );
                // The audit record above names the issue; a log field would be text of outside
                // origin, so the line says only what happened.
                tracing::error!(
                    "intake refuses the issue: the issue workflow policy cannot be used, so the design gate cannot judge"
                );
                return Err(StageError::Environment(
                    factory_domain::machines::guards::EnvironmentCause::PolicyUnloadable,
                ));
            }
            Err(DesignStop::Stage(error)) => return Err(error),
        };

        // 5. The original, stored apart under its hash.
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

        // A refused design ends the stage here: the person is answered, no sandbox is made and no
        // classifier runs. The decision is `decline`, and the gate reports BLOCKED.
        let mut design_status = None;
        if let DesignDecision::Refused { reason, .. } = &design_decision {
            design_status = Some(
                self.reply(
                    &identity,
                    &snapshot.issue,
                    reason.reply(),
                    design_rule.approved_label(),
                )
                .await?,
            );
        }
        if !matches!(design_decision, DesignDecision::NotOnTrack) {
            ctx.note_audit_because(
                AuditAction::new(
                    AuditKind::AuthorizationDecision,
                    if design_decision.allows_work() {
                        AuditDecision::Granted
                    } else {
                        AuditDecision::Denied
                    },
                ),
                self.redacted_reason(design::audit_reason(
                    &design_decision,
                    &issue_text,
                    design_status,
                )),
            );
        }
        // The stored document, and the report that is made from it, show the labels with every
        // secret replaced. The audit line above is redacted as a whole, on its own.
        let design_document = design::document(
            &self.redact_labels(design_decision.clone()),
            design_rule.approved_label(),
            design_status,
        );
        if !design_decision.allows_work() {
            // No sandbox was made and no agent ran, so there is no posture to verify. The engine
            // wants the readiness of a stage whose contract places it in a sandbox before it lets
            // the attempt finish, and it gives the same answer for a stage that needs none (the
            // engine's own preconditions are then the whole of the guard).
            ctx.report_sandbox_ready(SandboxReady {
                posture_verified: true,
                tool_grants_recorded: true,
                probe_satisfies_stage: true,
            });
            return Self::refused_output(&ports, &snapshot, original, design_document).await;
        }

        // 6. The prompt. The issue text is untrusted data.
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

        // 7. The classifier, in a verified sandbox.
        let token = ctx.job_token.ok_or(StageError::Internal)?;
        let need = RoutingNeed {
            stage: StageKind::Intake,
            tier: factory_domain::contracts::agent_manifest::RecommendedTier::Standard,
            required: Vec::new(),
            risk: factory_domain::vocabulary::RiskTier::Low,
            exclude: Vec::new(),
            probed: self.probes.probed(),
            author: None,
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
        match capabilities {
            Ok(_) => {}
            Err(error) => {
                let _ = session.stop_and_remove(TeardownReason::Failed).await;
                return Err(error.into());
            }
        };
        ctx.report_sandbox_ready(SandboxReady {
            posture_verified: true,
            tool_grants_recorded: true,
            // The classifier needs nothing of the runtime beyond a probe that succeeded.
            probe_satisfies_stage: true,
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

        // 8. The documents.
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
        let mut stored = Vec::with_capacity(4);
        for (name, value) in [
            ("normalized-request", normalized),
            (
                "intake-decision",
                decision_document(&outcome, &snapshot.sha256),
            ),
            (DESIGN_ARTIFACT, design_document),
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
        let (Some(normalized), Some(decision), Some(original), Some(design_stored)) = (
            read("normalized-request"),
            read("intake-decision"),
            read("original-request"),
            read(DESIGN_ARTIFACT),
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
        let design_bytes = fetch(design_stored).await.map_err(|_| StageError::Tool)?;
        let design_document: Value =
            serde_json::from_slice(&design_bytes).map_err(|_| StageError::InvalidOutput)?;
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
                        if design::is_refused(&design_document) {
                            "The request does not go on until the design is approved.".to_owned()
                        } else {
                            "The request does not go on without an operator.".to_owned()
                        },
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

        // Gate: the design. A design that is not approved is reported as BLOCKED with a code of
        // its own, and the run is blocked as a policy violation (the outcome above is `decline`).
        let design_report = gate_report(
            &subject(ctx),
            &design::gate_facts(&design_document, &self.config.definition_commit)?,
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
            reports: vec![original_report, outcome_report, design_report, readability],
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

/// Why the design gate could not give a decision.
enum DesignStop {
    /// The rule cannot be read. The stage refuses the issue and blocks the run.
    Unjudgeable,
    /// A read failed or the answer cannot be trusted. The attempt fails and may be tried again.
    Stage(StageError),
}

impl IntakeHandler {
    /// Judges the design of the issue. The labels come from a live fetch of the issue and the
    /// applier of the approved label from the timeline of the issue: nothing the webhook carried
    /// is used. A read that fails, or an issue other than the one asked for, fails the attempt
    /// (never a pass).
    async fn judge_design(
        &self,
        identity: &crate::handlers::RunIdentity,
        issue: &IssueRef,
        allowlist: &Allowlist,
        now: Timestamp,
    ) -> Result<(DesignGate, DesignDecision), DesignStop> {
        let rule = self
            .design
            .current()
            .await
            .map_err(|_| DesignStop::Unjudgeable)?;
        let scope = self.scope(identity, issue);
        let fetched = self
            .issues
            .fetch_issue(&scope, issue)
            .await
            .map_err(|_| DesignStop::Stage(StageError::Tool))?;
        if fetched.reference != *issue {
            return Err(DesignStop::Stage(StageError::Tool));
        }
        let mut labels = rule.classify(&fetched.labels);
        if labels == DesignLabels::NotOnTrack {
            // No design label now. The track is sticky: a design label that was applied and taken
            // off keeps the issue on it. That is in the events of the issue, which must be read to
            // the end: a list that is cut is an error here, and never "nothing was applied".
            let applied_before = self
                .issues
                .labels_ever_applied(&scope, issue)
                .await
                .map_err(|_| DesignStop::Stage(StageError::Tool))?;
            labels = rule.classify_past(&applied_before);
        }
        let applied = if labels == DesignLabels::ApprovalLabelOnly {
            self.issues
                .label_application(&scope, issue, rule.approved_label())
                .await
                .map_err(|_| DesignStop::Stage(StageError::Tool))?
        } else {
            None
        };
        let repository = format!("{}/{}", issue.repo.owner(), issue.repo.name());
        let decision = design::judge(
            &Judging {
                gate: &rule,
                authority: &self.policy.authority,
                allowlist,
                tenant: identity.tenant,
                repository: &repository,
                now: &now,
            },
            labels,
            applied.as_ref().map(Labeller::of),
        );
        Ok((rule, decision))
    }

    /// The text with every secret replaced. A label name is text of outside origin and could be
    /// shaped like a secret. A text the redactor cannot judge is not stored: `withheld` takes its
    /// place.
    fn redacted(&self, text: &str, withheld: &str) -> String {
        match self.redactor.redact_str(text) {
            Ok(redacted) => redacted.output.into_owned(),
            Err(_) => withheld.to_owned(),
        }
    }

    /// The reason line of an audit record, with every secret replaced.
    fn redacted_reason(&self, reason: String) -> String {
        self.redacted(
            &reason,
            "design gate: the reason was withheld because it could not be checked for secrets",
        )
    }

    /// The design labels seen, which the stored document and the report show, with every secret
    /// replaced.
    fn redact_labels(&self, decision: DesignDecision) -> DesignDecision {
        match decision {
            DesignDecision::Refused {
                reason,
                labels_seen,
                applied_by,
                allowlist_version,
            } => DesignDecision::Refused {
                reason,
                labels_seen: labels_seen
                    .iter()
                    .map(|label| self.redacted(label, "withheld"))
                    .collect(),
                applied_by,
                allowlist_version,
            },
            other => other,
        }
    }

    /// Answers the person on the issue, once for each stage run. A reply that cannot be delivered
    /// now fails the attempt, so that it is tried again; one that cannot be delivered at all is
    /// noted and does not change the refusal.
    async fn reply(
        &self,
        identity: &crate::handlers::RunIdentity,
        issue: &IssueRef,
        reply: Reply,
        approved_label: &str,
    ) -> Result<ReplyStatus, StageError> {
        let key = format!("design-gate-{}", identity.stage_run);
        let text = reply.text(&self.config.label, approved_label);
        match self.replies.post(identity.tenant, issue, &key, &text).await {
            Ok(()) => Ok(ReplyStatus::Posted),
            Err(ReplyError::NotSent) => Ok(ReplyStatus::NotSent),
            Err(ReplyError::Later) => Err(StageError::Tool),
        }
    }

    /// The output of a stage that refused the issue: the decision `decline`, a normalized request
    /// of fixed sentences (no classifier ran), the original and the design document.
    async fn refused_output(
        ports: &crate::handlers::StagePorts<'_>,
        snapshot: &RequestSnapshot,
        original: factory_domain::contracts::ArtifactRef,
        design_document: Value,
    ) -> Result<StageOutput, StageError> {
        let json_type = MediaType::parse("application/json").map_err(|_| StageError::Internal)?;
        let normalized = serde_json::json!({
            "schema_version": 1,
            "title": design::REFUSED_TITLE,
            "description": design::REFUSED_DESCRIPTION,
            "refused": design::REPORT_BLOCK_CODE,
            "original": {
                "revision": snapshot.revision,
                "sha256": snapshot.sha256,
                "artifact_sha256": original.sha256,
            },
        });
        let outcome = Outcome::Decline(DeclineReason::DesignNotApproved);
        let mut stored = Vec::with_capacity(4);
        for (name, value) in [
            ("normalized-request", normalized),
            (
                "intake-decision",
                decision_document(&outcome, &snapshot.sha256),
            ),
            (DESIGN_ARTIFACT, design_document),
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
            ..StageOutput::default()
        })
    }

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
        let (decision, application, _) = self.authorize_label(identity, &issue, now).await?;
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
