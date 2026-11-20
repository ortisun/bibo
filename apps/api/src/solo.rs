//! The immediate refusal of the solo mode (ADR 0021).
//!
//! A person who asked for a job and holds the designation a decision needs used to be told
//! nothing when they approved their own request: the API answered `202`, and minutes later the
//! worker wrote `decision.rejected` "The person may not take this decision now." The API now runs
//! the same `authorize_action` of the policy engine as the worker, with the facts it has, before it
//! records the decision, and refuses at once with a reason and the way out:
//!
//! * `ineligible_approver`: the requester may not take the decision alone, because the solo mode
//!   does not apply. `reason` is the first of `solo_mode_disabled`, `not_single_maintainer`,
//!   `more_than_one_approver`, `designation_missing` (with `needed_designation`); `approvers` lists
//!   who may approve.
//! * `confirmation_missing`: the solo mode applies and the decision needs the confirmation phrase,
//!   and the request carries none or another one. `expected_confirmation` is the phrase.
//!
//! Only the requester who holds the designation hears a reason: they are on the list with the
//! role, so the reason tells nobody anything about who is on it. Everybody else gets what they got
//! before (`202`, or the silent `403`). The wait is not checked here: the API does not know when
//! the stage run started to wait, and the worker or the engine refuses with `solo_delay`.

use axum::http::StatusCode;
use factory_composition::delivery::StoreApprovalSources;
use factory_composition::solo::{APPROVING, solo_inputs};
use factory_domain::ids::{AuditEventId, CorrelationId, StageRunId};
use factory_domain::policy::authority::{
    ActionContext, ActionDenialReason, ActionVerdict, Actor, ActorKind, AutonomyLevel, ChangeFacts,
    RepositoryIdentity,
};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::policy::solo::{ConfirmationWord, SoloTarget, SoloWait};
use factory_domain::vocabulary::{AutonomyLevel as VocabularyLevel, RiskTier};
use factory_ports::store::{
    AuditActor, AuditDecision, Job, NewAuditEvent, Repository, Tx, Witness,
};
use factory_workflow::stages::approval::ApprovalSources as _;
use serde_json::{Value, json};

use crate::answers::{Answer, ApiError, Reply};
use crate::auth::Caller;
use crate::jobs::{audit_action, commit};
use crate::limits::Refusal;
use crate::state::ApiState;

/// What one decision asks of the policy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SoloAsk<'a> {
    /// The action row.
    pub(crate) action: &'static str,
    /// The facts of the change.
    pub(crate) change: ChangeFacts,
    /// A designation that replaces the row's own, as the worker asks for build code.
    pub(crate) require_designation: Option<Designation>,
    /// What the confirmation phrase names, for a decision that needs one. `None` for the
    /// approval of a specification and of a low or medium pull request.
    pub(crate) phrase: Option<SoloTarget<'a>>,
}

impl SoloAsk<'_> {
    /// A decision that is not tiered and has no pull request: the worker asks with the medium
    /// tier and no sign (`dependency_decisions.rs`, `stage_decisions.rs`).
    pub(crate) fn untiered<'a>(
        action: &'static str,
        require_designation: Option<Designation>,
        phrase: SoloTarget<'a>,
    ) -> SoloAsk<'a> {
        SoloAsk {
            action,
            change: ChangeFacts {
                risk_tier: RiskTier::Medium,
                protected_path_change: false,
                sensitive_file_change: false,
                new_dependency: false,
            },
            require_designation,
            phrase: Some(phrase),
        }
    }
}

/// A refusal with a reason, for the requester who holds the designation.
#[derive(Debug, Clone)]
pub(crate) struct Explained {
    /// `ineligible_approver` or `confirmation_missing`.
    pub(crate) code: &'static str,
    /// The fields of the body besides `error`.
    pub(crate) details: Value,
    /// The fixed sentence the audit record keeps.
    pub(crate) audit: String,
}

fn level_of(level: VocabularyLevel) -> AutonomyLevel {
    match level {
        VocabularyLevel::L0 => AutonomyLevel::L0,
        VocabularyLevel::L1 => AutonomyLevel::L1,
        VocabularyLevel::L2 => AutonomyLevel::L2,
        VocabularyLevel::L3 => AutonomyLevel::L3,
    }
}

/// The ask of an `approve` of a stage run: the freezing of a specification with no tier, or the
/// approval of a pull request with the facts of the stored approval request. `None` for any
/// other stage run (the engine decides those as before).
///
/// # Errors
/// [`ApiError::Unavailable`] when the approval request cannot be read: nothing is recorded.
pub(crate) async fn approve_ask(
    state: &ApiState,
    caller: &Caller,
    tx: &mut dyn Tx,
    stage_run: StageRunId,
) -> Result<Option<SoloAsk<'static>>, ApiError> {
    let kind = tx.get_stage_run(stage_run).await?.value.kind;
    match kind {
        factory_domain::vocabulary::StageKind::Specification => Ok(Some(SoloAsk {
            action: "freeze_specification",
            change: ChangeFacts {
                risk_tier: RiskTier::Low,
                protected_path_change: false,
                sensitive_file_change: false,
                new_dependency: false,
            },
            require_designation: None,
            phrase: None,
        })),
        factory_domain::vocabulary::StageKind::Approval => {
            let Some(artifacts) = state.ports.artifacts.clone() else {
                return Err(ApiError::Unavailable);
            };
            let sources = StoreApprovalSources::new(
                state.ports.store.clone(),
                artifacts,
                state.allowlist_file.clone(),
            );
            let request = sources
                .request(caller.tenant, stage_run)
                .await
                .map_err(|_| ApiError::Unavailable)?;
            // A high or critical pull request needs the phrase; a low or medium one does not.
            let phrase =
                SoloWait::for_pull_request(request.tier).map(|_| SoloTarget::PullRequest {
                    number: request.pull_request,
                    tier: request.tier,
                });
            Ok(Some(SoloAsk {
                action: "approve_pr",
                change: ChangeFacts {
                    risk_tier: request.tier,
                    protected_path_change: request.protected_path_change,
                    sensitive_file_change: request.sensitive_file_change,
                    new_dependency: request.new_dependency,
                },
                require_designation: None,
                phrase,
            }))
        }
        _ => Ok(None),
    }
}

/// The immediate refusal of the solo mode for the caller's decision, or `None` when the API lets
/// it through to the worker as before. Asked only of the requester of `job` who holds the
/// designation the verb needs.
///
/// # Errors
/// [`ApiError::Unavailable`] when a fact cannot be read: nothing is recorded (fail closed).
pub(crate) async fn refusal(
    state: &ApiState,
    caller: &Caller,
    tx: &mut dyn Tx,
    (job, repository): (&Job, &Repository),
    ask: &SoloAsk<'_>,
    confirm: Option<&str>,
) -> Result<Option<Explained>, ApiError> {
    if job.requester != caller.principal {
        return Ok(None);
    }
    let Some(github) = caller.github_user_id.and_then(GithubUserId::new) else {
        return Ok(None);
    };
    let authority = &state.policies.engine.authority;
    let rules = authority.solo_rules();
    let now = state.ports.clock.now();
    let inputs = solo_inputs(tx, &state.allowlist_file, caller.tenant, repository.id, now)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let allowlist = state
        .allowlist_file
        .read()
        .map_err(|_| ApiError::Unavailable)?;
    let actor = Actor {
        github_user_id: github,
        login: "caller",
        kind: ActorKind::User,
        github_permission: None,
        author_association: None,
    };
    let verdict = authority.authorize_action(&ActionContext {
        action: ask.action,
        level: level_of(repository.autonomy_ceiling),
        tenant: &caller.tenant,
        repository: &repository.full_name,
        actor: &actor,
        allowlist: &allowlist,
        now: &now,
        requester: Some(github),
        change: ask.change,
        require_designation: ask.require_designation,
        step_up_done: false,
        solo: authority.solo_fact(inputs.single_maintainer, inputs.approver_count),
    });
    let ineligible = |reason: &'static str, needed: Option<Designation>| async move {
        let approvers = approvers(state, caller, tx, repository).await?;
        let mut details = json!({ "reason": reason, "approvers": approvers });
        if let Some(needed) = needed {
            details["needed_designation"] = json!(needed.as_str());
        }
        Ok::<_, ApiError>(Some(Explained {
            code: "ineligible_approver",
            details,
            audit: format!(
                "The requester asked to approve their own request and the solo mode does not apply: {reason}"
            ),
        }))
    };
    // The first reason that applies, in a fixed order.
    let fact_reason = if !rules.enabled() {
        Some("solo_mode_disabled")
    } else if !inputs.single_maintainer {
        Some("not_single_maintainer")
    } else if inputs.approver_count != 1 {
        Some("more_than_one_approver")
    } else {
        None
    };
    match verdict {
        ActionVerdict::Denied(denial) => match (&denial.reason, fact_reason) {
            (
                ActionDenialReason::SelfApproval | ActionDenialReason::MissingDesignation { .. },
                Some(reason),
            ) => ineligible(reason, None).await,
            (ActionDenialReason::MissingDesignation { needed }, None) => {
                ineligible("designation_missing", needed.first().copied()).await
            }
            // Any other refusal is the worker's to give, as before.
            _ => Ok(None),
        },
        ActionVerdict::Authorized(proof) if proof.solo_stamp() => {
            let Some(target) = ask.phrase else {
                return Ok(None);
            };
            let expected = rules.expected(&target);
            let given = confirm.map(ConfirmationWord::of);
            if given.as_ref() == Some(&ConfirmationWord::of(&expected)) {
                Ok(None)
            } else {
                Ok(Some(Explained {
                    code: "confirmation_missing",
                    details: json!({ "expected_confirmation": expected }),
                    audit: "The solo mode needs the confirmation phrase of this decision and the request carried none or another one.".to_owned(),
                }))
            }
        }
        ActionVerdict::Authorized(_) | ActionVerdict::NoHumanNeeded { .. } => Ok(None),
    }
}

/// The people who may approve on the repository now, for the answer: their numeric id and, for
/// display only, the login of their principal.
async fn approvers(
    state: &ApiState,
    caller: &Caller,
    tx: &mut dyn Tx,
    repository: &Repository,
) -> Result<Value, ApiError> {
    let roles: Vec<String> = APPROVING.iter().map(|name| (*name).to_owned()).collect();
    let holders = state
        .allowlist_file
        .holders_of(
            caller.tenant,
            &roles,
            &RepositoryIdentity::registered(
                &repository.full_name,
                repository.github_repository_id.0,
            ),
            state.ports.clock.now(),
        )
        .map_err(|_| ApiError::Unavailable)?;
    let mut list = Vec::new();
    for id in holders {
        let login = tx
            .find_principal_by_github_user(id)
            .await?
            .and_then(|principal| principal.login);
        list.push(json!({ "github_user_id": id, "login": login }));
    }
    Ok(Value::Array(list))
}

/// Records the immediate refusal as `decision.denied`, within what the audit log takes from one
/// person, and answers `409` with the reason. The answer does not depend on that budget.
///
/// # Errors
/// The store's errors.
pub(crate) async fn refuse_explained(
    state: &ApiState,
    caller: &Caller,
    mut tx: Box<dyn Tx>,
    subject: String,
    correlation_id: CorrelationId,
    explained: Explained,
) -> Answer {
    let record = matches!(
        state
            .refusals
            .admit(caller.principal, std::time::Instant::now()),
        Refusal::Record { .. }
    );
    if record {
        let id = AuditEventId::from_uuid(state.ports.ids.new_uuid());
        tx.record_audit(NewAuditEvent {
            id,
            actor: AuditActor::Human(caller.principal),
            action: audit_action("decision.denied")?,
            subject,
            decision: AuditDecision::Deny,
            reason: explained.audit.clone(),
            policy_hash: state.policy_hash(),
            job: None,
            stage_run: None,
            correlation_id,
        })
        .await?;
        commit(state, caller.scope(), tx, Witness::Audit(id)).await?;
    } else {
        let _ = tx.rollback().await;
    }
    let mut body = explained.details;
    body["error"] = json!(explained.code);
    Ok(Reply::new(StatusCode::CONFLICT, body))
}
