//! The engine's own check of a decision the requester took alone in the solo mode (ADR 0022).
//!
//! The policy engine grants the exception and stamps its proof; the engine does not take the
//! stamp as the whole truth. When it commits, it reads the facts again in its own transaction:
//! the switch of the policy it runs under, the `single_maintainer` mark of the job's repository,
//! and the number of people who may approve on it now (the [`Authority`](crate::commands::Authority)
//! seam). For the decisions that need them it also checks the minimum wait, from the moment the
//! stage run last asked, and the confirmation word. A missing milestone refuses.

use factory_domain::ids::{RepositoryId, TenantId};
use factory_domain::policy::decision::AuthorizedApproval;
use factory_domain::policy::solo::{ConfirmationWord, SoloRules, SoloWait};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{Job, PrincipalKind, Tx};

use super::Engine;
use super::error::{EngineError, SoloRefusal};
use crate::commands::{Actor, SoloRequest};

/// What the engine checks for a decision that needs the wait and the phrase.
#[derive(Debug, Clone)]
pub(super) struct SoloCheck<'a> {
    /// When the person asked and what they confirmed, as the signed request carried it.
    pub(super) request: Option<&'a SoloRequest>,
    /// When the stage run last entered the state that asks for the decision.
    pub(super) milestone: Option<Timestamp>,
    /// Which wait applies.
    pub(super) wait: SoloWait,
    /// The word of the phrase the decision needs.
    pub(super) expected: ConfirmationWord,
}

impl Engine {
    /// Whether the solo fact holds now for a job of `repository`, read in the engine's
    /// transaction. Fails closed: a protected configuration that cannot be read is a refusal.
    pub(super) async fn solo_fact_now(
        &self,
        tx: &mut dyn Tx,
        tenant: TenantId,
        repository: RepositoryId,
    ) -> Result<bool, EngineError> {
        if !self.config.solo.enabled() {
            return Ok(false);
        }
        let single_maintainer = tx.get_repository(repository).await?.value.single_maintainer;
        if !single_maintainer {
            return Ok(false);
        }
        let count = self
            .deps
            .authority
            .approver_count(tenant, repository)
            .await
            .map_err(|_| EngineError::Refused("the protected configuration cannot be read"))?;
        Ok(self.config.solo.fact(single_maintainer, count).holds())
    }

    /// Whether the requester's own approval of a stage run of `kind` may stand: the proof is
    /// there, carries the solo stamp, is for the approval of that stage (`approve_pr` or
    /// `freeze_specification`), names the acting person's numeric GitHub id, and the solo fact
    /// holds now. The approval of a specification and of a pull request has no wait of its own
    /// here: the approval stage checks the wait and the phrase of a high or critical pull request
    /// before it asks the engine.
    pub(super) async fn solo_approval_holds(
        &self,
        tx: &mut dyn Tx,
        actor: &Actor,
        job: &Job,
        kind: StageKind,
        proof: Option<&AuthorizedApproval>,
    ) -> Result<bool, EngineError> {
        let Some(proof) = proof else {
            return Ok(false);
        };
        let action = match kind {
            StageKind::Approval => "approve_pr",
            StageKind::Specification => "freeze_specification",
            _ => return Ok(false),
        };
        if !proof.solo_stamp() || proof.action() != action {
            return Ok(false);
        }
        let principal = tx.get_principal(actor.principal).await?;
        let PrincipalKind::Human { github_user_id } = principal.kind else {
            return Ok(false);
        };
        if principal.disabled_at.is_some() || github_user_id != proof.approver().get() {
            return Ok(false);
        }
        self.solo_fact_now(tx, actor.tenant, job.repository).await
    }
}

/// The wait and the phrase of a decision the requester takes alone, under `rules`. The phrase is
/// checked first, then the wait, the order the approval stage uses too. A request that carries
/// nothing has no phrase; a missing milestone fails the wait.
pub(super) fn check_wait_and_phrase(
    rules: &SoloRules,
    check: &SoloCheck<'_>,
) -> Result<(), EngineError> {
    let Some(request) = check.request else {
        return Err(EngineError::SoloRefused(SoloRefusal::ConfirmationMissing));
    };
    if request.confirmation.as_ref() != Some(&check.expected) {
        return Err(EngineError::SoloRefused(SoloRefusal::ConfirmationMissing));
    }
    if !rules.wait_passed(check.wait, check.milestone.as_ref(), &request.requested_at) {
        return Err(EngineError::SoloRefused(SoloRefusal::SoloDelay));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::policy::ApprovalPolicy;

    fn rules() -> SoloRules {
        let approval: ApprovalPolicy = serde_json::from_str(include_str!(
            "../../../domain/tests/fixtures/policy/approval.json"
        ))
        .expect("the approval policy");
        SoloRules::from_block(&approval.solo_mode).expect("a good block")
    }

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a time")
    }

    #[test]
    fn negative_nt_solo_03_a_missing_milestone_refuses() {
        let rules = rules();
        let word = ConfirmationWord::of("I confirm the solo approval of dependency a 1");
        let request = SoloRequest {
            requested_at: at("2026-11-20T12:00:00Z"),
            confirmation: Some(word.clone()),
        };
        fn check<'a>(
            milestone: Option<Timestamp>,
            request: Option<&'a SoloRequest>,
            expected: &ConfirmationWord,
        ) -> SoloCheck<'a> {
            SoloCheck {
                request,
                milestone,
                wait: SoloWait::Dependency,
                expected: expected.clone(),
            }
        }
        assert_eq!(
            check_wait_and_phrase(&rules, &check(None, Some(&request), &word)),
            Err(EngineError::SoloRefused(SoloRefusal::SoloDelay))
        );
        // Ten minutes exactly passes; a second less does not.
        assert_eq!(
            check_wait_and_phrase(
                &rules,
                &check(Some(at("2026-11-20T11:50:00Z")), Some(&request), &word)
            ),
            Ok(())
        );
        assert_eq!(
            check_wait_and_phrase(
                &rules,
                &check(Some(at("2026-11-20T11:50:01Z")), Some(&request), &word)
            ),
            Err(EngineError::SoloRefused(SoloRefusal::SoloDelay))
        );
        // No request part, or another word: the phrase is missing, whatever the wait.
        assert_eq!(
            check_wait_and_phrase(
                &rules,
                &check(Some(at("2026-11-20T10:00:00Z")), None, &word)
            ),
            Err(EngineError::SoloRefused(SoloRefusal::ConfirmationMissing))
        );
        let other = SoloRequest {
            confirmation: Some(ConfirmationWord::of(
                "I confirm the solo approval of dependency b 1",
            )),
            ..request.clone()
        };
        assert_eq!(
            check_wait_and_phrase(
                &rules,
                &check(Some(at("2026-11-20T10:00:00Z")), Some(&other), &word)
            ),
            Err(EngineError::SoloRefused(SoloRefusal::ConfirmationMissing))
        );
    }
}
