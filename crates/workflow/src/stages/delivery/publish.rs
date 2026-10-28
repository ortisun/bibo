//! The effects of the delivery stage on the code host, each safe to repeat.
//!
//! | Step | Port call | A repeat after a restart |
//! |---|---|---|
//! | Push the factory branch | `JobRepo::push` with a `ChangeHost::push_target` | A commit already on the branch is accepted unchanged |
//! | Open the pull request | `ChangeHost::open_draft_pull_request` | The same open head branch gives the same pull request |
//! | Write the body | `ChangeHost::update_pull_request_body` with the current tag | The same body changes nothing visible |
//!
//! The pull request is opened as a draft and read back: if the host reports it as anything else,
//! or at another commit than the one that was delivered, the stage stops. The port has no call
//! that marks a pull request ready, so there is nothing here that could.

use factory_domain::ids::StageRunId;
use factory_domain::values::Slug;
use factory_ports::clock::CancelSignal;
use factory_ports::githost::{
    ChangeHost, DraftPrRequest, GitHostError, GitScope, PullRequestLifecycle,
};
use factory_ports::workspace::JobRepo;

use super::handler::{host_error, slug, workspace_error};
use super::input::Dossier;
use super::pr::PrText;
use super::seams::DeliveryTarget;
use crate::handlers::StageError;

/// What the host holds after the effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The pull request number.
    pub number: u64,
    /// The identifier that makes the check runs of this stage run one run each.
    pub external_id: Slug,
}

/// Pushes the branch, opens the draft pull request and makes its body the one given.
///
/// # Errors
/// [`StageError`]: a refused push or credential is `PolicyDenied`, an outage is `Provider`, and a
/// pull request that is not an open draft at the delivered commit is `PolicyDenied`.
#[allow(clippy::too_many_arguments)]
pub async fn deliver(
    host: &dyn ChangeHost,
    repo: &dyn JobRepo,
    git: &GitScope,
    target: &DeliveryTarget,
    dossier: &Dossier,
    text: &PrText,
    stage_run: StageRunId,
    cancel: &dyn CancelSignal,
) -> Result<Published, StageError> {
    let push = host
        .push_target(git, &target.head)
        .await
        .map_err(|e| host_error(&e))?;
    repo.push(&push, &dossier.candidate.head, cancel)
        .await
        .map_err(|e| workspace_error(&e))?;
    let pr = host
        .open_draft_pull_request(
            git,
            DraftPrRequest {
                head: target.head.clone(),
                base: target.base.clone(),
                title: text.title.clone(),
                body: text.body.clone(),
            },
        )
        .await
        .map_err(|e| host_error(&e))?;
    let mut state = host
        .pull_request_state(git, &pr)
        .await
        .map_err(|e| host_error(&e))?;
    // The body is written again with the tag just read, so a repeat that has a new manifest hash
    // leaves the body and the stored manifest in agreement.
    for attempt in 0..2 {
        match host
            .update_pull_request_body(git, &pr, &text.body, Some(&state.body_etag))
            .await
        {
            Ok(()) => break,
            Err(GitHostError::Conflict) if attempt == 0 => {
                state = host
                    .pull_request_state(git, &pr)
                    .await
                    .map_err(|e| host_error(&e))?;
            }
            Err(error) => return Err(host_error(&error)),
        }
    }
    let state = host
        .pull_request_state(git, &pr)
        .await
        .map_err(|e| host_error(&e))?;
    let as_delivered = state.lifecycle == PullRequestLifecycle::Open
        && state.draft
        && state.head == target.head
        && state.head_sha == dossier.candidate.head;
    if !as_delivered {
        return Err(StageError::PolicyDenied);
    }
    Ok(Published {
        number: pr.number,
        external_id: slug(&format!("delivery-{stage_run}"))?,
    })
}
