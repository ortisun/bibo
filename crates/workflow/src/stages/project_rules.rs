//! The project's rules for agents, as every agent stage gives them to its agent (ADR 0026,
//! `docs/architecture/project-rules.md`, "How the agents read the rules").
//!
//! The repository stage reads `AGENTS.md` at the job's base commit and stores the text the agents
//! get as its output [`PROJECT_RULES`]. Each agent stage pins that output in its stage contract by
//! digest, as it pins every input, and gives it as the prompt block [`INPUT_NAME`], class
//! `repo_file`, in a quoted data block. Nothing here turns the text into an instruction.
//!
//! A stage whose contract has no such input (a job whose repository stage ran before this
//! change) gives the factory's built-in copy, so a job in flight is not blocked. A pinned input
//! that cannot be read blocks the stage, as every other pinned input does.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::project_rules::{FileFound, Template, rules_for_agents};
use factory_domain::scope::TenantScope;
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::StageKind;
use serde_json::{Value, json};

use crate::handlers::{StageContext, StageError, UpstreamRun};
use crate::prompts::{ContentClass, Input, Source};
use crate::stages::implementation::input::{input_artifact, upstream_output};
use crate::stages::intake::common::ContractInput;

/// The output of the repository stage that holds the rules text, and the name of the contract
/// input that pins it.
pub const PROJECT_RULES: &str = "project-rules";

/// The name of the prompt block.
pub const INPUT_NAME: &str = "project_rules";

/// What the contract says of the input.
const DESCRIPTION: &str = "The project's rules for agents: AGENTS.md read at the job's base commit, or the factory's built-in copy when the project has none yet.";

/// The contract input that pins the rules of the repository stage, or `None` when that stage
/// produced none (a job from before ADR 0026).
#[must_use]
pub fn contract_input(upstream: &[UpstreamRun], now: Timestamp) -> Option<ContractInput> {
    let (run, artifact) =
        upstream_output(upstream, StageKind::RepositoryIntelligence, PROJECT_RULES)?;
    Some(ContractInput {
        name: PROJECT_RULES,
        description: DESCRIPTION,
        sha256: artifact.sha256.clone(),
        media_type: "text/markdown",
        source: "previous_stage",
        produced_by: Some(run.id),
        commit_sha: None,
        retrieved_at: now,
        // Read from a repository: data to read, approved by the project's owners, never an
        // instruction.
        trust: "untrusted",
    })
}

/// The same input, in the JSON form of the stages that write their contract by hand.
#[must_use]
pub fn contract_input_json(upstream: &[UpstreamRun], retrieved: &str) -> Option<Value> {
    let (run, artifact) =
        upstream_output(upstream, StageKind::RepositoryIntelligence, PROJECT_RULES)?;
    Some(json!({
        "name": PROJECT_RULES,
        "description": DESCRIPTION,
        "artifact": { "sha256": artifact.sha256.as_str(), "media_type": artifact.media_type.as_str() },
        "provenance": {
            "source": "previous_stage",
            "produced_by_stage_run_id": run.id.to_string(),
            "retrieved_at": retrieved,
        },
        "trust": "untrusted",
    }))
}

/// The text the agents get when no rules are pinned: the factory's built-in copy.
#[must_use]
pub fn built_in() -> String {
    rules_for_agents(FileFound::Missing, Template::current()).text
}

/// The rules text of this stage run: the pinned output of the repository stage, or the built-in
/// copy when none is pinned.
///
/// # Errors
/// [`StageError::Blocked`] with `DependencyUnavailable` when the pinned bytes cannot be read.
pub async fn text(ctx: &StageContext<'_>) -> Result<(Sha256Digest, Vec<u8>), StageError> {
    let Some(reference) = input_artifact(ctx.contract, PROJECT_RULES) else {
        let bytes = built_in().into_bytes();
        return Ok((Sha256Digest::of(&bytes), bytes));
    };
    let bytes = ctx
        .ports
        .artifacts
        .get(&TenantScope::new(ctx.identity.tenant), &reference)
        .await
        .map_err(|_| StageError::Blocked(BlockedCode::DependencyUnavailable))?;
    Ok((reference.sha256, bytes))
}

/// The prompt block of the rules, from the text [`text`] read.
#[must_use]
pub fn input(ctx: &StageContext<'_>, digest: &Sha256Digest, bytes: Vec<u8>) -> Input {
    Input::untrusted(
        INPUT_NAME,
        ContentClass::RepoFile,
        Source::HostArtifact {
            kind: PROJECT_RULES.to_owned(),
            id: digest.to_string(),
        },
        ctx.identity.tenant,
        bytes,
    )
    .fetched_at(ctx.ports.clock.now())
}

/// Reads the rules and makes the block in one step.
///
/// # Errors
/// As [`text`].
pub async fn block(ctx: &StageContext<'_>) -> Result<Input, StageError> {
    let (digest, bytes) = text(ctx).await?;
    Ok(input(ctx, &digest, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_copy_is_the_factory_section_and_the_empty_project_section() {
        let text = built_in();
        assert!(text.starts_with("<!-- factory-rules begin version="));
        assert!(text.contains("## Documentation comes first"));
        assert!(text.ends_with(factory_domain::project_rules::DEFAULT_PROJECT_SECTION));
    }
}
