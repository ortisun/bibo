//! The skills the specification writer may see, built from the Spec Kit installed in the protected
//! checkout.
//!
//! The Claude Code adapter gives the specification stage exactly the skills of a
//! [`SkillBundle`] and none at all when it holds no bundle, so the stage was unavailable with the
//! real tool until something built one. [`bundle_for_writer`] builds it, and the rules are these.
//!
//! * **Which skills.** The policy allows four (`agent_stage_profiles`, profile `specification`:
//!   `speckit.constitution`, `speckit.specify`, `speckit.clarify`, `speckit.checklist`) and denies
//!   six. The writer's manifest names the ones the writer uses (`speckit.specify`,
//!   `speckit.clarify`, `speckit.checklist`: the constitution is a precondition of the repository
//!   that a person owns in Slice 1). The bundle holds the skills the manifest names, and a skill the
//!   policy does not allow, or denies, is refused by its id. Deny wins over allow.
//! * **From where.** From the installation in the **protected checkout** (the one the policies are
//!   read from), never from the repository under change, which a job's author controls.
//! * **Under which name.** The policy's ids are dotted. The directory of a skill is
//!   `speckit<separator><name>`, with the separator read from `.specify/integration.json` and not
//!   written here.
//! * **Whether it is the pinned one.** Every file must hash to the value the pinned manifest of the
//!   Spec Kit adapter records ([`factory_spec_adapter::pinned::CLAUDE_SKILLS`]). A file that does
//!   not is refused by the name of its skill, and nothing of it is read into a bundle.
//!
//! The adapter writes the bundle into the run's home and invokes the skill by the spelling the
//! host uses (`/speckit-specify` on Claude Code). Nothing here runs a skill.

use std::path::Path;

use factory_contracts::registry::FileAgentRegistry;
use factory_domain::policy::SecurityPolicy;
use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::registry::{AgentRegistry, VersionReq};
use factory_runtime::{PinnedSkill, SkillBundle, SkillFile};
use factory_spec_adapter::invocation::{
    Host, IntegrationConfig, Recognised, recognise, skill_name,
};
use factory_spec_adapter::pinned::CLAUDE_SKILLS;

/// The profile of the policy that governs the specification stage.
const PROFILE: &str = "specification";

/// Why a bundle cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecSkillsError {
    /// The writer's manifest could not be read.
    #[error("the manifest of the specification writer cannot be read: {0}")]
    Manifest(String),
    /// The policy has no specification profile with skills, so nothing is allowed.
    #[error("the security policy names no skills for the specification stage")]
    NoProfile,
    /// A skill the policy does not allow, or denies. The id is the one that was offered.
    #[error("the skill {0:?} is not one of the skills the policy allows the specification stage")]
    NotAllowed(String),
    /// The installation file in the protected checkout cannot be used.
    #[error("the Spec Kit installation cannot be used: {0}")]
    Installation(String),
    /// A skill file is missing or unreadable, with its path.
    #[error("the skill file {0} cannot be read")]
    Unreadable(String),
    /// A skill file is not the pinned one. The name is the skill's directory.
    #[error("the skill {0} is not the pinned file")]
    Modified(String),
    /// The pinned manifest has no entry for the skill, so there is nothing to check it against.
    #[error("the skill {0} has no pinned hash")]
    NotPinned(String),
    /// The skills do not make a bundle.
    #[error("the skills do not make a bundle: {0}")]
    Bundle(String),
}

/// The skill ids a manifest offers, in its order.
fn offered_by(definitions_root: &Path, writer: &str) -> Result<Vec<String>, SpecSkillsError> {
    let registry = FileAgentRegistry::load(definitions_root)
        .map_err(|error| SpecSkillsError::Manifest(error.to_string()))?;
    let id = Slug::parse(writer).map_err(|error| SpecSkillsError::Manifest(error.to_string()))?;
    let manifest = registry
        .manifest(&id, &VersionReq::Any)
        .map_err(|error| SpecSkillsError::Manifest(error.to_string()))?;
    Ok(manifest
        .skills
        .as_slice()
        .iter()
        .map(|skill| skill.id.as_str().to_owned())
        .collect())
}

/// The bundle of the skills the manifest of `writer` names, built from the Spec Kit installed in
/// `protected_checkout` and checked against the policy.
///
/// # Errors
/// [`SpecSkillsError`].
pub fn bundle_for_writer(
    definitions_root: &Path,
    protected_checkout: &Path,
    policy: &SecurityPolicy,
    writer: &str,
) -> Result<SkillBundle, SpecSkillsError> {
    let offered = offered_by(definitions_root, writer)?;
    let ids: Vec<&str> = offered.iter().map(String::as_str).collect();
    bundle_from_ids(protected_checkout, policy, &ids)
}

/// The bundle of the skills with these canonical ids, built from the Spec Kit installed in
/// `protected_checkout`. Every id must be allowed by the policy and not denied by it.
///
/// # Errors
/// [`SpecSkillsError`].
pub fn bundle_from_ids(
    protected_checkout: &Path,
    policy: &SecurityPolicy,
    ids: &[&str],
) -> Result<SkillBundle, SpecSkillsError> {
    let rules = policy
        .agent_stage_profiles
        .profiles
        .iter()
        .find(|profile| profile.id == PROFILE)
        .and_then(|profile| profile.skills.as_ref())
        .ok_or(SpecSkillsError::NoProfile)?;
    for id in ids {
        let allowed = rules.allowed.iter().any(|skill| skill.id == *id);
        let denied = rules.denied.iter().any(|skill| skill == id);
        if !allowed || denied {
            return Err(SpecSkillsError::NotAllowed((*id).to_owned()));
        }
    }

    let integration_path = protected_checkout.join(factory_spec_adapter::integrity::INTEGRATION);
    let shown = integration_path.display().to_string();
    let integration = std::fs::read(&integration_path)
        .map_err(|error| SpecSkillsError::Installation(format!("{shown}: {}", error.kind())))
        .and_then(|bytes| {
            IntegrationConfig::parse(&bytes)
                .map_err(|error| SpecSkillsError::Installation(format!("{shown}: {error}")))
        })?;
    // The adapter that reads this bundle is the Claude Code one, and the pinned hashes are those of
    // its skill files.
    if integration.host != Host::ClaudeCode {
        return Err(SpecSkillsError::Installation(format!(
            "{shown}: the default integration is not Claude Code"
        )));
    }

    let mut skills = Vec::with_capacity(ids.len());
    for id in ids {
        // The ids were checked against the policy above. The adapter's own reading of a prompt
        // says which of its four operations the dotted id stands for, and the pinned table gives
        // the directory of that operation under the separator the installation uses, so this
        // crate holds no part of the layout.
        let operation = match recognise(&format!("/{}", id.replace('.', "-"))) {
            Some(Recognised::Allowed(operation)) => operation,
            _ => return Err(SpecSkillsError::NotAllowed((*id).to_owned())),
        };
        let name = skill_name(operation);
        let suffix = format!("{}{name}/SKILL.md", integration.separator.as_char());
        let root = format!("{}/", Host::ClaudeCode.skill_root());
        let pinned = CLAUDE_SKILLS
            .iter()
            .find(|file| file.path.starts_with(&root) && file.path.ends_with(&suffix))
            .ok_or_else(|| SpecSkillsError::NotPinned((*id).to_owned()))?;
        let relative = pinned.path.to_owned();
        let directory = relative
            .strip_prefix(&root)
            .and_then(|rest| rest.strip_suffix("/SKILL.md"))
            .unwrap_or_default()
            .to_owned();
        let bytes = std::fs::read(protected_checkout.join(&relative))
            .map_err(|_| SpecSkillsError::Unreadable(relative.clone()))?;
        let sha256 = Sha256Digest::parse(&format!("sha256:{}", pinned.sha256))
            .map_err(|_| SpecSkillsError::NotPinned(directory.clone()))?;
        if Sha256Digest::of(&bytes) != sha256 {
            return Err(SpecSkillsError::Modified(directory));
        }
        let skill = PinnedSkill::new(
            &directory,
            vec![SkillFile {
                path: "SKILL.md".to_owned(),
                bytes,
                sha256,
            }],
        )
        .map_err(|error| SpecSkillsError::Bundle(error.to_string()))?;
        skills.push(skill);
    }
    SkillBundle::new(skills).map_err(|error| SpecSkillsError::Bundle(error.to_string()))
}
