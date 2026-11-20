//! Tool grants and per-stage skill profiles (`tools` and `agent_stage_profiles` of
//! `policies/security.yaml`).
//!
//! # Grants are an intersection
//!
//! A stage holds a tool only if all of these hold, and a deny anywhere is final:
//!
//! * the agent's manifest lists the tool in `allowed_tools`;
//! * the stage declares that it needs the tool;
//! * the tool is not in `never_grantable`;
//! * the policy has an entry for it, and the entry is not disabled;
//! * the agent's role is on the entry's `roles` (or the entry says `"*"`);
//! * the tool may run where it will run: in one of the entry's sandbox profiles, or, for an
//!   entry with no profile, in the control plane gateway.
//!
//! So [`GrantSet::granted`] is a subset of the manifest's tools whatever the other inputs are. An
//! unknown tool is denied, never granted by default. An agent cannot ask for a grant
//! ([`ToolPolicy::request_grant`] refuses it), because grants are issued by the policy engine
//! only (`tools.agents_may_self_grant: false`, which the engine will not run without).
//!
//! # Skills
//!
//! [`ToolPolicy::check_skill`] decides whether a stage may invoke a skill or slash command, in
//! every spelling an agent CLI accepts (`/name-part`, `$name-part`, `name.part`). The
//! profile comes from the stage kind. A skill on the profile's `denied` list is refused even if
//! it is also on `allowed` (deny wins), and so is every skill when the profile disables them.

use std::collections::{BTreeMap, BTreeSet};

use crate::vocabulary::StageKind;

use super::security::{HumanGate, SecurityPolicy, ToolRisk};
use super::{BuildError, RuleRef, SandboxProfileKind};

/// The most tools one grant request considers. A stage declares a handful.
const MAX_REQUESTED_TOOLS: usize = 256;

/// The per-task caps of a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolCaps {
    /// The most calls in one task.
    pub max_calls_per_task: u64,
    /// The largest result, in bytes.
    pub max_result_bytes: u64,
    /// The longest call, in seconds.
    pub timeout_s: u64,
}

/// A tool a stage holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The tool id, such as `fs.read`.
    pub tool: String,
    /// How risky it is.
    pub risk: ToolRisk,
    /// Whether a human must confirm each call or the whole task.
    pub human_gate: HumanGate,
    /// Its caps, when the policy sets them.
    pub caps: Option<ToolCaps>,
}

/// Why a tool was not granted or a call was refused. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ToolDenial {
    /// The manifest does not list the tool.
    #[error("the agent manifest does not allow the tool")]
    NotInManifest,
    /// The tool is on the never-grantable list.
    #[error("the tool can never be granted")]
    NeverGrantable,
    /// The policy has no entry for the tool.
    #[error("the tool is not registered")]
    UnknownTool,
    /// The entry is disabled (a break-glass tool).
    #[error("the tool is disabled")]
    Disabled,
    /// The agent's role is not on the entry's list.
    #[error("the role may not hold the tool")]
    RoleNotAllowed,
    /// The tool does not run in this sandbox profile, or runs only in the control plane.
    #[error("the tool does not run in this profile")]
    ProfileNotAllowed,
    /// An agent asked for a grant. Only the policy engine grants.
    #[error("an agent cannot grant itself a tool")]
    SelfGrant,
    /// The stage does not hold the tool.
    #[error("the stage does not hold the tool")]
    NotGranted,
    /// The call count reached the cap for the task.
    #[error("the call cap for the task is reached")]
    CapReached,
}

/// The answer for one tool call or grant request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolVerdict {
    /// Allowed. A `per_call` human gate still needs its decision before the call runs.
    Allowed {
        /// The gate that applies.
        human_gate: HumanGate,
    },
    /// Refused.
    Denied {
        /// Why.
        reason: ToolDenial,
        /// The tool entry or list behind it.
        rule: RuleRef,
    },
}

/// The tools a stage holds, and why the others are not held.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantSet {
    granted: BTreeMap<String, Grant>,
    denied: Vec<(String, ToolDenial)>,
}

impl GrantSet {
    /// The tools held, by id.
    #[must_use]
    pub fn granted(&self) -> &BTreeMap<String, Grant> {
        &self.granted
    }

    /// The tools asked for and not granted, each with its reason.
    #[must_use]
    pub fn denied(&self) -> &[(String, ToolDenial)] {
        &self.denied
    }

    /// True when the stage holds the tool.
    #[must_use]
    pub fn holds(&self, tool: &str) -> bool {
        self.granted.contains_key(tool)
    }
}

/// What a stage asks for.
#[derive(Debug, Clone, Copy)]
pub struct GrantRequest<'a> {
    /// The tools the agent manifest allows.
    pub manifest_allowed: &'a [String],
    /// The tools the stage declares it needs.
    pub stage_needs: &'a [String],
    /// The agent's role id.
    pub role: &'a str,
    /// Where the tools run. `None` means the control plane gateway.
    pub profile: Option<SandboxProfileKind>,
}

/// Who is asking for a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requester {
    /// The policy engine, deciding from the manifest and the stage.
    PolicyEngine,
    /// An agent, by tool call, output text or an edit of its own manifest.
    Agent,
}

#[derive(Debug)]
struct Entry {
    risk: ToolRisk,
    enabled: bool,
    profiles: BTreeSet<SandboxProfileKind>,
    roles: BTreeSet<String>,
    human_gate: HumanGate,
    caps: Option<ToolCaps>,
}

/// What a skill invocation is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillVerdict {
    /// The skill may run in this stage. `writes` are the globs it may write.
    Allowed {
        /// The write globs the profile names for the skill.
        writes: Vec<String>,
        /// True when the skill writes a protected path and so needs the protected-path exception
        /// flow before it runs.
        protected_path_exception_required: bool,
        /// The profile.
        profile: String,
    },
    /// The skill may not run.
    Denied {
        /// Why.
        reason: SkillDenial,
        /// The stage profile.
        rule: RuleRef,
    },
}

/// Why a skill was refused. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SkillDenial {
    /// The profile disables skills and slash commands.
    #[error("the stage profile disables skills")]
    SkillsDisabled,
    /// The profile names the skill as denied.
    #[error("the stage profile denies the skill")]
    Denied,
    /// The skill is not on the profile's allow list.
    #[error("the stage profile does not allow the skill")]
    NotAllowed,
    /// The text is empty or too long to be a skill.
    #[error("the skill name is not valid")]
    Malformed,
}

#[derive(Debug)]
struct SkillProfile {
    id: String,
    stage_kinds: BTreeSet<String>,
    allowlist_only: bool,
    allowed: BTreeMap<String, (Vec<String>, bool)>,
    denied: BTreeSet<String>,
}

/// The tool rules of one security policy.
#[derive(Debug)]
pub struct ToolPolicy {
    never_grantable: BTreeSet<String>,
    entries: BTreeMap<String, Entry>,
    skill_profiles: Vec<SkillProfile>,
    default_skill_profile: usize,
}

/// Writes a skill spelling in the one form the policy ids are compared in: lower case, without a
/// leading `/` or `$`, and with `-`, `_` and `:` turned into `.`. The policy ids go through the
/// same function, so a skill the policy names matches in every spelling an agent CLI accepts, and
/// a spelling that does not reduce to a listed id matches nothing.
fn canonical_skill(spelling: &str) -> Option<String> {
    let trimmed = spelling.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || trimmed.chars().any(char::is_control) {
        return None;
    }
    let stripped = trimmed.strip_prefix(['/', '$']).unwrap_or(trimmed);
    Some(
        stripped
            .to_lowercase()
            .chars()
            .map(|c| if matches!(c, '-' | '_' | ':') { '.' } else { c })
            .collect(),
    )
}

impl ToolPolicy {
    /// Reads the tool rules of `policy`.
    ///
    /// # Errors
    /// A [`BuildError`] when the policy lets agents grant themselves tools, lists a tool twice,
    /// names a profile or stage profile that does not exist, or names a profile twice.
    pub fn from_policy(policy: &SecurityPolicy) -> Result<Self, BuildError> {
        if policy.tools.agents_may_self_grant {
            return Err(BuildError::ProtectionDisabled {
                key: "tools.agents_may_self_grant",
                found: "true".to_owned(),
            });
        }
        if policy.tools.grant_authority != "policy_engine" {
            return Err(BuildError::UnknownValue {
                key: "tools.grant_authority",
                found: policy.tools.grant_authority.clone(),
            });
        }
        let mut entries = BTreeMap::new();
        for e in &policy.tools.entries {
            let mut profiles = BTreeSet::new();
            for name in &e.profiles {
                profiles.insert(SandboxProfileKind::parse(name).ok_or_else(|| {
                    BuildError::UnknownValue {
                        key: "tools.entries.profiles",
                        found: name.clone(),
                    }
                })?);
            }
            let entry = Entry {
                risk: e.risk,
                enabled: e.enabled.unwrap_or(true),
                profiles,
                roles: e.roles.iter().cloned().collect(),
                human_gate: e.human_gate,
                caps: e.limits.as_ref().map(|l| ToolCaps {
                    max_calls_per_task: l.max_calls_per_task,
                    max_result_bytes: l.max_result_bytes,
                    timeout_s: l.timeout_s,
                }),
            };
            if entries.insert(e.id.clone(), entry).is_some() {
                return Err(BuildError::Duplicate {
                    what: "tool",
                    name: e.id.clone(),
                });
            }
        }

        let mut skill_profiles = Vec::new();
        let mut default_skill_profile = None;
        for p in &policy.agent_stage_profiles.profiles {
            let allowlist_only = match p.skills_and_slash_commands.as_str() {
                "disabled" => false,
                "allowlist_only" => true,
                other => {
                    return Err(BuildError::UnknownValue {
                        key: "agent_stage_profiles.profiles.skills_and_slash_commands",
                        found: other.to_owned(),
                    });
                }
            };
            if skill_profiles.iter().any(|s: &SkillProfile| s.id == p.id) {
                return Err(BuildError::Duplicate {
                    what: "stage profile",
                    name: p.id.clone(),
                });
            }
            if p.id == policy.agent_stage_profiles.default_profile {
                default_skill_profile = Some(skill_profiles.len());
            }
            let skills = p.skills.as_ref();
            if skills.is_some_and(|s| !s.deny_wins_over_allow) {
                return Err(BuildError::ProtectionDisabled {
                    key: "agent_stage_profiles.profiles.skills.deny_wins_over_allow",
                    found: "false".to_owned(),
                });
            }
            skill_profiles.push(SkillProfile {
                id: p.id.clone(),
                stage_kinds: p.applies_to_stage_kinds.iter().cloned().collect(),
                allowlist_only,
                allowed: skills
                    .map(|s| {
                        s.allowed
                            .iter()
                            .map(|a| {
                                (
                                    canonical_skill(&a.id).unwrap_or_default(),
                                    (
                                        a.writes.iter().map(|g| g.0.clone()).collect(),
                                        a.protected_path_exception_required.unwrap_or(false),
                                    ),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                denied: skills
                    .map(|s| s.denied.iter().filter_map(|d| canonical_skill(d)).collect())
                    .unwrap_or_default(),
            });
        }
        let default_skill_profile =
            default_skill_profile.ok_or_else(|| BuildError::UnknownValue {
                key: "agent_stage_profiles.default_profile",
                found: policy.agent_stage_profiles.default_profile.clone(),
            })?;

        Ok(Self {
            never_grantable: policy.tools.never_grantable.iter().cloned().collect(),
            entries,
            skill_profiles,
            default_skill_profile,
        })
    }

    /// Why `tool` cannot be held by a stage with these facts, or `None` when it can.
    fn refusal(
        &self,
        tool: &str,
        role: &str,
        profile: Option<SandboxProfileKind>,
    ) -> Result<&Entry, ToolDenial> {
        if self.never_grantable.contains(tool) {
            return Err(ToolDenial::NeverGrantable);
        }
        let entry = self.entries.get(tool).ok_or(ToolDenial::UnknownTool)?;
        if !entry.enabled {
            return Err(ToolDenial::Disabled);
        }
        if !entry.roles.contains("*") && !entry.roles.contains(role) {
            return Err(ToolDenial::RoleNotAllowed);
        }
        let runs_here = match profile {
            Some(p) => entry.profiles.contains(&p),
            None => entry.profiles.is_empty(),
        };
        if !runs_here {
            return Err(ToolDenial::ProfileNotAllowed);
        }
        Ok(entry)
    }

    /// The tools a stage holds: the intersection described in the module notes.
    #[must_use]
    pub fn grant(&self, request: &GrantRequest<'_>) -> GrantSet {
        let manifest: BTreeSet<&str> = request
            .manifest_allowed
            .iter()
            .map(String::as_str)
            .collect();
        let mut set = GrantSet::default();
        let mut seen = BTreeSet::new();
        for tool in request.stage_needs.iter().take(MAX_REQUESTED_TOOLS) {
            if !seen.insert(tool.as_str()) {
                continue;
            }
            if !manifest.contains(tool.as_str()) {
                set.denied.push((tool.clone(), ToolDenial::NotInManifest));
                continue;
            }
            match self.refusal(tool, request.role, request.profile) {
                Ok(entry) => {
                    set.granted.insert(
                        tool.clone(),
                        Grant {
                            tool: tool.clone(),
                            risk: entry.risk,
                            human_gate: entry.human_gate,
                            caps: entry.caps,
                        },
                    );
                }
                Err(reason) => set.denied.push((tool.clone(), reason)),
            }
        }
        set
    }

    /// Decides a request for a grant. Only the policy engine grants; an agent asking, by tool
    /// call, by output text or by editing its manifest, is refused.
    #[must_use]
    pub fn request_grant(&self, from: Requester, tool: &str) -> ToolVerdict {
        match from {
            Requester::Agent => ToolVerdict::Denied {
                reason: ToolDenial::SelfGrant,
                rule: RuleRef::new("tools", "agents_may_self_grant"),
            },
            Requester::PolicyEngine => match self.refusal(tool, "*", None) {
                Ok(entry) => ToolVerdict::Allowed {
                    human_gate: entry.human_gate,
                },
                Err(ToolDenial::NeverGrantable) => ToolVerdict::Denied {
                    reason: ToolDenial::NeverGrantable,
                    rule: RuleRef::new("tools", "never_grantable"),
                },
                Err(reason) => ToolVerdict::Denied {
                    reason,
                    rule: RuleRef::new("tools.entries", tool),
                },
            },
        }
    }

    /// Decides one call of a tool by a stage holding `grants`, which has made `calls_so_far`
    /// calls of it in this task.
    #[must_use]
    pub fn check_call(&self, grants: &GrantSet, tool: &str, calls_so_far: u64) -> ToolVerdict {
        if self.never_grantable.contains(tool) {
            return ToolVerdict::Denied {
                reason: ToolDenial::NeverGrantable,
                rule: RuleRef::new("tools", "never_grantable"),
            };
        }
        let Some(grant) = grants.granted.get(tool) else {
            let reason = if self.entries.contains_key(tool) {
                ToolDenial::NotGranted
            } else {
                ToolDenial::UnknownTool
            };
            return ToolVerdict::Denied {
                reason,
                rule: RuleRef::new("tools", "default_action"),
            };
        };
        if let Some(caps) = grant.caps
            && calls_so_far >= caps.max_calls_per_task
        {
            return ToolVerdict::Denied {
                reason: ToolDenial::CapReached,
                rule: RuleRef::new("tools.entries", tool),
            };
        }
        ToolVerdict::Allowed {
            human_gate: grant.human_gate,
        }
    }

    /// Decides whether a stage of this kind may invoke a skill or slash command, written in any
    /// spelling.
    #[must_use]
    pub fn check_skill(&self, stage: StageKind, spelling: &str) -> SkillVerdict {
        let profile = self
            .skill_profiles
            .iter()
            .find(|p| p.stage_kinds.contains(stage.as_str()))
            .or_else(|| self.skill_profiles.get(self.default_skill_profile))
            .or_else(|| self.skill_profiles.first());
        let Some(profile) = profile else {
            return SkillVerdict::Denied {
                reason: SkillDenial::SkillsDisabled,
                rule: RuleRef::new("agent_stage_profiles", "default_profile"),
            };
        };
        let rule = RuleRef::new("agent_stage_profiles", profile.id.clone());
        let Some(id) = canonical_skill(spelling) else {
            return SkillVerdict::Denied {
                reason: SkillDenial::Malformed,
                rule,
            };
        };
        if profile.denied.contains(&id) {
            return SkillVerdict::Denied {
                reason: SkillDenial::Denied,
                rule,
            };
        }
        if !profile.allowlist_only {
            return SkillVerdict::Denied {
                reason: SkillDenial::SkillsDisabled,
                rule,
            };
        }
        match profile.allowed.get(&id) {
            Some((writes, exception)) => SkillVerdict::Allowed {
                writes: writes.clone(),
                protected_path_exception_required: *exception,
                profile: profile.id.clone(),
            },
            None => SkillVerdict::Denied {
                reason: SkillDenial::NotAllowed,
                rule,
            },
        }
    }
}
