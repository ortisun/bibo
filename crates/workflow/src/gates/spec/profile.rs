//! The stage profile check: no skill outside the profile ran or was visible, and no file of one
//! appeared.
//!
//! The rules come from the policy (`agent_stage_profiles`), so the lists of allowed and denied
//! skills and of forbidden files are data that a reviewer changes in one place. This module has
//! no list of its own. A denied skill id in the policy is written `<namespace>.<name>`; the host
//! spells it with a hyphen or a dot, and the check finds the namespace followed by one of those
//! and a name.
//!
//! What counts as a violation, from the policy's `detection` list:
//!
//! * a skill that is not in the allowed list appears in a denial or in the event stream of the
//!   run: it was called, typed as a slash command, or listed as visible;
//! * a file that only a denied skill writes exists after the run;
//! * a path outside the writes of the four skills changed.
//!
//! The check cannot be waived. A violation blocks the stage run, discards the output of the
//! agent and is recorded as a forbidden skill, and nobody is asked to override it.

use std::collections::BTreeSet;

use factory_domain::policy::SecurityPolicy;
use factory_ports::paths::{RepoGlob, RepoPath};
use serde_json::Value;

use super::Finding;

/// What a skill mention was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MentionKind {
    /// The skill was called, or typed as a command.
    Invoked,
    /// The skill was listed as visible to the agent.
    Visible,
    /// The runtime reported a denied call to the skill.
    Denied,
}

/// A skill outside the allowed list that turned up somewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillMention {
    /// How it turned up.
    pub kind: MentionKind,
    /// The name after the namespace.
    pub name: String,
}

/// The rules of one stage profile, read from the policy.
#[derive(Debug, Clone)]
pub struct ProfileRules {
    namespace: String,
    allowed: BTreeSet<String>,
    forbidden: Vec<RepoGlob>,
    writes: Vec<RepoGlob>,
}

/// What the stage saw after the run.
#[derive(Debug, Clone, Copy)]
pub struct ProfileEvidence<'a> {
    /// The tool calls the runtime reported as denied: the tool and the reason.
    pub denials: &'a [(String, String)],
    /// The transcripts of the runs, as stored.
    pub transcripts: &'a [Vec<u8>],
    /// The paths the audited ingestion reported as changed.
    pub changed: &'a [String],
    /// The paths that exist in the commit under the feature directory.
    pub committed: &'a [String],
}

fn name_after<'a>(text: &'a str, namespace: &str) -> Vec<&'a str> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(namespace) {
        let after = &rest[at + namespace.len()..];
        let mut chars = after.chars();
        if matches!(chars.next(), Some('-' | '.' | '_')) {
            let name: &str = {
                let tail = &after[1..];
                let end = tail
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(tail.len());
                &tail[..end]
            };
            if !name.is_empty() {
                names.push(name);
            }
        }
        rest = after;
    }
    names
}

impl ProfileRules {
    /// The rules of the profile that applies to `stage`, from the policy.
    #[must_use]
    pub fn from_policy(policy: &SecurityPolicy, stage: &str) -> Option<Self> {
        let profile = policy
            .agent_stage_profiles
            .profiles
            .iter()
            .find(|p| p.applies_to_stage_kinds.iter().any(|k| k == stage))?;
        let skills = profile.skills.as_ref()?;
        let namespace = skills.allowed.first()?.id.split('.').next()?.to_owned();
        let allowed = skills
            .allowed
            .iter()
            .filter_map(|s| s.id.split_once('.').map(|(_, name)| name.to_owned()))
            .collect();
        let glob = |text: &str| RepoGlob::new(text).ok();
        let forbidden = profile
            .forbidden_artifacts_after_run
            .as_ref()?
            .iter()
            .filter_map(|g| glob(g.pattern()))
            .collect();
        let writes = skills
            .allowed
            .iter()
            .flat_map(|s| s.writes.iter())
            .filter_map(|g| glob(g.pattern()))
            .collect();
        Some(Self {
            namespace,
            allowed,
            forbidden,
            writes,
        })
    }

    fn outside(&self, text: &str) -> Vec<String> {
        name_after(text, &self.namespace)
            .into_iter()
            .filter(|name| !self.allowed.contains(*name))
            .map(str::to_owned)
            .collect()
    }

    /// Reads a transcript for skills outside the allowed list. A line that is not JSON is read
    /// as plain text only when it starts with an invocation. This reads the structure of the
    /// events and not every word, because a skill file read by the agent may name the next skill
    /// in its own text.
    #[must_use]
    pub fn scan_transcript(&self, bytes: &[u8]) -> Vec<SkillMention> {
        scan_transcript(self, bytes)
    }

    /// Checks the evidence of a run.
    #[must_use]
    pub fn check(&self, evidence: &ProfileEvidence<'_>) -> Vec<Finding> {
        let mut found = Vec::new();
        let mut seen = BTreeSet::new();
        let mut note = |kind: &'static str, name: String, found: &mut Vec<Finding>| {
            if seen.insert((kind, name.clone())) {
                let message = match kind {
                    "forbidden_skill_invoked" => format!(
                        "The skill {name} is outside the profile of this stage and was called or denied during the run."
                    ),
                    _ => format!(
                        "The skill {name} is outside the profile of this stage and was visible to the agent."
                    ),
                };
                found.push(Finding::new(kind, message));
            }
        };
        for (tool, reason) in evidence.denials {
            for name in self.outside(tool).into_iter().chain(self.outside(reason)) {
                note("forbidden_skill_invoked", name, &mut found);
            }
        }
        for bytes in evidence.transcripts {
            for mention in self.scan_transcript(bytes) {
                let kind = match mention.kind {
                    MentionKind::Visible => "skill_visible_outside_profile",
                    MentionKind::Invoked | MentionKind::Denied => "forbidden_skill_invoked",
                };
                note(kind, mention.name, &mut found);
            }
        }
        for path in evidence.committed.iter().chain(evidence.changed) {
            let Ok(repo_path) = RepoPath::new(path) else {
                continue;
            };
            if self.forbidden.iter().any(|g| g.matches(&repo_path))
                && seen.insert(("forbidden_artifact_present", path.clone()))
            {
                found.push(Finding::new(
                    "forbidden_artifact_present",
                    format!("{path} exists, and only a skill outside the profile writes it."),
                ));
            }
        }
        for path in evidence.changed {
            let Ok(repo_path) = RepoPath::new(path) else {
                continue;
            };
            let allowed = self.writes.iter().any(|g| g.matches(&repo_path));
            let already = self.forbidden.iter().any(|g| g.matches(&repo_path));
            if !allowed && !already && seen.insert(("write_outside_profile", path.clone())) {
                found.push(Finding::new(
                    "write_outside_profile",
                    format!("{path} changed, and no skill of this stage may write it."),
                ));
            }
        }
        found
    }
}

fn strings_of(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|v| strings_of(v, out)),
        Value::Object(map) => map.values().for_each(|v| strings_of(v, out)),
        _ => {}
    }
}

/// Reads a transcript for skills outside the allowed list.
#[must_use]
pub fn scan_transcript(rules: &ProfileRules, bytes: &[u8]) -> Vec<SkillMention> {
    let mut found = Vec::new();
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            // Not an event. Only a line that is itself an invocation counts.
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix(['/', '$']) {
                for name in rules.outside(rest) {
                    if rest.starts_with(&rules.namespace) {
                        found.push(SkillMention {
                            kind: MentionKind::Invoked,
                            name,
                        });
                    }
                }
            }
            continue;
        };
        let kind = event.get("type").and_then(Value::as_str);
        match kind {
            Some("system") => {
                let mut listed = Vec::new();
                for key in ["skills", "slash_commands"] {
                    if let Some(list) = event.get(key) {
                        strings_of(list, &mut listed);
                    }
                }
                for entry in listed {
                    for name in rules.outside(&entry) {
                        found.push(SkillMention {
                            kind: MentionKind::Visible,
                            name,
                        });
                    }
                }
            }
            Some("assistant") => {
                let blocks = event
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for block in blocks {
                    if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                        let mut strings = Vec::new();
                        if let Some(input) = block.get("input") {
                            strings_of(input, &mut strings);
                        }
                        if block.get("name").and_then(Value::as_str) == Some("Skill") {
                            for s in strings {
                                for name in rules.outside(&s) {
                                    found.push(SkillMention {
                                        kind: MentionKind::Invoked,
                                        name,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Some("user") => {
                let mut strings = Vec::new();
                if let Some(content) = event.pointer("/message/content") {
                    strings_of(content, &mut strings);
                }
                for s in strings {
                    let trimmed = s.trim_start();
                    if let Some(rest) = trimmed.strip_prefix(['/', '$'])
                        && rest.starts_with(&rules.namespace)
                    {
                        for name in rules.outside(rest) {
                            found.push(SkillMention {
                                kind: MentionKind::Invoked,
                                name,
                            });
                        }
                    }
                }
            }
            Some("result") => {
                if let Some(denials) = event.get("permission_denials") {
                    let mut strings = Vec::new();
                    strings_of(denials, &mut strings);
                    for s in strings {
                        for name in rules.outside(&s) {
                            found.push(SkillMention {
                                kind: MentionKind::Denied,
                                name,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    found
}
