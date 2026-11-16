//! What reached the arguments of a Spec Kit skill, read from the run's transcript
//! (`skill-arguments-fixed`, reported as `skill_arguments_leak`).
//!
//! Spec Kit reads the text after a skill name as the user's own instruction, so the factory puts
//! only a fixed instruction there and hands the request over in a file. This check proves it on
//! the invocation itself. The `Input` line of `spec.md` is not evidence: it is text the model
//! wrote, and a real model restates the request on it (seen on the run of 2026-11-15).
//!
//! # Where the invocation is in a transcript
//!
//! Read from Claude Code 2.1.325 (`crates/workflow/tests/fixtures/transcripts`):
//!
//! * A typed command is a `user` event with `"isReplay": true` whose content is the text
//!   `<command-message>…</command-message>\n<command-name>/speckit-specify</command-name>\n<command-args>…</command-args>`.
//!   Claude Code writes this event only when it runs with `--input-format=stream-json
//!   --replay-user-messages`. With a prompt on plain standard input it writes no event for the
//!   prompt at all, so the transcript holds no invocation and this check fails closed.
//! * A call the model makes is an `assistant` event with a `tool_use` block named `Skill` whose
//!   input is `{"skill": "speckit-plan", "args": "…"}`.
//!
//! Nothing else counts. A tool result or the expanded text of a skill (a `user` event that is not
//! a replay) can quote an invocation, and a file the agent reads is not a call. The scripted
//! runtime of the testkit stores its transcript as one JSON array of the same events; that shape is
//! read too.
//!
//! # The rule
//!
//! For every skill run the stage recorded, the transcript of that run must show the invocation
//! the provider sent exactly once, with arguments equal to the fixed instruction once whitespace
//! is squashed, and no other invocation of a skill of the namespace. It fails closed: a run
//! without a transcript, a transcript that cannot be read, a transcript that shows no invocation,
//! and a real provider that does not say what it invoked are all failures. The arguments found
//! are never copied into a finding: they may be the untrusted text this check is there to catch.

use factory_domain::values::Sha256Digest;
use serde_json::Value;

use super::Finding;

/// The code of every finding of this check.
pub const CODE: &str = "skill_arguments_leak";

/// One skill run of the stage, as the stage recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationRecord {
    /// The operation, such as `specify`.
    pub operation: String,
    /// The skill the provider invoked, as the host names it (`speckit-specify`). `None` when a
    /// real provider did not say.
    pub skill: Option<String>,
    /// The arguments the provider sent: the fixed instruction.
    pub arguments: String,
    /// The hash of the run's stored transcript, when one was stored.
    pub transcript: Option<String>,
}

/// How an invocation turned up in a transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// A command typed in the prompt, as the host replayed it.
    Typed,
    /// A call of the `Skill` tool by the model.
    SkillTool,
}

/// An invocation of a skill of the namespace, found in a transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenInvocation {
    /// How it turned up.
    pub channel: Channel,
    /// The skill, without the sigil.
    pub skill: String,
    /// The arguments, as the host recorded them.
    pub arguments: String,
}

fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// True when `skill` is the namespace followed by a separator and a name.
fn in_namespace(skill: &str, namespace: &str) -> bool {
    skill
        .strip_prefix(namespace)
        .and_then(|rest| rest.strip_prefix(['-', '.', '_', ':']))
        .is_some_and(|name| !name.is_empty())
}

fn between<'a>(text: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = text.find(open)? + open.len();
    let end = text.rfind(close)?;
    (end >= start).then(|| &text[start..end])
}

/// The invocation a replayed command holds, when it holds one.
fn typed(content: &str) -> Option<(String, String)> {
    let name = between(content, "<command-name>", "</command-name>")?;
    let name = name.trim().trim_start_matches(['/', '$']).to_owned();
    let arguments = between(content, "<command-args>", "</command-args>")
        .unwrap_or("")
        .to_owned();
    Some((name, arguments))
}

fn events(bytes: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(bytes);
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(text.trim()) {
        return items;
    }
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(Value::is_object)
        .collect()
}

/// Every invocation of a skill of `namespace` in a transcript, in order.
#[must_use]
pub fn invocations_in(namespace: &str, bytes: &[u8]) -> Vec<SeenInvocation> {
    let mut found = Vec::new();
    for event in events(bytes) {
        match event.get("type").and_then(Value::as_str) {
            Some("user") if event.get("isReplay").and_then(Value::as_bool) == Some(true) => {
                if let Some(content) = event.pointer("/message/content").and_then(Value::as_str)
                    && let Some((skill, arguments)) = typed(content)
                    && in_namespace(&skill, namespace)
                {
                    found.push(SeenInvocation {
                        channel: Channel::Typed,
                        skill,
                        arguments,
                    });
                }
            }
            Some("assistant") => {
                let blocks = event
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for block in blocks {
                    if block.get("type").and_then(Value::as_str) != Some("tool_use")
                        || block.get("name").and_then(Value::as_str) != Some("Skill")
                    {
                        continue;
                    }
                    let skill = block
                        .pointer("/input/skill")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim_start_matches(['/', '$'])
                        .to_owned();
                    if in_namespace(&skill, namespace) {
                        found.push(SeenInvocation {
                            channel: Channel::SkillTool,
                            skill,
                            arguments: block
                                .pointer("/input/args")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    found
}

/// Checks every recorded skill run against its transcript. `transcripts` are the stored
/// transcripts as read back; each record finds its own by hash.
#[must_use]
pub fn check(
    namespace: &str,
    records: &[InvocationRecord],
    transcripts: &[Vec<u8>],
) -> Vec<Finding> {
    let mut found = Vec::new();
    for record in records {
        let op = &record.operation;
        let Some(skill) = record.skill.as_deref() else {
            found.push(Finding::new(
                CODE,
                format!(
                    "The provider did not say which skill the {op} step invoked, so what reached the arguments of the skill cannot be proved."
                ),
            ));
            continue;
        };
        let Some(hash) = record.transcript.as_deref() else {
            found.push(Finding::new(
                CODE,
                format!(
                    "No transcript of the {op} step was stored, so what reached the arguments of {skill} cannot be proved."
                ),
            ));
            continue;
        };
        let Some(bytes) = transcripts
            .iter()
            .find(|bytes| Sha256Digest::of(bytes).as_str() == hash)
        else {
            found.push(Finding::new(
                CODE,
                format!(
                    "The transcript of the {op} step could not be read, so what reached the arguments of {skill} cannot be proved."
                ),
            ));
            continue;
        };
        let seen = invocations_in(namespace, bytes);
        if seen.is_empty() {
            found.push(Finding::new(
                CODE,
                format!(
                    "The transcript of the {op} step shows no invocation of {skill}, so what reached its arguments cannot be proved."
                ),
            ));
            continue;
        }
        let expected = squash(&record.arguments);
        let mut exact = 0usize;
        for invocation in &seen {
            if invocation.skill == skill && squash(&invocation.arguments) == expected {
                exact += 1;
            } else if invocation.skill == skill {
                found.push(Finding::new(
                    CODE,
                    format!(
                        "The {op} step invoked {skill} with arguments that are not the fixed instruction, so other text reached the skill."
                    ),
                ));
            } else {
                found.push(Finding::new(
                    CODE,
                    format!(
                        "The {op} step also invoked the Spec Kit skill {}, which is not the invocation the factory sent.",
                        invocation.skill
                    ),
                ));
            }
        }
        if exact > 1 {
            found.push(Finding::new(
                CODE,
                format!(
                    "The {op} step invoked {skill} {exact} times; the factory sends exactly one invocation."
                ),
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_namespace_needs_a_separator_and_a_name() {
        assert!(in_namespace("speckit-specify", "speckit"));
        assert!(in_namespace("speckit.plan", "speckit"));
        assert!(!in_namespace("speckit", "speckit"));
        assert!(!in_namespace("speckit-", "speckit"));
        assert!(!in_namespace("speckitplan", "speckit"));
        assert!(!in_namespace("update-config", "speckit"));
    }

    #[test]
    fn a_replayed_command_gives_its_name_and_arguments() {
        let content = "<command-message>speckit-specify</command-message>\n<command-name>/speckit-specify</command-name>\n<command-args>Write it.</command-args>";
        assert_eq!(
            typed(content),
            Some(("speckit-specify".to_owned(), "Write it.".to_owned()))
        );
        assert_eq!(typed("/speckit-specify Write it."), None);
    }
}
