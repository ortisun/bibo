//! The evidence manifest of the implementation stage, and the deliverable that names the commits.
//!
//! Two documents leave the stage, both written by the factory from what it measured:
//!
//! * `implementation-result`: `{"base_commit": ..., "head_commit": ...}`, the document the
//!   validation and review stages read. It is made from the commit that `Workspace::commit`
//!   returned, never from anything the builder wrote.
//! * `implementation-evidence`: for each task, the commit, the paths the audited ingestion
//!   found changed, the diff statistics, and, marked as reported by the builder, the commands it
//!   says it ran. It also records a refusal, when the audit refused a change, with the paths and
//!   the rule, so a blocked attempt leaves its reason in the ledger and nothing is dropped.
//!
//! The builder's commands are a record for people. The validation stage runs the gates itself and
//! the report of a builder is never counted as a result.

use serde_json::{Value, json};

use super::report::ReportedCommand;

/// The name of the deliverable that names the commits.
pub const RESULT: &str = super::input::IMPLEMENTATION_RESULT;
/// The name of the deliverable that holds the evidence manifest.
pub const EVIDENCE: &str = "implementation-evidence";

/// One changed path as the audited ingestion reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    /// The path. A rename is a deletion and an addition.
    pub path: String,
    /// `added`, `modified` or `deleted`.
    pub kind: String,
}

/// What one task left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEvidence {
    /// The key of the task in the plan.
    pub key: String,
    /// The commit the task was built on.
    pub built_on: String,
    /// The commit the task produced.
    pub commit: String,
    /// The paths the audited ingestion found changed.
    pub changes: Vec<ChangedFile>,
    /// Lines added, from the exported patch.
    pub additions: u64,
    /// Lines removed, from the exported patch.
    pub deletions: u64,
    /// The commands the builder says it ran. Not evidence.
    pub reported_commands: Vec<ReportedCommand>,
    /// The tests the builder says it added. Not evidence.
    pub reported_tests: Vec<String>,
    /// Instructions in the data that the builder says it ignored.
    pub ignored_instructions: Vec<String>,
}

/// A change the audit refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The task whose change was refused. Nothing of it was committed.
    pub task: String,
    /// A slug naming the kind of refusal, such as `protected-path-changed`.
    pub code: String,
    /// The paths involved, with the rule that applies to each (a path mode or a finding rule).
    pub paths: Vec<(String, String)>,
}

/// What the builder consumed, as the broker metered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Spent {
    /// Tokens sent to the model.
    pub input_tokens: u64,
    /// Tokens the model wrote.
    pub output_tokens: u64,
    /// Cost in millionths of a US dollar.
    pub cost_micro_usd: u64,
    /// Model requests.
    pub requests: u64,
}

/// The manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplementationEvidence {
    /// The commit the work is relative to: the protected branch tip.
    pub base_commit: String,
    /// The last commit the stage made, or the base when it made none.
    pub head_commit: String,
    /// The tasks that produced a commit, in the order they ran.
    pub tasks: Vec<TaskEvidence>,
    /// The change the audit refused, when one was.
    pub refusal: Option<Refusal>,
    /// The round this run belongs to, for a rework run.
    pub rework_round: Option<u8>,
    /// What the run spent.
    pub spent: Spent,
    /// True when a fake stood in for the sandbox, the workspace or the runtime.
    pub fake: bool,
}

impl ImplementationEvidence {
    /// The deliverable that names the commits.
    #[must_use]
    pub fn result_json(&self) -> Value {
        json!({ "base_commit": self.base_commit, "head_commit": self.head_commit })
    }

    /// The manifest as a document.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let tasks: Vec<Value> = self
            .tasks
            .iter()
            .map(|task| {
                json!({
                    "key": task.key,
                    "built_on": task.built_on,
                    "commit": task.commit,
                    "changes": task.changes.iter()
                        .map(|c| json!({ "path": c.path, "kind": c.kind }))
                        .collect::<Vec<_>>(),
                    "diff_stats": { "additions": task.additions, "deletions": task.deletions },
                    "reported_by_builder": {
                        "note": "These are the builder's own statements. They are not evidence.",
                        "commands": task.reported_commands.iter()
                            .map(|c| json!({ "argv": c.argv, "exit_code": c.exit_code }))
                            .collect::<Vec<_>>(),
                        "tests_added": task.reported_tests,
                        "ignored_instructions": task.ignored_instructions,
                    },
                })
            })
            .collect();
        json!({
            "kind": EVIDENCE,
            "base_commit": self.base_commit,
            "head_commit": self.head_commit,
            "tasks": tasks,
            "refusal": self.refusal.as_ref().map(|r| json!({
                "task": r.task,
                "code": r.code,
                "paths": r.paths.iter()
                    .map(|(path, rule)| json!({ "path": path, "rule": rule }))
                    .collect::<Vec<_>>(),
            })),
            "rework_round": self.rework_round,
            "usage": {
                "input_tokens": self.spent.input_tokens,
                "output_tokens": self.spent.output_tokens,
                "cost_micro_usd": self.spent.cost_micro_usd,
                "requests": self.spent.requests,
            },
            "fake": self.fake,
        })
    }

    /// Reads a manifest written by [`to_json`](Self::to_json). `None` for anything else.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        if value.get("kind")?.as_str()? != EVIDENCE {
            return None;
        }
        let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
        let number = |v: &Value, key: &str| v.get(key).and_then(Value::as_u64);
        let mut tasks = Vec::new();
        for task in value.get("tasks")?.as_array()? {
            let reported = task.get("reported_by_builder")?;
            tasks.push(TaskEvidence {
                key: text(task, "key")?,
                built_on: text(task, "built_on")?,
                commit: text(task, "commit")?,
                changes: task
                    .get("changes")?
                    .as_array()?
                    .iter()
                    .map(|c| {
                        Some(ChangedFile {
                            path: text(c, "path")?,
                            kind: text(c, "kind")?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
                additions: number(task.get("diff_stats")?, "additions")?,
                deletions: number(task.get("diff_stats")?, "deletions")?,
                reported_commands: reported
                    .get("commands")?
                    .as_array()?
                    .iter()
                    .map(|c| {
                        Some(ReportedCommand {
                            argv: c
                                .get("argv")?
                                .as_array()?
                                .iter()
                                .map(|a| a.as_str().map(str::to_owned))
                                .collect::<Option<Vec<_>>>()?,
                            exit_code: c.get("exit_code")?.as_i64()?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
                reported_tests: strings(reported.get("tests_added")?)?,
                ignored_instructions: strings(reported.get("ignored_instructions")?)?,
            });
        }
        let refusal = match value.get("refusal") {
            None | Some(Value::Null) => None,
            Some(r) => Some(Refusal {
                task: text(r, "task")?,
                code: text(r, "code")?,
                paths: r
                    .get("paths")?
                    .as_array()?
                    .iter()
                    .map(|p| Some((text(p, "path")?, text(p, "rule")?)))
                    .collect::<Option<Vec<_>>>()?,
            }),
        };
        let usage = value.get("usage")?;
        Some(Self {
            base_commit: text(value, "base_commit")?,
            head_commit: text(value, "head_commit")?,
            tasks,
            refusal,
            rework_round: value
                .get("rework_round")
                .and_then(Value::as_u64)
                .and_then(|n| u8::try_from(n).ok()),
            spent: Spent {
                input_tokens: number(usage, "input_tokens")?,
                output_tokens: number(usage, "output_tokens")?,
                cost_micro_usd: number(usage, "cost_micro_usd")?,
                requests: number(usage, "requests")?,
            },
            fake: value.get("fake")?.as_bool()?,
        })
    }
}

fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// Lines added and removed, counted from a unified patch. The headers (`+++`, `---`) and the body
/// of a binary patch are not lines of the change.
#[must_use]
pub fn diff_stats(patch: &[u8]) -> (u64, u64) {
    let text = String::from_utf8_lossy(patch);
    let (mut additions, mut deletions) = (0_u64, 0_u64);
    let mut in_hunk = false;
    for line in text.lines() {
        if line.starts_with("diff --git ") {
            in_hunk = false;
        } else if line.starts_with("@@") {
            in_hunk = true;
        } else if line.starts_with("GIT binary patch") {
            in_hunk = false;
        } else if in_hunk {
            if line.starts_with('+') {
                additions += 1;
            } else if line.starts_with('-') {
                deletions += 1;
            }
        }
    }
    (additions, deletions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ImplementationEvidence {
        ImplementationEvidence {
            base_commit: "a".repeat(40),
            head_commit: "b".repeat(40),
            tasks: vec![TaskEvidence {
                key: "add-flag".to_owned(),
                built_on: "a".repeat(40),
                commit: "b".repeat(40),
                changes: vec![ChangedFile {
                    path: "src/main.rs".to_owned(),
                    kind: "modified".to_owned(),
                }],
                additions: 12,
                deletions: 3,
                reported_commands: vec![ReportedCommand {
                    argv: vec!["cargo".to_owned(), "test".to_owned()],
                    exit_code: 0,
                }],
                reported_tests: vec!["it_prints_json".to_owned()],
                ignored_instructions: Vec::new(),
            }],
            refusal: Some(Refusal {
                task: "add-flag".to_owned(),
                code: "protected-path-changed".to_owned(),
                paths: vec![(
                    ".github/workflows/ci.yml".to_owned(),
                    "deny_write".to_owned(),
                )],
            }),
            rework_round: Some(1),
            spent: Spent {
                input_tokens: 100,
                output_tokens: 50,
                cost_micro_usd: 7,
                requests: 2,
            },
            fake: true,
        }
    }

    #[test]
    fn the_manifest_survives_its_document_form() {
        let original = sample();
        assert_eq!(
            ImplementationEvidence::from_json(&original.to_json()),
            Some(original)
        );
    }

    #[test]
    fn the_result_names_only_the_two_commits() {
        let result = sample().result_json();
        let keys: Vec<&String> = result.as_object().expect("object").keys().collect();
        assert_eq!(keys, ["base_commit", "head_commit"]);
    }

    #[test]
    fn the_builders_statements_are_marked_as_not_evidence() {
        let document = sample().to_json().to_string();
        assert!(document.contains("They are not evidence"));
        assert!(!document.contains("summary"));
    }

    #[test]
    fn a_document_of_another_kind_is_not_read() {
        assert_eq!(ImplementationEvidence::from_json(&json!({})), None);
        let mut other = sample().to_json();
        other["kind"] = json!("something-else");
        assert_eq!(ImplementationEvidence::from_json(&other), None);
    }

    #[test]
    fn diff_statistics_ignore_headers_and_binary_bodies() {
        let patch = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,3 @@\n keep\n-old\n+new\n+more\ndiff --git a/y b/y\nGIT binary patch\nliteral 4\n+not a line\n";
        assert_eq!(diff_stats(patch.as_bytes()), (2, 1));
    }
}
