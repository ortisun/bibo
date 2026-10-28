//! The evidence document of the specification stage: what the host measured and what the skills
//! and the reviewer left, as `evaluate` reads it back.
//!
//! The document holds the host's measurements (commits, changed paths, the hash of every file
//! read from the commit, the tool calls the runtime denied, the audit refusal) and the failures
//! the adapter reported. It holds nothing the writer said about its own work.

use std::collections::BTreeMap;

use factory_ports::spec::ParseReason;
use serde_json::{Value, json};

/// How the independent review stands.
#[derive(Debug, Clone, PartialEq)]
pub enum ReviewRecord {
    /// The review did not run, with the reason as a code.
    NotRun(String),
    /// The reviewer answered. The answer is kept as it was validated.
    Answered {
        /// The reviewer agent.
        agent: String,
        /// Its version.
        version: String,
        /// The validated answer.
        answer: Value,
    },
}

/// One failure the adapter reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The name of the failed condition.
    pub name: String,
    /// What was found.
    pub detail: String,
}

/// The audit refused a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The code, such as `secret-found`.
    pub code: String,
    /// The paths and the rule for each.
    pub paths: Vec<(String, String)>,
}

/// The facts about a revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    /// The version that was replaced.
    pub basis_version: u32,
    /// The feature directory it was written in.
    pub basis_directory: String,
    /// Why, as the person wrote it.
    pub reason: String,
}

/// The evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    /// The feature directory the factory chose.
    pub feature_directory: String,
    /// The commit the run started from.
    pub base_commit: String,
    /// The commit that holds the files, when any skill ran.
    pub head_commit: Option<String>,
    /// The operations that ran, in order.
    pub operations: Vec<String>,
    /// Every path the audited ingestions reported as changed.
    pub changed: Vec<String>,
    /// The SHA-256 of every file read from the head commit, by path.
    pub committed: BTreeMap<String, String>,
    /// The tool calls the runtime reported as denied.
    pub denials: Vec<(String, String)>,
    /// The hashes of the stored transcripts.
    pub transcripts: Vec<String>,
    /// A refusal of the audited ingestion.
    pub refusal: Option<Refusal>,
    /// A file the parser did not understand: path and reason.
    pub parse_failure: Option<(String, ParseReason)>,
    /// The post-conditions that did not hold.
    pub post_conditions: Vec<Failure>,
    /// Findings of the authorization rule on the writer's draft.
    pub draft_authorization: Vec<(String, String)>,
    /// The review.
    pub review: ReviewRecord,
    /// The revision, when this run revises a frozen specification.
    pub revision: Option<Revision>,
    /// The hash of the draft the person was asked to approve, once there is one.
    pub draft_sha256: Option<String>,
    /// The questions put to people: the identifier and the text, unchanged.
    pub questions: Vec<(String, String)>,
    /// True when a fake component produced any of it.
    pub fake: bool,
}

const fn reason_name(reason: ParseReason) -> &'static str {
    match reason {
        ParseReason::Missing => "missing",
        ParseReason::NotText => "not_text",
        ParseReason::SectionMissing => "section_missing",
        ParseReason::BadId => "bad_id",
        ParseReason::TooLarge => "too_large",
    }
}

fn reason_of(name: &str) -> Option<ParseReason> {
    Some(match name {
        "missing" => ParseReason::Missing,
        "not_text" => ParseReason::NotText,
        "section_missing" => ParseReason::SectionMissing,
        "bad_id" => ParseReason::BadId,
        "too_large" => ParseReason::TooLarge,
        _ => return None,
    })
}

impl Evidence {
    /// An evidence document for a run that has done nothing yet.
    #[must_use]
    pub fn new(feature_directory: String, base_commit: String) -> Self {
        Self {
            feature_directory,
            base_commit,
            head_commit: None,
            operations: Vec::new(),
            changed: Vec::new(),
            committed: BTreeMap::new(),
            denials: Vec::new(),
            transcripts: Vec::new(),
            refusal: None,
            parse_failure: None,
            post_conditions: Vec::new(),
            draft_authorization: Vec::new(),
            review: ReviewRecord::NotRun("not-reached".to_owned()),
            revision: None,
            draft_sha256: None,
            questions: Vec::new(),
            fake: false,
        }
    }

    /// The document.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "kind": "specification-evidence",
            "schema_version": 1,
            "feature_directory": self.feature_directory,
            "base_commit": self.base_commit,
            "head_commit": self.head_commit,
            "operations": self.operations,
            "changed": self.changed,
            "committed": self.committed,
            "denials": self.denials.iter().map(|(t, r)| json!([t, r])).collect::<Vec<_>>(),
            "transcripts": self.transcripts,
            "refusal": self.refusal.as_ref().map(|r| json!({
                "code": r.code,
                "paths": r.paths.iter().map(|(p, m)| json!([p, m])).collect::<Vec<_>>(),
            })),
            "parse_failure": self.parse_failure.as_ref().map(|(path, reason)| json!({
                "path": path, "reason": reason_name(*reason),
            })),
            "post_conditions": self.post_conditions.iter().map(|f| json!({
                "name": f.name, "detail": f.detail,
            })).collect::<Vec<_>>(),
            "draft_authorization": self.draft_authorization.iter().map(|(c, m)| json!([c, m])).collect::<Vec<_>>(),
            "review": match &self.review {
                ReviewRecord::NotRun(why) => json!({"outcome": "not_run", "reason": why}),
                ReviewRecord::Answered { agent, version, answer } => json!({
                    "outcome": "answered", "agent": agent, "version": version, "answer": answer,
                }),
            },
            "revision": self.revision.as_ref().map(|r| json!({
                "basis_version": r.basis_version,
                "basis_directory": r.basis_directory,
                "reason": r.reason,
            })),
            "draft_sha256": self.draft_sha256,
            "questions": self.questions.iter().map(|(i, t)| json!([i, t])).collect::<Vec<_>>(),
            "fake": self.fake,
        })
    }

    /// Reads the document back. `None` for anything that is not the document this writes.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let text = |key: &str| value.get(key)?.as_str().map(str::to_owned);
        let list = |key: &str| -> Option<Vec<String>> {
            value
                .get(key)?
                .as_array()?
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect()
        };
        let pairs = |key: &str| -> Option<Vec<(String, String)>> {
            value
                .get(key)?
                .as_array()?
                .iter()
                .map(|v| {
                    let pair = v.as_array()?;
                    Some((
                        pair.first()?.as_str()?.to_owned(),
                        pair.get(1)?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        };
        let committed = value
            .get("committed")?
            .as_object()?
            .iter()
            .map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
            .collect::<Option<BTreeMap<_, _>>>()?;
        let refusal = match value.get("refusal")? {
            Value::Null => None,
            other => Some(Refusal {
                code: other.get("code")?.as_str()?.to_owned(),
                paths: other
                    .get("paths")?
                    .as_array()?
                    .iter()
                    .map(|v| {
                        let pair = v.as_array()?;
                        Some((
                            pair.first()?.as_str()?.to_owned(),
                            pair.get(1)?.as_str()?.to_owned(),
                        ))
                    })
                    .collect::<Option<Vec<_>>>()?,
            }),
        };
        let parse_failure = match value.get("parse_failure")? {
            Value::Null => None,
            other => Some((
                other.get("path")?.as_str()?.to_owned(),
                reason_of(other.get("reason")?.as_str()?)?,
            )),
        };
        let post_conditions = value
            .get("post_conditions")?
            .as_array()?
            .iter()
            .map(|v| {
                Some(Failure {
                    name: v.get("name")?.as_str()?.to_owned(),
                    detail: v.get("detail")?.as_str()?.to_owned(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let review_value = value.get("review")?;
        let review = match review_value.get("outcome")?.as_str()? {
            "not_run" => ReviewRecord::NotRun(review_value.get("reason")?.as_str()?.to_owned()),
            "answered" => ReviewRecord::Answered {
                agent: review_value.get("agent")?.as_str()?.to_owned(),
                version: review_value.get("version")?.as_str()?.to_owned(),
                answer: review_value.get("answer")?.clone(),
            },
            _ => return None,
        };
        let revision = match value.get("revision")? {
            Value::Null => None,
            other => Some(Revision {
                basis_version: u32::try_from(other.get("basis_version")?.as_u64()?).ok()?,
                basis_directory: other.get("basis_directory")?.as_str()?.to_owned(),
                reason: other.get("reason")?.as_str()?.to_owned(),
            }),
        };
        Some(Self {
            feature_directory: text("feature_directory")?,
            base_commit: text("base_commit")?,
            head_commit: value.get("head_commit")?.as_str().map(str::to_owned),
            operations: list("operations")?,
            changed: list("changed")?,
            committed,
            denials: pairs("denials")?,
            transcripts: list("transcripts")?,
            refusal,
            parse_failure,
            post_conditions,
            draft_authorization: pairs("draft_authorization")?,
            review,
            revision,
            draft_sha256: value.get("draft_sha256")?.as_str().map(str::to_owned),
            questions: pairs("questions")?,
            fake: value.get("fake")?.as_bool()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_evidence_survives_the_record() {
        let mut evidence = Evidence::new("specs/a".to_owned(), "a".repeat(40));
        evidence.head_commit = Some("b".repeat(40));
        evidence.operations = vec!["specify".to_owned()];
        evidence
            .committed
            .insert("specs/a/spec.md".to_owned(), "sha256:x".to_owned());
        evidence.parse_failure = Some(("specs/a/spec.md".to_owned(), ParseReason::BadId));
        evidence.post_conditions = vec![Failure {
            name: "n".to_owned(),
            detail: "d".to_owned(),
        }];
        evidence.refusal = Some(Refusal {
            code: "secret-found".to_owned(),
            paths: vec![("p".to_owned(), "r".to_owned())],
        });
        evidence.revision = Some(Revision {
            basis_version: 1,
            basis_directory: "specs/a".to_owned(),
            reason: "why".to_owned(),
        });
        evidence.questions = vec![("Q-001".to_owned(), "Which?".to_owned())];
        evidence.review = ReviewRecord::Answered {
            agent: "r".to_owned(),
            version: "1.0.0".to_owned(),
            answer: json!({"verdict": "PASS"}),
        };
        let back = Evidence::from_json(&evidence.to_json()).expect("reads back");
        assert_eq!(back, evidence);
        assert_eq!(Evidence::from_json(&json!({})), None);
    }
}
