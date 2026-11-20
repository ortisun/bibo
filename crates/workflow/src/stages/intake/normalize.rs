//! The normalized request and the decision, as the documents the stage returns.
//!
//! The normalized request is what later stages read. It holds a plain-English title and
//! description written from the classifier's summary and from its list of what the request
//! states, and it points at the original text by hash.
//! It holds no byte of the original text: the original is stored once, apart (FR-003), and a later
//! stage that wants it receives it only as quoted data.
//!
//! The title is the first sentence of the summary, cut at a word if it is long. The stage writes
//! no words of its own into it. Whether the result reads well is the readability gate's call, and
//! a title that does not pass is not repaired here: the stage fails its gate and the engine sends
//! it back.

use factory_domain::contracts::ArtifactRef;
use factory_domain::values::Sha256Digest;
use serde_json::{Value, json};

use super::classify::{Classification, DeclineReason, Outcome};

/// The longest title the schema of the classifier allows for a human title.
const TITLE_MAX: usize = 100;

/// The first sentence of `summary` as a title in sentence case, at most 100 characters.
#[must_use]
pub fn title_from(summary: &str) -> String {
    let text = summary.trim();
    let mut end = text.len();
    let bytes = text.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(byte, b'.' | b'!' | b'?') {
            let next = bytes.get(index + 1).copied();
            if next.is_none_or(|b| b.is_ascii_whitespace()) {
                end = index;
                break;
            }
        }
    }
    let mut title: String = text.get(..end).unwrap_or(text).trim().to_owned();
    if title.chars().count() > TITLE_MAX {
        let cut: String = title.chars().take(TITLE_MAX).collect();
        title = match cut.rfind(' ') {
            Some(space) => cut.get(..space).unwrap_or(&cut).trim_end().to_owned(),
            None => cut,
        };
    }
    let title = title.trim_end_matches([',', ';', ':', '-', ' ']).to_owned();
    let mut chars = title.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => title,
    }
}

/// The description: the summary, what the request states, the kind of work, and the reasons for
/// a risk above low.
///
/// The list of what the request states is how the detail of the request reaches the stages after
/// this one. They read this description and never the original text, so a summary of two or three
/// sentences alone would lose every acceptance criterion the person wrote.
#[must_use]
pub fn description_from(classification: &Classification) -> String {
    let mut text = classification.summary.trim().to_owned();
    if !classification.stated_requirements.is_empty() {
        text.push_str("\n\nWhat the request states:\n");
        for stated in &classification.stated_requirements {
            text.push_str("- ");
            // One line for each item, so that an item cannot pose as another section.
            text.push_str(&stated.split_whitespace().collect::<Vec<_>>().join(" "));
            text.push('\n');
        }
        text.truncate(text.trim_end().len());
    }
    text.push_str("\n\nType of work: ");
    text.push_str(classification.kind.as_str());
    text.push('.');
    if !classification.risk_reasons.is_empty() {
        text.push_str("\n\nWhy the risk is ");
        text.push_str(classification.risk.as_str());
        text.push_str(":\n");
        for reason in &classification.risk_reasons {
            text.push_str("- ");
            text.push_str(reason.trim());
            text.push('\n');
        }
    }
    text.trim_end().to_owned()
}

/// What the stage knows about the original text, to point at it.
#[derive(Debug, Clone)]
pub struct OriginalRef<'a> {
    /// The revision.
    pub revision: u32,
    /// The hash of the original text.
    pub sha256: &'a Sha256Digest,
    /// The artifact that holds the original bytes.
    pub artifact: &'a ArtifactRef,
}

/// The classifier run that the documents came from.
#[derive(Debug, Clone)]
pub struct ClassifierRef<'a> {
    /// The agent id.
    pub agent: &'a str,
    /// Its version.
    pub version: String,
    /// The hash of the exact bytes it returned.
    pub output_sha256: &'a Sha256Digest,
}

/// The normalized request document.
#[must_use]
pub fn normalized_request(
    classification: &Classification,
    title: &str,
    description: &str,
    original: &OriginalRef<'_>,
    classifier: &ClassifierRef<'_>,
) -> Value {
    json!({
        "schema_version": 1,
        "title": title,
        "description": description,
        "request_kind": classification.kind.as_str(),
        "domain_tags": classification.domain_tags,
        "risk_hint": classification.risk.as_str(),
        "risk_reasons": classification.risk_reasons,
        "confidence": classification.confidence,
        "ignored_instructions": classification.ignored_instructions,
        "original": {
            "revision": original.revision,
            "sha256": original.sha256,
            "artifact_sha256": original.artifact.sha256,
        },
        "classifier": {
            "agent": classifier.agent,
            "version": classifier.version,
            "output_sha256": classifier.output_sha256,
        },
    })
}

/// The sentence a person reads when the factory declines. It is fixed for each reason.
#[must_use]
pub fn decline_explanation(reason: DeclineReason) -> &'static str {
    match reason {
        DeclineReason::DesignNotApproved => {
            "The design for this issue is not approved yet, so the factory does not start work. Work starts after the label of the approved design is on the issue, applied by an approver, and the factory label is applied again."
        }
        DeclineReason::TextNotTheIssue => {
            "The text of the job is not the text of the issue as it is now, so the factory does not start work. The factory acts only on the title and the body of the issue. Put any note in the body of the issue, and apply the factory label again."
        }
        DeclineReason::KindNotSupported(kind) => match kind.as_str() {
            "question" => {
                "This request asks a question and does not ask for a change to the software. The factory changes software and does not answer questions. An operator can override this decision."
            }
            _ => {
                "The factory does not take this kind of request. An operator can override this decision."
            }
        },
    }
}

/// The sentence a person reads when the factory asks for the request to be split.
#[must_use]
pub fn split_explanation(areas: &[String]) -> String {
    format!(
        "This request reaches {} separate areas: {}. The factory takes one area for each job, so please file one request for each area. An operator can override this decision.",
        areas.len(),
        areas.join(", ")
    )
}

/// The decision document.
#[must_use]
pub fn decision_document(outcome: &Outcome, original_sha256: &Sha256Digest) -> Value {
    let mut document = json!({
        "schema_version": 1,
        "decision": outcome.word(),
        "original_sha256": original_sha256,
    });
    if let Some(map) = document.as_object_mut() {
        match outcome {
            Outcome::Accept => {
                map.insert(
                    "explanation".into(),
                    json!("The request is clear and the factory can start work on it."),
                );
            }
            Outcome::Clarify { question } => {
                map.insert("question".into(), json!(question));
                map.insert(
                    "explanation".into(),
                    json!(
                        "One fact is missing, so the factory asks one question before it goes on."
                    ),
                );
            }
            Outcome::Decline(reason) => {
                map.insert("explanation".into(), json!(decline_explanation(*reason)));
            }
            Outcome::Split { areas } => {
                map.insert("areas".into(), json!(areas));
                map.insert("explanation".into(), json!(split_explanation(areas)));
            }
        }
    }
    document
}
