//! What the classifier said, read into a typed value, and what the stage does about it.
//!
//! The schema check of `AgentOutputCheck` is the first defence. This module is the second: it reads
//! the document by hand and refuses anything that is not exactly the shape the schema describes,
//! including the three rules the schema states with `if` and `then`. A permissive check in front
//! of it therefore cannot let a malformed answer through, and an answer is never "repaired".
//!
//! # The outcomes
//!
//! * **Clarify.** The classifier asked for a person (`NEEDS_HUMAN`), or found a material
//!   ambiguity. The stage asks exactly ONE question: the classifier's own question, the first when
//!   it listed several. It never writes a question itself.
//! * **Decline.** The kind of request is one the rules decline. The default declines `question`,
//!   because the factory changes software and does not answer questions.
//! * **Split.** The request names more areas than one job takes, when the rules set a limit. The
//!   classifier has no field that says "split", so this is a rule on its domain tags, off by
//!   default.
//! * **Accept.** Everything else.
//!
//! A decline or a split is not final. The stage run is blocked, an operator can override it, and
//! the override is audited.

use serde_json::Value;

/// The kind of work, as the schema spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    /// A new capability.
    Feature,
    /// A defect.
    Bugfix,
    /// Documentation only.
    Documentation,
    /// A change of structure with no change of behavior.
    Refactor,
    /// Maintenance.
    Chore,
    /// A question, not a change.
    Question,
    /// The classifier could not tell.
    Unclear,
}

impl RequestKind {
    /// The schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Feature => "feature",
            Self::Bugfix => "bugfix",
            Self::Documentation => "documentation",
            Self::Refactor => "refactor",
            Self::Chore => "chore",
            Self::Question => "question",
            Self::Unclear => "unclear",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::Feature,
            Self::Bugfix,
            Self::Documentation,
            Self::Refactor,
            Self::Chore,
            Self::Question,
            Self::Unclear,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == text)
    }
}

/// The risk hint. A hint only: the policy engine computes the tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskHint {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

impl RiskHint {
    /// The schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::Low, Self::Medium, Self::High, Self::Critical]
            .into_iter()
            .find(|hint| hint.as_str() == text)
    }
}

/// The classifier's answer, read.
#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    /// `NEEDS_HUMAN` rather than `CLASSIFIED`.
    pub needs_human: bool,
    /// The kind of work.
    pub kind: RequestKind,
    /// Two or three plain sentences.
    pub summary: String,
    /// One to five tags.
    pub domain_tags: Vec<String>,
    /// The hint.
    pub risk: RiskHint,
    /// Reasons for a hint above low.
    pub risk_reasons: Vec<String>,
    /// A fact is missing that would change the kind of work or the risk.
    pub material_ambiguity: bool,
    /// Up to three questions.
    pub questions: Vec<String>,
    /// The one question of a `NEEDS_HUMAN` answer.
    pub human_question: Option<String>,
    /// 0 to 1.
    pub confidence: f64,
    /// Instructions the classifier found in the data and did not follow.
    pub ignored_instructions: Vec<String>,
}

/// Why an answer is not accepted. The set is closed and carries no text of the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReadProblem {
    /// A field is missing, has the wrong type or holds a value outside its set.
    #[error("the answer does not have the shape of the intake classification")]
    Shape,
    /// A rule that the schema states with `if` and `then` is broken.
    #[error("the answer breaks a rule of the intake classification")]
    Rule,
    /// The kind is `unclear` and no question was asked, so there is nothing to ask a person and
    /// nothing to go on.
    #[error("the answer does not classify the request and asks nothing")]
    Unusable,
}

const FIELDS: [&str; 11] = [
    "schema_version",
    "status",
    "request_kind",
    "summary",
    "domain_tags",
    "risk_hint",
    "risk_reasons",
    "ambiguity",
    "human_question",
    "confidence",
    "ignored_instructions",
];

fn text_list(value: &Value, max: usize) -> Result<Vec<String>, ReadProblem> {
    let items = value.as_array().ok_or(ReadProblem::Shape)?;
    if items.len() > max {
        return Err(ReadProblem::Shape);
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|text| (10..=4000).contains(&text.chars().count()))
                .map(str::to_owned)
                .ok_or(ReadProblem::Shape)
        })
        .collect()
}

impl Classification {
    /// Reads an answer.
    ///
    /// # Errors
    /// [`ReadProblem`].
    pub fn read(value: &Value) -> Result<Self, ReadProblem> {
        let object = value.as_object().ok_or(ReadProblem::Shape)?;
        if object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
            return Err(ReadProblem::Shape);
        }
        if object.get("schema_version") != Some(&Value::from(1)) {
            return Err(ReadProblem::Shape);
        }
        let status = object
            .get("status")
            .and_then(Value::as_str)
            .ok_or(ReadProblem::Shape)?;
        let needs_human = match status {
            "CLASSIFIED" => false,
            "NEEDS_HUMAN" => true,
            _ => return Err(ReadProblem::Shape),
        };
        let kind = object
            .get("request_kind")
            .and_then(Value::as_str)
            .and_then(RequestKind::parse)
            .ok_or(ReadProblem::Shape)?;
        let summary = object
            .get("summary")
            .and_then(Value::as_str)
            .filter(|text| (10..=4000).contains(&text.chars().count()))
            .ok_or(ReadProblem::Shape)?
            .to_owned();
        let tags = object.get("domain_tags").ok_or(ReadProblem::Shape)?;
        let domain_tags = text_tags(tags)?;
        let risk = object
            .get("risk_hint")
            .and_then(Value::as_str)
            .and_then(RiskHint::parse)
            .ok_or(ReadProblem::Shape)?;
        let risk_reasons = match object.get("risk_reasons") {
            Some(reasons) => text_list(reasons, 5)?,
            None => Vec::new(),
        };
        let ambiguity = object
            .get("ambiguity")
            .and_then(Value::as_object)
            .ok_or(ReadProblem::Shape)?;
        if ambiguity
            .keys()
            .any(|key| key != "material" && key != "questions")
        {
            return Err(ReadProblem::Shape);
        }
        let material_ambiguity = ambiguity
            .get("material")
            .and_then(Value::as_bool)
            .ok_or(ReadProblem::Shape)?;
        let questions = text_list(ambiguity.get("questions").ok_or(ReadProblem::Shape)?, 3)?;
        let human_question = match object.get("human_question") {
            Some(question) => Some(
                question
                    .as_str()
                    .filter(|text| (10..=4000).contains(&text.chars().count()))
                    .ok_or(ReadProblem::Shape)?
                    .to_owned(),
            ),
            None => None,
        };
        let confidence = object
            .get("confidence")
            .and_then(Value::as_f64)
            .filter(|number| (0.0..=1.0).contains(number))
            .ok_or(ReadProblem::Shape)?;
        let ignored_instructions = text_list(
            object
                .get("ignored_instructions")
                .ok_or(ReadProblem::Shape)?,
            10,
        )?;

        // The three rules the schema states with `if` and `then`.
        if needs_human && human_question.is_none() {
            return Err(ReadProblem::Rule);
        }
        if material_ambiguity && questions.is_empty() {
            return Err(ReadProblem::Rule);
        }
        if risk != RiskHint::Low && risk_reasons.is_empty() {
            return Err(ReadProblem::Rule);
        }
        Ok(Self {
            needs_human,
            kind,
            summary,
            domain_tags,
            risk,
            risk_reasons,
            material_ambiguity,
            questions,
            human_question,
            confidence,
            ignored_instructions,
        })
    }
}

fn text_tags(value: &Value) -> Result<Vec<String>, ReadProblem> {
    let items = value.as_array().ok_or(ReadProblem::Shape)?;
    if items.is_empty() || items.len() > 5 {
        return Err(ReadProblem::Shape);
    }
    let mut tags: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let tag = item.as_str().ok_or(ReadProblem::Shape)?;
        let bytes = tag.as_bytes();
        let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let valid = !bytes.is_empty()
            && bytes.len() <= 64
            && bytes.first().copied().is_some_and(edge)
            && bytes.last().copied().is_some_and(edge)
            && bytes
                .iter()
                .all(|b| edge(*b) || matches!(b, b'.' | b'_' | b'-'));
        if !valid || tags.iter().any(|seen| seen == tag) {
            return Err(ReadProblem::Shape);
        }
        tags.push(tag.to_owned());
    }
    Ok(tags)
}

/// The rules that turn a classification into an outcome. They are data, so a policy can change
/// them without touching the stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakeRules {
    /// Kinds of request the factory declines.
    pub declined_kinds: Vec<RequestKind>,
    /// More domain tags than this means the request is several jobs. `None` turns the rule off.
    pub max_tags_per_job: Option<usize>,
}

impl Default for IntakeRules {
    fn default() -> Self {
        Self {
            declined_kinds: vec![RequestKind::Question],
            max_tags_per_job: None,
        }
    }
}

/// Why a request is declined. A closed set, so the explanation is a fixed sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclineReason {
    /// The kind of request is one the rules decline.
    KindNotSupported(RequestKind),
}

/// What the stage does with a classified request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Go on to repository intelligence.
    Accept,
    /// Ask this one question and wait for the answer.
    Clarify {
        /// The classifier's own question.
        question: String,
    },
    /// Do not go on. An operator can override.
    Decline(DeclineReason),
    /// The request is several jobs. An operator can override.
    Split {
        /// The areas the classifier found, which are its domain tags.
        areas: Vec<String>,
    },
}

impl Outcome {
    /// The word recorded in the decision document.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Clarify { .. } => "clarify",
            Self::Decline(_) => "decline",
            Self::Split { .. } => "split",
        }
    }
}

/// Decides the outcome. The order matters: a question comes before a decline, because a request
/// the classifier could not read should be asked about and not declined on a guess.
///
/// # Errors
/// [`ReadProblem::Unusable`] when the kind is `unclear` and the classifier asked nothing.
pub fn decide(
    classification: &Classification,
    rules: &IntakeRules,
) -> Result<Outcome, ReadProblem> {
    if classification.needs_human {
        return classification
            .human_question
            .clone()
            .map(|question| Outcome::Clarify { question })
            .ok_or(ReadProblem::Rule);
    }
    if classification.material_ambiguity {
        return classification
            .questions
            .first()
            .cloned()
            .map(|question| Outcome::Clarify { question })
            .ok_or(ReadProblem::Rule);
    }
    if classification.kind == RequestKind::Unclear {
        return Err(ReadProblem::Unusable);
    }
    if rules.declined_kinds.contains(&classification.kind) {
        return Ok(Outcome::Decline(DeclineReason::KindNotSupported(
            classification.kind,
        )));
    }
    if rules
        .max_tags_per_job
        .is_some_and(|max| classification.domain_tags.len() > max)
    {
        return Ok(Outcome::Split {
            areas: classification.domain_tags.clone(),
        });
    }
    Ok(Outcome::Accept)
}
