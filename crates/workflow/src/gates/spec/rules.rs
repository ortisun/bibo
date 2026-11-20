//! The rules of the specification gate. Each is a pure function of the contract and plain values.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::contracts::SpecificationContract;
use factory_domain::contracts::specification_contract::{
    ConstraintKind, Level, QuestionStatus, SpecArtifactRole, SpecStatus,
};
use factory_domain::values::Sha256Digest;
use factory_ports::spec::ParseReason;

use super::Finding;

/// The words every question made from a checklist item starts with. The adapter writes them and
/// the checklist rule reads them.
pub const CHECKLIST_PREFIX: &str = "Checklist item ";

/// What the gate is configured with. The word lists belong to the domain profile and the policy,
/// so a composition root passes them in.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Implementation technology that a requirement must not name. Matched as whole words,
    /// ignoring case.
    pub technology_words: Vec<String>,
    /// Phrases that ask to bypass a control, matched ignoring case.
    pub bypass_phrases: Vec<String>,
    /// Whether a specification with no risk is a finding.
    pub require_risks: bool,
    /// Whether a specification with no scope boundary is a finding.
    pub require_scope_boundary: bool,
    /// Whether a specification with no success criterion is a finding.
    pub require_success_criteria: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            technology_words: [
                "postgres",
                "postgresql",
                "mysql",
                "redis",
                "kafka",
                "kubernetes",
                "docker",
                "react",
                "angular",
                "graphql",
                "python",
                "java",
                "javascript",
                "typescript",
                "golang",
            ]
            .map(str::to_owned)
            .to_vec(),
            bypass_phrases: [
                "without review",
                "skip the review",
                "skip review",
                "bypass",
                "disable the gate",
                "ignore the policy",
                "without approval",
                "no human",
                "turn off the check",
            ]
            .map(str::to_owned)
            .to_vec(),
            require_risks: true,
            require_scope_boundary: true,
            require_success_criteria: true,
        }
    }
}

fn words(text: &str) -> Vec<&str> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect()
}

/// The finding that a parse failure of a file stands for.
#[must_use]
pub fn parse_failure(path: &str, reason: ParseReason) -> Finding {
    match reason {
        ParseReason::Missing => Finding::new(
            "specification-file-missing",
            format!("The file {path} was not left by the skill."),
        ),
        ParseReason::NotText => Finding::new(
            "specification-not-text",
            format!("The file {path} is not text."),
        ),
        ParseReason::SectionMissing => Finding::new(
            "required-structure-missing",
            format!("The file {path} lacks a required heading, field, priority or scenario."),
        ),
        ParseReason::BadId => Finding::new(
            "identifier-malformed",
            format!(
                "The file {path} has an identifier or a priority in a form the contract does not allow."
            ),
        ),
        ParseReason::TooLarge => Finding::new(
            "specification-too-large",
            format!("The file {path} is larger than the limit."),
        ),
    }
}

/// Completeness of what the contract holds.
#[must_use]
pub fn structure(contract: &SpecificationContract, limits: &Limits) -> Vec<Finding> {
    let mut found = Vec::new();
    if limits.require_scope_boundary && contract.out_of_scope.is_empty() {
        found.push(Finding::new(
            "no-scope-boundary",
            "The specification does not say what is out of scope. The first edge case must.",
        ));
    }
    if limits.require_risks && contract.risks.is_empty() {
        found.push(Finding::new(
            "no-risks",
            "The specification records no risk. Each risk is an assumption that starts with Risk:.",
        ));
    }
    if limits.require_success_criteria && contract.nonfunctional_requirements.is_empty() {
        found.push(Finding::new(
            "no-measurable-criterion",
            "The specification has no success criterion, so nothing says how to tell that it worked.",
        ));
    }
    found
}

/// Every identifier is unique.
#[must_use]
pub fn identifiers(contract: &SpecificationContract) -> Vec<Finding> {
    fn duplicates<'a>(kind: &str, ids: impl Iterator<Item = &'a str>, found: &mut Vec<Finding>) {
        let mut seen = BTreeSet::new();
        for id in ids {
            if !seen.insert(id) {
                found.push(Finding::new(
                    "duplicate-identifier",
                    format!("The {kind} identifier {id} is used more than once."),
                ));
            }
        }
    }
    let mut found = Vec::new();
    duplicates(
        "requirement",
        contract
            .requirements
            .as_slice()
            .iter()
            .map(|r| r.id.as_str()),
        &mut found,
    );
    duplicates(
        "scenario",
        contract
            .acceptance_scenarios
            .as_slice()
            .iter()
            .map(|s| s.id.as_str()),
        &mut found,
    );
    duplicates(
        "success criterion",
        contract
            .nonfunctional_requirements
            .iter()
            .map(|n| n.id.as_str()),
        &mut found,
    );
    duplicates(
        "question",
        contract.open_questions.iter().map(|q| q.id.as_str()),
        &mut found,
    );
    found
}

const KEYWORDS: [&str; 3] = ["MUST", "SHOULD", "MAY"];

/// Every requirement holds MUST, MUST NOT, SHOULD, SHOULD NOT or MAY, in capitals.
#[must_use]
pub fn requirement_keywords(contract: &SpecificationContract) -> Vec<Finding> {
    contract
        .requirements
        .as_slice()
        .iter()
        .filter(|r| !words(r.statement.as_str()).iter().any(|w| KEYWORDS.contains(w)))
        .map(|r| {
            Finding::new(
                "requirement-keyword-missing",
                format!(
                    "{} does not say MUST, MUST NOT, SHOULD or MAY in capitals, so it is not testable as written.",
                    r.id.as_str()
                ),
            )
        })
        .collect()
}

/// No requirement or success criterion names an implementation technology.
#[must_use]
pub fn technology_names(contract: &SpecificationContract, limits: &Limits) -> Vec<Finding> {
    let wanted: BTreeSet<String> = limits
        .technology_words
        .iter()
        .map(|w| w.to_lowercase())
        .collect();
    let mut found = Vec::new();
    let mut check = |id: &str, text: &str| {
        for word in words(text) {
            if wanted.contains(&word.to_lowercase()) {
                found.push(Finding::new(
                    "technology-named",
                    format!("{id} names the technology {word}. A requirement says what is needed, not how to build it."),
                ));
            }
        }
    };
    for r in contract.requirements.as_slice() {
        check(r.id.as_str(), r.statement.as_str());
    }
    for n in &contract.nonfunctional_requirements {
        check(n.id.as_str(), n.statement.as_str());
    }
    found
}

/// The texts a person wrote, with where each came from.
fn texts(contract: &SpecificationContract) -> Vec<(String, &str)> {
    let mut all: Vec<(String, &str)> = vec![
        ("the title".to_owned(), contract.title.as_str()),
        ("the summary".to_owned(), contract.summary.as_str()),
    ];
    for r in contract.requirements.as_slice() {
        all.push((r.id.as_str().to_owned(), r.statement.as_str()));
    }
    for s in contract.acceptance_scenarios.as_slice() {
        all.push((s.id.as_str().to_owned(), s.given.as_str()));
        all.push((s.id.as_str().to_owned(), s.when.as_str()));
        all.push((s.id.as_str().to_owned(), s.then.as_str()));
    }
    for n in &contract.nonfunctional_requirements {
        all.push((n.id.as_str().to_owned(), n.statement.as_str()));
    }
    for risk in &contract.risks {
        all.push((risk.id.as_str().to_owned(), risk.description.as_str()));
    }
    for c in &contract.constraints {
        all.push((c.id.as_str().to_owned(), c.description.as_str()));
    }
    all
}

/// True when the text holds a template placeholder: `$ARGUMENTS`, `[FEATURE NAME]`, `[DATE]`,
/// `[###-feature-name]` or a bracketed token in capitals with an underscore.
#[must_use]
pub fn has_placeholder(text: &str) -> bool {
    if text.contains("$ARGUMENTS")
        || text.contains("[FEATURE NAME]")
        || text.contains("[DATE]")
        || text.contains("[###-feature-name]")
    {
        return true;
    }
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(']') else { break };
        let token = &after[..close];
        let shaped = token.contains('_')
            && token.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && token
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if shaped {
            return true;
        }
        rest = &after[close + 1..];
    }
    false
}

/// The questions a person has waived, by identifier.
pub type Waived = BTreeSet<String>;

/// No marker, no placeholder and no open blocking question beyond what a person waived. The
/// checklist items are the checklist rule's, not this one's.
#[must_use]
pub fn clarity(contract: &SpecificationContract, waived: &Waived) -> Vec<Finding> {
    let mut found = Vec::new();
    for (place, text) in texts(contract) {
        if text.contains("NEEDS CLARIFICATION") {
            found.push(Finding::new(
                "unresolved-marker",
                format!("{place} still holds a NEEDS CLARIFICATION marker."),
            ));
        }
        if has_placeholder(text) {
            found.push(Finding::new(
                "template-placeholder",
                format!("{place} still holds template placeholder text."),
            ));
        }
    }
    for q in &contract.open_questions {
        let checklist = q.question.as_str().starts_with(CHECKLIST_PREFIX);
        if !checklist
            && q.blocking
            && q.status == QuestionStatus::Open
            && !waived.contains(q.id.as_str())
        {
            found.push(Finding::new(
                "blocking-question-open",
                format!(
                    "The question {} is still open and blocks the specification: {}",
                    q.id.as_str(),
                    q.question.as_str()
                ),
            ));
        }
    }
    found
}

/// Requirements and scenarios link to each other, both ways, and every reference resolves.
#[must_use]
pub fn traceability(contract: &SpecificationContract) -> Vec<Finding> {
    let mut found = Vec::new();
    let requirements: BTreeMap<&str, &[_]> = contract
        .requirements
        .as_slice()
        .iter()
        .map(|r| (r.id.as_str(), r.acceptance_scenario_ids.as_slice()))
        .collect();
    let scenarios: BTreeMap<&str, Vec<&str>> = contract
        .acceptance_scenarios
        .as_slice()
        .iter()
        .map(|s| {
            (
                s.id.as_str(),
                s.requirement_ids
                    .as_slice()
                    .iter()
                    .map(|id| id.as_str())
                    .collect(),
            )
        })
        .collect();
    for (id, scenario_ids) in &requirements {
        if scenario_ids.is_empty() {
            found.push(Finding::new(
                "requirement-without-scenario",
                format!("{id} has no acceptance scenario."),
            ));
        }
        for scenario in *scenario_ids {
            match scenarios.get(scenario.as_str()) {
                None => found.push(Finding::new(
                    "dangling-scenario-reference",
                    format!(
                        "{id} cites the scenario {}, which does not exist.",
                        scenario.as_str()
                    ),
                )),
                Some(back) if !back.contains(id) => found.push(Finding::new(
                    "asymmetric-link",
                    format!(
                        "{id} cites the scenario {}, but that scenario does not name {id}.",
                        scenario.as_str()
                    ),
                )),
                Some(_) => {}
            }
        }
    }
    for (id, requirement_ids) in &scenarios {
        if requirement_ids.is_empty() {
            found.push(Finding::new(
                "scenario-without-requirement",
                format!("The scenario {id} names no requirement."),
            ));
        }
        for requirement in requirement_ids {
            match requirements.get(requirement) {
                None => found.push(Finding::new(
                    "dangling-requirement-reference",
                    format!("The scenario {id} names {requirement}, which does not exist."),
                )),
                Some(listed) if !listed.iter().any(|s| s.as_str() == *id) => {
                    found.push(Finding::new(
                        "asymmetric-link",
                        format!(
                            "The scenario {id} names {requirement}, but {requirement} does not list the scenario."
                        ),
                    ));
                }
                Some(_) => {}
            }
        }
    }
    found
}

fn normalise(text: &str) -> Vec<String> {
    const STOP: [&str; 14] = [
        "the", "a", "an", "to", "of", "be", "is", "in", "and", "or", "for", "that", "it", "by",
    ];
    words(text)
        .into_iter()
        .map(str::to_lowercase)
        .filter(|w| !STOP.contains(&w.as_str()))
        .collect()
}

fn content_tokens(statement: &str) -> BTreeSet<String> {
    normalise(statement)
        .into_iter()
        .filter(|w| !["must", "should", "may", "not", "shall"].contains(&w.as_str()))
        .collect()
}

fn modal(statement: &str) -> Option<(bool, bool)> {
    // (is_negative, is_strong): MUST NOT is the negative of MUST, SHOULD NOT of SHOULD.
    let tokens = words(statement);
    for (index, word) in tokens.iter().enumerate() {
        if *word == "MUST" || *word == "SHOULD" {
            let negative = tokens.get(index + 1) == Some(&"NOT");
            return Some((negative, *word == "MUST"));
        }
    }
    None
}

/// The number that follows "at most", "no more than", "at least" and the like, with the word
/// after it as the unit.
fn bound(statement: &str) -> Option<(bool, f64, String)> {
    let lower = statement.to_lowercase();
    let tokens: Vec<&str> = words(&lower);
    for (index, token) in tokens.iter().enumerate() {
        let upper = match *token {
            "most" | "maximum" | "within" | "under" => true,
            "least" | "minimum" | "over" => false,
            _ => continue,
        };
        // "at most N unit", "no more than N unit", "maximum of N unit"
        for ahead in 1..=3 {
            if let Some(number) = tokens
                .get(index + ahead)
                .and_then(|t| t.parse::<f64>().ok())
                && let Some(unit) = tokens.get(index + ahead + 1)
            {
                return Some((upper, number, (*unit).to_owned()));
            }
        }
    }
    None
}

/// Requirements that cannot both hold, found by fixed heuristics.
#[must_use]
pub fn contradictions(contract: &SpecificationContract) -> Vec<Finding> {
    let mut found = Vec::new();
    let all = contract.requirements.as_slice();
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            let (sa, sb) = (a.statement.as_str(), b.statement.as_str());
            let (ta, tb) = (content_tokens(sa), content_tokens(sb));
            let shared = ta.intersection(&tb).count();
            let union = ta.union(&tb).count().max(1);
            let similar = shared >= 3 && shared * 10 >= union * 6;
            if similar
                && let (Some((na, _)), Some((nb, _))) = (modal(sa), modal(sb))
                && na != nb
            {
                found.push(Finding::new(
                    "opposite-requirements",
                    format!(
                        "{} and {} say nearly the same thing, one as a duty and one as a ban.",
                        a.id.as_str(),
                        b.id.as_str()
                    ),
                ));
            }
            if similar && normalise(sa) == normalise(sb) && a.priority != b.priority {
                found.push(Finding::new(
                    "same-requirement-two-priorities",
                    format!(
                        "{} and {} are the same sentence with different priorities.",
                        a.id.as_str(),
                        b.id.as_str()
                    ),
                ));
            }
            if let (Some((upper_a, na, unit_a)), Some((upper_b, nb, unit_b))) =
                (bound(sa), bound(sb))
                && unit_a == unit_b
                && shared >= 2
                && upper_a != upper_b
            {
                let (max, min) = if upper_a { (na, nb) } else { (nb, na) };
                if max < min {
                    found.push(Finding::new(
                        "numeric-bounds-conflict",
                        format!(
                            "{} and {} set bounds on {unit_a} that cannot both hold ({max} at most, {min} at least).",
                            a.id.as_str(),
                            b.id.as_str()
                        ),
                    ));
                }
            }
        }
    }
    found
}

/// A high risk has a mitigation or a safety or legal constraint, and no requirement asks to
/// bypass a control.
#[must_use]
pub fn safety(contract: &SpecificationContract, limits: &Limits) -> Vec<Finding> {
    let mut found = Vec::new();
    let protected = contract
        .constraints
        .iter()
        .any(|c| matches!(c.kind, ConstraintKind::Safety | ConstraintKind::Legal));
    for risk in &contract.risks {
        if risk.impact == Level::High && risk.mitigation.is_none() && !protected {
            found.push(Finding::new(
                "high-risk-unmitigated",
                format!(
                    "The risk {} has a high impact, no mitigation, and no safety or legal constraint beside it.",
                    risk.id.as_str()
                ),
            ));
        }
    }
    for r in contract.requirements.as_slice() {
        let lower = r.statement.as_str().to_lowercase();
        let prohibition = words(r.statement.as_str())
            .windows(2)
            .any(|w| w == ["MUST", "NOT"])
            || lower.contains("never");
        if prohibition {
            continue;
        }
        if let Some(phrase) = limits
            .bypass_phrases
            .iter()
            .find(|phrase| lower.contains(&phrase.to_lowercase()))
        {
            found.push(Finding::new(
                "safety-bypass-requested",
                format!(
                    "{} asks for \"{phrase}\". A person must decide whether a control may be bypassed.",
                    r.id.as_str()
                ),
            ));
        }
    }
    found
}

/// A draft carries no approval. Authorization is a structured field that the factory writes when
/// a person decides, never a statement the writer makes.
#[must_use]
pub fn authorization(contract: &SpecificationContract) -> Vec<Finding> {
    let meta = &contract.metadata;
    let mut found = Vec::new();
    if meta.status != SpecStatus::Draft {
        found.push(Finding::new(
            "specification-arrived-approved",
            "The specification arrived with a status other than draft. Only the factory freezes one.",
        ));
    }
    if meta.approved_by.is_some() || meta.approved_at.is_some() {
        found.push(Finding::new(
            "approval-written-by-the-writer",
            "The specification arrived with an approver or an approval time. A person's decision is recorded by the engine, not written in the contract.",
        ));
    }
    found
}

/// The committed set matches the recorded one.
///
/// `committed` is the hash of the bytes the host read back from the commit, for every path it
/// read. `unlisted` is the files under the feature directory that the contract does not record.
#[must_use]
pub fn artifacts(
    contract: &SpecificationContract,
    committed: &BTreeMap<String, Sha256Digest>,
    unlisted: &[String],
) -> Vec<Finding> {
    let mut found = Vec::new();
    let recorded = contract.provenance.artifacts.as_slice();
    for artifact in recorded {
        match committed.get(artifact.path.as_str()) {
            None => found.push(Finding::new(
                "artifact-missing",
                format!(
                    "{} is recorded but is not in the commit.",
                    artifact.path.as_str()
                ),
            )),
            Some(hash) if *hash != artifact.sha256 => found.push(Finding::new(
                "artifact-hash-mismatch",
                format!(
                    "{} is recorded with one hash and the commit holds other bytes.",
                    artifact.path.as_str()
                ),
            )),
            Some(_) => {}
        }
    }
    for role in [
        SpecArtifactRole::Specification,
        SpecArtifactRole::RequirementsChecklist,
        SpecArtifactRole::CustomChecklist,
    ] {
        if !recorded.iter().any(|a| a.role == role) {
            found.push(Finding::new(
                "artifact-set-incomplete",
                format!(
                    "The recorded set has no file with the role {}.",
                    role.as_str()
                ),
            ));
        }
    }
    for path in unlisted {
        found.push(Finding::new(
            "artifact-unlisted",
            format!("{path} is in the feature directory and the contract does not record it."),
        ));
    }
    found
}
