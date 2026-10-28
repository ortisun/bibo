//! The deterministic architecture acceptance gate.
//!
//! Two gates read the same design. The traceability gate asks whether the design and the frozen
//! specification belong together: every requirement has a design element, and every design element
//! has a requirement that exists. The completeness gate asks whether the design is the kind a
//! person can approve: for a change that is not trivial it weighed alternatives, it named the ways
//! it can fail, it did not add more than the requirements justify, and it did not reach into a path
//! that policy protects. A design the agent called `DONE` is judged by these checks and not by its
//! own account.
//!
//! # What "trivial" means
//!
//! A change is trivial when the policy puts it in the lowest tier, it answers few requirements,
//! touches few files and asks for nothing a person must approve. For a trivial change one design is
//! enough, and the stage records why in plain English, from the facts above. Everything else is
//! non-trivial and must show that at least two ways were weighed.

use std::collections::BTreeSet;

use factory_domain::contracts::SpecificationContract;
use factory_domain::vocabulary::RiskTier;

use super::design::{Design, Status};

/// Every identifier of the frozen specification that a design element may satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpecIds {
    /// The functional requirements, such as `FR-001`.
    pub functional: BTreeSet<String>,
    /// The non-functional requirements and the success criteria, such as `NFR-001` and `SC-001`.
    pub quality: BTreeSet<String>,
}

impl SpecIds {
    /// Reads the identifiers from the typed specification.
    #[must_use]
    pub fn from_contract(spec: &SpecificationContract) -> Self {
        Self {
            functional: spec
                .requirements
                .iter()
                .map(|requirement| requirement.id.as_str().to_owned())
                .collect(),
            quality: spec
                .nonfunctional_requirements
                .iter()
                .map(|requirement| requirement.id.as_str().to_owned())
                .collect(),
        }
    }

    /// All of them, sorted.
    #[must_use]
    pub fn all(&self) -> BTreeSet<String> {
        self.functional.union(&self.quality).cloned().collect()
    }
}

/// The numbers of the gate. They are configuration, set from the policy of the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rules {
    /// A change with more requirements than this is not trivial.
    pub trivial_max_requirements: usize,
    /// A change that touches more files than this is not trivial.
    pub trivial_max_files: usize,
    /// The fewest alternatives, counted over all decisions, that a non-trivial change must weigh.
    pub min_alternatives: usize,
    /// The most design elements per requirement before the design counts as built for its own
    /// sake.
    pub max_elements_per_requirement: usize,
    /// The tier from which an independent critic must review the design.
    pub critic_from: RiskTier,
    /// The tier from which a person approves the design whatever the checks say.
    pub human_from: RiskTier,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            trivial_max_requirements: 2,
            trivial_max_files: 3,
            min_alternatives: 2,
            max_elements_per_requirement: 3,
            critic_from: RiskTier::High,
            human_from: RiskTier::High,
        }
    }
}

/// Which rule a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    /// A requirement of the specification has no design element.
    UnmappedRequirement,
    /// A design element names a requirement the specification does not hold.
    UnknownRequirement,
    /// A design element satisfies no requirement that exists.
    ElementWithoutRequirement,
    /// Two elements or two decisions share an identifier.
    DuplicateId,
    /// The design says `DONE` and lists requirements it could not cover.
    DoneWithUncoveredRequirements,
    /// A change that is not trivial has no decision.
    NoDecision,
    /// A change that is not trivial weighed too few alternatives.
    TooFewAlternatives,
    /// A change that is not trivial names no way it could fail.
    NoFailureModes,
    /// The design has more elements than its requirements justify.
    BuiltForItsOwnSake,
    /// The design touches a path that policy protects.
    ProtectedPath,
}

impl Check {
    /// The stable name, in the form of a slug.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnmappedRequirement => "unmapped-requirement",
            Self::UnknownRequirement => "unknown-requirement",
            Self::ElementWithoutRequirement => "element-without-requirement",
            Self::DuplicateId => "duplicate-id",
            Self::DoneWithUncoveredRequirements => "done-with-uncovered-requirements",
            Self::NoDecision => "no-decision",
            Self::TooFewAlternatives => "too-few-alternatives",
            Self::NoFailureModes => "no-failure-modes",
            Self::BuiltForItsOwnSake => "built-for-its-own-sake",
            Self::ProtectedPath => "protected-path",
        }
    }
}

/// One thing wrong with the design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule.
    pub check: Check,
    /// What it is about: a requirement, an element, a decision or a path.
    pub subject: String,
    /// What is wrong and what to do about it, in plain English.
    pub message: String,
}

impl Finding {
    fn new(check: Check, subject: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check,
            subject: subject.into(),
            message: message.into(),
        }
    }

    /// The identifier a gate report gives the failed check: the rule and a short hash of the
    /// subject, so the same problem in the same place keeps its identifier from round to round.
    #[must_use]
    pub fn check_id(&self) -> String {
        let digest = factory_domain::values::Sha256Digest::of(self.subject.as_bytes());
        format!(
            "{}.{}",
            self.check.name(),
            digest.hex().get(..8).unwrap_or("00000000")
        )
    }
}

/// Whether the change is small enough that one design is enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Complexity {
    /// One design is enough. The text says why, from the facts.
    Trivial(String),
    /// At least two ways must have been weighed.
    NonTrivial,
}

/// Decides how much design the change needs.
#[must_use]
pub fn complexity(design: &Design, spec: &SpecIds, tier: RiskTier, rules: &Rules) -> Complexity {
    let requirements = spec.functional.len() + spec.quality.len();
    let files = design.touched().len();
    let asks_a_person = design.decisions.iter().any(|d| d.needs_person);
    if tier == RiskTier::Low
        && requirements <= rules.trivial_max_requirements
        && files <= rules.trivial_max_files
        && !asks_a_person
    {
        Complexity::Trivial(format!(
            "The policy puts this change in the {} risk tier, it answers {requirements} requirement(s), it touches {files} file(s) and it asks for nothing a person must approve, so one design is enough.",
            tier.as_str()
        ))
    } else {
        Complexity::NonTrivial
    }
}

/// The alternatives the design weighed, counted over all decisions.
#[must_use]
pub fn alternatives(design: &Design) -> usize {
    design.decisions.iter().map(|d| d.alternatives.len()).sum()
}

/// The result of the two deterministic gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// What is wrong with how the design maps to the specification.
    pub traceability: Vec<Finding>,
    /// What is wrong with the design as a design.
    pub completeness: Vec<Finding>,
    /// How much design the change needed.
    pub complexity: Complexity,
}

/// Runs both gates over a design that says `DONE`.
#[must_use]
pub fn check(
    design: &Design,
    spec: &SpecIds,
    tier: RiskTier,
    protected: &[&str],
    rules: &Rules,
) -> Outcome {
    let known = spec.all();
    let mut traceability = Vec::new();
    let mut completeness = Vec::new();

    let mut satisfied: BTreeSet<&str> = BTreeSet::new();
    for element in &design.elements {
        let mut any_known = false;
        for id in &element.satisfies {
            if known.contains(id) {
                satisfied.insert(id.as_str());
                any_known = true;
            } else {
                traceability.push(Finding::new(
                    Check::UnknownRequirement,
                    format!("{}>{id}", element.id),
                    format!(
                        "The design element {} says it satisfies {id}, which the frozen specification does not hold. Remove it: a design element answers a requirement that exists.",
                        element.id
                    ),
                ));
            }
        }
        if !any_known {
            traceability.push(Finding::new(
                Check::ElementWithoutRequirement,
                element.id.clone(),
                format!(
                    "The design element {} satisfies no requirement of the frozen specification. Remove it or tie it to a requirement.",
                    element.id
                ),
            ));
        }
    }
    for id in &known {
        if !satisfied.contains(id.as_str()) {
            traceability.push(Finding::new(
                Check::UnmappedRequirement,
                id.clone(),
                format!(
                    "No design element satisfies the requirement {id}. Every requirement of the frozen specification needs a design element."
                ),
            ));
        }
    }
    if !design.uncovered.is_empty() {
        traceability.push(Finding::new(
            Check::DoneWithUncoveredRequirements,
            design.uncovered.join(","),
            format!(
                "The design says it is done and also lists requirements it could not cover: {}. A finished design covers them all.",
                design.uncovered.join(", ")
            ),
        ));
    }

    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for id in design
        .elements
        .iter()
        .map(|e| e.id.as_str())
        .chain(design.decisions.iter().map(|d| d.id.as_str()))
    {
        if !ids.insert(id) {
            completeness.push(Finding::new(
                Check::DuplicateId,
                id,
                format!("Two parts of the design share the identifier {id}. Give each its own."),
            ));
        }
    }

    let kind = complexity(design, spec, tier, rules);
    if kind == Complexity::NonTrivial {
        if design.decisions.is_empty() {
            completeness.push(Finding::new(
                Check::NoDecision,
                "decisions",
                "This change is not trivial, and the design records no decision. Record what was chosen and what else was weighed.",
            ));
        }
        let total = alternatives(design);
        if total < rules.min_alternatives {
            completeness.push(Finding::new(
                Check::TooFewAlternatives,
                "alternatives",
                format!(
                    "This change is not trivial, so the design must weigh at least {} alternatives, and it names {total}. Add the ways you did not choose and why.",
                    rules.min_alternatives
                ),
            ));
        }
        if design.risks.is_empty() {
            completeness.push(Finding::new(
                Check::NoFailureModes,
                "risks",
                "This change is not trivial, and the design names no way it could fail. List the risks, so that a person can see what the design gives up.",
            ));
        }
    }
    let ids_total = known.len().max(1);
    if design.elements.len() > ids_total.saturating_mul(rules.max_elements_per_requirement) {
        completeness.push(Finding::new(
            Check::BuiltForItsOwnSake,
            "elements",
            format!(
                "The design has {} elements for {} requirements, and the limit is {} per requirement. Remove what no requirement needs.",
                design.elements.len(),
                known.len(),
                rules.max_elements_per_requirement
            ),
        ));
    }
    for path in protected {
        completeness.push(Finding::new(
            Check::ProtectedPath,
            *path,
            format!(
                "The design touches {path}, which policy protects. A design cannot plan a change to a protected path."
            ),
        ));
    }
    Outcome {
        traceability,
        completeness,
        complexity: kind,
    }
}

/// True when the status asks for a person and so no deterministic check applies.
#[must_use]
pub fn asks_a_person(design: &Design) -> bool {
    design.status == Status::NeedsHuman
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::architecture::design::{Decision, Element};

    fn ids(functional: &[&str], quality: &[&str]) -> SpecIds {
        SpecIds {
            functional: functional.iter().map(|s| (*s).to_owned()).collect(),
            quality: quality.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn element(id: &str, satisfies: &[&str], touches: &[&str]) -> Element {
        Element {
            id: id.into(),
            title: "A part of the design".into(),
            responsibility: "It does one thing for the requirement.".into(),
            kind: "module".into(),
            satisfies: satisfies.iter().map(|s| (*s).to_owned()).collect(),
            touches: touches.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn decision(id: &str, alternatives: usize, needs_person: bool) -> Decision {
        Decision {
            id: id.into(),
            title: "A decision of the design".into(),
            choice: "The choice that was made and why.".into(),
            alternatives: (0..alternatives)
                .map(|n| format!("The alternative number {n} that was weighed."))
                .collect(),
            consequences: "What follows from the choice.".into(),
            needs_person,
        }
    }

    fn design(elements: Vec<Element>, decisions: Vec<Decision>, risks: usize) -> Design {
        Design {
            status: Status::Done,
            title: "A design for the change".into(),
            summary: "A short summary of the design.".into(),
            elements,
            decisions,
            risks: (0..risks)
                .map(|n| format!("The risk number {n}."))
                .collect(),
            open_questions: Vec::new(),
            uncovered: Vec::new(),
            human_question: None,
            ignored_instructions: Vec::new(),
        }
    }

    fn names(findings: &[Finding]) -> Vec<Check> {
        findings.iter().map(|f| f.check).collect()
    }

    #[test]
    fn a_requirement_without_a_design_element_is_unmapped() {
        let spec = ids(&["FR-001", "FR-002"], &[]);
        let d = design(
            vec![element("a", &["FR-001"], &["src/a.rs"])],
            Vec::new(),
            0,
        );
        let out = check(&d, &spec, RiskTier::Low, &[], &Rules::default());
        assert_eq!(names(&out.traceability), [Check::UnmappedRequirement]);
        assert_eq!(out.traceability[0].subject, "FR-002");
    }

    #[test]
    fn an_element_for_a_requirement_that_does_not_exist_is_refused() {
        let spec = ids(&["FR-001"], &[]);
        let d = design(
            vec![
                element("a", &["FR-001"], &["src/a.rs"]),
                element("novelty", &["FR-900"], &["src/b.rs"]),
            ],
            Vec::new(),
            0,
        );
        let out = check(&d, &spec, RiskTier::Low, &[], &Rules::default());
        let found = names(&out.traceability);
        assert!(found.contains(&Check::UnknownRequirement));
        assert!(found.contains(&Check::ElementWithoutRequirement));
    }

    #[test]
    fn a_trivial_change_needs_one_design_and_the_stage_records_why() {
        let spec = ids(&["FR-001"], &[]);
        let d = design(
            vec![element("a", &["FR-001"], &["src/a.rs"])],
            Vec::new(),
            0,
        );
        let out = check(&d, &spec, RiskTier::Low, &[], &Rules::default());
        assert!(out.completeness.is_empty(), "{:?}", out.completeness);
        let Complexity::Trivial(why) = out.complexity else {
            panic!("a trivial change");
        };
        assert!(why.contains("one design is enough"), "{why}");
    }

    #[test]
    fn a_change_that_is_not_trivial_must_weigh_alternatives_and_name_its_failure_modes() {
        let spec = ids(&["FR-001", "FR-002", "FR-003"], &[]);
        let elements = vec![element("a", &["FR-001", "FR-002", "FR-003"], &["src/a.rs"])];
        let bare = check(
            &design(elements.clone(), Vec::new(), 0),
            &spec,
            RiskTier::Low,
            &[],
            &Rules::default(),
        );
        assert_eq!(
            names(&bare.completeness),
            [
                Check::NoDecision,
                Check::TooFewAlternatives,
                Check::NoFailureModes
            ]
        );
        let weighed = check(
            &design(elements.clone(), vec![decision("d", 2, false)], 1),
            &spec,
            RiskTier::Low,
            &[],
            &Rules::default(),
        );
        assert!(
            weighed.completeness.is_empty(),
            "{:?}",
            weighed.completeness
        );
        let one = check(
            &design(elements, vec![decision("d", 1, false)], 1),
            &spec,
            RiskTier::Low,
            &[],
            &Rules::default(),
        );
        assert_eq!(names(&one.completeness), [Check::TooFewAlternatives]);
    }

    #[test]
    fn a_higher_tier_or_a_decision_for_a_person_makes_the_change_non_trivial() {
        let spec = ids(&["FR-001"], &[]);
        let plain = design(
            vec![element("a", &["FR-001"], &["src/a.rs"])],
            Vec::new(),
            0,
        );
        assert!(matches!(
            complexity(&plain, &spec, RiskTier::Low, &Rules::default()),
            Complexity::Trivial(_)
        ));
        assert_eq!(
            complexity(&plain, &spec, RiskTier::Medium, &Rules::default()),
            Complexity::NonTrivial
        );
        let asks = design(
            vec![element("a", &["FR-001"], &["src/a.rs"])],
            vec![decision("d", 0, true)],
            0,
        );
        assert_eq!(
            complexity(&asks, &spec, RiskTier::Low, &Rules::default()),
            Complexity::NonTrivial
        );
    }

    #[test]
    fn a_design_with_far_more_elements_than_requirements_is_built_for_its_own_sake() {
        let spec = ids(&["FR-001"], &[]);
        let many: Vec<Element> = (0..4)
            .map(|n| element(&format!("part-{n}"), &["FR-001"], &["src/a.rs"]))
            .collect();
        let out = check(
            &design(many, vec![decision("d", 2, false)], 1),
            &spec,
            RiskTier::Low,
            &[],
            &Rules::default(),
        );
        assert!(names(&out.completeness).contains(&Check::BuiltForItsOwnSake));
    }

    #[test]
    fn a_protected_path_and_a_repeated_identifier_are_findings() {
        let spec = ids(&["FR-001"], &[]);
        let d = design(
            vec![
                element("a", &["FR-001"], &[".github/workflows/ci.yml"]),
                element("a", &["FR-001"], &[]),
            ],
            Vec::new(),
            0,
        );
        let out = check(
            &d,
            &spec,
            RiskTier::Low,
            &[".github/workflows/ci.yml"],
            &Rules::default(),
        );
        let found = names(&out.completeness);
        assert!(found.contains(&Check::ProtectedPath));
        assert!(found.contains(&Check::DuplicateId));
    }

    #[test]
    fn a_done_design_that_lists_uncovered_requirements_is_a_finding() {
        let spec = ids(&["FR-001"], &[]);
        let mut d = design(
            vec![element("a", &["FR-001"], &["src/a.rs"])],
            Vec::new(),
            0,
        );
        d.uncovered = vec!["FR-001".into()];
        let out = check(&d, &spec, RiskTier::Low, &[], &Rules::default());
        assert!(names(&out.traceability).contains(&Check::DoneWithUncoveredRequirements));
    }

    #[test]
    fn the_check_id_keeps_its_name_for_the_same_subject() {
        let a = Finding::new(Check::UnmappedRequirement, "FR-002", "one");
        let b = Finding::new(Check::UnmappedRequirement, "FR-002", "two");
        assert_eq!(a.check_id(), b.check_id());
        assert!(a.check_id().starts_with("unmapped-requirement."));
    }
}
