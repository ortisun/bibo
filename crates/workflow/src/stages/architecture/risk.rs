//! The risk of a design, computed from facts and never from what the architect says.
//!
//! The policy engine turns facts into a tier (`RiskPolicy::assess`). Some facts are known before
//! the design exists and come from the job (the composition root supplies them through the
//! `JobRisk` seam). The others are measured here from the design itself: which files it touches
//! and how the path policy treats them, how many modules it spans, whether it changes an
//! interface, a data shape or a dependency. The two sets are joined with OR, so the design can
//! raise the tier that the job started with and never lower it.
//!
//! A design that matches no criterion of the policy is `high`, because the policy says that not
//! knowing what a change is does not make it safe.

use factory_domain::policy::PolicyEngine;
use factory_domain::policy::RepoKind;
use factory_domain::policy::paths::{ChangeEvidence, Operation, PathVerdict};
use factory_domain::policy::risk::{RiskAssessment, RiskFacts};
use factory_domain::vocabulary::RiskTier;

use super::design::Design;

/// The top-level directories that are not a module of the product.
const NOT_A_MODULE: [&str; 8] = [
    "tests", "test", "docs", "doc", "benches", "examples", "fixtures", "scripts",
];

/// The directories whose children are the modules.
const CONTAINERS: [&str; 6] = ["crates", "apps", "packages", "services", "libs", "modules"];

pub(crate) fn module_of(path: &str) -> Option<String> {
    let mut parts = path.trim_start_matches("./").split('/');
    let first = parts.next()?;
    // A file at the top of the repository belongs to no module.
    let second = parts.next()?;
    if NOT_A_MODULE.contains(&first) {
        return None;
    }
    if CONTAINERS.contains(&first) {
        return Some(format!("{first}/{second}"));
    }
    Some(first.to_owned())
}

pub(crate) fn is_documentation(path: &str) -> bool {
    path.starts_with("docs/")
        || path.starts_with("doc/")
        || path.to_ascii_lowercase().ends_with(".md")
}

/// Joins two sets of facts: a fact holds when it holds in either.
#[must_use]
pub fn either(a: RiskFacts, b: RiskFacts) -> RiskFacts {
    RiskFacts {
        docs_only: a.docs_only || b.docs_only,
        tests_only_new_files: a.tests_only_new_files || b.tests_only_new_files,
        single_module_change_without_sensitive_or_protected_paths: a
            .single_module_change_without_sensitive_or_protected_paths
            || b.single_module_change_without_sensitive_or_protected_paths,
        multi_module_change: a.multi_module_change || b.multi_module_change,
        public_api_change: a.public_api_change || b.public_api_change,
        schema_migration_without_data_loss: a.schema_migration_without_data_loss
            || b.schema_migration_without_data_loss,
        design_decision_needs_person: a.design_decision_needs_person
            || b.design_decision_needs_person,
        authn_authz_change: a.authn_authz_change || b.authn_authz_change,
        secret_handling_change: a.secret_handling_change || b.secret_handling_change,
        new_dependency: a.new_dependency || b.new_dependency,
        sensitive_file_change: a.sensitive_file_change || b.sensitive_file_change,
        data_migration: a.data_migration || b.data_migration,
        concurrency_or_locking_change: a.concurrency_or_locking_change
            || b.concurrency_or_locking_change,
        infra_change: a.infra_change || b.infra_change,
        protected_path_change: a.protected_path_change || b.protected_path_change,
        policy_or_sandbox_change: a.policy_or_sandbox_change || b.policy_or_sandbox_change,
        money_movement: a.money_movement || b.money_movement,
        physical_actuation: a.physical_actuation || b.physical_actuation,
        regulated_workflow: a.regulated_workflow || b.regulated_workflow,
        production_data_access: a.production_data_access || b.production_data_access,
    }
}

/// The paths of the design that the path policy refuses to let an agent change, as it sees them
/// when the file is added. A path that is refused for an addition is refused for any change.
#[must_use]
pub fn protected_paths<'a>(design: &'a Design, policy: &PolicyEngine) -> Vec<&'a str> {
    design
        .touched()
        .into_iter()
        .filter(|path| {
            matches!(
                policy.paths.check(
                    RepoKind::Target,
                    path,
                    Operation::Add,
                    None,
                    &ChangeEvidence::default()
                ),
                PathVerdict::Denied(_)
            )
        })
        .collect()
}

/// The paths of the design that the path policy lets an agent change and marks sensitive, such as
/// a dependency manifest: a change to one runs extra checks and raises the tier to `high`.
#[must_use]
pub fn sensitive_paths<'a>(design: &'a Design, policy: &PolicyEngine) -> Vec<&'a str> {
    design
        .touched()
        .into_iter()
        .filter(|path| {
            matches!(
                policy.paths.check(
                    RepoKind::Target,
                    path,
                    Operation::Add,
                    None,
                    &ChangeEvidence::default()
                ),
                PathVerdict::Allowed(allowance) if !allowance.sensitive.is_empty()
            )
        })
        .collect()
}

/// The decisions of the design that a person must approve. They make the criterion
/// `design_decision_needs_person` hold (ADR 0037), not `new_dependency`: a real new dependency is a
/// change to a manifest, which is `sensitive_file_change` here and `new_dependency` in the diff.
#[must_use]
pub fn decisions_for_a_person(design: &Design) -> Vec<&str> {
    design
        .decisions
        .iter()
        .filter(|decision| decision.needs_person)
        .map(|decision| decision.id.as_str())
        .collect()
}

/// The facts the design shows.
#[must_use]
pub fn measure(design: &Design, policy: &PolicyEngine) -> RiskFacts {
    let touched = design.touched();
    let mut facts = RiskFacts::default();
    let sensitive = !sensitive_paths(design, policy).is_empty();
    let protected = !protected_paths(design, policy).is_empty();
    facts.sensitive_file_change = sensitive;
    facts.protected_path_change = protected;

    let mut modules: Vec<String> = touched.iter().filter_map(|path| module_of(path)).collect();
    modules.sort();
    modules.dedup();
    facts.multi_module_change = modules.len() > 1;
    facts.public_api_change = design.elements.iter().any(|e| e.kind == "interface");
    facts.schema_migration_without_data_loss = design.elements.iter().any(|e| e.kind == "data");
    facts.design_decision_needs_person = !decisions_for_a_person(design).is_empty();

    let every = |kind: &str| {
        !design.elements.is_empty() && design.elements.iter().all(|element| element.kind == kind)
    };
    facts.docs_only = every("documentation")
        || (!touched.is_empty() && touched.iter().all(|path| is_documentation(path)));
    facts.tests_only_new_files = every("test");
    facts.single_module_change_without_sensitive_or_protected_paths = modules.len() <= 1
        && !sensitive
        && !protected
        && !facts.design_decision_needs_person
        && !facts.public_api_change
        && !touched.is_empty();
    facts
}

/// The tier of the design: the facts of the job joined with the facts of the design, assessed by
/// the policy. The agent's own claim can raise the tier and never lowers it.
#[must_use]
pub fn assess(
    design: &Design,
    policy: &PolicyEngine,
    job: RiskFacts,
    agent_claim: Option<RiskTier>,
) -> RiskAssessment {
    policy
        .risk
        .assess(&either(job, measure(design, policy)), agent_claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::architecture::design::{Decision, Element, Status};

    fn element(kind: &str, touches: &[&str]) -> Element {
        Element {
            id: "an-element".into(),
            title: "An element of the design".into(),
            responsibility: "It does one thing for the requirement.".into(),
            kind: kind.into(),
            satisfies: vec!["FR-001".into()],
            touches: touches.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    fn design(elements: Vec<Element>, decisions: Vec<Decision>) -> Design {
        Design {
            status: Status::Done,
            title: "A design for the change".into(),
            summary: "A short summary of the design.".into(),
            elements,
            decisions,
            risks: Vec::new(),
            open_questions: Vec::new(),
            uncovered: Vec::new(),
            human_question: None,
            ignored_instructions: Vec::new(),
        }
    }

    #[test]
    fn a_module_is_the_top_directory_or_the_child_of_a_container() {
        assert_eq!(module_of("src/main.rs").as_deref(), Some("src"));
        assert_eq!(
            module_of("crates/a/src/lib.rs").as_deref(),
            Some("crates/a")
        );
        assert_eq!(module_of("tests/it.rs"), None);
        assert_eq!(module_of("README.md"), None);
    }

    #[test]
    fn files_in_one_module_are_not_a_multi_module_change() {
        let one = design(
            vec![element("module", &["src/a.rs", "src/b.rs"])],
            Vec::new(),
        );
        let two = design(
            vec![element("module", &["src/a.rs", "lib/b.rs"])],
            Vec::new(),
        );
        assert!(is_single(&one));
        assert!(!is_single(&two));
    }

    fn policy() -> PolicyEngine {
        let security: factory_domain::policy::SecurityPolicy = serde_json::from_str(include_str!(
            "../../../../domain/tests/fixtures/policy/security.json"
        ))
        .expect("the security policy fixture");
        let approval: factory_domain::policy::ApprovalPolicy = serde_json::from_str(include_str!(
            "../../../../domain/tests/fixtures/policy/approval.json"
        ))
        .expect("the approval policy fixture");
        PolicyEngine::new(&security, &approval).expect("the policies build")
    }

    fn named(id: &str, kind: &str, satisfies: &[&str], touches: &[&str]) -> Element {
        Element {
            id: id.into(),
            kind: kind.into(),
            satisfies: satisfies.iter().map(|s| (*s).to_owned()).collect(),
            ..element(kind, touches)
        }
    }

    fn decision(id: &str, needs_person: bool) -> Decision {
        Decision {
            id: id.into(),
            title: "Write the JSON text by hand".into(),
            choice: "Build the JSON text with the standard library, with no new dependency.".into(),
            alternatives: vec!["Add a JSON library as a dependency.".into()],
            consequences: "The formatter escapes nothing, because the object holds three numbers."
                .into(),
            needs_person,
        }
    }

    /// The design an architect would give for the job of real run 27 of scenario E1: a `--json`
    /// option on the word count tool, with its tests, README and changelog, and no new dependency
    /// (FR-001 to FR-013 of the frozen specification).
    fn json_option_design() -> Design {
        design(
            vec![
                named(
                    "json-option",
                    "interface",
                    &["FR-001", "FR-011", "FR-012"],
                    &["src/main.rs"],
                ),
                named(
                    "json-formatter",
                    "module",
                    &["FR-002", "FR-003", "FR-004", "FR-010", "FR-013"],
                    &["src/main.rs"],
                ),
                named(
                    "plain-output-kept",
                    "module",
                    &["FR-005", "FR-006"],
                    &["src/main.rs"],
                ),
                named(
                    "json-option-tests",
                    "test",
                    &["FR-001", "FR-003", "FR-004", "FR-006", "FR-012"],
                    &["tests/cli.rs"],
                ),
                named(
                    "json-option-docs",
                    "documentation",
                    &["FR-007", "FR-008"],
                    &["README.md", "CHANGELOG.md"],
                ),
            ],
            vec![decision("hand-written-json", false)],
        )
    }

    fn tier_of(design: &Design, claim: Option<RiskTier>) -> RiskAssessment {
        assess(design, &policy(), RiskFacts::default(), claim)
    }

    #[test]
    fn a_json_option_with_tests_and_docs_is_a_public_interface_change_at_medium() {
        let design = json_option_design();
        let assessment = tier_of(&design, None);
        assert_eq!(assessment.tier, RiskTier::Medium);
        assert_eq!(assessment.computed, RiskTier::Medium);
        assert_eq!(assessment.matched, ["public_api_change"]);
        assert!(!assessment.unclassified);
        // The tests and the top-level documents are no module, so the change spans one module.
        let facts = measure(&design, &policy());
        assert!(!facts.multi_module_change);
        assert!(sensitive_paths(&design, &policy()).is_empty());
        // The critic is asked from the high tier, so this design needs none.
        assert!(assessment.tier < super::super::checks::Rules::default().critic_from);
    }

    #[test]
    fn the_same_design_without_an_interface_element_is_low() {
        let mut design = json_option_design();
        design.elements[0].kind = "module".into();
        let assessment = tier_of(&design, None);
        assert_eq!(assessment.tier, RiskTier::Low);
        assert_eq!(
            assessment.matched,
            ["single_module_change_without_sensitive_or_protected_paths"]
        );
    }

    #[test]
    fn a_dependency_manifest_in_touches_makes_the_design_high() {
        // FR-009 says the change adds no dependency. An element that lists the manifest it read to
        // show that, as files it touches, says that it changes a sensitive file.
        let mut design = json_option_design();
        design.elements.push(named(
            "no-new-dependency",
            "module",
            &["FR-009"],
            &["Cargo.toml", "Cargo.lock"],
        ));
        let assessment = tier_of(&design, None);
        assert_eq!(assessment.tier, RiskTier::High);
        assert!(
            assessment
                .matched
                .contains(&"sensitive_file_change".to_owned()),
            "{:?}",
            assessment.matched
        );
        assert_eq!(
            sensitive_paths(&design, &policy()),
            ["Cargo.toml", "Cargo.lock"]
        );
    }

    #[test]
    fn a_decision_for_a_person_is_its_own_fact_at_medium_and_no_new_dependency() {
        // ADR 0037: before, such a decision counted as `new_dependency` and made the design high.
        let mut design = json_option_design();
        design.elements[0].kind = "module".into();
        design.decisions[0].needs_person = true;
        let assessment = tier_of(&design, None);
        assert_eq!(assessment.tier, RiskTier::Medium);
        assert_eq!(assessment.matched, ["design_decision_needs_person"]);
        let facts = measure(&design, &policy());
        assert!(facts.design_decision_needs_person);
        assert!(!facts.new_dependency);
        assert!(!facts.single_module_change_without_sensitive_or_protected_paths);
        assert_eq!(decisions_for_a_person(&design), ["hand-written-json"]);
    }

    #[test]
    fn a_decision_for_a_person_that_touches_the_manifest_is_still_high() {
        // A real new dependency changes a manifest, a sensitive path, so it stays high.
        let mut design = json_option_design();
        design.decisions[0].needs_person = true;
        design.elements.push(named(
            "add-a-json-library",
            "module",
            &["FR-009"],
            &["Cargo.toml", "Cargo.lock"],
        ));
        let assessment = tier_of(&design, None);
        assert_eq!(assessment.tier, RiskTier::High);
        assert!(
            assessment
                .matched
                .contains(&"sensitive_file_change".to_owned())
        );
        assert!(
            assessment
                .matched
                .contains(&"design_decision_needs_person".to_owned())
        );
    }

    #[test]
    fn the_intakes_claim_raises_the_tier_and_never_lowers_it() {
        let design = json_option_design();
        let raised = tier_of(&design, Some(RiskTier::High));
        assert_eq!(raised.tier, RiskTier::High);
        assert_eq!(raised.computed, RiskTier::Medium);
        let lowered = tier_of(&design, Some(RiskTier::Low));
        assert_eq!(lowered.tier, RiskTier::Medium);
    }

    #[test]
    fn a_design_that_touches_no_file_matches_no_criterion_and_is_high() {
        let mut design = json_option_design();
        for element in &mut design.elements {
            element.touches.clear();
        }
        let assessment = tier_of(&design, None);
        // The interface element still holds; with it gone, nothing is known.
        assert_eq!(assessment.tier, RiskTier::Medium);
        design.elements[0].kind = "module".into();
        let assessment = tier_of(&design, None);
        assert!(assessment.unclassified);
        assert_eq!(assessment.tier, RiskTier::High);
    }

    fn is_single(design: &Design) -> bool {
        let mut modules: Vec<String> = design
            .touched()
            .iter()
            .filter_map(|path| module_of(path))
            .collect();
        modules.sort();
        modules.dedup();
        modules.len() <= 1
    }
}
