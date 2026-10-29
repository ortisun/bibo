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

/// The facts the design shows.
#[must_use]
pub fn measure(design: &Design, policy: &PolicyEngine) -> RiskFacts {
    let touched = design.touched();
    let mut facts = RiskFacts::default();
    let mut sensitive = false;
    for path in &touched {
        if let PathVerdict::Allowed(allowance) = policy.paths.check(
            RepoKind::Target,
            path,
            Operation::Add,
            None,
            &ChangeEvidence::default(),
        ) && !allowance.sensitive.is_empty()
        {
            sensitive = true;
        }
    }
    let protected = !protected_paths(design, policy).is_empty();
    facts.sensitive_file_change = sensitive;
    facts.protected_path_change = protected;

    let mut modules: Vec<String> = touched.iter().filter_map(|path| module_of(path)).collect();
    modules.sort();
    modules.dedup();
    facts.multi_module_change = modules.len() > 1;
    facts.public_api_change = design.elements.iter().any(|e| e.kind == "interface");
    facts.schema_migration_without_data_loss = design.elements.iter().any(|e| e.kind == "data");
    facts.new_dependency = design.decisions.iter().any(|d| d.needs_person);

    let every = |kind: &str| {
        !design.elements.is_empty() && design.elements.iter().all(|element| element.kind == kind)
    };
    facts.docs_only = every("documentation")
        || (!touched.is_empty() && touched.iter().all(|path| is_documentation(path)));
    facts.tests_only_new_files = every("test");
    facts.single_module_change_without_sensitive_or_protected_paths = modules.len() <= 1
        && !sensitive
        && !protected
        && !facts.new_dependency
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
