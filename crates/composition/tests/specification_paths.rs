//! The path rules of the specification stage, built from the real policy.
//!
//! Found by the full run (`apps/api/tests/full_run.rs`): the policy protects `.specify/**` and the
//! same policy lists `.specify/feature.json` among the writes of the specify skill, so the host
//! refused the pointer the skill must leave and the stage ended `BLOCKED` on its first run.

use std::path::PathBuf;

use factory_composition::providers::{path_rules, specification_path_rules};
use factory_composition::startup::load_policy;
use factory_ports::paths::{PathMode, RepoPath};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn path(text: &str) -> RepoPath {
    RepoPath::new(text).expect("a repository path")
}

#[test]
fn the_plain_rules_refuse_the_pointer_the_specify_skill_must_write() {
    // The defect the full run found: with the plain rules the pointer is a protected path.
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let plain = path_rules(&policies.security);
    assert_eq!(
        plain.classify(&path(".specify/feature.json")),
        Some(PathMode::DenyWrite)
    );
}

#[test]
fn the_specification_rules_let_the_skills_write_what_the_policy_lists_and_nothing_more() {
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let rules = specification_path_rules(&policies.security);
    // The writes of speckit.specify, speckit.clarify and speckit.checklist.
    for allowed in [
        ".specify/feature.json",
        "specs/add-a-json-option-1a2b3c4d/spec.md",
        "specs/add-a-json-option-1a2b3c4d/checklists/requirements.md",
        "specs/add-a-json-option-1a2b3c4d/checklists/requirements-quality.md",
    ] {
        assert_eq!(rules.classify(&path(allowed)), None, "{allowed}");
    }
    // The rest of the Spec Kit state, the project configuration and the CI files stay protected.
    // The constitution needs a person's exception (`protected_path_exception_required`).
    for protected in [
        ".specify/memory/constitution.md",
        ".specify/extensions.yml",
        ".specify/integration.json",
        ".specify/templates/spec-template.md",
        ".factory/project.yaml",
        ".github/workflows/ci.yml",
        "CODEOWNERS",
    ] {
        assert!(
            rules.classify(&path(protected)).is_some(),
            "{protected} must stay protected"
        );
    }
}

#[test]
fn the_other_stages_keep_the_plain_rules() {
    // The builder and the documenter use `path_rules`, so they still cannot write the pointer.
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let plain = path_rules(&policies.security);
    let specification = specification_path_rules(&policies.security);
    assert_ne!(plain, specification);
    assert!(plain.classify(&path(".specify/feature.json")).is_some());
}
