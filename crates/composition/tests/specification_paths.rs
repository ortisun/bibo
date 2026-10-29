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

// ---- the compiled policy the real workspace looks at a change with -----------------------------

#[test]
fn the_second_look_of_the_workspace_lets_the_skills_write_what_the_policy_lists_and_nothing_more() {
    // Found by the live-adapters run: the real workspace judges a change by the rules of the
    // request AND by the compiled policy, and the stricter answer stands. The stage's rules lift the
    // writes of its skills, but the compiled policy still protected `.specify/**`, so the real
    // workspace refused the pointer the specify skill had just written and the stage ended BLOCKED.
    use factory_composition::providers::layer_policy;
    use factory_domain::policy::RepoKind;
    use factory_domain::policy::paths::{DiffEntry, DiffVerdict, PathPolicy};
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let verdict = |policy: &PathPolicy, path: &str| {
        policy.check_diff(
            RepoKind::Target,
            &[DiffEntry::Added {
                path: path.to_owned(),
            }],
            None,
            &Default::default(),
        )
    };
    let compiled = PathPolicy::from_policy(&policies.security).expect("the compiled policy");
    // Before: the plain compiled policy refuses the pointer.
    assert!(matches!(
        verdict(&compiled, ".specify/feature.json"),
        DiffVerdict::Blocked { .. }
    ));
    // After: the second look allows the writes the policy lists for the skills...
    let layer = PathPolicy::from_policy(&layer_policy(&policies.security)).expect("the layer");
    for allowed in [
        ".specify/feature.json",
        "specs/add-a-json-option-1a2b3c4d/spec.md",
        "specs/add-a-json-option-1a2b3c4d/checklists/requirements-quality.md",
    ] {
        assert!(
            matches!(verdict(&layer, allowed), DiffVerdict::Allowed { .. }),
            "{allowed}: {:?}",
            verdict(&layer, allowed)
        );
    }
    // ...and still refuses the rest: the constitution (a person's exception), the project
    // configuration, the CI files, the other Spec Kit state.
    for protected in [
        ".specify/memory/constitution.md",
        ".specify/extensions.yml",
        ".specify/integration.json",
        ".specify/templates/spec-template.md",
        ".github/workflows/ci.yml",
        "CODEOWNERS",
    ] {
        assert!(
            matches!(verdict(&layer, protected), DiffVerdict::Blocked { .. }),
            "{protected} must stay protected for the second look"
        );
    }
}
