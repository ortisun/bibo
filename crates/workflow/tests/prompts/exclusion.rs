//! What must never reach a prompt: files the path policy hides, another tenant's text, and texts
//! the caller says are withheld.

use factory_domain::values::Sha256Digest;
use factory_testkit::fx::canary::{CanaryKind, CanarySet, Sweeper};
use factory_workflow::prompts::{
    Assembler, AssemblyError, AssemblyRequest, ExclusionReason, Input, Limits, Source,
};

use super::prompts_check::decode;
use super::prompts_support::{
    Agent, agent, class_of, names, other_tenant, outside_lines, path_policy, request, scope,
    shared_redactor, tenant,
};

fn file(agent: &Agent, name: &str, path: &str, text: &str) -> Input {
    Input::untrusted(
        name,
        class_of(agent, name),
        Source::RepoFile {
            path: path.to_owned(),
            commit: None,
            lines: None,
        },
        tenant(),
        text,
    )
}

fn required(agent: &Agent) -> Vec<Input> {
    vec![
        super::prompts_support::input(agent, "frozen_specification", "the specification"),
        super::prompts_support::input(agent, "repository_map", "the map"),
    ]
}

/// Paths and whether the policy lets a model read them.
const PATHS: &[(&str, bool)] = &[
    ("src/main.rs", true),
    ("README.md", true),
    (".env.example", true),
    ("docs/holdout-policy.md", true),
    ("evals/case-1.json", false),
    ("tests/evals/case-1.json", false),
    ("tests/holdout/a.json", false),
    ("crates/x/holdout/a.json", false),
    ("crates/x/heldout/a.json", false),
    (".env", false),
    (".env.production", false),
    ("deploy/server.pem", false),
    ("deploy/signing.key", false),
    ("keys/store.p12", false),
    ("keys/store.pfx", false),
    ("home/.ssh/id_rsa", false),
    ("home/.ssh/id_rsa.pub", false),
    ("home/.ssh/id_ed25519", false),
    (".netrc", false),
    // Spelled to dodge a plain comparison.
    ("EVALS/case-1.json", false),
    ("ev\u{200B}als/case-1.json", false),
    ("tests/hold\u{202E}out/a.json", false),
    ("\u{FF45}vals/case-1.json", false),
    // A path that cannot be checked is left out as well.
    (".git/config", false),
    ("../secrets/x", false),
    ("/etc/passwd", false),
    ("a\\b", false),
    ("", false),
];

#[test]
fn prompts_exclusion_a_file_the_path_policy_hides_is_left_out_of_an_optional_input() {
    let agent = agent("architect");
    let canaries = CanarySet::generate();
    let holdout = canaries.get(CanaryKind::HoldoutString).value().to_owned();
    let sweeper = Sweeper::new(&canaries);
    for (path, readable) in PATHS {
        let mut inputs = required(&agent);
        inputs.push(file(&agent, "rework_findings", path, &holdout));
        let assembled = Assembler::new(shared_redactor(), path_policy(), Limits::default())
            .assemble(request(&agent, inputs))
            .unwrap_or_else(|e| panic!("{path:?}: {e}"));
        let record = assembled
            .manifest()
            .input("rework_findings")
            .expect("record");
        let in_prompt = !sweeper
            .scan("prompt", assembled.text().as_bytes())
            .is_empty();
        assert_eq!(in_prompt, *readable, "{path:?}");
        assert_eq!(record.provided, *readable, "{path:?}");
        assert_eq!(
            assembled.manifest().exclusions.is_empty(),
            *readable,
            "{path:?}"
        );
        let decoded = decode(&outside_lines(&agent), &names(&agent), assembled.text());
        assert!(
            decoded.problems.is_empty(),
            "{path:?}: {:#?}",
            decoded.problems
        );
    }
}

#[test]
fn prompts_exclusion_records_the_path_and_the_rule_and_nothing_of_the_content() {
    let agent = agent("architect");
    let mut inputs = required(&agent);
    inputs.push(file(
        &agent,
        "rework_findings",
        "tests/holdout/a.json",
        "hidden words",
    ));
    let assembled = Assembler::new(shared_redactor(), path_policy(), Limits::default())
        .assemble(request(&agent, inputs))
        .expect("assembles");
    let exclusion = &assembled.manifest().exclusions[0];
    assert_eq!(exclusion.name, "rework_findings");
    match &exclusion.reason {
        ExclusionReason::HiddenPath { rule, path } => {
            assert_eq!(rule, "protected_paths.groups:evaluation_holdouts");
            assert_eq!(path, "tests/holdout/a.json");
        }
    }
    let record = assembled
        .manifest()
        .input("rework_findings")
        .expect("record");
    assert_eq!(record.original_bytes, 0);
    assert_eq!(record.original_sha256, Sha256Digest::of(b""));
    assert!(!format!("{:?}", assembled.manifest()).contains("hidden words"));
}

#[test]
fn prompts_exclusion_a_required_input_made_of_a_hidden_file_fails_the_assembly() {
    let agent = agent("architect");
    let inputs = vec![
        file(&agent, "frozen_specification", ".env", "KEY=value"),
        super::prompts_support::input(&agent, "repository_map", "the map"),
    ];
    let result = Assembler::new(shared_redactor(), path_policy(), Limits::default())
        .assemble(request(&agent, inputs));
    assert!(
        matches!(result, Err(AssemblyError::ExcludedRequiredInput { .. })),
        "{result:?}"
    );
}

#[test]
fn prompts_exclusion_one_hidden_path_among_many_leaves_the_whole_input_out() {
    // A diff or a map is one piece of text. If it is made of a hidden file too, all of it goes.
    let agent = agent("architect");
    let mut inputs = required(&agent);
    inputs.push(
        super::prompts_support::input(&agent, "rework_findings", "a diff of two files").touching([
            "src/lib.rs",
            "tests/holdout/x.json",
            "README.md",
        ]),
    );
    let assembled = Assembler::new(shared_redactor(), path_policy(), Limits::default())
        .assemble(request(&agent, inputs))
        .expect("assembles");
    assert!(!assembled.text().contains("a diff of two files"));
    assert_eq!(assembled.manifest().exclusions.len(), 1);
}

#[test]
fn prompts_exclusion_paths_of_the_factory_repository_are_checked_by_its_own_kind() {
    // The scope names the kind of repository, and the policy applies groups by kind.
    let agent = agent("architect");
    let canaries = CanarySet::generate();
    let sweeper = Sweeper::new(&canaries);
    let holdout = canaries.get(CanaryKind::HoldoutString).value().to_owned();
    let mut inputs = required(&agent);
    inputs.push(file(&agent, "rework_findings", "evals/x.json", &holdout));
    let factory_scope = factory_domain::policy::RepoKind::Factory;
    let assembled = Assembler::new(shared_redactor(), path_policy(), Limits::default())
        .assemble(AssemblyRequest::new(
            &agent.manifest,
            &agent.prompt,
            factory_workflow::prompts::Scope::new(tenant(), factory_scope),
            inputs,
        ))
        .expect("assembles");
    assert!(
        sweeper
            .scan("prompt", assembled.text().as_bytes())
            .is_empty()
    );
}

#[test]
fn prompts_exclusion_text_of_another_tenant_fails_the_assembly() {
    let agent = agent("intake-classifier");
    let foreign = Input::untrusted(
        "request",
        class_of(&agent, "request"),
        Source::Issue { number: 7 },
        other_tenant(),
        "text of the other tenant",
    );
    let result = Assembler::new(shared_redactor(), path_policy(), Limits::default())
        .assemble(request(&agent, vec![foreign]));
    assert!(
        matches!(result, Err(AssemblyError::ForeignTenant { .. })),
        "{result:?}"
    );
}

#[test]
fn prompts_exclusion_a_text_the_caller_withholds_fails_the_assembly() {
    let agent = agent("intake-classifier");
    let withheld = Sha256Digest::of(b"the builder's summary");
    let scope = scope().withholding(withheld);
    let given = super::prompts_support::input(&agent, "request", "the builder's summary");
    let result = Assembler::new(shared_redactor(), path_policy(), Limits::default()).assemble(
        AssemblyRequest::new(&agent.manifest, &agent.prompt, scope.clone(), vec![given]),
    );
    assert!(
        matches!(result, Err(AssemblyError::WithheldContent { .. })),
        "{result:?}"
    );
    // Another text is not affected.
    let other = super::prompts_support::input(&agent, "request", "a different text");
    assert!(
        Assembler::new(shared_redactor(), path_policy(), Limits::default())
            .assemble(AssemblyRequest::new(
                &agent.manifest,
                &agent.prompt,
                scope,
                vec![other]
            ))
            .is_ok()
    );
}
