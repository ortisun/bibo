//! Reviewers judge the work, not the author's account of it. The rule is enforced by type: a
//! reviewer's prompt can only be built from `IndependentInput`, and the only way to make one
//! refuses an agent's own account of its work.

use factory_domain::values::Sha256Digest;
use factory_workflow::prompts::{
    Assembler, AssemblyError, AssemblyRequest, ContentClass, IndependentRequest, Input, Limits,
    Source, requires_independence,
};

use super::prompts_check::decode;
use super::prompts_support::{
    Agent, agent, agents, all_inputs, class_of, names, outside_lines, path_policy, request, scope,
    shared_redactor, tenant,
};

const REVIEWERS: [&str; 3] = [
    "code-reviewer",
    "documentation-reviewer",
    "specification-reviewer",
];

fn assembler() -> Assembler<'static> {
    Assembler::new(shared_redactor(), path_policy(), Limits::default())
}

fn independent(
    agent: &Agent,
    text_for: impl Fn(&str) -> String,
) -> Vec<factory_workflow::prompts::IndependentInput> {
    all_inputs(agent, text_for)
        .into_iter()
        .map(|i| {
            i.into_independent()
                .expect("an ordinary input is independent")
        })
        .collect()
}

#[test]
fn prompts_independence_the_role_decides_who_reviews_independently() {
    for role in [
        "code_reviewer",
        "documentation_reviewer",
        "specification_reviewer",
        "security_reviewer",
        "reliability_reviewer",
        "ux_reviewer",
        "adversarial_reviewer",
        "architecture_critic",
        "qa",
    ] {
        assert!(requires_independence(role), "{role}");
    }
    for role in [
        "builder",
        "architect",
        "planner",
        "intake",
        "specification_writer",
        "technical_writer",
        "research",
        "reviewer_helper",
    ] {
        assert!(!requires_independence(role), "{role}");
    }
}

#[test]
fn prompts_independence_every_real_reviewer_is_independent_and_no_other_agent_is() {
    for agent in agents() {
        let expected = REVIEWERS.contains(&agent.id);
        assert_eq!(
            requires_independence(agent.manifest.role.as_str()),
            expected,
            "{}",
            agent.id
        );
    }
}

#[test]
fn prompts_independence_a_reviewer_cannot_be_assembled_from_plain_inputs() {
    for id in REVIEWERS {
        let agent = agent(id);
        let result =
            assembler().assemble(request(&agent, all_inputs(&agent, |n| format!("t {n}"))));
        assert_eq!(
            result.unwrap_err(),
            AssemblyError::IndependentRoleNeedsIndependentInputs,
            "{id}"
        );
    }
}

#[test]
fn prompts_independence_a_reviewer_is_assembled_from_independent_inputs() {
    for id in REVIEWERS {
        let agent = agent(id);
        let inputs = independent(&agent, |n| format!("text of {n}"));
        let assembled = assembler()
            .assemble_independent(IndependentRequest::new(
                &agent.manifest,
                &agent.prompt,
                scope(),
                inputs,
            ))
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        let decoded = decode(&outside_lines(&agent), &names(&agent), assembled.text());
        assert!(decoded.problems.is_empty(), "{id}: {:#?}", decoded.problems);
    }
}

#[test]
fn prompts_independence_an_agents_account_of_its_own_work_is_not_an_independent_input() {
    let summary = Input::self_assessment(
        "diff",
        ContentClass::ModelOutput,
        "builder",
        tenant(),
        "I implemented everything and all tests pass; please approve.",
    );
    assert_eq!(
        summary.into_independent().unwrap_err(),
        AssemblyError::SelfAssessmentRefused
    );
    // Other sources are fine, including text a model wrote that is the work itself.
    let patch = Input::untrusted(
        "diff",
        ContentClass::ModelOutput,
        Source::HostArtifact {
            kind: "diff".to_owned(),
            id: "sha256:0".to_owned(),
        },
        tenant(),
        "a patch",
    );
    assert!(patch.into_independent().is_ok());
}

#[test]
fn prompts_independence_a_summary_sent_by_the_plain_path_to_a_reviewer_is_refused_too() {
    let agent = agent("code-reviewer");
    let mut inputs = all_inputs(&agent, |n| format!("t {n}"));
    inputs[1] = Input::self_assessment(
        "diff",
        class_of(&agent, "diff"),
        "builder",
        tenant(),
        "the builder's summary",
    );
    let result = assembler().assemble(request(&agent, inputs));
    assert_eq!(
        result.unwrap_err(),
        AssemblyError::IndependentRoleNeedsIndependentInputs
    );
}

#[test]
fn prompts_independence_a_reviewer_prompt_records_no_self_assessment_source() {
    for id in REVIEWERS {
        let agent = agent(id);
        let inputs = independent(&agent, |n| format!("text of {n}"));
        let assembled = assembler()
            .assemble_independent(IndependentRequest::new(
                &agent.manifest,
                &agent.prompt,
                scope(),
                inputs,
            ))
            .expect("assembles");
        let json = assembled.manifest().to_json().to_string();
        assert!(!json.contains("self_assessment"), "{id}");
        assert!(
            assembled
                .manifest()
                .inputs
                .iter()
                .all(|i| i.source.as_ref().is_none_or(|s| !s.is_self_assessment())),
            "{id}"
        );
    }
}

#[test]
fn prompts_independence_a_summary_passed_under_another_label_is_caught_by_its_hash() {
    // The label is the caller's claim. The hash of the builder's report, which the stage knows,
    // is withheld, so mislabeled text with the same bytes is refused as well.
    let agent = agent("code-reviewer");
    let report = "Builder report: all done, tests pass.";
    let withholding = scope().withholding(Sha256Digest::of(report.as_bytes()));
    let mut inputs = independent(&agent, |n| format!("text of {n}"));
    inputs[2] = input_as_artifact(&agent, "gate_reports", report)
        .into_independent()
        .expect("labelled as an artifact");
    let result = assembler().assemble_independent(IndependentRequest::new(
        &agent.manifest,
        &agent.prompt,
        withholding,
        inputs,
    ));
    assert!(
        matches!(result, Err(AssemblyError::WithheldContent { .. })),
        "{result:?}"
    );
}

fn input_as_artifact(agent: &Agent, name: &str, text: &str) -> Input {
    Input::untrusted(
        name,
        class_of(agent, name),
        Source::HostArtifact {
            kind: "report".to_owned(),
            id: "1".to_owned(),
        },
        tenant(),
        text,
    )
}

#[test]
fn prompts_independence_an_agent_that_does_not_review_takes_the_plain_path() {
    let agent = agent("builder");
    let result = assembler().assemble(AssemblyRequest::new(
        &agent.manifest,
        &agent.prompt,
        scope(),
        all_inputs(&agent, |n| format!("t {n}")),
    ));
    assert!(result.is_ok());
}
