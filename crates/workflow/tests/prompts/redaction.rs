//! Secrets never leave in a prompt: they are replaced in every input, and the finished prompt is
//! checked again. If one is still there, nothing is released.

use factory_domain::redaction::{Limits as RedactorLimits, Redactor};
use factory_domain::values::{PositiveInt, Sha256Digest};
use factory_testkit::fx::canary::{CanaryKind, CanarySet, Form, Sweeper};
use factory_workflow::prompts::{
    Assembled, Assembler, AssemblyError, ContentClass, Input, Limits, Source,
};

use super::prompts_check::{attribute, decode};
use super::prompts_support::{
    Agent, agent, agents, all_inputs, input, names, outside_lines, path_policy, redactor, request,
    tenant, with_prompt_text,
};

/// The kinds that are secrets. The holdout and second-tenant strings are not secrets: other
/// controls keep them out.
const SECRETS: [CanaryKind; 6] = [
    CanaryKind::GithubInstallationToken,
    CanaryKind::AppPrivateKey,
    CanaryKind::WebhookSecret,
    CanaryKind::ModelApiKey,
    CanaryKind::DatabasePassword,
    CanaryKind::JobToken,
];

fn redactor_for(canaries: &CanarySet) -> Redactor {
    let redactor = redactor();
    for kind in SECRETS {
        let canary = canaries.get(kind);
        redactor
            .register(canary.label(), canary.value())
            .expect("a canary can be registered");
    }
    redactor
}

fn assemble_with(
    redactor: &Redactor,
    agent: &Agent,
    inputs: Vec<Input>,
) -> Result<Assembled, AssemblyError> {
    Assembler::new(redactor, path_policy(), Limits::default()).assemble(request(agent, inputs))
}

#[test]
fn prompts_redaction_every_secret_in_every_spelling_is_replaced() {
    let agent = agent("intake-classifier");
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let sweeper = Sweeper::new(&canaries);
    for kind in SECRETS {
        let value = canaries.get(kind).value().to_owned();
        for form in Form::ALL {
            let spelled = String::from_utf8(form.encode(&value).expect("a spelling"))
                .expect("a spelling is text");
            let text = format!("Please use this: {spelled} thanks");
            let assembled = assemble_with(&redactor, &agent, vec![input(&agent, "request", text)])
                .unwrap_or_else(|e| panic!("{kind:?} as {form}: {e}"));
            let hits = sweeper.scan("prompt", assembled.text().as_bytes());
            assert!(hits.is_empty(), "{kind:?} as {form}: {hits:?}");
            let record = assembled.manifest().input("request").expect("a record");
            assert!(record.redacted >= 1, "{kind:?} as {form}");
            assert!(assembled.manifest().has_signal("secret_redacted"));
            let manifest_text = format!("{:?}", assembled.manifest());
            assert!(
                sweeper
                    .scan("manifest", manifest_text.as_bytes())
                    .is_empty()
            );
        }
    }
}

#[test]
fn prompts_redaction_the_count_is_in_the_opening_line_and_the_secret_is_not() {
    let agent = agent("intake-classifier");
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let token = canaries.get(CanaryKind::GithubInstallationToken).value();
    let text = format!("first {token}\nsecond {token}");
    let assembled =
        assemble_with(&redactor, &agent, vec![input(&agent, "request", text)]).expect("assembles");
    let decoded = decode(&outside_lines(&agent), &names(&agent), assembled.text());
    assert!(decoded.problems.is_empty(), "{:#?}", decoded.problems);
    assert_eq!(attribute(&decoded.headers[0], "redacted"), Some("2"));
    assert!(decoded.bodies[0].contains("[REDACTED:"));
    assert!(!decoded.bodies[0].contains(&token[..8]));
}

#[test]
fn prompts_redaction_secrets_split_by_hidden_characters_are_still_found() {
    let agent = agent("intake-classifier");
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let sweeper = Sweeper::new(&canaries);
    let noise = [
        '\u{200B}',
        '\u{202E}',
        '\u{0}',
        '\u{E0041}',
        '\u{FE0F}',
        '\u{1b}',
        '\u{7f}',
    ];
    for kind in SECRETS {
        let value = canaries.get(kind).value();
        for filler in noise {
            let split: String = value.chars().flat_map(|c| [c, filler]).collect();
            let assembled = assemble_with(
                &redactor,
                &agent,
                vec![input(&agent, "request", format!("x {split} y"))],
            )
            .unwrap_or_else(|e| panic!("{kind:?} with {filler:?}: {e}"));
            let hits = sweeper.scan("prompt", assembled.text().as_bytes());
            assert!(hits.is_empty(), "{kind:?} with {filler:?}: {hits:?}");
        }
    }
}

#[test]
fn prompts_redaction_a_canary_in_every_field_of_every_agent_does_not_reach_the_prompt() {
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let sweeper = Sweeper::new(&canaries);
    let token = canaries.get(CanaryKind::ModelApiKey).value().to_owned();
    let key = canaries.get(CanaryKind::AppPrivateKey).value().to_owned();
    for agent in agents() {
        let inputs = all_inputs(&agent, |name| format!("{name}: {token}\n{key}\nend"));
        let assembled = assemble_with(&redactor, &agent, inputs).expect("assembles");
        let hits = sweeper.scan(agent.id, assembled.text().as_bytes());
        assert!(hits.is_empty(), "{}: {hits:?}", agent.id);
    }
}

#[test]
fn prompts_redaction_a_cut_never_leaves_part_of_a_secret() {
    // Redaction runs before the cut, so wherever the cut falls the secret is already a marker.
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let sweeper = Sweeper::new(&canaries);
    let value = canaries
        .get(CanaryKind::GithubInstallationToken)
        .value()
        .to_owned();
    let mut roomy = agent("intake-classifier");
    roomy.manifest.resource_limits.max_tokens = PositiveInt::new(4_000_000).expect("positive");
    for fill in 300..420 {
        let text = format!("{}{value}{}", "a ".repeat(fill), " tail".repeat(30));
        let limits = Limits {
            max_block_bytes: 700,
            ..Limits::default()
        };
        let assembled = Assembler::new(&redactor, path_policy(), limits)
            .assemble(request(&roomy, vec![input(&roomy, "request", text)]))
            .expect("assembles");
        let hits = sweeper.scan("prompt", assembled.text().as_bytes());
        assert!(hits.is_empty(), "fill {fill}: {hits:?}");
    }
}

#[test]
fn prompts_redaction_the_hash_of_an_input_with_a_secret_is_not_the_hash_of_the_secret_text() {
    let agent = agent("intake-classifier");
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let token = canaries.get(CanaryKind::JobToken).value().to_owned();
    let plain = assemble_with(
        &redactor,
        &agent,
        vec![input(&agent, "request", "no secret")],
    )
    .expect("assembles");
    let record = plain.manifest().input("request").expect("a record");
    assert_eq!(record.original_sha256, Sha256Digest::of(b"no secret"));
    assert!(!record.hash_is_of_redacted_text);

    let with = assemble_with(
        &redactor,
        &agent,
        vec![input(&agent, "request", token.clone())],
    )
    .expect("assembles");
    let record = with.manifest().input("request").expect("a record");
    assert!(record.hash_is_of_redacted_text);
    assert_ne!(record.original_sha256, Sha256Digest::of(token.as_bytes()));
    assert_eq!(record.original_bytes, token.len());
}

#[test]
fn prompts_redaction_fails_closed_when_a_secret_is_in_the_instructions() {
    // The template is checked by hash, not by content. If it held a secret the final check of
    // the whole prompt still finds it and nothing is released.
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let base = agent("intake-classifier");
    let leaked = canaries.get(CanaryKind::DatabasePassword).value();
    let text = base.prompt.text.replacen(
        "## Role and boundaries\n",
        &format!("## Role and boundaries\n\nNote: {leaked}\n"),
        1,
    );
    let tampered = with_prompt_text(&base, &text);
    let result = assemble_with(
        &redactor,
        &tampered,
        vec![input(&tampered, "request", "harmless")],
    );
    assert_eq!(result.unwrap_err(), AssemblyError::SecretInPrompt);
}

#[test]
fn prompts_redaction_fails_closed_when_a_secret_is_passed_as_a_trusted_identifier() {
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let base = agent("intake-classifier");
    let text = base.prompt.text.replacen(
        "## Role and boundaries\n",
        "## Role and boundaries\n\nJob: {{trusted.job}}\n",
        1,
    );
    let agent = with_prompt_text(&base, &text);
    let token = canaries.get(CanaryKind::JobToken).value();
    let trusted = Input::trusted_identifier(
        "job",
        ContentClass::ToolOutput,
        Source::HostArtifact {
            kind: "job".to_owned(),
            id: "1".to_owned(),
        },
        tenant(),
        token,
    )
    .expect("a token has the shape of an identifier");
    let result = assemble_with(
        &redactor,
        &agent,
        vec![trusted, input(&agent, "request", "harmless")],
    );
    assert_eq!(result.unwrap_err(), AssemblyError::SecretInPrompt);
}

#[test]
fn prompts_redaction_drops_the_input_and_fails_when_the_redactor_cannot_check_it() {
    let agent = agent("intake-classifier");
    let small = Redactor::builder()
        .limits(RedactorLimits {
            max_input_bytes: 64,
            ..RedactorLimits::default()
        })
        .build()
        .expect("a redactor");
    let result = assemble_with(
        &small,
        &agent,
        vec![input(&agent, "request", "z".repeat(500))],
    );
    assert!(
        matches!(result, Err(AssemblyError::RedactionFailed { .. })),
        "{result:?}"
    );
}

#[test]
fn prompts_redaction_a_clean_prompt_is_released_without_a_signal() {
    let agent = agent("intake-classifier");
    let canaries = CanarySet::generate();
    let redactor = redactor_for(&canaries);
    let assembled = assemble_with(
        &redactor,
        &agent,
        vec![input(
            &agent,
            "request",
            "Add a retry to the upload. See issue 12.",
        )],
    )
    .expect("assembles");
    assert!(!assembled.manifest().has_signal("secret_redacted"));
    assert_eq!(
        assembled
            .manifest()
            .input("request")
            .expect("record")
            .redacted,
        0
    );
}
