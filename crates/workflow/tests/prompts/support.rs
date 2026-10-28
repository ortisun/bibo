//! Shared fixtures: the nine real agents, the real policy, a redactor built from the policy
//! patterns, and builders for inputs.

#![allow(dead_code)]

use std::sync::LazyLock;

use factory_domain::contracts::AgentManifest;
use factory_domain::ids::TenantId;
use factory_domain::policy::paths::PathPolicy;
use factory_domain::policy::{RepoKind, SecurityPolicy};
use factory_domain::redaction::{EntropySpec, PatternAction, PatternSpec, Redactor};
use factory_ports::registry::LoadedPrompt;
use factory_workflow::prompts::{
    Assembled, Assembler, AssemblyError, AssemblyRequest, ContentClass, Input, Limits, Scope,
    Source, Template,
};
use uuid::Uuid;

const SECURITY_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");

/// One agent: its manifest and its prompt, exactly as the registry would load them.
pub struct Agent {
    pub id: &'static str,
    pub manifest: AgentManifest,
    pub prompt: LoadedPrompt,
}

macro_rules! agent_files {
    ($($id:literal),* $(,)?) => {
        &[$((
            $id,
            include_str!(concat!("../../../../agents/", $id, "/manifest.json")),
            include_str!(concat!("../../../../agents/", $id, "/prompt.md")),
        )),*]
    };
}

const AGENT_FILES: &[(&str, &str, &str)] = agent_files!(
    "architect",
    "builder",
    "code-reviewer",
    "documentation-reviewer",
    "documentation-writer",
    "intake-classifier",
    "planner",
    "specification-reviewer",
    "specification-writer",
);

pub fn agents() -> Vec<Agent> {
    AGENT_FILES
        .iter()
        .map(|(id, manifest, prompt)| {
            let manifest: AgentManifest =
                serde_json::from_str(manifest).expect("a real manifest is valid");
            let loaded = LoadedPrompt {
                template: manifest.prompt.clone(),
                text: (*prompt).to_owned(),
            };
            Agent {
                id,
                manifest,
                prompt: loaded,
            }
        })
        .collect()
}

pub fn agent(id: &str) -> Agent {
    agents()
        .into_iter()
        .find(|a| a.id == id)
        .unwrap_or_else(|| panic!("no agent {id}"))
}

/// The parsed template of an agent.
pub fn template_of(agent: &Agent) -> Template {
    Template::parse(&agent.prompt.text).expect("a real prompt parses")
}

/// The names of the data inputs of an agent, in template order.
pub fn names(agent: &Agent) -> Vec<String> {
    template_of(agent)
        .inputs()
        .iter()
        .map(|i| i.name().to_owned())
        .collect()
}

pub fn policy() -> &'static SecurityPolicy {
    static POLICY: LazyLock<SecurityPolicy> = LazyLock::new(|| {
        serde_json::from_str(SECURITY_POLICY).expect("the security policy fixture is valid")
    });
    &POLICY
}

pub fn path_policy() -> &'static PathPolicy {
    static PATHS: LazyLock<PathPolicy> =
        LazyLock::new(|| PathPolicy::from_policy(policy()).expect("the real policy builds"));
    &PATHS
}

/// A redactor with the patterns of the policy and nothing registered.
pub fn redactor() -> Redactor {
    let secrets = &policy().secrets;
    let patterns = secrets.patterns.iter().map(|p| {
        let action = match p.action {
            factory_domain::policy::security::SecretAction::Block => PatternAction::Block,
            factory_domain::policy::security::SecretAction::Flag => PatternAction::Flag,
        };
        PatternSpec::new(p.id.clone(), p.regex.0.clone(), action)
    });
    Redactor::builder()
        .patterns(patterns)
        .entropy(EntropySpec {
            min_length: 32,
            min_bits_per_char: 4.2,
            action: PatternAction::Flag,
        })
        .build()
        .expect("the policy patterns compile")
}

pub fn shared_redactor() -> &'static Redactor {
    static REDACTOR: LazyLock<Redactor> = LazyLock::new(redactor);
    &REDACTOR
}

pub fn tenant() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x0001_0000_0000_0000_0000_0000_0000_0001))
}

pub fn other_tenant() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x0002_0000_0000_0000_0000_0000_0000_0002))
}

pub fn scope() -> Scope {
    Scope::new(tenant(), RepoKind::Target)
}

/// An assembler over the shared redactor and the real path policy.
pub fn assembler() -> Assembler<'static> {
    Assembler::new(shared_redactor(), path_policy(), Limits::default())
}

pub fn assembler_with(limits: Limits) -> Assembler<'static> {
    Assembler::new(shared_redactor(), path_policy(), limits)
}

/// An untrusted input with the class the template gives it.
pub fn input(agent: &Agent, name: &str, text: impl Into<Vec<u8>>) -> Input {
    let class = class_of(agent, name);
    Input::untrusted(
        name,
        class,
        Source::HostArtifact {
            kind: "test".to_owned(),
            id: name.to_owned(),
        },
        tenant(),
        text,
    )
}

pub fn class_of(agent: &Agent, name: &str) -> ContentClass {
    template_of(agent)
        .inputs()
        .iter()
        .find(|i| i.name() == name)
        .map(|i| i.class())
        .unwrap_or_else(|| panic!("{} has no input {name}", agent.id))
}

/// One input for every placeholder of the agent, with the text `text_for` gives.
pub fn all_inputs(agent: &Agent, text_for: impl Fn(&str) -> String) -> Vec<Input> {
    names(agent)
        .iter()
        .map(|name| input(agent, name, text_for(name)))
        .collect()
}

pub fn request<'a>(agent: &'a Agent, inputs: Vec<Input>) -> AssemblyRequest<'a> {
    AssemblyRequest::new(&agent.manifest, &agent.prompt, scope(), inputs)
}

/// Assembles with the default assembler.
pub fn assemble(agent: &Agent, inputs: Vec<Input>) -> Result<Assembled, AssemblyError> {
    assembler().assemble(request(agent, inputs))
}

/// The lines of the template that are not placeholders: what must be identical in every prompt of
/// the agent whatever the data is.
pub fn outside_lines(agent: &Agent) -> Vec<String> {
    agent
        .prompt
        .text
        .split('\n')
        .filter(|line| !(line.starts_with("{{input.") && line.ends_with("}}")))
        .map(str::to_owned)
        .collect()
}
