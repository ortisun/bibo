//! The loaders: agent manifests, domain capability profiles and project manifests, from JSON and
//! from the restricted YAML subset. Every failure names the file, the field and, for YAML, the
//! line. The names of the tests that start with `loader_errors_name_file_and_field` are the
//! work package's done check for that rule.

mod support;

use factory_contracts::loader::{
    DefinitionFormat, DefinitionLoader, LoadErrorKind, MAX_DEFINITION_BYTES,
};
use factory_domain::contracts::{
    AgentManifest, Contract, DomainCapabilityProfile, ProjectManifest,
};
use factory_domain::values::Sha256Digest;
use factory_ports::registry::ContractKind;
use serde_json::{Value, json};
use support::{TempDir, example_dir, read_example, to_block_yaml};

const PROMPT: &str = "You are the builder. Implement the planned task.\n";

fn loader() -> DefinitionLoader {
    DefinitionLoader::new().expect("the embedded schemas compile")
}

/// The builder example with a prompt whose hash is right for `PROMPT`.
fn builder_manifest(prompt_hash: &Sha256Digest) -> Value {
    let mut manifest =
        read_example(&example_dir(ContractKind::AgentManifest, "valid").join("builder.json"));
    manifest["prompt"]["template_sha256"] = json!(prompt_hash.as_str());
    manifest
}

fn repo_with_builder(
    manifest_format: DefinitionFormat,
    prompt_hash: &Sha256Digest,
) -> (TempDir, std::path::PathBuf) {
    let repo = TempDir::new("loader");
    repo.write("agents/builder/prompt.md", PROMPT);
    let manifest = builder_manifest(prompt_hash);
    let path = match manifest_format {
        DefinitionFormat::Json => repo.write(
            "agents/builder/manifest.json",
            serde_json::to_vec_pretty(&manifest).expect("serialize"),
        ),
        DefinitionFormat::Yaml => {
            repo.write("agents/builder/manifest.yaml", to_block_yaml(&manifest))
        }
    };
    (repo, path)
}

// ---- The done check: the file and the field are named ---------------------------------------

#[test]
fn loader_errors_name_file_and_field_for_a_prompt_whose_hash_differs() {
    let wrong = Sha256Digest::of(b"some other prompt text\n");
    let (repo, path) = repo_with_builder(DefinitionFormat::Json, &wrong);
    let error = loader()
        .agent_with_prompt(repo.path(), &path)
        .expect_err("the hash does not match");
    assert_eq!(error.kind, LoadErrorKind::PromptHashMismatch);
    assert_eq!(error.field.as_deref(), Some("prompt.template_sha256"));
    let text = error.to_string();
    assert!(text.contains(&path.display().to_string()), "{text}");
    assert!(text.contains("prompt.template_sha256"), "{text}");
    assert!(text.contains("agents/builder/prompt.md"), "{text}");
    assert!(
        text.contains(Sha256Digest::of(PROMPT.as_bytes()).as_str()),
        "the actual hash: {text}"
    );
}

#[test]
fn loader_errors_name_file_and_field_and_line_for_a_yaml_manifest() {
    let wrong = Sha256Digest::of(b"some other prompt text\n");
    let (repo, path) = repo_with_builder(DefinitionFormat::Yaml, &wrong);
    let source = std::fs::read_to_string(&path).expect("read back");
    let line = source
        .lines()
        .position(|l| l.contains("template_sha256"))
        .expect("the field is written")
        + 1;
    let error = loader()
        .agent_with_prompt(repo.path(), &path)
        .expect_err("the hash does not match");
    assert_eq!(error.kind, LoadErrorKind::PromptHashMismatch);
    assert_eq!(error.line, Some(line), "{error}");
    assert!(
        error.to_string().contains(&format!(
            "manifest.yaml:{line} (field `prompt.template_sha256`)"
        )),
        "{error}"
    );
}

#[test]
fn loader_errors_name_file_and_field_for_a_missing_prompt_file() {
    let repo = TempDir::new("loader");
    let manifest = builder_manifest(&Sha256Digest::of(PROMPT.as_bytes()));
    let path = repo.write(
        "agents/builder/manifest.json",
        serde_json::to_vec(&manifest).expect("serialize"),
    );
    let error = loader()
        .agent_with_prompt(repo.path(), &path)
        .expect_err("no prompt file");
    assert_eq!(error.kind, LoadErrorKind::PromptMissing);
    assert_eq!(error.field.as_deref(), Some("prompt.template_path"));
    assert!(
        error.to_string().contains("agents/builder/prompt.md"),
        "{error}"
    );
}

#[test]
fn loader_errors_name_file_and_field_for_a_schema_violation_with_the_line() {
    let hash = Sha256Digest::of(PROMPT.as_bytes());
    let mut manifest = builder_manifest(&hash);
    manifest["permissions"]["production_access"] = json!("read");
    let repo = TempDir::new("loader");
    repo.write("agents/builder/prompt.md", PROMPT);
    let path = repo.write("agents/builder/manifest.yaml", to_block_yaml(&manifest));
    let error = loader()
        .agent_with_prompt(repo.path(), &path)
        .expect_err("production access is forbidden");
    assert_eq!(error.kind, LoadErrorKind::Schema);
    assert_eq!(
        error.field.as_deref(),
        Some("permissions.production_access")
    );
    assert!(error.line.is_some_and(|l| l > 1), "{error}");
    assert!(error.to_string().contains("manifest.yaml:"), "{error}");
}

#[test]
fn loader_errors_name_file_and_field_for_an_unknown_key() {
    let hash = Sha256Digest::of(PROMPT.as_bytes());
    let mut manifest = builder_manifest(&hash);
    manifest["approved"] = json!(true);
    let error = loader()
        .agent_manifest(
            "agents/builder/manifest.json",
            DefinitionFormat::Json,
            &serde_json::to_vec(&manifest).expect("serialize"),
        )
        .expect_err("unknown key");
    assert_eq!(error.kind, LoadErrorKind::Schema);
    assert!(error.message.contains("`approved`"), "{error}");
    assert!(
        error
            .to_string()
            .starts_with("agents/builder/manifest.json"),
        "{error}"
    );
}

// ---- Acceptance -----------------------------------------------------------------------------

#[test]
fn a_good_manifest_loads_from_json_and_from_yaml_to_the_same_typed_value() {
    let hash = Sha256Digest::of(PROMPT.as_bytes());
    let (repo_json, json_path) = repo_with_builder(DefinitionFormat::Json, &hash);
    let (repo_yaml, yaml_path) = repo_with_builder(DefinitionFormat::Yaml, &hash);
    let from_json = loader()
        .agent_with_prompt(repo_json.path(), &json_path)
        .expect("json loads");
    let from_yaml = loader()
        .agent_with_prompt(repo_yaml.path(), &yaml_path)
        .expect("yaml loads");
    assert_eq!(from_json.manifest, from_yaml.manifest);
    assert_eq!(from_json.prompt.text, PROMPT);
    assert_eq!(from_json.prompt.template, from_json.manifest.prompt);
    let expected = AgentManifest::from_json_value(builder_manifest(&hash)).expect("typed");
    assert_eq!(from_json.manifest, expected);
}

#[test]
fn every_valid_example_loads_into_its_typed_contract() {
    let loader = loader();
    for (kind, ext) in [
        (ContractKind::AgentManifest, "json"),
        (ContractKind::DomainCapabilityProfile, "json"),
        (ContractKind::ProjectManifest, "json"),
    ] {
        for path in support::files_in(&example_dir(kind, "valid"), &[ext, "yaml"]) {
            let bytes = std::fs::read(&path).expect("read");
            let format = DefinitionFormat::from_path(&path).expect("a known extension");
            let label = path.display().to_string();
            let outcome = match kind {
                ContractKind::AgentManifest => {
                    loader.agent_manifest(&label, format, &bytes).map(|_| ())
                }
                ContractKind::DomainCapabilityProfile => loader
                    .capability_profile(&label, format, &bytes)
                    .map(|_| ()),
                _ => loader.project_manifest(&label, format, &bytes).map(|_| ()),
            };
            outcome.unwrap_or_else(|e| panic!("{label}: {e}"));
        }
    }
}

// ---- Rules a schema cannot state ------------------------------------------------------------

#[test]
fn a_profile_whose_probes_and_required_tools_differ_is_refused_with_the_field() {
    let mut profile = read_example(
        &example_dir(ContractKind::DomainCapabilityProfile, "valid")
            .join("general-software-active.json"),
    );
    profile["required_tools"] = json!(["git", "container-sandbox", "formatter"]);
    let error = loader()
        .capability_profile(
            "profiles/general/profile.json",
            DefinitionFormat::Json,
            &serde_json::to_vec(&profile).expect("serialize"),
        )
        .expect_err("probes differ");
    assert_eq!(error.kind, LoadErrorKind::Consistency);
    assert_eq!(error.field.as_deref(), Some("tool_probes"));
    assert!(error.message.contains("formatter"), "{error}");

    let mut profile = read_example(
        &example_dir(ContractKind::DomainCapabilityProfile, "valid")
            .join("general-software-active.json"),
    );
    profile["tool_probes"][0]["tool"] = json!("unlisted-tool");
    let error = loader()
        .capability_profile(
            "profiles/general/profile.json",
            DefinitionFormat::Json,
            &serde_json::to_vec(&profile).expect("serialize"),
        )
        .expect_err("a probe names an unlisted tool");
    assert!(error.message.contains("unlisted-tool"), "{error}");
}

#[test]
fn a_project_manifest_that_runs_a_gate_through_a_shell_is_refused() {
    let mut manifest = read_example(
        &example_dir(ContractKind::ProjectManifest, "valid").join("word-count-minimal.json"),
    );
    manifest["gates"][0]["argv"] = json!(["bash", "-c", "cargo build"]);
    let error = loader()
        .project_manifest(
            ".factory/project.json",
            DefinitionFormat::Json,
            &serde_json::to_vec(&manifest).expect("serialize"),
        )
        .expect_err("shell gate");
    assert_eq!(error.kind, LoadErrorKind::Schema);
    assert_eq!(error.field.as_deref(), Some("gates[0].argv[0]"));
}

// ---- Forbidden input ------------------------------------------------------------------------

#[test]
fn a_yaml_manifest_with_an_anchor_or_a_merge_key_is_refused_with_the_line() {
    let loader = loader();
    for (text, line) in [
        ("schema_version: 1\nid: &x builder\n", 2usize),
        ("schema_version: 1\nbase:\n  <<: {a: 1}\n", 3),
        ("schema_version: 1\nid: !!str builder\n", 2),
        ("schema_version: 1\nid: no\n", 2),
        ("schema_version: 1\nid: ~\n", 2),
        ("schema_version: 1\nschema_version: 1\n", 2),
    ] {
        let error = loader
            .agent_manifest(
                "agents/x/manifest.yaml",
                DefinitionFormat::Yaml,
                text.as_bytes(),
            )
            .expect_err(text);
        assert_eq!(error.kind, LoadErrorKind::Forbidden, "{text}: {error}");
        assert_eq!(error.line, Some(line), "{text}: {error}");
    }
}

#[test]
fn a_file_over_the_size_limit_is_refused_before_it_is_read_as_a_document() {
    let error = loader()
        .agent_manifest(
            "agents/x/manifest.json",
            DefinitionFormat::Json,
            &vec![b' '; MAX_DEFINITION_BYTES + 1],
        )
        .expect_err("too large");
    assert_eq!(error.kind, LoadErrorKind::Limits);
}

#[test]
fn a_manifest_whose_prompt_path_leaves_the_repository_is_refused() {
    let hash = Sha256Digest::of(PROMPT.as_bytes());
    let mut manifest = builder_manifest(&hash);
    manifest["prompt"]["template_path"] = json!("../outside/prompt.md");
    let repo = TempDir::new("loader");
    let path = repo.write(
        "agents/builder/manifest.json",
        serde_json::to_vec(&manifest).expect("serialize"),
    );
    let error = loader()
        .agent_with_prompt(repo.path(), &path)
        .expect_err("a traversal path");
    assert_eq!(error.kind, LoadErrorKind::UnsafePath);
    assert_eq!(error.field.as_deref(), Some("prompt.template_path"));
}

#[cfg(unix)]
#[test]
fn a_prompt_that_is_a_link_to_a_file_outside_the_repository_is_refused() {
    let outside = TempDir::new("outside");
    outside.write("secret.md", PROMPT);
    let repo = TempDir::new("loader");
    std::fs::create_dir_all(repo.path().join("agents/builder")).expect("mkdir");
    std::os::unix::fs::symlink(
        outside.path().join("secret.md"),
        repo.path().join("agents/builder/prompt.md"),
    )
    .expect("symlink");
    let manifest = builder_manifest(&Sha256Digest::of(PROMPT.as_bytes()));
    let path = repo.write(
        "agents/builder/manifest.json",
        serde_json::to_vec(&manifest).expect("serialize"),
    );
    let error = loader()
        .agent_with_prompt(repo.path(), &path)
        .expect_err("the link leaves the repository");
    assert_eq!(error.kind, LoadErrorKind::UnsafePath);
    assert_eq!(error.field.as_deref(), Some("prompt.template_path"));
}

#[cfg(unix)]
#[test]
fn a_manifest_that_is_a_symbolic_link_is_not_followed() {
    let repo = TempDir::new("loader");
    let real = repo.write("elsewhere/manifest.json", b"{}");
    std::fs::create_dir_all(repo.path().join("agents/builder")).expect("mkdir");
    let link = repo.path().join("agents/builder/manifest.json");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let error = loader()
        .agent_with_prompt(repo.path(), &link)
        .expect_err("a link");
    assert_eq!(error.kind, LoadErrorKind::Unreadable);
}

#[test]
fn the_typed_contracts_agree_with_the_json_documents() {
    // The loader returns the same typed value as the domain crate builds from the same JSON.
    let profile = read_example(
        &example_dir(ContractKind::DomainCapabilityProfile, "valid")
            .join("general-software-active.json"),
    );
    let loaded = loader()
        .capability_profile(
            "profiles/general-software/profile.json",
            DefinitionFormat::Json,
            &serde_json::to_vec(&profile).expect("serialize"),
        )
        .expect("loads");
    assert_eq!(
        loaded,
        DomainCapabilityProfile::from_json_value(profile).expect("typed")
    );
    let project = read_example(
        &example_dir(ContractKind::ProjectManifest, "valid").join("word-count-minimal.json"),
    );
    let loaded = loader()
        .project_manifest(
            ".factory/project.json",
            DefinitionFormat::Json,
            &serde_json::to_vec(&project).expect("serialize"),
        )
        .expect("loads");
    assert_eq!(
        loaded,
        ProjectManifest::from_json_value(project).expect("typed")
    );
}
