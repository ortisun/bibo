//! The real YAML example files, read directly, against the JSON transcriptions that the domain
//! crate's tests use.
//!
//! `factory-domain` has no YAML parser, so its tests read hand-made JSON copies of the two YAML
//! examples (`crates/domain/tests/fixtures/yaml_transcriptions/`). That leaves the question of
//! whether the YAML files and the copies say the same thing. This test answers it: each YAML file
//! is read by the restricted reader, loaded into its typed contract, and compared with the typed
//! contract the domain crate builds from the JSON copy. The JSON value of the YAML document must
//! also equal the copy, and the document must pass the schema.

mod support;

use std::path::PathBuf;

use factory_contracts::loader::{DefinitionFormat, DefinitionLoader};
use factory_contracts::schemas::SCHEMA_VERSION;
use factory_contracts::validator::SchemaOutputValidator;
use factory_domain::contracts::{Contract, DomainCapabilityProfile, ProjectManifest};
use factory_ports::registry::ContractKind;
use serde_json::Value;
use support::{example_dir, files_in, read_text, repo_root};

fn transcription(kind: ContractKind, stem: &str) -> PathBuf {
    repo_root()
        .join("crates/domain/tests/fixtures/yaml_transcriptions")
        .join(format!("{}--{stem}.json", kind.schema_name()))
}

/// Every YAML example file under `schemas/examples`, with its kind.
fn yaml_examples() -> Vec<(ContractKind, PathBuf)> {
    let mut found = Vec::new();
    for kind in ContractKind::ALL {
        for which in ["valid", "invalid"] {
            for path in files_in(&example_dir(kind, which), &["yaml", "yml"]) {
                found.push((kind, path));
            }
        }
    }
    found
}

#[test]
fn the_yaml_examples_are_the_two_the_domain_crate_transcribed() {
    let names: Vec<String> = yaml_examples()
        .iter()
        .map(|(_, path)| {
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    assert_eq!(
        names,
        [
            "quant-trading-from-master-prompt.yaml",
            "word-count-fixture.yaml"
        ],
        "a YAML example was added or removed; add or remove its JSON transcription in the domain fixtures"
    );
}

#[test]
fn each_real_yaml_example_equals_its_json_transcription() {
    let loader = DefinitionLoader::new().expect("the embedded schemas compile");
    let validator = SchemaOutputValidator::new().expect("the embedded schemas compile");
    for (kind, path) in yaml_examples() {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("a file stem");
        let copy_path = transcription(kind, stem);
        assert!(
            copy_path.is_file(),
            "{} has no JSON transcription at {}",
            path.display(),
            copy_path.display()
        );
        let copy: Value = serde_json::from_str(&read_text(&copy_path)).expect("the copy is JSON");

        // The YAML file, read by the restricted reader, is the same document as the copy.
        let yaml_text = read_text(&path);
        let document = factory_contracts::yaml::read(
            &yaml_text,
            factory_contracts::yaml::YamlLimits::DEFINITION,
        )
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(
            document.to_json(),
            copy,
            "{} as JSON differs from its transcription",
            path.display()
        );

        // It passes the schema.
        validator
            .check(kind, SCHEMA_VERSION, &document.to_json())
            .unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));

        // And the typed value read from the YAML equals the typed value the domain crate builds
        // from the transcription.
        let bytes = yaml_text.as_bytes();
        let label = path.display().to_string();
        match kind {
            ContractKind::DomainCapabilityProfile => {
                let from_yaml = loader
                    .capability_profile(&label, DefinitionFormat::Yaml, bytes)
                    .unwrap_or_else(|e| panic!("{e}"));
                let from_copy = DomainCapabilityProfile::from_json_value(copy).expect("typed copy");
                assert_eq!(from_yaml, from_copy, "{label}");
            }
            ContractKind::ProjectManifest => {
                let from_yaml = loader
                    .project_manifest(&label, DefinitionFormat::Yaml, bytes)
                    .unwrap_or_else(|e| panic!("{e}"));
                let from_copy = ProjectManifest::from_json_value(copy).expect("typed copy");
                assert_eq!(from_yaml, from_copy, "{label}");
            }
            other => panic!("{label}: no test for {other:?} YAML examples"),
        }
    }
}

#[test]
fn a_yaml_example_with_one_word_changed_to_a_boolean_spelling_is_refused() {
    // The real file, with `integration: claude` replaced by a word YAML 1.1 reads as a boolean.
    let text = read_text(
        &example_dir(ContractKind::ProjectManifest, "valid").join("word-count-fixture.yaml"),
    );
    let changed = text.replace("may_initialize: true", "may_initialize: yes");
    assert_ne!(text, changed);
    let loader = DefinitionLoader::new().expect("the embedded schemas compile");
    let error = loader
        .project_manifest(
            "word-count-fixture.yaml",
            DefinitionFormat::Yaml,
            changed.as_bytes(),
        )
        .expect_err("`yes` is ambiguous");
    assert_eq!(
        error.kind,
        factory_contracts::loader::LoadErrorKind::Forbidden
    );
    assert!(error.line.is_some(), "{error}");
}
