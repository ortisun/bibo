//! The agent manifests, prompts and capability profiles that the repository ships, checked the way
//! the factory will load them.
//!
//! Work package: `s1-agent-definitions`. The package owns `agents/` and `profiles/`. These tests
//! are new files in the contracts crate because the done-checks of the package name them there;
//! no existing contracts file was changed.

mod agent_defs;
mod support;

use std::collections::BTreeSet;

use factory_contracts::loader::{DefinitionFormat, DefinitionLoader};
use serde_json::Value;

use agent_defs::{profile_files, profile_value};
use support::{example_dir, read_example};

use factory_ports::registry::ContractKind;

fn loader() -> DefinitionLoader {
    DefinitionLoader::new().expect("the embedded schemas compile")
}

// ---------------------------------------------------------------------------------------------
// Capability profiles
// ---------------------------------------------------------------------------------------------

#[test]
fn there_are_profiles_and_each_validates_through_the_loader() {
    let files = profile_files();
    assert!(
        files.len() >= 2,
        "expected the universal profile and the Rust profile, found {} file(s) under profiles/",
        files.len()
    );
    let loader = loader();
    for file in &files {
        loader
            .capability_profile(
                &file.path.display().to_string(),
                DefinitionFormat::Json,
                file.text.as_bytes(),
            )
            .unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn a_profile_lives_in_a_directory_named_after_its_id() {
    for file in profile_files() {
        let value = profile_value(&file);
        let id = value["id"].as_str().expect("an id");
        let directory = file
            .path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .expect("a directory name");
        assert_eq!(directory, id, "{}", file.path.display());
    }
}

#[test]
fn the_universal_profile_names_the_universal_gates_as_mandatory() {
    let files = profile_files();
    let universal = files
        .iter()
        .map(profile_value)
        .find(|v| v["id"] == "general-software")
        .expect("a profile with the id general-software");
    let mandatory = strings(&universal["mandatory_gates"]);
    for gate in [
        "build",
        "unit-tests",
        "protected-paths-unchanged",
        "secret-scan",
        "documentation-quality",
    ] {
        assert!(mandatory.contains(gate), "{gate} is not a mandatory gate");
    }
}

#[test]
fn a_gate_is_never_both_mandatory_and_conditional() {
    for file in profile_files() {
        let value = profile_value(&file);
        let mandatory = strings(&value["mandatory_gates"]);
        let conditional = strings(&value["conditional_gates"]);
        let both: Vec<_> = mandatory.intersection(&conditional).collect();
        assert!(
            both.is_empty(),
            "{}: {both:?} is listed as mandatory and as conditional, so a missing tool could pass as a warning",
            file.path.display()
        );
    }
}

#[test]
fn every_profile_forbids_merge_deploy_and_publishing_without_a_human() {
    for file in profile_files() {
        let value = profile_value(&file);
        let forbidden = strings(&value["forbidden_autonomous_actions"]);
        for action in ["merge", "deploy", "publish-package"] {
            assert!(
                forbidden.contains(action),
                "{} does not forbid {action}",
                file.path.display()
            );
        }
    }
}

#[test]
fn a_probe_is_a_typed_command_and_never_a_shell_string() {
    for file in profile_files() {
        let value = profile_value(&file);
        for probe in value["tool_probes"].as_array().expect("probes") {
            let argv = probe["argv"].as_array().expect("an argv");
            let first = argv[0].as_str().expect("a program");
            assert!(
                !["sh", "bash", "zsh", "dash", "cmd", "powershell"].contains(&first),
                "{}: the probe for {} starts a shell",
                file.path.display(),
                probe["tool"]
            );
            assert!(
                !argv.iter().any(|a| a == "-c"),
                "{}: the probe for {} passes -c",
                file.path.display(),
                probe["tool"]
            );
        }
    }
}

/// The fixture's project manifest names its domain tags and the gates it can run. Every mandatory
/// gate of every profile that matches those tags must be runnable for it, or the job would be
/// blocked on a gate nobody can run.
#[test]
fn every_mandatory_gate_can_run_for_the_fixture_project() {
    const BUILT_IN_GATES: [&str; 3] = [
        "protected-paths-unchanged",
        "secret-scan",
        "documentation-quality",
    ];
    let project = read_example(
        &example_dir(ContractKind::ProjectManifest, "valid").join("word-count-fixture.yaml"),
    );
    let tags = strings(&project["project"]["domain_tags"]);
    let project_gates: Vec<(String, bool)> = project["gates"]
        .as_array()
        .expect("gates")
        .iter()
        .map(|g| {
            (
                g["id"].as_str().expect("a gate id").to_owned(),
                g["mandatory"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    let mut matched = 0;
    for file in profile_files() {
        let value = profile_value(&file);
        if strings(&value["matches"]).is_disjoint(&tags) {
            continue;
        }
        matched += 1;
        for gate in strings(&value["mandatory_gates"]) {
            let built_in = BUILT_IN_GATES.contains(&gate.as_str());
            let declared = project_gates
                .iter()
                .any(|(id, mandatory)| *id == gate && *mandatory);
            assert!(
                built_in || declared,
                "{}: the mandatory gate {gate} is neither built in nor a mandatory gate of the fixture project",
                file.path.display()
            );
        }
    }
    assert!(
        matched >= 2,
        "the universal and the Rust profile both match the fixture"
    );
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
