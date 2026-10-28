//! Helpers for the tests of the agent and profile definitions that live in `agents/` and
//! `profiles/`.
//!
//! This module only adds files. It reads the repository's own definitions, and the checks in it
//! return a list of plain-English problems instead of panicking, so that one test can run a check
//! on the real files (the list must be empty) and another can run the same check on a deliberately
//! broken copy (the list must name the break).

// Each test binary uses a different part of this module.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use factory_contracts::policy::{PolicyLoader, ProtectedPolicySource, SecurityPolicy};
use factory_contracts::schema_engine::Schema;
use serde_json::Value;

use crate::support::{read_text, repo_root};

pub mod checks;
pub mod render;

/// The Slice 1 agent set, by directory name. The package `s1-agent-definitions` asks for exactly
/// these nine roles and no others.
pub const SLICE_1_AGENTS: [&str; 9] = [
    "intake-classifier",
    "specification-writer",
    "specification-reviewer",
    "architect",
    "planner",
    "builder",
    "code-reviewer",
    "documentation-writer",
    "documentation-reviewer",
];

pub fn agents_dir() -> PathBuf {
    repo_root().join("agents")
}

pub fn profiles_dir() -> PathBuf {
    repo_root().join("profiles")
}

/// The security policy as the loader types it.
pub fn security_policy() -> SecurityPolicy {
    let source = ProtectedPolicySource::protected_default_branch(&repo_root(), &[])
        .expect("the repository root exists");
    PolicyLoader::load_security(&source)
        .unwrap_or_else(|e| panic!("{e}"))
        .document
}

/// One agent as the repository holds it: the directory name, the manifest as JSON and the prompt.
#[derive(Clone)]
pub struct Agent {
    pub dir_name: String,
    pub manifest: Value,
    pub prompt: String,
}

/// Every directory below `agents/` that holds a `manifest.json`, sorted by name.
pub fn agents() -> Vec<Agent> {
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(agents_dir()) {
        for entry in entries.filter_map(Result::ok) {
            let manifest_path = entry.path().join("manifest.json");
            if !manifest_path.is_file() {
                continue;
            }
            let manifest: Value = serde_json::from_str(&read_text(&manifest_path))
                .unwrap_or_else(|e| panic!("{} is not JSON: {e}", manifest_path.display()));
            let prompt_path = repo_root().join(
                manifest["prompt"]["template_path"]
                    .as_str()
                    .expect("a prompt path"),
            );
            found.push(Agent {
                dir_name: entry.file_name().to_string_lossy().into_owned(),
                manifest,
                prompt: read_text(&prompt_path),
            });
        }
    }
    found.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
    // A loop over no agents would pass without checking anything.
    assert!(
        !found.is_empty(),
        "there is no manifest.json below {}",
        agents_dir().display()
    );
    found
}

/// One profile file: where it is and its text.
pub struct ProfileFile {
    pub path: PathBuf,
    pub text: String,
}

/// Every `profile.json` below `profiles/`, sorted by path.
pub fn profile_files() -> Vec<ProfileFile> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(profiles_dir()) else {
        return found;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path().join("profile.json");
        if path.is_file() {
            found.push(ProfileFile {
                text: read_text(&path),
                path,
            });
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    // A loop over no profiles would pass without checking anything, so an empty directory fails.
    assert!(
        !found.is_empty(),
        "there is no profile.json below {}",
        profiles_dir().display()
    );
    found
}

/// A profile file as a JSON value.
pub fn profile_value(file: &ProfileFile) -> Value {
    serde_json::from_str(&file.text)
        .unwrap_or_else(|e| panic!("{} is not JSON: {e}", file.path.display()))
}

/// The output schema each agent returns, by agent directory name. The manifests must agree.
pub const OUTPUT_SCHEMA_OF: [(&str, &str); 9] = [
    ("intake-classifier", "intake-classification"),
    ("specification-writer", "specification-report"),
    ("specification-reviewer", "review-findings"),
    ("architect", "architecture-design"),
    ("planner", "planner-result"),
    ("builder", "builder-report"),
    ("code-reviewer", "review-findings"),
    ("documentation-writer", "documentation-report"),
    ("documentation-reviewer", "review-findings"),
];

/// The file of an agent input or output schema: `agents/schemas/<name>.v<version>.schema.json`.
pub fn agent_schema_path(name: &str, version: u64) -> PathBuf {
    agents_dir()
        .join("schemas")
        .join(format!("{name}.v{version}.schema.json"))
}

/// Compiles an agent schema with the crate's own closed schema engine.
pub fn compile_schema(path: &Path) -> Schema {
    Schema::compile_text(&read_text(path))
        .unwrap_or_else(|e| panic!("{} does not compile: {e}", path.display()))
}

/// The violations of `instance` against `schema`, each as `path: message`.
pub fn violations(schema: &Schema, instance: &Value) -> Vec<String> {
    schema
        .validate(instance)
        .0
        .into_iter()
        .map(|v| format!("{}: {}", v.path, v.message))
        .collect()
}

/// A fixture: its file name without the extension, and the JSON it holds.
pub struct Fixture {
    pub name: String,
    pub value: Value,
}

/// Like [`fixtures`], but fails when there are none, so a loop over the result cannot pass
/// without checking anything.
pub fn some_fixtures(agent: &str, kind: &str) -> Vec<Fixture> {
    let found = fixtures(agent, kind);
    assert!(
        !found.is_empty(),
        "{agent} has no fixture under fixtures/{kind}/"
    );
    found
}

/// The fixtures of an agent in `agents/<agent>/fixtures/<kind>/`, where `kind` is `valid` or
/// `invalid`, sorted by name.
pub fn fixtures(agent: &str, kind: &str) -> Vec<Fixture> {
    let dir = agents_dir().join(agent).join("fixtures").join(kind);
    let mut found: Vec<Fixture> = fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "json"))
                .map(|p| Fixture {
                    name: p
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                        .to_owned(),
                    value: serde_json::from_str(&read_text(&p))
                        .unwrap_or_else(|e| panic!("{} is not JSON: {e}", p.display())),
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}
