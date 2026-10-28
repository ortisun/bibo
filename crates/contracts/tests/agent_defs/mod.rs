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
use std::path::PathBuf;

use factory_contracts::policy::{PolicyLoader, ProtectedPolicySource, SecurityPolicy};
use serde_json::Value;

use crate::support::{read_text, repo_root};

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
