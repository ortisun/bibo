//! Helpers the integration tests share: where the repository files are, and how to read an
//! example document, whether it is JSON or YAML.

// Each test binary uses a different part of this module.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use factory_contracts::yaml::{self, YamlLimits};
use factory_ports::registry::ContractKind;
use serde_json::Value;

/// The repository root, found from this crate's manifest directory.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn schemas_dir() -> PathBuf {
    repo_root().join("schemas")
}

pub fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Reads a `.json` or `.yaml` document as JSON. YAML goes through the restricted reader.
pub fn read_example(path: &Path) -> Value {
    let text = read_text(path);
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display())),
        Some("yaml" | "yml") => yaml::read(&text, YamlLimits::DEFINITION)
            .unwrap_or_else(|e| panic!("{} is refused by the YAML reader: {e}", path.display()))
            .to_json(),
        other => panic!("{} has an unexpected extension {other:?}", path.display()),
    }
}

/// Files in a directory, sorted by name, optionally only those with one of the extensions.
pub fn files_in(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| extensions.contains(&e))
        })
        .collect();
    files.sort();
    files
}

/// `examples/<schema>/valid` or `invalid` for a kind.
pub fn example_dir(kind: ContractKind, which: &str) -> PathBuf {
    schemas_dir()
        .join("examples")
        .join(kind.schema_name())
        .join(which)
}
