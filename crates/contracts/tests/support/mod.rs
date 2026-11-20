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

/// A directory under the system temporary directory that is removed when the value is dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = format!(
            "{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir()
            .join("factory-contracts-tests")
            .join(unique);
        fs::create_dir_all(&path).expect("create the temporary directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Writes a file, creating the directories above it.
    pub fn write(&self, relative: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().expect("a file has a parent")).expect("create parents");
        fs::write(&path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Writes a JSON value as block-style YAML, one key per line, so a test can predict the line of
/// any field. Every string and key is double quoted, which is valid YAML and never ambiguous.
pub fn to_block_yaml(value: &Value) -> String {
    fn scalar(value: &Value) -> String {
        match value {
            Value::String(text) => serde_json::to_string(text).expect("a string serializes"),
            other => other.to_string(),
        }
    }
    fn write(value: &Value, indent: usize, out: &mut String) {
        let pad = " ".repeat(indent);
        match value {
            Value::Object(map) if !map.is_empty() => {
                for (key, child) in map {
                    let key = serde_json::to_string(key).expect("a key serializes");
                    match child {
                        Value::Object(inner) if !inner.is_empty() => {
                            out.push_str(&format!("{pad}{key}:\n"));
                            write(child, indent + 2, out);
                        }
                        Value::Array(inner) if !inner.is_empty() => {
                            out.push_str(&format!("{pad}{key}:\n"));
                            write(child, indent + 2, out);
                        }
                        Value::Object(_) => out.push_str(&format!("{pad}{key}: {{}}\n")),
                        Value::Array(_) => out.push_str(&format!("{pad}{key}: []\n")),
                        other => out.push_str(&format!("{pad}{key}: {}\n", scalar(other))),
                    }
                }
            }
            Value::Array(items) if !items.is_empty() => {
                for item in items {
                    match item {
                        Value::Object(inner) if !inner.is_empty() => {
                            let mut nested = String::new();
                            write(item, indent + 2, &mut nested);
                            // The first line of the nested block shares the dash.
                            let first_pad = " ".repeat(indent + 2);
                            let rest = nested.strip_prefix(&first_pad).unwrap_or(&nested);
                            out.push_str(&format!("{pad}- {rest}"));
                        }
                        Value::Array(inner) if !inner.is_empty() => {
                            out.push_str(&format!("{pad}-\n"));
                            write(item, indent + 2, out);
                        }
                        Value::Object(_) => out.push_str(&format!("{pad}- {{}}\n")),
                        Value::Array(_) => out.push_str(&format!("{pad}- []\n")),
                        other => out.push_str(&format!("{pad}- {}\n", scalar(other))),
                    }
                }
            }
            other => out.push_str(&format!("{pad}{}\n", scalar(other))),
        }
    }
    let mut out = String::new();
    write(value, 0, &mut out);
    out
}

/// `examples/<schema>/valid` or `invalid` for a kind.
pub fn example_dir(kind: ContractKind, which: &str) -> PathBuf {
    schemas_dir()
        .join("examples")
        .join(kind.schema_name())
        .join(which)
}
