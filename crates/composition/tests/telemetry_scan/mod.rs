//! Reading the production source tree and the conventions page, for the scans of the telemetry
//! checks. A scan reads text, so it misses a name built at run time; it is a guard rail.
//!
//! These scans live in the composition crate's tests because the inner crates, `workflow` among
//! them, may not read files, tests included (rule DEP-05). Each test file includes this module with
//! `mod telemetry_scan;` and uses the parts it needs.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The conventions page the tables are read from.
pub const CONVENTIONS: &str = include_str!("../../../../docs/observability/conventions.md");

pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under the `src` directory of every crate and app, with its path relative to the
/// repository root and its text, in path order. The observability crate is included: a caller that
/// must leave it out filters on the path.
pub fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, into: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, into);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                into.push((relative, text));
            }
        }
    }
    let root = repository_root();
    let mut found = Vec::new();
    for group in ["crates", "apps"] {
        let Ok(members) = std::fs::read_dir(root.join(group)) else {
            continue;
        };
        for member in members.flatten() {
            walk(&member.path().join("src"), &root, &mut found);
        }
    }
    found.sort();
    found
}

/// The rows of the table between `<!-- table:NAME -->` and `<!-- /table:NAME -->`, header and
/// separator removed. Each cell is trimmed and loses the backticks around it.
pub fn table(name: &str) -> Vec<Vec<String>> {
    let begin = format!("<!-- table:{name} -->");
    let end = format!("<!-- /table:{name} -->");
    let start = CONVENTIONS
        .find(&begin)
        .unwrap_or_else(|| panic!("the conventions page has no marker {begin}"));
    let stop = CONVENTIONS
        .find(&end)
        .unwrap_or_else(|| panic!("the conventions page has no marker {end}"));
    CONVENTIONS[start + begin.len()..stop]
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .skip(2)
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_owned())
                .collect()
        })
        .collect()
}

/// The names in a cell such as "`a`, `b`".
pub fn names_in(cell: &str) -> Vec<String> {
    cell.split(',')
        .map(|part| part.trim().trim_matches('`').to_owned())
        .filter(|part| !part.is_empty() && part != "none")
        .collect()
}

/// The span names of the conventions page.
pub fn span_names() -> Vec<String> {
    let mut names: Vec<String> = table("spans")
        .into_iter()
        .map(|row| row[0].clone())
        .collect();
    names.sort();
    names
}
