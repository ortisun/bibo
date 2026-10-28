//! `cargo xtask check-invariants`: every invariant in the register has a test or a marker that
//! names it (review finding F-24).
//!
//! The register is the `invariants` list of `docs/architecture/state-machine.json`. An invariant
//! `INV-05` counts as named when, somewhere under `crates/`, either
//!
//! * a `#[test]` function has `inv_05` in its name (`fn inv_05_a_zombie_worker_is_fenced`), or
//! * a comment or doc comment contains `INV-05` (`// INV-05` above a test is the usual marker).
//!
//! A mention in a string does not count, and neither does a function without `#[test]`. The check
//! finds the name, not whether the test is good; reading the test is the reviewer's job.

use crate::finding::Finding;
use crate::scan;
use crate::syntax;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The ids of the register, in file order.
pub fn register_ids(text: &str) -> Result<Vec<String>, String> {
    let doc: Value = serde_json::from_str(text)
        .map_err(|e| format!("the invariant register is not JSON: {e}"))?;
    let list = doc["invariants"]
        .as_array()
        .ok_or("the invariant register has no `invariants` list")?;
    list.iter()
        .map(|entry| {
            entry["id"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "an invariant in the register has no `id`".to_string())
        })
        .collect()
}

/// The ids that no test name or marker under `root/crates` mentions.
pub fn check(root: &Path, register: &Path) -> Result<(Vec<String>, Vec<Finding>), String> {
    let text = fs::read_to_string(register).map_err(|e| {
        format!(
            "cannot read the invariant register {}: {e}",
            register.display()
        )
    })?;
    let ids = register_ids(&text)?;
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files)?;
    let mut named: BTreeSet<String> = BTreeSet::new();
    for file in files {
        let source = fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        named.extend(names_in(&source, &ids));
    }
    let findings = ids
        .iter()
        .filter(|id| !named.contains(*id))
        .map(|id| {
            Finding::new(
                id,
                register.strip_prefix(root).unwrap_or(register).to_string_lossy().replace('\\', "/"),
                format!(
                    "no #[test] function named {} and no comment containing {id} under crates/; name the test, or put `// {id}` above it",
                    id.to_ascii_lowercase().replace('-', "_")
                ),
            )
        })
        .collect();
    Ok((ids, findings))
}

/// The ids from `ids` that the source names in a test function name or in a comment.
fn names_in(source: &str, ids: &[String]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let comments_only = scan::mask(source).with_strings;
    let functions = syntax::lex(source).test_function_names();
    for id in ids {
        let function_part = id.to_ascii_lowercase().replace('-', "_");
        let in_function = functions.iter().any(|name| {
            let lower = name.to_ascii_lowercase();
            lower.match_indices(&function_part).any(|(at, _)| {
                !lower
                    .as_bytes()
                    .get(at + function_part.len())
                    .is_some_and(u8::is_ascii_digit)
            })
        });
        let in_comment = source.match_indices(id.as_str()).any(|(at, _)| {
            let end = at + id.len();
            let whole = !source.as_bytes().get(end).is_some_and(u8::is_ascii_digit);
            // The masked view keeps strings and blanks comments, so a blank means a comment.
            let blank = comments_only
                .get(at..end)
                .is_some_and(|s| s.bytes().all(|b| b == b' '));
            whole && blank
        });
        if in_function || in_comment {
            found.insert(id.clone());
        }
    }
    found
}

fn rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let Ok(kind) = fs::symlink_metadata(&path).map(|m| m.file_type()) else {
            continue;
        };
        if kind.is_dir() {
            if path.file_name().is_some_and(|n| n != "target") {
                rust_files(&path, files)?;
            }
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files.sort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Vec<String> {
        ["INV-01", "INV-02", "INV-03", "INV-11"]
            .map(String::from)
            .to_vec()
    }

    #[test]
    fn a_test_name_a_line_comment_and_a_doc_comment_each_name_an_invariant() {
        let source = "#[test]\nfn inv_01_only_the_engine_writes() {}\n// INV-02\nfn a() {}\n/// Covers INV-03.\nfn b() {}\n";
        let found = names_in(source, &ids());
        assert_eq!(
            found.into_iter().collect::<Vec<_>>(),
            ["INV-01", "INV-02", "INV-03"]
        );
    }

    #[test]
    fn async_tests_count() {
        let found = names_in(
            "#[tokio::test(flavor = \"current_thread\")]\nasync fn inv_11_invalidation() {}\n",
            &ids(),
        );
        assert!(found.contains("INV-11"));
    }

    #[test]
    fn a_string_a_plain_function_and_a_longer_number_do_not_count() {
        let source = "const M: &str = \"INV-01\";\nfn inv_02_helper() {}\n// INV-011 is something else\n#[test]\nfn inv_031_other() {}\n#[cfg(test)]\nfn inv_03_not_a_test() {}\n";
        assert!(names_in(source, &ids()).is_empty());
    }

    #[test]
    fn the_register_ids_come_from_the_invariants_list() {
        let ids =
            register_ids("{\"invariants\": [{\"id\": \"INV-01\"}, {\"id\": \"INV-02\"}]}").unwrap();
        assert_eq!(ids, ["INV-01", "INV-02"]);
        assert!(register_ids("{}").is_err());
        assert!(register_ids("{\"invariants\": [{}]}").is_err());
    }
}
