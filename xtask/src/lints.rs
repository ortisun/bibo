//! DEP-06: no crate uses unsafe code. The rule works through the workspace lint named in the
//! rules file (`unsafe_code = forbid`), and a lint only reaches a crate that opts in with
//! `[lints] workspace = true`. This checks both halves: the root manifest sets the lint, and
//! every workspace crate inherits it.
//!
//! `cargo metadata` does not report lints, so this reads the manifests as text. It accepts the
//! spellings Cargo documents and reports anything else as a violation, never as a pass.

use crate::finding::Finding;
use crate::metadata::Workspace;
use crate::rules::{Rules, WorkspaceLint};
use crate::scan::without_hash_comments;
use std::fs;

pub fn check(rules: &Rules, ws: &Workspace) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lint = &rules.workspace_lint;

    match fs::read_to_string(ws.root.join("Cargo.toml")) {
        Ok(text) if root_sets_lint(&text, lint) => {}
        Ok(_) => findings.push(Finding::new(
            "DEP-06",
            "Cargo.toml",
            format!(
                "the root manifest does not set {} = \"{}\" under [workspace.lints.{}]",
                lint.name, lint.level, lint.table
            ),
        )),
        Err(e) => findings.push(Finding::new(
            "DEP-06",
            "Cargo.toml",
            format!("cannot read the root manifest: {e}"),
        )),
    }

    for member in &ws.members {
        let location = format!("{}/Cargo.toml", ws.relative_dir(member));
        match fs::read_to_string(member.dir.join("Cargo.toml")) {
            Ok(text) if inherits_workspace_lints(&text) => {}
            Ok(_) => findings.push(Finding::new(
                "DEP-06",
                location,
                format!(
                    "{} does not inherit the workspace lints, so {} is not enforced for it; add `[lints]` with `workspace = true`",
                    member.name, lint.name
                ),
            )),
            Err(e) => findings.push(Finding::new("DEP-06", location, format!("cannot read the manifest: {e}"))),
        }
    }
    findings
}

/// A manifest split into its tables. The first table has the header "" and holds the keys that
/// come before any `[header]`.
fn tables(manifest: &str) -> Vec<(String, Vec<String>)> {
    let mut tables = vec![(String::new(), Vec::new())];
    for line in without_hash_comments(manifest).lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            tables.push((
                header.trim_matches(['[', ']']).trim().to_string(),
                Vec::new(),
            ));
        } else if !line.is_empty()
            && let Some((_, lines)) = tables.last_mut()
        {
            lines.push(line.to_string());
        }
    }
    tables
}

/// Split `key = value` and remove the spaces from the value.
fn key_value(line: &str) -> Option<(&str, String)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.split_whitespace().collect()))
}

/// `[lints]` with `workspace = true`, or the same written as a root key: `lints.workspace = true`
/// or `lints = { workspace = true }`.
pub fn inherits_workspace_lints(manifest: &str) -> bool {
    tables(manifest).iter().any(|(header, lines)| {
        lines
            .iter()
            .filter_map(|l| key_value(l))
            .any(|(key, value)| match header.as_str() {
                "lints" => key == "workspace" && value == "true",
                "" => {
                    (key == "lints.workspace" && value == "true")
                        || (key == "lints" && value.contains("workspace=true"))
                }
                _ => false,
            })
    })
}

/// The root manifest sets the lint to the level, under `[workspace.lints.<table>]` or as
/// `<table>.<name>` under `[workspace.lints]`. The value is the level as a string or a table
/// with `level = "..."`.
pub fn root_sets_lint(manifest: &str, lint: &WorkspaceLint) -> bool {
    let table_header = format!("workspace.lints.{}", lint.table);
    let dotted_key = format!("{}.{}", lint.table, lint.name);
    let plain = format!("\"{}\"", lint.level);
    let in_table = format!("level={plain}");
    tables(manifest).iter().any(|(header, lines)| {
        lines
            .iter()
            .filter_map(|l| key_value(l))
            .any(|(key, value)| {
                let right_key = (header == &table_header && key == lint.name)
                    || (header == "workspace.lints" && key == dotted_key);
                right_key
                    && (value == plain || (value.starts_with('{') && value.contains(&in_table)))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsafe_forbid() -> WorkspaceLint {
        WorkspaceLint {
            table: "rust".into(),
            name: "unsafe_code".into(),
            level: "forbid".into(),
        }
    }

    #[test]
    fn the_documented_spellings_inherit() {
        for manifest in [
            "[package]\nname = \"a\"\n\n[lints]\nworkspace = true\n",
            "[lints]\n  workspace   =   true  # inherit\n",
            "lints.workspace = true\n\n[package]\nname = \"a\"\n",
            "lints = { workspace = true }\n\n[package]\nname = \"a\"\n",
            "[package]\nname = \"a\"\n[lints]\nworkspace = true\n[dependencies]\n",
        ] {
            assert!(inherits_workspace_lints(manifest), "{manifest:?}");
        }
    }

    #[test]
    fn everything_else_does_not() {
        for manifest in [
            "[package]\nname = \"a\"\n",
            "[lints]\nworkspace = false\n",
            "# [lints]\n# workspace = true\n",
            "[lints.rust]\nunsafe_code = \"forbid\"\n",
            "[package]\nworkspace = true\n",
            "[dependencies]\nworkspace = true\n",
            "[lints]\nrust = { workspace = true }\n",
            "[package]\nname = \"a\"\n\n[package.metadata]\nlints = { workspace = true }\n",
        ] {
            assert!(!inherits_workspace_lints(manifest), "{manifest:?}");
        }
    }

    #[test]
    fn the_root_lint_is_found_in_the_documented_spellings() {
        for manifest in [
            "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n",
            "[workspace.lints.rust]\nunsafe_code = { level = \"forbid\", priority = 0 }\n",
            "[workspace.lints.rust]\nrust_2018_idioms = \"warn\"\nunsafe_code=\"forbid\" # DEP-06\n",
            "[workspace.lints]\nrust.unsafe_code = \"forbid\"\n",
        ] {
            assert!(root_sets_lint(manifest, &unsafe_forbid()), "{manifest:?}");
        }
    }

    #[test]
    fn a_weaker_or_misplaced_root_lint_is_not_enough() {
        for manifest in [
            "",
            "[workspace.lints.rust]\nunsafe_code = \"warn\"\n",
            "[workspace.lints.rust]\nunsafe_code = \"deny\"\n",
            "[workspace.lints.clippy]\nunsafe_code = \"forbid\"\n",
            "[lints.rust]\nunsafe_code = \"forbid\"\n",
            "# [workspace.lints.rust]\n# unsafe_code = \"forbid\"\n",
            "[workspace.lints.rust]\nother = \"forbid\"\n",
        ] {
            assert!(!root_sets_lint(manifest, &unsafe_forbid()), "{manifest:?}");
        }
    }

    #[test]
    fn a_clippy_lint_is_looked_up_in_the_clippy_table() {
        let lint = WorkspaceLint {
            table: "clippy".into(),
            name: "dbg_macro".into(),
            level: "deny".into(),
        };
        assert!(root_sets_lint(
            "[workspace.lints.clippy]\ndbg_macro = \"deny\"\n",
            &lint
        ));
        assert!(!root_sets_lint(
            "[workspace.lints.rust]\ndbg_macro = \"deny\"\n",
            &lint
        ));
    }
}
