//! Lint levels and compiler flags in TOML files, read with the reader of the supply chain gate
//! (RR-13).
//!
//! The rule used to find a lint table by the exact text of its header and a level by its
//! double-quoted word. TOML has more spellings than that: white space around the dots of a
//! header, a dotted key at the top of the file (`lints.rust.unused = "allow"`), quoted keys, single
//! quoted strings, and inline tables (`rust = { unused = "deny", dead_code = "allow" }`). Cargo reads
//! all of them, and so does the reader in [`crate::gates::supply_chain::toml`], which turns each into
//! the same tree. This module walks that tree.
//!
//! A file the reader refuses (it refuses rather than guesses: a duplicate key, a syntax it does not
//! know, a document that is too large) is not read at all, and the caller reports it.
//!
//! What is read from a `Cargo.toml`:
//!
//! * `lints.workspace = true`, the inheritance of the lint levels of the workspace;
//! * `lints.<tool>.<lint>` and `workspace.lints.<tool>.<lint>`, each a level (`"allow"`, `"warn"`,
//!   `"deny"`, `"forbid"`) or a table with a `level` and a `priority`;
//! * any key named `rustflags` or `rustdocflags`, at any depth.
//!
//! What is read from a cargo configuration file: any key that sets compiler flags or the compiler
//! itself (`rustflags`, `rustdocflags`, the `RUSTFLAGS` of the `[env]` table, `cap-lints`,
//! `rustc`, `rustc-wrapper`, `rustc-workspace-wrapper`), and any string that carries an allow flag
//! (`-A`, `--allow`, `--cap-lints`), such as an alias for a lint command.

use std::collections::BTreeMap;

use crate::gates::supply_chain::toml::{self, Table, TomlError, Value};

/// The rank of a level: a higher number is a stronger level.
#[must_use]
pub fn rank(level: &str) -> Option<u8> {
    match level {
        "allow" => Some(1),
        "warn" => Some(2),
        "deny" => Some(3),
        "forbid" => Some(4),
        _ => None,
    }
}

/// One lint level set in a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The rank of the level, see [`rank`].
    pub rank: u8,
    /// The priority: among the entries of one crate, the lower is applied first.
    pub priority: i64,
}

/// What a file sets that bears on lints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// `Some(true)` when `lints.workspace = true`.
    pub inherits: Option<bool>,
    /// The lint levels, by `lints.<tool>.<lint>` or `workspace.lints.<tool>.<lint>`.
    pub entries: BTreeMap<String, Entry>,
    /// The compiler flags and lint caps, by the path of the key, with the canonical text of the
    /// value.
    pub flags: BTreeMap<String, String>,
}

/// The keys of a manifest that set compiler flags.
const MANIFEST_FLAG_KEYS: [&str; 2] = ["rustflags", "rustdocflags"];

/// The keys of a cargo configuration that set compiler flags, the lint cap or the compiler.
const CONFIG_FLAG_KEYS: [&str; 8] = [
    "rustflags",
    "rustdocflags",
    "cargo_encoded_rustflags",
    "cargo_encoded_rustdocflags",
    "cap-lints",
    "rustc",
    "rustc-wrapper",
    "rustc-workspace-wrapper",
];

/// The level and priority a value sets, if it sets one: a string, or a table with a `level`.
fn entry_of(value: &Value) -> Option<Entry> {
    match value {
        Value::Str(level) => rank(level).map(|rank| Entry { rank, priority: 0 }),
        Value::Table(table) => {
            let level = table.get("level")?.as_str()?;
            Some(Entry {
                rank: rank(level)?,
                priority: table.get("priority").and_then(Value::as_int).unwrap_or(0),
            })
        }
        _ => None,
    }
}

/// Collects the entries of a `lints` table whose path so far is `prefix`.
fn lint_entries(prefix: &str, table: &Table, settings: &mut Settings) {
    for (tool, value) in table {
        if prefix == "lints" && tool == "workspace" {
            if let Some(flag) = value.as_bool() {
                settings.inherits = Some(flag);
            }
            continue;
        }
        match value {
            Value::Table(names) if entry_of(value).is_none() => {
                for (name, level) in names {
                    if let Some(entry) = entry_of(level) {
                        settings
                            .entries
                            .insert(format!("{prefix}.{tool}.{name}"), entry);
                    }
                }
            }
            other => {
                // A level set directly under `lints`, without a tool table.
                if let Some(entry) = entry_of(other) {
                    settings.entries.insert(format!("{prefix}.{tool}"), entry);
                }
            }
        }
    }
}

/// Collects the keys named in `keys`, at any depth, with the canonical text of their value.
fn flag_keys(prefix: &str, table: &Table, keys: &[&str], out: &mut BTreeMap<String, String>) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if keys.contains(&key.to_ascii_lowercase().as_str()) {
            out.insert(path.clone(), value.canonical());
        }
        match value {
            Value::Table(inner) => flag_keys(&path, inner, keys, out),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    if let Value::Table(inner) = item {
                        flag_keys(&format!("{path}[{index}]"), inner, keys, out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// True when a string carries a flag that allows lints.
fn allows_lints(text: &str) -> bool {
    text.split_whitespace().any(|word| {
        word == "-A"
            || (word.starts_with("-A") && word.len() > 2)
            || word.starts_with("--allow")
            || word.contains("cap-lints")
    })
}

/// Collects the strings that carry an allow flag, by path.
fn allow_strings(prefix: &str, value: &Value, out: &mut BTreeMap<String, String>) {
    match value {
        Value::Str(text) if allows_lints(text) => {
            out.insert(prefix.to_owned(), value.canonical());
        }
        Value::Table(table) => {
            for (key, inner) in table {
                allow_strings(&format!("{prefix}.{key}"), inner, out);
            }
        }
        Value::Array(items) => {
            // The words of a command given as an array are joined, so that `["-A", "warnings"]`
            // and `"-A warnings"` are the same.
            let words: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
            if words.len() == items.len() && allows_lints(&words.join(" ")) {
                out.insert(prefix.to_owned(), value.canonical());
            } else {
                for (index, item) in items.iter().enumerate() {
                    allow_strings(&format!("{prefix}[{index}]"), item, out);
                }
            }
        }
        _ => {}
    }
}

/// The settings of a `Cargo.toml`.
///
/// # Errors
/// [`TomlError`] when the reader refuses the text.
pub fn read_manifest(text: &str) -> Result<Settings, TomlError> {
    let document = toml::parse(text)?;
    let mut settings = Settings::default();
    if let Some(Value::Table(lints)) = document.get("lints") {
        lint_entries("lints", lints, &mut settings);
    }
    if let Some(Value::Table(lints)) = document
        .get("workspace")
        .and_then(Value::as_table)
        .and_then(|workspace| workspace.get("lints"))
    {
        lint_entries("workspace.lints", lints, &mut settings);
    }
    flag_keys("", &document, &MANIFEST_FLAG_KEYS, &mut settings.flags);
    Ok(settings)
}

/// The settings of a cargo configuration file.
///
/// # Errors
/// [`TomlError`] when the reader refuses the text.
pub fn read_cargo_configuration(text: &str) -> Result<Settings, TomlError> {
    let document = toml::parse(text)?;
    let mut settings = Settings::default();
    flag_keys("", &document, &CONFIG_FLAG_KEYS, &mut settings.flags);
    for (key, value) in &document {
        allow_strings(key, value, &mut settings.flags);
    }
    Ok(settings)
}

/// The line, from 1, of the first line of `text` that holds `needle` as the last segment of a path
/// (`lints.rust.unused` finds `unused`). A best effort for a message: the tree has no lines.
#[must_use]
pub fn line_of(text: &str, path: &str) -> Option<u32> {
    let name = path.rsplit('.').next().unwrap_or(path);
    let name = name.split('[').next().unwrap_or(name);
    if name.is_empty() {
        return None;
    }
    text.lines()
        .position(|line| {
            line.match_indices(name).any(|(at, _)| {
                let before = line[..at].chars().next_back();
                let after = line[at + name.len()..].chars().next();
                let edge = |c: Option<char>| {
                    c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                };
                edge(before) && edge(after)
            })
        })
        .and_then(|index| u32::try_from(index + 1).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(text: &str) -> Vec<(String, u8)> {
        read_manifest(text)
            .expect("reads")
            .entries
            .into_iter()
            .map(|(key, entry)| (key, entry.rank))
            .collect()
    }

    #[test]
    fn every_spelling_of_a_lint_table_gives_the_same_entries() {
        let spellings = [
            "[lints.rust]\nunused = \"deny\"\n",
            "[lints . rust]\nunused = \"deny\"\n",
            "[ lints . rust ]\n unused = \"deny\"\n",
            "[\"lints\".\"rust\"]\n\"unused\" = \"deny\"\n",
            "[lints.rust]\nunused = 'deny'\n",
            "lints.rust.unused = \"deny\"\n",
            "lints . rust . unused = \"deny\"\n",
            "[lints]\nrust = { unused = \"deny\" }\n",
            "[lints]\nrust.unused = \"deny\"\n",
            "[lints.rust]\nunused = { level = \"deny\" }\n",
            "[lints.rust]\nunused = { level = 'deny', priority = 0 }\n",
        ];
        for text in spellings {
            assert_eq!(
                entries(text),
                [("lints.rust.unused".to_owned(), 3)],
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_workspace_tables_and_the_inheritance_are_read() {
        let settings = read_manifest(
            "[workspace.lints.clippy]\nall = { level = \"warn\", priority = -1 }\nunwrap_used = \"forbid\"\n",
        )
        .expect("reads");
        assert_eq!(
            settings.entries["workspace.lints.clippy.all"],
            Entry {
                rank: 2,
                priority: -1
            }
        );
        assert_eq!(
            settings.entries["workspace.lints.clippy.unwrap_used"].rank,
            4
        );
        for text in [
            "[lints]\nworkspace = true\n",
            "lints.workspace = true\n",
            "[lints]\nworkspace = true # yes\n",
        ] {
            assert_eq!(
                read_manifest(text).expect("reads").inherits,
                Some(true),
                "{text:?}"
            );
        }
        assert_eq!(
            read_manifest("[package]\nname = \"x\"\n")
                .expect("reads")
                .inherits,
            None
        );
    }

    #[test]
    fn rustflags_are_found_at_any_depth_in_a_manifest() {
        let settings = read_manifest(
            "[package]\nname = \"x\"\n[profile.dev]\nrustflags = [\"-A\", \"warnings\"]\n[target.'cfg(unix)']\nRustFlags = \"x\"\n",
        )
        .expect("reads");
        assert_eq!(settings.flags.len(), 2, "{:?}", settings.flags);
    }

    #[test]
    fn a_cargo_configuration_names_flags_wrappers_and_allow_strings() {
        let text = "[build]\nrustflags = [\"-A\", \"warnings\"]\nrustc-wrapper = \"w\"\n[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"x\"]\n[env]\nRUSTFLAGS = \"-A warnings\"\nOTHER = { value = \"1\", force = true }\n[alias]\nlint = \"clippy -- -A clippy::all\"\nfine = \"build --release\"\n";
        let flags = read_cargo_configuration(text).expect("reads").flags;
        for key in [
            "build.rustflags",
            "build.rustc-wrapper",
            "target.x86_64-unknown-linux-gnu.rustflags",
            "env.RUSTFLAGS",
            "alias.lint",
        ] {
            assert!(flags.contains_key(key), "{key} in {flags:?}");
        }
        assert!(!flags.contains_key("alias.fine"));
        assert!(!flags.contains_key("env.OTHER"));
        assert!(
            read_cargo_configuration("[net]\nretry = 3\n")
                .expect("reads")
                .flags
                .is_empty()
        );
    }

    #[test]
    fn a_file_the_reader_refuses_is_an_error_and_not_a_guess() {
        assert!(read_manifest("[lints.rust\nunused = \"deny\"\n").is_err());
        assert!(read_manifest("[lints.rust]\nunused = \"deny\"\nunused = \"allow\"\n").is_err());
        assert!(read_cargo_configuration("rustflags = [\n").is_err());
    }

    #[test]
    fn the_line_of_a_key_is_found_when_it_stands_alone_as_a_word() {
        let text = "[lints.rust]\nunused_imports = \"deny\"\nunused = \"allow\"\n";
        assert_eq!(line_of(text, "lints.rust.unused"), Some(3));
        assert_eq!(line_of(text, "lints.rust.missing"), None);
    }
}
