//! Lints that were relaxed inside a change, which no path rule and no lint command can see.
//!
//! `policies/security.yaml` lists `lint_relaxation` among the semantic checks of the gate
//! integrity rules ("lint level lowered, allow attributes added, ignore lists grown") and says it
//! blocks until a person approves. A lint command reads only its exit code, and an attribute in the
//! source outranks the `-D warnings` of the command line: a crate-level `#![allow(warnings)]` turns
//! a failing lint run into a passing one. So the change is read here, on the host, from both
//! versions of each file, before any command runs.
//!
//! What counts, for the files the change touches:
//!
//! * a new `allow(..)` or `expect(..)` in an attribute (`#[..]`, `#![..]`, `cfg_attr(..)`), at any
//!   level of the source, and a `deny` or `forbid` attribute that is gone;
//! * in a `Cargo.toml`, a lint table (`[lints]`, `[lints.rust]`, `[lints.clippy]`, `[workspace.lints..]`)
//!   whose entry is new at `allow`, is lowered, or is removed from `deny` or `forbid`, and a
//!   `[lints] workspace = true` that is gone;
//! * any change to the configuration of a lint or format tool (`clippy.toml`, `rustfmt.toml`);
//! * a new `rustflags`, `RUSTFLAGS` or `cap-lints` in a cargo configuration file;
//! * in other languages, a new suppression comment (`# noqa`, `eslint-disable`, `//nolint`,
//!   `@SuppressWarnings`, `#pragma warning disable`, `# pylint: disable`), and a new line in an
//!   ignore list of a lint tool's own configuration.
//!
//! The rules look at the lines a change adds and removes, never at what a file says about itself.
//! They name the path and the line and never print the content. A hit is a failed host-side result,
//! so the lint gate cannot say it passed.

use std::collections::BTreeMap;

use super::Violation;
use super::diff::FileChange;
use super::lines;

/// The check slug of every hit of this module.
const CHECK: &str = "lint-relaxed";

fn text(line: &[u8]) -> String {
    String::from_utf8_lossy(line).into_owned()
}

fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// True when `line` calls `name(` as a whole word, so `disallow(` is not `allow(`.
fn calls(line: &str, name: &str) -> bool {
    let pattern = format!("{name}(");
    line.match_indices(&pattern).any(|(at, _)| {
        line[..at]
            .chars()
            .next_back()
            .is_none_or(|before| !is_identifier_char(before))
    })
}

/// True for a line that is only a comment in Rust, Python or TOML. A suppression marker in a
/// comment of a language that has comment markers is judged separately.
fn is_comment(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with('#') && !trimmed.starts_with("#[") && !trimmed.starts_with("#!")
}

/// True when the line sits in a Rust attribute.
fn in_attribute(trimmed: &str) -> bool {
    trimmed.starts_with("#[") || trimmed.starts_with("#![")
}

/// The attribute's text when it silences a lint, with a short description for the message.
fn rust_relaxation(line: &str) -> Option<&'static str> {
    let trimmed = line.trim();
    if is_comment(trimmed) || !in_attribute(trimmed) {
        return None;
    }
    let crate_level = trimmed.starts_with("#![");
    let everything = ["warnings", "clippy::all", "unused", "clippy::pedantic"]
        .iter()
        .any(|group| trimmed.contains(group));
    if calls(trimmed, "allow") || calls(trimmed, "expect") {
        return Some(match (crate_level, everything) {
            (true, true) => "a crate-level attribute that silences a whole group of lints",
            (true, false) => "a crate-level attribute that silences a lint",
            (false, _) => "an attribute that silences a lint",
        });
    }
    None
}

fn is_lint_deny(line: &str) -> bool {
    let trimmed = line.trim();
    !is_comment(trimmed)
        && in_attribute(trimmed)
        && (calls(trimmed, "deny") || calls(trimmed, "forbid"))
}

/// A level in a `[lints]` table, ranked so that a lower number is a weaker level.
fn level_rank(level: &str) -> Option<u8> {
    match level {
        "allow" => Some(1),
        "warn" => Some(2),
        "deny" => Some(3),
        "forbid" => Some(4),
        _ => None,
    }
}

/// The lint levels a `Cargo.toml` sets, by table and name, and whether a `[lints]` table inherits
/// the workspace's.
#[derive(Default)]
struct Levels {
    entries: BTreeMap<String, (u8, u32)>,
    inherits: bool,
}

fn is_lints_table(name: &str) -> bool {
    let name = name.trim_start_matches("workspace.");
    name == "lints" || name.starts_with("lints.")
}

fn levels_of(data: &[u8]) -> Levels {
    let mut found = Levels::default();
    let mut table = String::new();
    for (index, raw) in lines::split(data).into_iter().enumerate() {
        let line = text(raw);
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            table = name.trim().to_owned();
            continue;
        }
        if !is_lints_table(&table) || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let value = value.trim();
        if key == "workspace" && value.starts_with("true") {
            found.inherits = true;
            continue;
        }
        let level = ["forbid", "deny", "warn", "allow"]
            .into_iter()
            .find(|level| value.contains(&format!("\"{level}\"")));
        if let Some(rank) = level.and_then(level_rank) {
            let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
            found
                .entries
                .insert(format!("{table}:{key}"), (rank, number));
        }
    }
    found
}

fn manifest_relaxations(file: &FileChange, found: &mut Vec<Violation>) {
    let before = levels_of(file.before_or_empty());
    let after = levels_of(file.after_or_empty());
    let mut hit = |number: u32, message: String| {
        found.push(Violation {
            check: CHECK,
            message,
            path: Some(file.path.clone()),
            line: Some(number),
        });
    };
    for (key, (rank, number)) in &after.entries {
        let name = key.split_once(':').map_or(key.as_str(), |(_, name)| name);
        match before.entries.get(key) {
            Some((was, _)) if rank < was => hit(
                *number,
                format!(
                    "The path {} lowers the level of the lint {name} at line {number}.",
                    file.path
                ),
            ),
            None if *rank == 1 => hit(
                *number,
                format!(
                    "The path {} sets the lint {name} to allow at line {number}.",
                    file.path
                ),
            ),
            _ => {}
        }
    }
    for (key, (rank, _)) in &before.entries {
        let name = key.split_once(':').map_or(key.as_str(), |(_, name)| name);
        if *rank >= 3 && !after.entries.contains_key(key) {
            hit(
                1,
                format!(
                    "The path {} no longer sets the lint {name} to deny or forbid.",
                    file.path
                ),
            );
        }
    }
    if before.inherits && !after.inherits {
        hit(
            1,
            format!(
                "The path {} no longer takes the lint levels of the workspace.",
                file.path
            ),
        );
    }
}

/// Files that configure a lint or format tool of the language: any change to them changes what the
/// lint gate means.
fn is_tool_configuration(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "clippy.toml" | ".clippy.toml" | "rustfmt.toml" | ".rustfmt.toml"
    )
}

fn is_cargo_configuration(path: &str) -> bool {
    path.starts_with(".cargo/") || path.contains("/.cargo/")
}

/// The ignore lists of lint tools of other languages.
fn is_foreign_lint_configuration(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "pyproject.toml"
            | "ruff.toml"
            | ".ruff.toml"
            | ".flake8"
            | "setup.cfg"
            | "tox.ini"
            | ".pylintrc"
            | ".eslintrc"
            | ".eslintrc.json"
            | ".eslintrc.js"
            | ".eslintignore"
            | "eslint.config.js"
            | "eslint.config.mjs"
    )
}

fn suppresses_foreign_lint(line: &str) -> bool {
    const MARKERS: [&str; 7] = [
        "# noqa",
        "eslint-disable",
        "//nolint",
        "// nolint",
        "@SuppressWarnings",
        "#pragma warning disable",
        "# pylint: disable",
    ];
    MARKERS.iter().any(|marker| line.contains(marker))
}

fn widens_ignore_list(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let trimmed = lower.trim();
    !trimmed.starts_with('#')
        && (trimmed.contains("ignore")
            || trimmed.contains("disable")
            || trimmed.contains("\"off\""))
}

fn violation(file: &FileChange, line: Option<u32>, message: String) -> Violation {
    Violation {
        check: CHECK,
        message,
        path: Some(file.path.clone()),
        line,
    }
}

/// What the files of a change say about relaxed lints.
#[must_use]
pub fn relaxed(files: &[FileChange]) -> Vec<Violation> {
    let mut found = Vec::new();
    for file in files {
        if file.after.is_some() {
            relaxed_in(file, &mut found);
        }
    }
    found
}

fn relaxed_in(file: &FileChange, found: &mut Vec<Violation>) {
    let after = file.after_or_empty();
    let before = file.before_or_empty();
    let path = file.path.as_str();
    if is_tool_configuration(path) && before != after {
        found.push(violation(
            file,
            None,
            format!("The path {path} changes the configuration of a lint or format tool."),
        ));
    }
    let manifest = path == "Cargo.toml" || path.ends_with("/Cargo.toml");
    if manifest {
        manifest_relaxations(file, found);
    }
    let cargo_configuration = is_cargo_configuration(path);
    let foreign = is_foreign_lint_configuration(path);
    for (number, raw) in lines::added(before, after) {
        let line = text(raw);
        let lower = line.to_ascii_lowercase();
        if manifest {
            if lower.trim_start().starts_with("rustflags") {
                found.push(violation(
                    file,
                    Some(number),
                    format!("The path {path} sets compiler flags at line {number}."),
                ));
            }
            continue;
        }
        if let Some(what) = rust_relaxation(&line) {
            found.push(violation(
                file,
                Some(number),
                format!("The path {path} gains {what}, at line {number}."),
            ));
        }
        if suppresses_foreign_lint(&line) {
            found.push(violation(
                file,
                Some(number),
                format!(
                    "The path {path} gains a comment that suppresses a lint, at line {number}."
                ),
            ));
        }
        if cargo_configuration && (lower.contains("rustflags") || lower.contains("cap-lints")) {
            found.push(violation(
                file,
                Some(number),
                format!("The path {path} sets compiler flags or the lint cap, at line {number}."),
            ));
        }
        if foreign && widens_ignore_list(&line) {
            found.push(violation(
                file,
                Some(number),
                format!(
                    "The path {path} grows an ignore or disable list of a lint tool, at line {number}."
                ),
            ));
        }
    }
    if file.before.is_some() && count_lines(before, is_lint_deny) > count_lines(after, is_lint_deny)
    {
        found.push(violation(
            file,
            None,
            format!(
                "The path {path} loses a deny or forbid attribute, so a lint level is lowered."
            ),
        ));
    }
}

fn count_lines(data: &[u8], keep: impl Fn(&str) -> bool) -> usize {
    lines::split(data)
        .into_iter()
        .filter(|line| keep(&text(line)))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_ports::workspace::ChangeKind;

    fn modified(path: &str, before: &str, after: &str) -> FileChange {
        FileChange {
            path: path.to_owned(),
            kind: ChangeKind::Modified,
            before: Some(before.as_bytes().to_vec()),
            after: Some(after.as_bytes().to_vec()),
            readable: true,
        }
    }

    fn added(path: &str, after: &str) -> FileChange {
        FileChange {
            path: path.to_owned(),
            kind: ChangeKind::Added,
            before: None,
            after: Some(after.as_bytes().to_vec()),
            readable: true,
        }
    }

    #[test]
    fn a_word_that_only_ends_in_allow_is_not_an_allow() {
        assert!(calls("#[allow(dead_code)]", "allow"));
        assert!(calls("#![cfg_attr(test, allow(unused))]", "allow"));
        assert!(!calls("#[disallow(dead_code)]", "allow"));
        assert!(!calls("#[no_allow(x)]", "allow"));
    }

    #[test]
    fn a_comment_that_mentions_an_attribute_is_not_one() {
        assert_eq!(rust_relaxation("// #![allow(warnings)]"), None);
        assert_eq!(rust_relaxation("let x = 1;"), None);
        assert!(rust_relaxation("#![allow(warnings)]").is_some());
        assert!(rust_relaxation("    #[expect(clippy::too_many_arguments)]").is_some());
    }

    #[test]
    fn an_unchanged_allow_is_not_new() {
        let same = "#![allow(unused)]\npub fn one() {}\n";
        assert!(relaxed(&[modified("src/lib.rs", same, same)]).is_empty());
    }

    #[test]
    fn levels_are_read_per_table() {
        let levels = levels_of(
            b"[lints.rust]\nunsafe_code = \"forbid\"\n[lints.clippy]\nall = { level = \"warn\", priority = -1 }\n[package]\nname = \"x\"\n",
        );
        assert_eq!(levels.entries.len(), 2);
        assert_eq!(levels.entries["lints.rust:unsafe_code"].0, 4);
        assert_eq!(levels.entries["lints.clippy:all"].0, 2);
    }

    #[test]
    fn a_lowered_removed_or_allowed_lint_in_a_manifest_is_a_hit() {
        let before = "[lints.rust]\nunsafe_code = \"forbid\"\nunused = \"deny\"\n";
        let lowered = "[lints.rust]\nunsafe_code = \"warn\"\nunused = \"deny\"\n";
        let removed = "[lints.rust]\nunsafe_code = \"forbid\"\n";
        let allowed =
            "[lints.rust]\nunsafe_code = \"forbid\"\nunused = \"deny\"\ndead_code = \"allow\"\n";
        for after in [lowered, removed, allowed] {
            assert!(
                !relaxed(&[modified("Cargo.toml", before, after)]).is_empty(),
                "{after}"
            );
        }
        let strengthened =
            "[lints.rust]\nunsafe_code = \"forbid\"\nunused = \"forbid\"\ndead_code = \"warn\"\n";
        assert!(relaxed(&[modified("Cargo.toml", before, strengthened)]).is_empty());
        let inherits = "[lints]\nworkspace = true\n";
        assert!(!relaxed(&[modified("crates/a/Cargo.toml", inherits, "[package]\n")]).is_empty());
    }

    #[test]
    fn a_new_manifest_that_allows_a_lint_is_a_hit_and_one_that_denies_is_not() {
        assert!(!relaxed(&[added("Cargo.toml", "[lints.clippy]\nall = \"allow\"\n")]).is_empty());
        assert!(relaxed(&[added("Cargo.toml", "[lints.clippy]\nall = \"deny\"\n")]).is_empty());
    }

    #[test]
    fn the_configuration_of_a_tool_and_the_compiler_flags_are_hits() {
        assert!(!relaxed(&[modified("clippy.toml", "a = 1\n", "a = 2\n")]).is_empty());
        assert!(!relaxed(&[added("rustfmt.toml", "max_width = 200\n")]).is_empty());
        assert!(
            !relaxed(&[added(
                ".cargo/config.toml",
                "[build]\nrustflags = [\"-A\", \"warnings\"]\n"
            )])
            .is_empty()
        );
        assert!(relaxed(&[added(".cargo/config.toml", "[net]\nretry = 3\n")]).is_empty());
        assert!(
            !relaxed(&[modified(
                "Cargo.toml",
                "[package]\n",
                "[package]\nrustflags = [\"-A\", \"warnings\"]\n"
            )])
            .is_empty()
        );
    }

    #[test]
    fn a_lost_deny_attribute_is_a_hit() {
        let before = "#![deny(warnings)]\npub fn one() {}\n";
        let after = "pub fn one() {}\n";
        assert!(!relaxed(&[modified("src/lib.rs", before, after)]).is_empty());
        let weaker = "#![warn(warnings)]\npub fn one() {}\n";
        assert!(!relaxed(&[modified("src/lib.rs", before, weaker)]).is_empty());
        assert!(relaxed(&[modified("src/lib.rs", before, before)]).is_empty());
    }

    #[test]
    fn suppression_comments_and_ignore_lists_of_other_tools_are_hits() {
        assert!(!relaxed(&[added("app.py", "import os  # noqa\n")]).is_empty());
        assert!(!relaxed(&[added("app.js", "// eslint-disable-next-line\nx()\n")]).is_empty());
        assert!(
            !relaxed(&[modified(
                "ruff.toml",
                "line-length = 88\n",
                "line-length = 88\nignore = [\"E501\"]\n"
            )])
            .is_empty()
        );
        assert!(relaxed(&[added("app.py", "print('hello')\n")]).is_empty());
    }
}
