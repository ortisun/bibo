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
//! * in Rust source, the attributes that set the level of a lint, read as tokens
//!   ([`attributes`]): comments, string literals and white space of any kind between the tokens of
//!   an attribute do not change what is read. A suppression (`allow`, `expect`, also inside a
//!   `cfg_attr`) that the file did not have, and fewer attributes at a level (`deny`, `forbid`,
//!   `warn`) for a lint than the file had, are hits. A lint dropped from a `deny` list, a `forbid`
//!   written as `deny` and a `deny` written as `warn` are fewer. A tightening is never a hit;
//! * in a `Cargo.toml`, the lint tables read with the TOML reader of the supply chain gate
//!   ([`tables`]), in any of the spellings of TOML (`[lints.rust]`, `[lints . rust]`, a dotted key
//!   at the top of the file, an inline table, quoted keys, single-quoted strings): a lint new at
//!   `allow`, a level lowered, a `deny` or `forbid` removed, a priority moved so that a weaker entry
//!   comes last, any change of the `lints.workspace = true` inheritance, and any new or changed
//!   `rustflags`. The same for `[workspace.lints]`;
//! * any change to, or removal of, the configuration of a lint or format tool (`clippy.toml`,
//!   `rustfmt.toml`);
//! * in a cargo configuration file (`.cargo/config.toml`, `.cargo/config`), any new, changed or
//!   removed `rustflags`, `rustdocflags`, `RUSTFLAGS` of the `[env]` table, `cap-lints`, compiler
//!   or compiler wrapper, in the `[build]` table or a `[target.*]` table, and any new string that
//!   carries an allow flag;
//! * in other languages, a new suppression comment (`# noqa`, `eslint-disable`, `//nolint`,
//!   `@SuppressWarnings`, `#pragma warning disable`, `# pylint: disable`), and a new line in an
//!   ignore list of a lint tool's own configuration.
//!
//! A file that the readers refuse (invalid TOML, a document that is too large) is a hit when it
//! changed: a change that cannot be read is not a change that is known to be harmless.
//!
//! The rules look at the two versions of each file, never at what a file says about itself. They
//! name the path and the line and never print the content. A hit is a failed host-side result, so
//! the lint gate cannot say it passed.

mod attributes;
mod tables;

use super::Violation;
use super::diff::FileChange;
use super::lines;

use attributes::Change;
use tables::Settings;

/// The check slug of every hit of this module.
const CHECK: &str = "lint-relaxed";

fn text(line: &[u8]) -> String {
    String::from_utf8_lossy(line).into_owned()
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

fn is_manifest(path: &str) -> bool {
    path == "Cargo.toml" || path.ends_with("/Cargo.toml")
}

/// The extensions of files that are certainly not Rust source. A file with any other extension (or
/// none) may be included into Rust code (`include!`), so its attributes are read.
const NOT_RUST: [&str; 28] = [
    "py", "pyi", "js", "mjs", "cjs", "ts", "tsx", "jsx", "go", "java", "kt", "rb", "php", "cs",
    "swift", "md", "markdown", "rst", "html", "css", "json", "yaml", "yml", "toml", "lock", "svg",
    "sh", "bash",
];

fn might_hold_rust(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((_, extension)) => !NOT_RUST.contains(&extension.to_ascii_lowercase().as_str()),
        None => true,
    }
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
        } else if file.before.is_some() {
            removed_in(file, &mut found);
        }
    }
    found
}

/// A file that is gone: the configuration of a tool or of cargo takes its settings with it.
fn removed_in(file: &FileChange, found: &mut Vec<Violation>) {
    let path = file.path.as_str();
    if is_tool_configuration(path) {
        found.push(violation(
            file,
            None,
            format!("The path {path} removes the configuration of a lint or format tool."),
        ));
    } else if is_cargo_configuration(path) && file.before_or_empty() != b"" {
        let before = String::from_utf8_lossy(file.before_or_empty());
        let carried = match tables::read_cargo_configuration(&before) {
            Ok(settings) => !settings.flags.is_empty(),
            // Unreadable: it may have carried anything.
            Err(_) => true,
        };
        if carried {
            found.push(violation(
                file,
                None,
                format!("The path {path} removes compiler flags or a lint cap."),
            ));
        }
    }
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
    if is_manifest(path) {
        manifest_changes(file, found);
        return;
    }
    if is_cargo_configuration(path) {
        cargo_configuration_changes(file, found);
    } else if might_hold_rust(path) && before != after {
        rust_changes(file, found);
    }
    let foreign = is_foreign_lint_configuration(path);
    for (number, raw) in lines::added(before, after) {
        let line = text(raw);
        if suppresses_foreign_lint(&line) {
            found.push(violation(
                file,
                Some(number),
                format!(
                    "The path {path} gains a comment that suppresses a lint, at line {number}."
                ),
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
}

// ------------------------------------------------------------------------------------------
// Rust source
// ------------------------------------------------------------------------------------------

fn rust_changes(file: &FileChange, found: &mut Vec<Violation>) {
    let path = file.path.as_str();
    let before = String::from_utf8_lossy(file.before_or_empty());
    let after = String::from_utf8_lossy(file.after_or_empty());
    let mut lowered = false;
    for change in attributes::compare(&before, &after) {
        match change {
            Change::Suppressed { line, inner, group } => {
                let what = match (inner, group) {
                    (true, true) => "a crate-level attribute that silences a whole group of lints",
                    (true, false) => "a crate-level attribute that silences a lint",
                    (false, _) => "an attribute that silences a lint",
                };
                found.push(violation(
                    file,
                    Some(line),
                    format!("The path {path} gains {what}, at line {line}."),
                ));
            }
            // One hit for the file, however many lints lost a level.
            Change::Lowered if !lowered => {
                lowered = true;
                found.push(violation(
                    file,
                    None,
                    format!(
                        "The path {path} loses a deny or forbid attribute, so a lint level is lowered."
                    ),
                ));
            }
            Change::Lowered => {}
        }
    }
}

// ------------------------------------------------------------------------------------------
// TOML
// ------------------------------------------------------------------------------------------

/// A hit about a TOML file that could not be read, when it changed.
fn unreadable(file: &FileChange, found: &mut Vec<Violation>) {
    if file.before != file.after {
        found.push(violation(
            file,
            None,
            format!(
                "The path {} cannot be read as TOML, so its lint levels and flags cannot be compared.",
                file.path
            ),
        ));
    }
}

fn manifest_changes(file: &FileChange, found: &mut Vec<Violation>) {
    let path = file.path.as_str();
    let after_text = String::from_utf8_lossy(file.after_or_empty());
    let before_text = String::from_utf8_lossy(file.before_or_empty());
    let Ok(after) = tables::read_manifest(&after_text) else {
        unreadable(file, found);
        return;
    };
    // A base that cannot be read has nothing to compare with: every lint set to allow is new.
    let before = tables::read_manifest(&before_text).unwrap_or_default();
    let mut hit = |line: Option<u32>, message: String| found.push(violation(file, line, message));
    let at = |key: &str| tables::line_of(&after_text, key);
    let inherits = |settings: &Settings| settings.inherits == Some(true);
    if inherits(&before) != inherits(&after) {
        hit(
            None,
            format!(
                "The path {path} changes whether the crate takes the lint levels of the workspace."
            ),
        );
    }
    for (key, entry) in &after.entries {
        let name = key.rsplit('.').next().unwrap_or(key);
        match before.entries.get(key) {
            Some(was) if entry.rank < was.rank => hit(
                at(key),
                format!("The path {path} lowers the level of the lint {name}."),
            ),
            Some(was)
                if (entry.rank >= 3 && entry.priority < was.priority)
                    || (entry.rank <= 2 && entry.priority > was.priority) =>
            {
                hit(
                    at(key),
                    format!(
                        "The path {path} moves the priority of the lint {name} so that a weaker entry comes last."
                    ),
                );
            }
            None if entry.rank == 1 => hit(
                at(key),
                format!("The path {path} sets the lint {name} to allow."),
            ),
            _ => {}
        }
    }
    for (key, was) in &before.entries {
        if was.rank >= 3 && !after.entries.contains_key(key) {
            let name = key.rsplit('.').next().unwrap_or(key);
            hit(
                None,
                format!("The path {path} no longer sets the lint {name} to deny or forbid."),
            );
        }
    }
    for (key, value) in &after.flags {
        if before.flags.get(key) != Some(value) {
            hit(at(key), format!("The path {path} sets compiler flags."));
        }
    }
}

fn cargo_configuration_changes(file: &FileChange, found: &mut Vec<Violation>) {
    let path = file.path.as_str();
    let after_text = String::from_utf8_lossy(file.after_or_empty());
    let before_text = String::from_utf8_lossy(file.before_or_empty());
    let Ok(after) = tables::read_cargo_configuration(&after_text) else {
        unreadable(file, found);
        return;
    };
    let before = tables::read_cargo_configuration(&before_text).unwrap_or_default();
    for (key, value) in &after.flags {
        if before.flags.get(key) != Some(value) {
            found.push(violation(
                file,
                tables::line_of(&after_text, key),
                format!("The path {path} sets compiler flags or the lint cap."),
            ));
        }
    }
    for key in before.flags.keys() {
        if !after.flags.contains_key(key) {
            found.push(violation(
                file,
                None,
                format!("The path {path} removes compiler flags or a lint cap."),
            ));
        }
    }
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

    fn deleted(path: &str, before: &str) -> FileChange {
        FileChange {
            path: path.to_owned(),
            kind: ChangeKind::Deleted,
            before: Some(before.as_bytes().to_vec()),
            after: None,
            readable: true,
        }
    }

    #[test]
    fn a_comment_that_mentions_an_attribute_is_not_one() {
        assert!(relaxed(&[added("src/lib.rs", "// #![allow(warnings)]\nlet x = 1;\n")]).is_empty());
        assert!(!relaxed(&[added("src/lib.rs", "#![allow(warnings)]\n")]).is_empty());
        assert!(
            !relaxed(&[added(
                "src/lib.rs",
                "    #[expect(clippy::too_many_arguments)]\n"
            )])
            .is_empty()
        );
    }

    #[test]
    fn a_word_that_only_ends_in_allow_is_not_an_allow() {
        assert!(
            relaxed(&[added(
                "src/lib.rs",
                "#[disallow(dead_code)]\n#[no_allow(x)]\n"
            )])
            .is_empty()
        );
    }

    #[test]
    fn an_unchanged_allow_is_not_new() {
        let same = "#![allow(unused)]\npub fn one() {}\n";
        assert!(relaxed(&[modified("src/lib.rs", same, same)]).is_empty());
        // Nor is one that moved.
        assert!(
            relaxed(&[modified(
                "src/lib.rs",
                "#![allow(unused)]\npub fn one() {}\n",
                "pub fn one() {}\n#![allow(unused)]\n"
            )])
            .is_empty()
        );
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
        assert!(!relaxed(&[modified("crates/a/Cargo.toml", "[package]\n", inherits)]).is_empty());
    }

    #[test]
    fn a_priority_that_lets_a_weaker_entry_win_is_a_hit() {
        let before = "[lints.clippy]\nunwrap_used = { level = \"deny\", priority = 0 }\nall = { level = \"warn\", priority = -1 }\n";
        let lowered = "[lints.clippy]\nunwrap_used = { level = \"deny\", priority = -5 }\nall = { level = \"warn\", priority = -1 }\n";
        let raised = "[lints.clippy]\nunwrap_used = { level = \"deny\", priority = 0 }\nall = { level = \"warn\", priority = 10 }\n";
        assert!(!relaxed(&[modified("Cargo.toml", before, lowered)]).is_empty());
        assert!(!relaxed(&[modified("Cargo.toml", before, raised)]).is_empty());
        assert!(relaxed(&[modified("Cargo.toml", before, before)]).is_empty());
    }

    #[test]
    fn a_new_manifest_that_allows_a_lint_is_a_hit_and_one_that_denies_is_not() {
        assert!(!relaxed(&[added("Cargo.toml", "[lints.clippy]\nall = \"allow\"\n")]).is_empty());
        assert!(relaxed(&[added("Cargo.toml", "[lints.clippy]\nall = \"deny\"\n")]).is_empty());
    }

    #[test]
    fn a_manifest_that_cannot_be_read_is_a_hit_when_it_changed() {
        let broken = "[lints.rust\nunused = \"deny\"\n";
        assert!(!relaxed(&[modified("Cargo.toml", "[package]\n", broken)]).is_empty());
        assert!(relaxed(&[modified("Cargo.toml", broken, broken)]).is_empty());
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
    fn a_removed_configuration_is_a_hit() {
        assert!(!relaxed(&[deleted("clippy.toml", "a = 1\n")]).is_empty());
        assert!(
            !relaxed(&[deleted(
                ".cargo/config.toml",
                "[build]\nrustflags = [\"-D\", \"warnings\"]\n"
            )])
            .is_empty()
        );
        // A cargo configuration with no flags in it takes nothing away.
        assert!(relaxed(&[deleted(".cargo/config.toml", "[net]\nretry = 3\n")]).is_empty());
        // Nor does a source file that is gone.
        assert!(relaxed(&[deleted("src/old.rs", "#![deny(warnings)]\n")]).is_empty());
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

    #[test]
    fn a_file_that_may_be_included_into_rust_is_read_and_a_python_file_is_not() {
        assert!(!relaxed(&[added("src/generated.inc", "#![allow(warnings)]\n")]).is_empty());
        assert!(!relaxed(&[added("build/lints", "#![allow(warnings)]\n")]).is_empty());
        assert!(relaxed(&[added("tools/check.py", "# [allow(warnings)]\n")]).is_empty());
        assert!(relaxed(&[added("docs/notes.md", "#![allow(warnings)]\n")]).is_empty());
    }
}
