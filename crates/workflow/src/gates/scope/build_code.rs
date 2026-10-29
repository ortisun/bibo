//! Build code that is new to the project, which no path rule and no command can hold for review.
//!
//! `policies/security.yaml` lists `build_script_added` among the semantic checks of the gate
//! integrity rules ("new build.rs, setup.py, postinstall or similar") and says it blocks until a
//! security review. A build script, a procedural macro and the dependencies of a build script run
//! code on whoever builds the project: here, in every gate, and after the merge, in every build.
//! The supply chain gate holds the build code of a *dependency* (`approve_build_code`, bound to the
//! name, version and checksum of a package). This module holds the build code of the builder's own
//! repository, from the committed trees on the host, before any command runs. A command that
//! built the change would run the very code this rule is about.
//!
//! What counts, for the files the change touches:
//!
//! * a `build.rs` (matched without regard to case, in any directory, a vendored dependency's
//!   included) that is new at its path or gains a line: an added file, a moved or renamed one (the
//!   store shows it as a file new at its place), a copy, and an edit of an existing one;
//! * in a `Cargo.toml`, a new `build = "..."` key in `[package]` (a `build = false` turns the
//!   script off and is not build code), a new `proc-macro = true` or `crate-type` that lists
//!   `proc-macro` in `[lib]`, and a new `[build-dependencies]` table or entry (also the target
//!   forms, `[target.'cfg(unix)'.build-dependencies]`).
//!
//! A deletion is not a finding: the change removes code and adds none. The rules read the lines a
//! change adds, never what a file says about itself, and they name the path and the line and never
//! print the content.
//!
//! **A limit.** A build script with another name (`build = "scripts/gen.rs"` already in the base
//! manifest) is seen when the `build` key is added, not when the script it names is edited later:
//! the host reads the files the change touches and not the manifest of the base for every edit.
//! The supply chain gate reads the manifests of both commits and holds a new package that has
//! such a script.
//!
//! A hit is a decision a security approver takes (`approve_build_code`), so the gate that reports
//! it is BLOCKED and not failed, and no sandbox is made.

use super::Violation;
use super::diff::FileChange;
use super::lines;

/// The check slug of every hit of this module.
pub const CHECK: &str = "build-code-added";

/// The words of the decision that lifts the block. Plain text for a person.
pub const DECISION: &str = "approve_build_code";

fn is_build_script(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("build.rs"))
}

fn is_manifest(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("Cargo.toml"))
}

/// The table a TOML line opens, without its brackets, or `None` for any other line.
fn table_header(trimmed: &str) -> Option<String> {
    let inner = trimmed.strip_prefix('[')?;
    let inner = inner.strip_prefix('[').unwrap_or(inner);
    let end = inner.find(']')?;
    Some(
        inner[..end]
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .collect::<String>()
            .to_ascii_lowercase(),
    )
}

fn is_build_dependencies(table: &str) -> bool {
    table == "build-dependencies"
        || table.starts_with("build-dependencies.")
        || table.ends_with(".build-dependencies")
        || table.contains(".build-dependencies.")
}

/// The key and value of a `key = value` line, with the value cut at a comment.
fn key_value(trimmed: &str) -> Option<(&str, &str)> {
    let (key, value) = trimmed.split_once('=')?;
    let key = key.trim();
    let value = value.split('#').next().unwrap_or_default().trim();
    (!key.is_empty()).then_some((key, value))
}

/// What a line of a manifest adds, given the table it sits in. `None` for a line that is not build
/// code.
fn manifest_line(table: &str, trimmed: &str) -> Option<&'static str> {
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    if let Some(opened) = table_header(trimmed) {
        return is_build_dependencies(&opened)
            .then_some("opens a table of build dependencies, which a build script uses");
    }
    if is_build_dependencies(table) {
        return Some("adds a build dependency, which a build script uses");
    }
    let (key, value) = key_value(trimmed)?;
    match (table, key) {
        ("package" | "project", "build") if value != "false" => {
            Some("names a build script with the build key")
        }
        ("lib", "proc-macro") if value == "true" => Some("makes the library a procedural macro"),
        ("lib", "crate-type") if value.contains("proc-macro") => {
            Some("makes the library a procedural macro")
        }
        // `[lib]` written as a dotted key of the package table is not valid; `lib.proc-macro = true`
        // at the top is not either. A dotted key under `[package]` named `build` is read above.
        _ => None,
    }
}

/// The table each line of `data` sits in, from line 1.
fn tables(data: &[u8]) -> Vec<String> {
    let mut current = String::new();
    lines::split(data)
        .into_iter()
        .map(|raw| {
            let line = String::from_utf8_lossy(raw);
            if let Some(opened) = table_header(line.trim()) {
                current = opened;
            }
            current.clone()
        })
        .collect()
}

/// What the files of a change add in the way of build code. See the module notes.
#[must_use]
pub fn added(files: &[FileChange]) -> Vec<Violation> {
    let mut found = Vec::new();
    for file in files {
        let Some(after) = &file.after else {
            continue;
        };
        let before = file.before_or_empty();
        if is_build_script(&file.path) {
            // A script is new code when it is new at its place or gains a line. A file that only
            // lost lines adds none.
            let gained = lines::added(before, after);
            if let Some((number, _)) = gained.first() {
                found.push(Violation {
                    check: CHECK,
                    message: format!(
                        "The path {} is a build script that is new or changed. It runs whenever the project is built, so it waits for a security approver ({DECISION}).",
                        file.path
                    ),
                    path: Some(file.path.clone()),
                    line: Some(*number),
                });
            }
        } else if is_manifest(&file.path) {
            let table_of = tables(after);
            for (number, raw) in lines::added(before, after) {
                let line = String::from_utf8_lossy(raw);
                let table = number
                    .checked_sub(1)
                    .and_then(|at| table_of.get(usize::try_from(at).unwrap_or(usize::MAX)))
                    .map_or("", String::as_str);
                if let Some(what) = manifest_line(table, line.trim()) {
                    found.push(Violation {
                        check: CHECK,
                        message: format!(
                            "The path {} {what}, at line {number}. Build code runs whenever the project is built, so it waits for a security approver ({DECISION}).",
                            file.path
                        ),
                        path: Some(file.path.clone()),
                        line: Some(number),
                    });
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use factory_ports::workspace::ChangeKind;

    use super::*;

    fn change(
        path: &str,
        kind: ChangeKind,
        before: Option<&str>,
        after: Option<&str>,
    ) -> FileChange {
        FileChange {
            path: path.to_owned(),
            kind,
            before: before.map(|text| text.as_bytes().to_vec()),
            after: after.map(|text| text.as_bytes().to_vec()),
            readable: true,
        }
    }

    fn checks(files: &[FileChange]) -> Vec<(String, Option<u32>)> {
        added(files)
            .into_iter()
            .map(|violation| (violation.path.unwrap_or_default(), violation.line))
            .collect()
    }

    const SCRIPT: &str = "fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}\n";

    #[test]
    fn a_new_build_script_in_any_directory_and_in_any_case_is_build_code() {
        for path in [
            "build.rs",
            "crates/a/build.rs",
            "Build.rs",
            "BUILD.RS",
            "vendor/some-crate/build.rs",
            "third_party/x/y/build.rs",
        ] {
            let files = [change(path, ChangeKind::Added, None, Some(SCRIPT))];
            assert_eq!(checks(&files), [(path.to_owned(), Some(1))], "{path}");
        }
    }

    #[test]
    fn an_edit_of_an_existing_script_is_build_code_and_a_deletion_is_not() {
        let edited = [change(
            "build.rs",
            ChangeKind::Modified,
            Some(SCRIPT),
            Some(&format!("{SCRIPT}std::process::Command::new(\"sh\");\n")),
        )];
        assert_eq!(checks(&edited), [("build.rs".to_owned(), Some(4))]);
        let removed = [change("build.rs", ChangeKind::Deleted, Some(SCRIPT), None)];
        assert!(added(&removed).is_empty());
        // An edit that only removes lines adds no code.
        let shortened = [change(
            "build.rs",
            ChangeKind::Modified,
            Some(SCRIPT),
            Some("fn main() {\n}\n"),
        )];
        assert!(added(&shortened).is_empty());
    }

    #[test]
    fn a_script_moved_or_renamed_into_place_is_new_at_its_place() {
        // The object store shows a move as a file that is new at its destination.
        for destination in ["build.rs", "crates/inner/build.rs", "tools/build.rs"] {
            let files = [
                change("old/gen.rs", ChangeKind::Deleted, Some(SCRIPT), None),
                change(destination, ChangeKind::Added, None, Some(SCRIPT)),
            ];
            assert_eq!(checks(&files).len(), 1, "{destination}");
        }
        // A script that moves out of the way adds nothing at the old place.
        let away = [change("build.rs", ChangeKind::Deleted, Some(SCRIPT), None)];
        assert!(added(&away).is_empty());
    }

    #[test]
    fn a_file_that_only_looks_like_a_build_script_is_not_one() {
        for path in [
            "build.rs/readme.md",
            "src/build.rs.bak",
            "src/rebuild.rs",
            "src/mybuild.rs",
            "docs/build.md",
            "src/lib.rs",
        ] {
            let files = [change(path, ChangeKind::Added, None, Some(SCRIPT))];
            assert!(added(&files).is_empty(), "{path}");
        }
    }

    #[test]
    fn a_new_build_key_a_procedural_macro_and_build_dependencies_are_build_code() {
        let base = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\n";
        let cases: [(&str, &str); 7] = [
            (
                "build = \"build.rs\"\n",
                "[package]\nname = \"x\"\nbuild = \"build.rs\"\n",
            ),
            (
                "build = \"gen/custom.rs\"\n",
                "[package]\nbuild = \"gen/custom.rs\"\n",
            ),
            ("proc-macro = true\n", "[lib]\nproc-macro = true\n"),
            (
                "crate-type = [\"proc-macro\"]\n",
                "[lib]\ncrate-type = [\"proc-macro\"]\n",
            ),
            (
                "[build-dependencies]\ncc = \"1\"\n",
                "[build-dependencies]\ncc = \"1\"\n",
            ),
            (
                "[target.'cfg(unix)'.build-dependencies]\ncc = \"1\"\n",
                "[target.'cfg(unix)'.build-dependencies]\ncc = \"1\"\n",
            ),
            (
                "[build-dependencies.cc]\nversion = \"1\"\n",
                "[build-dependencies.cc]\nversion = \"1\"\n",
            ),
        ];
        for (name, tail) in cases {
            let after = format!("{base}{tail}");
            let files = [change(
                "Cargo.toml",
                ChangeKind::Modified,
                Some(base),
                Some(&after),
            )];
            assert!(!added(&files).is_empty(), "{name}");
        }
    }

    #[test]
    fn a_new_entry_in_an_existing_table_of_build_dependencies_is_build_code() {
        let before = "[package]\nname = \"x\"\n\n[build-dependencies]\ncc = \"1\"\n";
        let after =
            "[package]\nname = \"x\"\n\n[build-dependencies]\ncc = \"1\"\nbindgen = \"0.70\"\n";
        let files = [change(
            "crates/a/Cargo.toml",
            ChangeKind::Modified,
            Some(before),
            Some(after),
        )];
        assert_eq!(
            checks(&files),
            [("crates/a/Cargo.toml".to_owned(), Some(6))]
        );
    }

    #[test]
    fn an_ordinary_manifest_change_and_a_disabled_build_script_are_not_build_code() {
        let before = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\n";
        for after in [
            // A new ordinary dependency is the dependency gates' business.
            format!("{before}serde = \"1\"\n"),
            // `build = false` turns the script off.
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\nbuild = false\n\n[dependencies]\n"
                .to_owned(),
            // A library that is not a macro.
            format!("{before}\n[lib]\ncrate-type = [\"cdylib\"]\nproc-macro = false\n"),
            // A comment that talks about it.
            format!("{before}# build = \"build.rs\" would go here\n"),
            // The word in another table.
            format!("{before}\n[package.metadata.docs]\nbuild = \"yes\"\n"),
        ] {
            let files = [change(
                "Cargo.toml",
                ChangeKind::Modified,
                Some(before),
                Some(&after),
            )];
            assert!(added(&files).is_empty(), "{after}");
        }
    }

    #[test]
    fn a_build_key_that_was_already_there_is_not_new() {
        let before = "[package]\nname = \"x\"\nbuild = \"build.rs\"\n";
        let after = "[package]\nname = \"x\"\nbuild = \"build.rs\"\nversion = \"0.2.0\"\n";
        let files = [change(
            "Cargo.toml",
            ChangeKind::Modified,
            Some(before),
            Some(after),
        )];
        assert!(added(&files).is_empty());
    }

    #[test]
    fn a_hit_names_the_path_and_the_line_and_never_the_content() {
        let secret_looking = "fn main() { let _ = \"do-not-print-this-line\"; }\n";
        let files = [change(
            "build.rs",
            ChangeKind::Added,
            None,
            Some(secret_looking),
        )];
        let found = added(&files);
        assert_eq!(found.len(), 1);
        assert!(!found[0].message.contains("do-not-print-this-line"));
        assert!(found[0].message.contains(DECISION));
        assert_eq!(found[0].check, CHECK);
    }
}
