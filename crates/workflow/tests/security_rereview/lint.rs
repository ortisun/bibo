//! The host-side rule for a lint that was relaxed inside a change (AUT-4, `lint_relaxation`),
//! attacked with the spellings of Rust and TOML that the line-based reader does not read.
//!
//! The rule is a pure function of the files of a change, so the attacks call it directly.

use factory_ports::workspace::ChangeKind;
use factory_workflow::gates::scope::FileChange;
use factory_workflow::gates::scope::lint::relaxed;

fn added(path: &str, after: &str) -> FileChange {
    FileChange {
        path: path.to_owned(),
        kind: ChangeKind::Added,
        before: None,
        after: Some(after.as_bytes().to_vec()),
        readable: true,
    }
}

fn modified(path: &str, before: &str, after: &str) -> FileChange {
    FileChange {
        path: path.to_owned(),
        kind: ChangeKind::Modified,
        before: Some(before.as_bytes().to_vec()),
        after: Some(after.as_bytes().to_vec()),
        readable: true,
    }
}

/// Names of the cases whose change the rule did not report.
fn unreported(cases: &[(&str, FileChange)]) -> Vec<String> {
    cases
        .iter()
        .filter(|(_, change)| relaxed(std::slice::from_ref(change)).is_empty())
        .map(|(name, _)| (*name).to_owned())
        .collect()
}

/// Control: the spellings the rule is known to read are reported.
#[test]
fn held_the_plain_spellings_are_reported() {
    let cases = [
        (
            "inner allow",
            added("src/lib.rs", "#![allow(warnings)]\nfn f() {}\n"),
        ),
        (
            "outer allow",
            added("src/lib.rs", "#[allow(dead_code)]\nfn f() {}\n"),
        ),
        (
            "expect",
            added("src/lib.rs", "#[expect(unused)]\nfn f() {}\n"),
        ),
        (
            "cfg_attr allow",
            added("src/lib.rs", "#![cfg_attr(not(test), allow(unused))]\n"),
        ),
        (
            "an allow in a module file",
            added("src/inner/mod.rs", "#![allow(clippy::all)]\n"),
        ),
        (
            "a lint table entry new at allow",
            modified(
                "Cargo.toml",
                "[lints.rust]\nunsafe_code = \"forbid\"\n",
                "[lints.rust]\nunsafe_code = \"forbid\"\nunused = \"allow\"\n",
            ),
        ),
        (
            "a deny that is gone",
            modified("src/lib.rs", "#![deny(warnings)]\n", "\n"),
        ),
        (
            "rustflags in a cargo config",
            added(
                ".cargo/config.toml",
                "[build]\nrustflags = [\"-A\", \"warnings\"]\n",
            ),
        ),
        (
            "a cargo config without the extension",
            added(
                ".cargo/config",
                "[build]\nrustflags = [\"-A\", \"warnings\"]\n",
            ),
        ),
        (
            "a target table rustflags",
            added(
                ".cargo/config.toml",
                "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-A\", \"warnings\"]\n",
            ),
        ),
        (
            "a clippy threshold",
            modified("clippy.toml", "a = 1\n", "a = 99\n"),
        ),
        (
            "the workspace lints no longer inherited",
            modified(
                "crates/x/Cargo.toml",
                "[lints]\nworkspace = true\n",
                "[package]\nname = \"x\"\n",
            ),
        ),
    ];
    let missed = unreported(&cases);
    assert!(missed.is_empty(), "not reported: {missed:?}");
}

/// RR-11 (fixed). The attribute reader works on single lines that begin with `#[` or `#![` and look for the
/// text `allow(`. Rust reads attributes as tokens: white space may stand between `#` and `[`, between
/// the name and its parenthesis, and across lines; and an attribute may follow code on the same line,
/// which is how a macro body or a one-line item is written. Each of these relaxes a lint and none is
/// reported.
#[test]
fn rr_11_an_allow_attribute_is_found_whatever_its_spacing() {
    let cases = [
        (
            "space before the parenthesis",
            added("src/lib.rs", "#![allow (warnings)]\nfn f() {}\n"),
        ),
        (
            "space between the hash and the bracket",
            added("src/lib.rs", "# ![allow(warnings)]\nfn f() {}\n"),
        ),
        (
            "the name on the next line",
            added("src/lib.rs", "#![\n    allow(warnings)\n]\nfn f() {}\n"),
        ),
        (
            "the attribute after code on the line",
            added("src/lib.rs", "fn a() {} #[allow(dead_code)] fn b() {}\n"),
        ),
        (
            "inside a macro body",
            added(
                "src/lib.rs",
                "macro_rules! quiet { () => { #[allow(dead_code)] fn hidden() {} }; }\nquiet!();\n",
            ),
        ),
        (
            "after a statement in a function",
            added(
                "src/lib.rs",
                "fn f() { let a = 1; #[allow(unused_variables)] let b = 2; }\n",
            ),
        ),
    ];
    let missed = unreported(&cases);
    assert!(missed.is_empty(), "not reported: {missed:?}");
}

/// RR-12 (fixed). A lint level is lowered without an `allow` and without a `deny` line going away. The rule
/// counts the lines that hold a `deny` or a `forbid`, so a list that loses a name, and a `forbid`
/// that becomes a `deny` (which an inner `allow` can then override in a later change), keep the count.
#[test]
fn rr_12_a_lowered_level_is_found_when_the_line_stays() {
    let cases = [
        (
            "a lint dropped from a deny list",
            modified(
                "src/lib.rs",
                "#![deny(clippy::unwrap_used, clippy::panic)]\n",
                "#![deny(clippy::panic)]\n",
            ),
        ),
        (
            "forbid becomes deny",
            modified(
                "src/lib.rs",
                "#![forbid(unsafe_code)]\n",
                "#![deny(unsafe_code)]\n",
            ),
        ),
        (
            "deny becomes warn on the same line count",
            modified(
                "src/lib.rs",
                "#![deny(warnings)]\n#![deny(missing_docs)]\n",
                "#![warn(warnings)]\n#![deny(missing_docs)]\n#![deny(unused)]\n",
            ),
        ),
    ];
    let missed = unreported(&cases);
    assert!(missed.is_empty(), "not reported: {missed:?}");
}

/// RR-13 (fixed). The reader of `Cargo.toml` finds a lint table by the exact text of its header and its
/// level by the double-quoted word. TOML allows white space around the dots of a header, a dotted
/// key at the top of the file, a single-quoted string and a quoted key. Cargo reads all of them.
#[test]
fn rr_13_a_lint_level_written_in_other_toml_spellings_is_found() {
    let base = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[lints.rust]\nunused = \"deny\"\n";
    let cases = [
        (
            "spaces around the dot of the header",
            modified(
                "Cargo.toml",
                base,
                &format!("{base}\n[lints . clippy]\nall = \"allow\"\n"),
            ),
        ),
        (
            "a single-quoted level on a new entry",
            modified("Cargo.toml", base, &format!("{base}dead_code = 'allow'\n")),
        ),
        (
            "a dotted key at the top of the file",
            modified(
                "Cargo.toml",
                base,
                &format!("lints.rust.dead_code = \"allow\"\n{base}"),
            ),
        ),
        (
            "a quoted table name",
            modified(
                "Cargo.toml",
                base,
                &format!("{base}\n[\"lints\".clippy]\nall = \"allow\"\n"),
            ),
        ),
        (
            "a second lint added to an inline table that already has a deny",
            modified(
                "Cargo.toml",
                "[lints]\nrust = { unused = \"deny\" }\n",
                "[lints]\nrust = { unused = \"deny\", dead_code = \"allow\" }\n",
            ),
        ),
    ];
    let missed = unreported(&cases);
    assert!(missed.is_empty(), "not reported: {missed:?}");
}
