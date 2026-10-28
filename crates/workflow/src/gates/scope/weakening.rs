//! Tests that were weakened inside a file, which no path rule can see.
//!
//! The path rules protect test files by name. Rust keeps unit tests inside the source files, and
//! any language lets a builder add a marker that stops a test from running. This module reads the
//! new lines of every changed file (the lines the base version did not hold) and the counts of
//! test markers and assertions, and names:
//!
//! * a new line that skips, ignores, focuses or expects the failure of a test, across the
//!   supported frameworks (`#[ignore]`, `@pytest.mark.skip` and `xfail`, `test.skip`, `it.only`,
//!   `t.Skip`, `@Disabled`);
//! * a new line in a `Cargo.toml` that turns the test harness off (`harness = false`), which
//!   lets a test target print any result it likes;
//! * a file with tests whose number of test markers fell (a removed test), and one whose number
//!   of assertions fell (a weakened test).
//!
//! The set of tests that ran is compared with the baseline run elsewhere, and that is the
//! complete check for a removed test. These rules catch the change at the source, where the
//! message can name the file and the line.

use super::Violation;
use super::diff::FileChange;
use super::lines;

/// A line that stops a test from running, with the check it belongs to.
fn marker(line: &str) -> Option<&'static str> {
    let text = line.trim();
    let comment = text.starts_with("//") || (text.starts_with('#') && !text.starts_with("#["));
    if comment {
        return None;
    }
    if text.contains("#[ignore") {
        return Some("test-ignored");
    }
    const SKIPS: [&str; 12] = [
        "@pytest.mark.skip",
        "@pytest.mark.xfail",
        "pytest.skip(",
        "pytest.xfail(",
        "@unittest.skip",
        "test.skip(",
        "it.skip(",
        "describe.skip(",
        "t.Skip(",
        "t.SkipNow(",
        "@Disabled",
        "@Ignore",
    ];
    if SKIPS.iter().any(|skip| text.contains(skip))
        || ["xit(", "xdescribe(", "xtest("]
            .iter()
            .any(|skip| text.starts_with(skip))
    {
        return Some("test-skipped");
    }
    if [".only(", "fit(", "fdescribe("]
        .iter()
        .any(|focus| text.contains(focus) && (focus.starts_with('.') || text.starts_with(focus)))
    {
        return Some("test-focused");
    }
    None
}

/// True for a line of a `Cargo.toml` that turns the harness off.
fn disables_harness(line: &str) -> bool {
    let text = line.trim();
    let mut parts = text.splitn(2, '=');
    let (key, value) = (parts.next().map(str::trim), parts.next().map(str::trim));
    key == Some("harness") && value.is_some_and(|value| value.starts_with("false"))
}

/// A line that marks a test (a Rust test attribute or a Python test function).
fn is_test_marker(line: &str) -> bool {
    let text = line.trim_start();
    text.starts_with("#[test")
        || text.starts_with("#[tokio::test")
        || text.starts_with("#[rstest")
        || text.starts_with("def test_")
        || text.starts_with("async def test_")
}

fn count_lines(data: &[u8], keep: impl Fn(&str) -> bool) -> usize {
    lines::split(data)
        .into_iter()
        .filter(|line| keep(&String::from_utf8_lossy(line)))
        .count()
}

/// What the new lines and the counts of the changed files say about weakened tests.
#[must_use]
pub fn weakened(files: &[FileChange]) -> Vec<Violation> {
    let mut found = Vec::new();
    for file in files {
        let Some(after) = &file.after else {
            continue;
        };
        let before = file.before_or_empty();
        let is_cargo_manifest = file.path == "Cargo.toml" || file.path.ends_with("/Cargo.toml");
        for (number, raw) in lines::added(before, after) {
            let line = String::from_utf8_lossy(raw);
            if let Some(check) = marker(&line) {
                found.push(Violation {
                    check,
                    message: format!(
                        "The path {} gains a line that stops a test from counting, at line {number}.",
                        file.path
                    ),
                    path: Some(file.path.clone()),
                    line: Some(number),
                });
            }
            if is_cargo_manifest && disables_harness(&line) {
                found.push(Violation {
                    check: "test-harness-disabled",
                    message: format!(
                        "The path {} turns the test harness off, at line {number}, so a test target could print any result.",
                        file.path
                    ),
                    path: Some(file.path.clone()),
                    line: Some(number),
                });
            }
        }
        if file.before.is_some() && count_lines(before, is_test_marker) > 0 {
            if count_lines(after, is_test_marker) < count_lines(before, is_test_marker) {
                found.push(Violation {
                    check: "test-removed",
                    message: format!(
                        "The path {} holds fewer tests than it did before.",
                        file.path
                    ),
                    path: Some(file.path.clone()),
                    line: None,
                });
            }
            let asserts = |line: &str| line.contains("assert");
            if count_lines(after, asserts) < count_lines(before, asserts) {
                found.push(Violation {
                    check: "assertion-count-drop",
                    message: format!(
                        "The path {} holds fewer assertions than it did before.",
                        file.path
                    ),
                    path: Some(file.path.clone()),
                    line: None,
                });
            }
        }
    }
    found
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

    fn checks(files: &[FileChange]) -> Vec<&'static str> {
        weakened(files).iter().map(|v| v.check).collect()
    }

    #[test]
    fn each_supported_framework_marker_is_found_on_a_new_line() {
        let cases = [
            (
                "src/lib.rs",
                "#[test]\n#[ignore]\nfn a() {}\n",
                "test-ignored",
            ),
            ("src/lib.rs", "#[ignore = \"flaky\"]\n", "test-ignored"),
            (
                "t.py",
                "@pytest.mark.skip(reason='x')\ndef test_a(): pass\n",
                "test-skipped",
            ),
            ("t.py", "@pytest.mark.xfail\n", "test-skipped"),
            ("t.test.js", "test.skip('a', () => {})\n", "test-skipped"),
            ("t.test.js", "it.skip('a', () => {})\n", "test-skipped"),
            ("t.test.js", "xit('a', () => {})\n", "test-skipped"),
            ("t.test.js", "it.only('a', () => {})\n", "test-focused"),
            (
                "a_test.go",
                "func TestA(t *testing.T) {\n\tt.Skip(\"later\")\n}\n",
                "test-skipped",
            ),
            ("A.java", "@Disabled\n", "test-skipped"),
        ];
        for (path, after, expected) in cases {
            let found = checks(&[modified(path, "", after)]);
            assert!(
                found.contains(&expected),
                "{path}: {after:?} gave {found:?}"
            );
        }
    }

    #[test]
    fn a_marker_that_was_already_there_is_not_new() {
        let text = "#[test]\n#[ignore]\nfn slow() {}\n";
        assert!(checks(&[modified("src/lib.rs", text, &format!("{text}// more\n"))]).is_empty());
    }

    #[test]
    fn a_comment_that_mentions_a_marker_is_not_a_marker() {
        assert!(
            checks(&[modified(
                "a.rs",
                "",
                "// do not #[ignore] this\n# @pytest.mark.skip\n"
            )])
            .is_empty()
        );
    }

    #[test]
    fn a_harness_switched_off_in_a_cargo_manifest_is_found() {
        let after = "[package]\nname = \"x\"\n[[test]]\nname = \"it\"\nharness = false\n";
        let found = checks(&[modified("Cargo.toml", "[package]\nname = \"x\"\n", after)]);
        assert_eq!(found, vec!["test-harness-disabled"]);
        assert!(checks(&[modified("notes.md", "", "harness = false\n")]).is_empty());
    }

    #[test]
    fn a_removed_test_and_a_dropped_assertion_in_a_source_file_are_found() {
        let before = "fn f() {}\n#[cfg(test)]\nmod t {\n#[test]\nfn a() { assert_eq!(1, 1); }\n#[test]\nfn b() { assert!(true); }\n}\n";
        let removed =
            "fn f() {}\n#[cfg(test)]\nmod t {\n#[test]\nfn a() { assert_eq!(1, 1); }\n}\n";
        assert_eq!(
            checks(&[modified("src/lib.rs", before, removed)]),
            vec!["test-removed", "assertion-count-drop"]
        );
        let weakened = before.replace("assert_eq!(1, 1);", "let _ = 1;");
        assert_eq!(
            checks(&[modified("src/lib.rs", before, &weakened)]),
            vec!["assertion-count-drop"]
        );
    }

    #[test]
    fn a_file_with_no_tests_may_lose_assertions() {
        assert!(checks(&[modified("src/lib.rs", "assert!(x);\n", "")]).is_empty());
    }

    #[test]
    fn an_added_test_is_fine() {
        let before = "#[test]\nfn a() { assert!(true); }\n";
        let after = format!("{before}#[test]\nfn b() {{ assert!(true); }}\n");
        assert!(checks(&[modified("tests/it.rs", before, &after)]).is_empty());
    }
}
