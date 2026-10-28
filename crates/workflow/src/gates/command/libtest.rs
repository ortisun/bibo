//! Reading the output of `cargo test` (the Rust test harness, libtest).
//!
//! The supervisor stored the two streams of the command, redacted. This module reads them to
//! learn which tests ran and how each ended. It is deliberately suspicious, because test code can
//! print what it likes:
//!
//! * **Two streams, one story.** Cargo names each test binary on standard error (`Running
//!   tests/it.rs (...)`, `Doc-tests name`), and libtest prints the results on standard output.
//!   The k-th binary named on standard error owns the k-th `running N tests` section on standard
//!   output. A different number of names and sections makes the reading inconsistent.
//! * A test line counts only at the start of a line and outside the captured output of a failed
//!   test (`---- name stdout ----` until `failures:`).
//! * Each section is announced by `running N tests`, holds exactly N test lines and ends with
//!   exactly one `test result:` line whose three counts equal the lines read. A section that
//!   breaks any of these makes the whole reading [inconsistent](Outcomes::is_consistent), and a
//!   gate that cannot trust its output is `BLOCKED`.
//! * A test is named by the binary it ran in and its own name, so the same name in two binaries
//!   is two tests.
//!
//! None of this makes the reading proof against a test that takes over the output device and
//! writes a whole, coherent report before it exits with code 0 (the validation stage documents
//! this under "What this does not defend against"). It does reject a forged line, a forged
//! summary and a count that does not add up.

use std::collections::BTreeMap;

/// How a test ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// The test ran and passed.
    Passed,
    /// The test ran and failed.
    Failed,
    /// The test was marked `#[ignore]` and did not run.
    Ignored,
}

/// What the output says about the tests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcomes {
    results: BTreeMap<String, Status>,
    consistent: bool,
}

#[derive(Debug, Default)]
struct Section {
    label: String,
    announced: usize,
    passed: usize,
    failed: usize,
    ignored: usize,
    summaries: Vec<(usize, usize, usize)>,
}

impl Section {
    fn lines(&self) -> usize {
        self.passed + self.failed + self.ignored
    }

    /// True when the section is what libtest prints.
    fn is_coherent(&self) -> bool {
        let summary_matches = match self.summaries.as_slice() {
            [(passed, failed, ignored)] => {
                *passed == self.passed && *failed == self.failed && *ignored == self.ignored
            }
            _ => false,
        };
        self.announced == self.lines() && summary_matches
    }

    fn count(&mut self, status: Status) {
        match status {
            Status::Passed => self.passed += 1,
            Status::Failed => self.failed += 1,
            Status::Ignored => self.ignored += 1,
        }
    }
}

/// The binaries cargo names on its standard error, in order.
fn binaries(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            if let Some(rest) = line.strip_prefix("Running ") {
                Some(rest.split(" (").next().unwrap_or(rest).trim().to_owned())
            } else {
                line.strip_prefix("Doc-tests ")
                    .map(|rest| format!("doc-tests {}", rest.trim()))
            }
        })
        .collect()
}

impl Outcomes {
    /// Reads the two streams of a test command.
    #[must_use]
    pub fn parse(stdout: &str, stderr: &str) -> Self {
        let labels = binaries(stderr);
        let mut results = BTreeMap::new();
        let mut consistent = true;
        let mut sections = 0usize;
        let mut current: Option<Section> = None;
        let mut capturing = false;

        for line in stdout.lines() {
            if let Some(count) = line.strip_prefix("running ").and_then(announced_count)
                && !capturing
            {
                if let Some(done) = current.take() {
                    consistent &= done.is_coherent();
                }
                let label = labels.get(sections).cloned().unwrap_or_else(|| {
                    consistent = false;
                    format!("binary-{sections}")
                });
                sections += 1;
                current = Some(Section {
                    label,
                    announced: count,
                    ..Section::default()
                });
            } else if line.starts_with("---- ") && line.ends_with(" stdout ----") {
                capturing = true;
            } else if line == "failures:" {
                capturing = false;
            } else if capturing {
                // The captured output of a failed test is the test's own text.
            } else if let Some(rest) = line.strip_prefix("test result: ") {
                match current.as_mut() {
                    Some(section) => section.summaries.push(summary_counts(rest)),
                    None => consistent = false,
                }
            } else if let Some(rest) = line.strip_prefix("test ")
                && let Some((name, outcome)) = rest.rsplit_once(" ... ")
            {
                let status = if outcome == "ok" {
                    Status::Passed
                } else if outcome == "FAILED" {
                    Status::Failed
                } else if outcome.starts_with("ignored") {
                    Status::Ignored
                } else {
                    continue;
                };
                let Some(section) = current.as_mut() else {
                    consistent = false;
                    continue;
                };
                section.count(status);
                let id = format!("{}::{}", section.label, name.trim());
                if results.insert(id, status).is_some() {
                    consistent = false;
                }
            }
        }
        if let Some(done) = current.take() {
            consistent &= done.is_coherent();
        }
        consistent &= sections == labels.len();
        Self {
            results,
            consistent,
        }
    }

    /// True when both streams are what libtest and cargo print. An output that is not consistent
    /// proves nothing.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.consistent
    }

    /// Every test, by identifier, with how it ended.
    #[must_use]
    pub fn results(&self) -> &BTreeMap<String, Status> {
        &self.results
    }

    /// How many tests ended with this status.
    #[must_use]
    pub fn count(&self, status: Status) -> usize {
        self.results.values().filter(|s| **s == status).count()
    }

    /// The identifiers of the tests that ended with this status, in order.
    #[must_use]
    pub fn ids(&self, status: Status) -> Vec<&str> {
        self.results
            .iter()
            .filter(|(_, s)| **s == status)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// True when at least one test ran to a result. A run in which every test is ignored, or in
    /// which none exists, has shown nothing.
    #[must_use]
    pub fn ran_something(&self) -> bool {
        self.count(Status::Passed) + self.count(Status::Failed) > 0
    }
}

/// `2 tests` or `1 test` after `running `.
fn announced_count(rest: &str) -> Option<usize> {
    let (number, noun) = rest.split_once(' ')?;
    if noun != "tests" && noun != "test" {
        return None;
    }
    number.parse().ok()
}

/// `ok. 1 passed; 0 failed; 1 ignored; ...` after `test result: `. A count that is missing reads
/// as the largest number, which no section can match.
fn summary_counts(rest: &str) -> (usize, usize, usize) {
    let count_of = |word: &str| -> usize {
        rest.split(';')
            .filter_map(|part| {
                let part = part.trim();
                let part = part.rsplit_once(". ").map_or(part, |(_, tail)| tail);
                let (number, name) = part.split_once(' ')?;
                (name.trim() == word).then(|| number.parse().ok()).flatten()
            })
            .next()
            .unwrap_or(usize::MAX)
    };
    (count_of("passed"), count_of("failed"), count_of("ignored"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from the pinned verify image on a two-binary fixture crate with one failing
    /// test and one ignored test.
    const FAILING_OUT: &str =
        include_str!("../../../tests/validation/fixtures/cargo_test_failing.stdout");
    const FAILING_ERR: &str =
        include_str!("../../../tests/validation/fixtures/cargo_test_failing.stderr");
    const PASSING_OUT: &str =
        include_str!("../../../tests/validation/fixtures/cargo_test_passing.stdout");
    const PASSING_ERR: &str =
        include_str!("../../../tests/validation/fixtures/cargo_test_passing.stderr");

    #[test]
    fn the_recorded_output_of_the_pinned_image_is_read() {
        let out = Outcomes::parse(FAILING_OUT, FAILING_ERR);
        assert!(out.is_consistent());
        assert_eq!(
            out.results()
                .get("unittests src/lib.rs::tests::counts_words"),
            Some(&Status::Passed)
        );
        assert_eq!(
            out.results().get("unittests src/lib.rs::tests::slow_one"),
            Some(&Status::Ignored)
        );
        assert_eq!(
            out.results().get("tests/it.rs::fr_002_failing_case"),
            Some(&Status::Failed)
        );
        assert_eq!(out.count(Status::Passed), 2);
        assert!(out.ran_something());
    }

    #[test]
    fn a_passing_run_with_doc_tests_is_consistent_and_has_no_failure() {
        let out = Outcomes::parse(PASSING_OUT, PASSING_ERR);
        assert!(out.is_consistent());
        assert_eq!(out.count(Status::Failed), 0);
        assert_eq!(out.count(Status::Passed), 3);
    }

    #[test]
    fn a_forged_line_in_the_captured_output_of_a_failed_test_is_not_read() {
        let forged = FAILING_OUT.replace(
            "assertion `left == right` failed",
            "test fr_999_forged ... ok\ntest result: ok. 99 passed; 0 failed; 0 ignored",
        );
        let out = Outcomes::parse(&forged, FAILING_ERR);
        assert!(out.is_consistent(), "captured text is skipped");
        assert!(!out.results().keys().any(|id| id.contains("forged")));
    }

    #[test]
    fn a_forged_line_outside_the_captured_block_makes_the_output_inconsistent() {
        let forged = PASSING_OUT.replacen(
            "test result: ok.",
            "test tests::forged ... ok\ntest result: ok.",
            1,
        );
        assert!(!Outcomes::parse(&forged, PASSING_ERR).is_consistent());
    }

    #[test]
    fn a_second_summary_makes_the_output_inconsistent() {
        let forged = format!("{PASSING_OUT}\ntest result: ok. 99 passed; 0 failed; 0 ignored\n");
        assert!(!Outcomes::parse(&forged, PASSING_ERR).is_consistent());
    }

    #[test]
    fn a_summary_that_disagrees_with_the_lines_makes_the_output_inconsistent() {
        let forged = PASSING_OUT.replacen("1 passed", "7 passed", 1);
        assert!(!Outcomes::parse(&forged, PASSING_ERR).is_consistent());
    }

    #[test]
    fn a_different_number_of_named_binaries_and_sections_is_inconsistent() {
        let one_less = "    Finished `test` profile\n     Running tests/it.rs (x)\n";
        assert!(!Outcomes::parse(PASSING_OUT, one_less).is_consistent());
    }

    #[test]
    fn an_indented_line_is_not_a_test_line() {
        let out = "running 1 test\n  test a ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n";
        let parsed = Outcomes::parse(out, "     Running tests/it.rs (x)\n");
        assert!(!parsed.is_consistent());
        assert!(parsed.results().is_empty());
    }

    #[test]
    fn output_with_no_test_shows_nothing_ran() {
        let out = Outcomes::parse("", "   Compiling x v0.1.0\n    Finished `test` profile\n");
        assert!(out.is_consistent());
        assert!(!out.ran_something());
        let ignored =
            "running 1 test\ntest a ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored\n";
        assert!(!Outcomes::parse(ignored, "     Running tests/it.rs (x)\n").ran_something());
    }

    #[test]
    fn the_same_name_in_two_binaries_is_two_tests() {
        let out = "running 1 test\ntest t ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n\nrunning 1 test\ntest t ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n";
        let err = "     Running unittests src/lib.rs (a)\n     Running tests/it.rs (b)\n";
        let parsed = Outcomes::parse(out, err);
        assert!(parsed.is_consistent());
        assert_eq!(parsed.results().len(), 2);
    }

    #[test]
    fn a_test_line_before_any_section_is_inconsistent() {
        assert!(!Outcomes::parse("test a ... ok\n", "").is_consistent());
    }
}
