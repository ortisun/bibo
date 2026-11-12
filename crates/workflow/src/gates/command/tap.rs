//! Reading a Test Anything Protocol report, version 13 or 14.
//!
//! ```text
//! TAP version 14
//! 1..3
//! ok 1 - fr_001 counts a line
//! not ok 2 - counts nothing
//!   ---
//!   message: expected 0, got 1
//!   ...
//! ok 3 - reads a large file # SKIP needs a large file
//! ```
//!
//! | The line | The test |
//! |---|---|
//! | `ok` | passed |
//! | `not ok` | failed |
//! | `ok` or `not ok` with the directive `# SKIP` | skipped |
//! | `not ok` with the directive `# TODO` | skipped: the protocol says such a test is expected to fail and is not a failure, and the factory does not count it as a test that ran |
//! | `ok` with the directive `# TODO` | passed |
//!
//! The report is untrusted input, and test code can print lines of its own into it. Like the
//! libtest reading, this one counts only what adds up, and a report that does not add up makes
//! the gate `BLOCKED`:
//!
//! * A line counts only when it starts in the first column. An indented line belongs to a
//!   subtest or to a diagnostic block and is skipped, so only the top-level tests are read.
//! * There must be exactly one plan (`1..N`), before the first test line or after the last, and
//!   exactly N test lines. A test line that carries a number must carry its own position.
//! * `Bail out!` means the run stopped early, and the report is refused.
//! * A version line, when there is one, must come before the plan and before every test line,
//!   only once, and must say 13 or 14. Text before it is skipped, because a tool that starts
//!   the test runner (`npm test`, for example) prints lines of its own first.
//! * Two tests with the same description are refused, because the comparison with the base
//!   commit matches tests by name. A test line without a description is named `test <number>`.
//! * At most [`MAX_BYTES`] of text and [`MAX_CASES`] test lines.
//!
//! Every other line that starts in the first column (a comment, a pragma, text that a tool
//! printed) is skipped, as the protocol asks.

use std::collections::BTreeMap;

use super::outcomes::{Outcomes, Status};

/// The largest report that is read, in bytes.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// The most test lines one report may hold.
pub const MAX_CASES: usize = 100_000;
/// The longest description of a test, in bytes.
const MAX_NAME_BYTES: usize = 1024;

/// Why a report is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// The report is longer than [`MAX_BYTES`].
    TooLarge,
    /// The report lists more than [`MAX_CASES`] tests.
    TooManyCases,
    /// The version line comes after a plan or a test line, appears twice, or names a version
    /// other than 13 and 14.
    Version,
    /// There is no plan, more than one, a plan between test lines, or a plan that cannot be read.
    Plan,
    /// The number of test lines is not the number the plan announces, or a test line carries a
    /// number that is not its position.
    Count,
    /// The run bailed out.
    BailOut,
    /// A description is too long.
    Unnamed,
    /// Two tests have the same description.
    Duplicate,
}

impl Problem {
    /// The reason as a plain sentence, for the gate report.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::TooLarge => {
                "The TAP report is larger than the factory reads, so it is not accepted as evidence."
            }
            Self::TooManyCases => {
                "The TAP report lists more tests than the factory reads, so it is not accepted as evidence."
            }
            Self::Version => {
                "The TAP report has a version line that follows a plan or a test line, that appears twice, or that names a version other than 13 and 14, so it is not accepted as evidence."
            }
            Self::Plan => {
                "The TAP report has no plan line, more than one, or one that cannot be read, so the gate cannot tell whether the report is whole and it is not accepted as evidence."
            }
            Self::Count => {
                "The test lines of the TAP report disagree with its plan or with their own numbers, so it is not accepted as evidence."
            }
            Self::BailOut => {
                "The TAP report says that the test run bailed out, so it is not accepted as evidence."
            }
            Self::Unnamed => {
                "The TAP report holds a test with a description that is too long, so it is not accepted as evidence."
            }
            Self::Duplicate => {
                "The TAP report lists two tests with the same description, so its tests cannot be told apart and it is not accepted as evidence."
            }
        }
    }
}

/// Reads a TAP report. A report that is refused is not consistent and says why.
#[must_use]
pub fn read(text: &str) -> Outcomes {
    match parse(text) {
        Ok(results) => Outcomes::trusted(results),
        Err(problem) => Outcomes::untrusted(BTreeMap::new(), problem.sentence()),
    }
}

/// The rest of a test line after `ok` or `not ok`, when the line is a test line.
fn test_line(line: &str) -> Option<(bool, &str)> {
    let (passed, rest) = match line.strip_prefix("not ok") {
        Some(rest) => (false, rest),
        None => (true, line.strip_prefix("ok")?),
    };
    (rest.is_empty() || rest.starts_with([' ', '\t'])).then_some((passed, rest))
}

/// What a test line says after its status: the number, the description and the directive.
struct Described<'a> {
    number: Option<usize>,
    description: &'a str,
    skip: bool,
    todo: bool,
}

fn describe(rest: &str) -> Described<'_> {
    let rest = rest.trim();
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let after_digits = &rest[digits..];
    let (number, rest) =
        if digits > 0 && (after_digits.is_empty() || after_digits.starts_with([' ', '\t'])) {
            // A number too large to hold reads as one that no position equals.
            (
                Some(rest[..digits].parse().unwrap_or(usize::MAX)),
                after_digits,
            )
        } else {
            (None, rest)
        };
    // A directive starts at a `#` that follows white space and is not escaped.
    let mut description = rest;
    let (mut skip, mut todo) = (false, false);
    for (at, _) in rest.match_indices('#') {
        let before = &rest[..at];
        let escaped = before.ends_with('\\');
        let after_space = before.is_empty() || before.ends_with([' ', '\t']);
        if escaped || !after_space {
            continue;
        }
        let word = rest[at + 1..].trim_start().to_ascii_lowercase();
        if word.starts_with("skip") {
            skip = true;
        } else if word.starts_with("todo") {
            todo = true;
        } else {
            continue;
        }
        description = before;
        break;
    }
    let description = description.trim();
    let description = description
        .strip_prefix('-')
        .map_or(description, str::trim_start);
    Described {
        number,
        description,
        skip,
        todo,
    }
}

/// The number a plan line announces. `rest` follows `1..`.
fn planned(rest: &str) -> Result<usize, Problem> {
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let tail = rest[digits..].trim_start();
    if digits == 0 || !(tail.is_empty() || tail.starts_with('#')) {
        return Err(Problem::Plan);
    }
    rest[..digits].parse().map_err(|_| Problem::Plan)
}

/// Reads a TAP report into the tests it lists.
///
/// # Errors
/// The [`Problem`] that makes the report refused.
pub fn parse(text: &str) -> Result<BTreeMap<String, Status>, Problem> {
    if text.len() > MAX_BYTES {
        return Err(Problem::TooLarge);
    }
    let mut results = BTreeMap::new();
    let mut plan: Option<usize> = None;
    let mut plan_after_tests = false;
    let mut tests = 0usize;
    let mut version_seen = false;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(version) = line.strip_prefix("TAP version ") {
            let misplaced = version_seen || plan.is_some() || tests > 0;
            if misplaced || !matches!(version.trim(), "13" | "14") {
                return Err(Problem::Version);
            }
            version_seen = true;
        } else if line.starts_with("Bail out!") {
            return Err(Problem::BailOut);
        } else if let Some(rest) = line.strip_prefix("1..") {
            if plan.is_some() {
                return Err(Problem::Plan);
            }
            plan = Some(planned(rest)?);
            plan_after_tests = tests > 0;
        } else if let Some((passed, rest)) = test_line(line) {
            if plan_after_tests {
                return Err(Problem::Plan);
            }
            tests += 1;
            if tests > MAX_CASES {
                return Err(Problem::TooManyCases);
            }
            let said = describe(rest);
            if said.number.is_some_and(|number| number != tests) {
                return Err(Problem::Count);
            }
            let status = match (passed, said.skip, said.todo) {
                (_, true, _) | (false, _, true) => Status::Ignored,
                (true, false, _) => Status::Passed,
                (false, false, false) => Status::Failed,
            };
            let name = if said.description.is_empty() {
                format!("test {tests}")
            } else {
                said.description
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect()
            };
            if name.len() > MAX_NAME_BYTES {
                return Err(Problem::Unnamed);
            }
            if results.insert(name, status).is_some() {
                return Err(Problem::Duplicate);
            }
        }
    }
    match plan {
        None => Err(Problem::Plan),
        Some(planned) if planned != tests => Err(Problem::Count),
        Some(_) => Ok(results),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn counts(text: &str) -> (usize, usize, usize) {
        let out = read(text);
        assert!(out.is_consistent(), "{:?}", out.problem());
        (
            out.count(Status::Passed),
            out.count(Status::Failed),
            out.count(Status::Ignored),
        )
    }

    fn problem(text: &str) -> Problem {
        parse(text).expect_err("the report is refused")
    }

    /// Hand-written in the shape that `node --test --test-reporter=tap` prints. NOT recorded
    /// from the tool.
    const NODE_SHAPED: &str = "TAP version 13\n# Subtest: fr_001 counts a line\nok 1 - fr_001 counts a line\n  ---\n  duration_ms: 0.412\n  ...\n# Subtest: counts nothing\nnot ok 2 - counts nothing\n  ---\n  duration_ms: 0.91\n  failureType: 'testCodeFailure'\n  error: |-\n    Expected values to be strictly equal:\n    1 !== 0\n  code: 'ERR_ASSERTION'\n  ...\n# Subtest: reads a large file\nok 3 - reads a large file # SKIP needs a large file\n  ---\n  duration_ms: 0.05\n  ...\n1..3\n# tests 3\n# pass 1\n# fail 1\n# skipped 1\n";

    #[test]
    fn a_report_in_the_shape_of_the_node_test_runner_is_read() {
        let out = read(NODE_SHAPED);
        assert!(out.is_consistent());
        assert_eq!(
            out.results().get("fr_001 counts a line"),
            Some(&Status::Passed)
        );
        assert_eq!(out.results().get("counts nothing"), Some(&Status::Failed));
        assert_eq!(
            out.results().get("reads a large file"),
            Some(&Status::Ignored)
        );
    }

    #[test]
    fn the_plan_may_come_first_and_numbers_and_descriptions_are_optional() {
        assert_eq!(counts("1..3\nok\nnot ok\nok 3\n"), (2, 1, 0));
        let out = read("1..2\nok\nok 2 second\n");
        assert_eq!(out.ids(Status::Passed), ["second", "test 1"]);
    }

    #[test]
    fn a_todo_test_that_fails_is_skipped_and_one_that_passes_is_passed() {
        assert_eq!(
            counts(
                "1..3\nnot ok 1 - a # TODO not written yet\nok 2 - b # todo bonus\nok 3 - c # Skipped: no network\n"
            ),
            (1, 0, 2)
        );
    }

    #[test]
    fn a_hash_that_is_escaped_or_is_not_a_directive_stays_in_the_description() {
        let out = read("1..2\nok 1 - issue \\#12 is fixed\nok 2 - counts # of words\n");
        assert_eq!(
            out.ids(Status::Passed),
            ["counts # of words", "issue \\#12 is fixed"]
        );
    }

    #[test]
    fn indented_lines_are_not_tests() {
        assert_eq!(
            counts(
                "TAP version 14\n1..1\n    ok 1 - inner\n    ok 2 - forged\n    1..2\nok 1 - outer\n"
            ),
            (1, 0, 0)
        );
    }

    #[test]
    fn a_report_with_no_test_shows_nothing_ran() {
        let out = read("1..0 # SKIP nothing to run\n");
        assert!(out.is_consistent());
        assert!(!out.ran_something());
        let skipped = read("1..1\nok 1 - a # SKIP\n");
        assert!(skipped.is_consistent());
        assert!(!skipped.ran_something());
    }

    #[test]
    fn a_report_without_exactly_one_readable_plan_is_refused() {
        assert_eq!(problem(""), Problem::Plan);
        assert_eq!(problem("ok 1 - a\n"), Problem::Plan);
        assert_eq!(problem("1..1\nok 1 - a\n1..1\n"), Problem::Plan);
        assert_eq!(problem("1..x\nok 1 - a\n"), Problem::Plan);
        assert_eq!(problem("1..1 tests\nok 1 - a\n"), Problem::Plan);
        assert_eq!(
            problem("ok 1 - a\n1..2\nok 2 - b\n"),
            Problem::Plan,
            "a plan between test lines"
        );
    }

    #[test]
    fn a_forged_or_missing_test_line_breaks_the_count() {
        assert_eq!(
            problem("1..2\nok 1 - a\n"),
            Problem::Count,
            "truncated: fewer lines than planned"
        );
        assert_eq!(
            problem("1..1\nok 1 - a\nok 2 - fr_001_forged\n"),
            Problem::Count
        );
        assert_eq!(
            problem("1..2\nok 1 - a\nok 1 - fr_001_forged\n"),
            Problem::Count,
            "a number that is not the position"
        );
        assert_eq!(
            problem("1..2\nok 1 - a\nok 99999999999999999999999999 - b\n"),
            Problem::Count
        );
    }

    #[test]
    fn a_bail_out_a_bad_version_and_a_repeated_description_are_refused() {
        assert_eq!(
            problem("1..2\nok 1 - a\nBail out! no database\n"),
            Problem::BailOut
        );
        assert_eq!(problem("TAP version 12\n1..1\nok 1\n"), Problem::Version);
        assert_eq!(problem("1..1\nTAP version 13\nok 1\n"), Problem::Version);
        assert_eq!(problem("ok 1\nTAP version 13\n1..1\n"), Problem::Version);
        assert_eq!(
            problem("TAP version 13\nTAP version 13\n1..1\nok 1\n"),
            Problem::Version
        );
        assert_eq!(problem("1..2\nok 1 - a\nok 2 - a\n"), Problem::Duplicate);
        let long = format!("1..1\nok 1 - {}\n", "x".repeat(MAX_NAME_BYTES + 1));
        assert_eq!(problem(&long), Problem::Unnamed);
    }

    #[test]
    fn lines_that_a_launcher_prints_before_the_version_line_are_skipped() {
        let text = "\n> word-count@1.0.0 test\n> node --test --test-reporter=tap\n\nTAP version 13\nok 1 - a\n1..1\n";
        assert_eq!(counts(text), (1, 0, 0));
    }

    #[test]
    fn a_word_that_only_starts_with_ok_is_not_a_test_line() {
        assert_eq!(counts("1..1\nokay then\nnot okay\nok 1 - a\n"), (1, 0, 0));
    }

    fn tap_piece() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("ok".to_owned()),
            Just("not ok".to_owned()),
            Just("1..".to_owned()),
            Just("TAP version 13".to_owned()),
            Just("Bail out!".to_owned()),
            Just(" # SKIP".to_owned()),
            Just(" # TODO".to_owned()),
            Just("\n".to_owned()),
            Just(" ".to_owned()),
            Just("#".to_owned()),
            Just("-".to_owned()),
            "[0-9]{1,25}",
            "\\PC{0,6}",
        ]
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_make_the_reader_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let text = String::from_utf8_lossy(&bytes);
            let out = read(&text);
            prop_assert_eq!(out.is_consistent(), out.problem().is_none());
        }

        #[test]
        fn text_made_of_protocol_pieces_never_makes_the_reader_panic(pieces in proptest::collection::vec(tap_piece(), 0..40)) {
            let _ = read(&pieces.concat());
        }

        #[test]
        fn a_generated_report_reads_back_with_the_counts_it_was_made_from(
            statuses in proptest::collection::vec(0u8..4, 0..60),
            plan_first in any::<bool>(),
            numbered in any::<bool>(),
        ) {
            let mut body = String::new();
            let (mut passed, mut failed, mut ignored) = (0usize, 0usize, 0usize);
            for (index, status) in statuses.iter().enumerate() {
                let number = if numbered { format!(" {}", index + 1) } else { String::new() };
                let (word, directive) = match status {
                    0 => { passed += 1; ("ok", "") }
                    1 => { failed += 1; ("not ok", "") }
                    2 => { ignored += 1; ("ok", " # SKIP not here") }
                    _ => { ignored += 1; ("not ok", " # TODO later") }
                };
                body.push_str(&format!("{word}{number} - case {index}{directive}\n  ---\n  note: ok 99 - inner\n  ...\n"));
            }
            let plan = format!("1..{}\n", statuses.len());
            let text = if plan_first { format!("TAP version 14\n{plan}{body}") } else { format!("{body}{plan}") };
            prop_assert_eq!(counts(&text), (passed, failed, ignored));
        }
    }
}
