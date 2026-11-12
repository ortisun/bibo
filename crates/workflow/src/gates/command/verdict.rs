//! What the supervisor's observation of a command means for its gate.
//!
//! The only evidence of a command gate is what the supervisor saw: how the process ended, when,
//! and the redacted text it wrote. [`interpret`] maps that to one of three answers:
//!
//! | The supervisor saw | The gate is |
//! |---|---|
//! | Exit code 0, and for a test gate the test report shows tests that ran | `PASSED` |
//! | Another exit code from a tool that ran | `FAILED` |
//! | The tool missing (126, 127), a timeout, a signal, an out-of-memory kill, no exit code, a test report that is missing, cut, malformed, does not add up or cannot be read, or a test gate that ran no test | `BLOCKED` |
//!
//! The test report is the output of the Rust test harness by default, or a JUnit XML or TAP
//! report when the project manifest says so ([`Reading`]). The rules are the same for every
//! format, because they are applied to the one model of [`super::outcomes`]:
//!
//! | Exit code | The test report | The gate is |
//! |---|---|---|
//! | 0 | whole, adds up, at least one test ran, no failed test | `PASSED` |
//! | 0 | missing, empty, cut, malformed, or its totals disagree with its test cases | `BLOCKED` |
//! | 0 | lists no test, or only skipped tests | `BLOCKED` |
//! | 0 | lists a failed test | `BLOCKED`: the report and the exit code disagree |
//! | not 0 | any | `FAILED`, and the failed tests are named when the report can be trusted |
//!
//! `NOT_APPLICABLE` is not an answer of this function: only a rule that is recorded with its
//! inputs may say that a gate does not apply (policy `gate_integrity.missing_evidence_is`).
//! There is no path from a missing observation to `PASSED`.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_ports::sandbox::ExecResult;

use super::definition::Role;
use super::outcomes::{Outcomes, ReportKind, Status};

/// The exit code a shell and a container runtime give a program that cannot be run.
const CANNOT_EXECUTE: i32 = 126;
/// The exit code for a program that is not found.
const NOT_FOUND: i32 = 127;
/// The most failed tests named in one failure list.
const MOST_NAMED: usize = 20;

/// One check that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    /// A slug naming the check, such as `exit-code` or `test-failed`.
    pub check: &'static str,
    /// What went wrong, in a plain sentence.
    pub message: String,
}

/// Why a gate could not produce evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Why {
    /// The category the report carries.
    pub code: BlockedCode,
    /// What was absent, as the report's `missing` list names it.
    pub missing: &'static str,
    /// A plain sentence for the reason of the report.
    pub reason: &'static str,
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The command ran and showed what the gate needs.
    Passed,
    /// The command ran and its tool reported a problem.
    Failed(Vec<Fail>),
    /// The command did not give evidence.
    Blocked(Why),
}

/// The output of a command, as far as the gate could read it.
#[derive(Debug)]
pub enum Reading<'a> {
    /// Both streams were read. A test gate reads them as the output of the Rust test harness.
    Read {
        /// Standard output.
        stdout: &'a str,
        /// Standard error.
        stderr: &'a str,
    },
    /// The test report that the project manifest names was read: the standard output of the
    /// test command, or the report file that the supervisor read back after it.
    Report {
        /// The format of the report.
        kind: ReportKind,
        /// The text of the report.
        text: &'a str,
        /// True when the text was cut at the size limit.
        cut: bool,
    },
    /// The project manifest names a report file, and the supervisor could not read it back: the
    /// test command did not write it, or the command that reads it failed.
    NoReport,
    /// The artifact store could not give the output back, or it was not text.
    Unreadable,
}

impl Reading<'_> {
    /// What the test report says, when there is one to read. The result may be a report that
    /// cannot be trusted ([`Outcomes::is_consistent`]).
    #[must_use]
    pub fn outcomes(&self) -> Option<Outcomes> {
        match self {
            Self::Read { stdout, stderr } => Some(super::libtest::read(stdout, stderr)),
            Self::Report { kind, text, .. } => Some(kind.read(text)),
            Self::NoReport | Self::Unreadable => None,
        }
    }
}

/// Interprets one command of a gate.
#[must_use]
pub fn interpret(role: Role, exec: &ExecResult, reading: &Reading<'_>) -> Verdict {
    if exec.timed_out {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "completion within the time limit",
            "The command ran past its time limit and was stopped, so it gave no result.",
        );
    }
    if exec.oom_killed {
        return blocked(
            BlockedCode::EnvironmentUnsupported,
            "enough memory to finish",
            "The kernel stopped the command for using too much memory, so it gave no result.",
        );
    }
    if exec.signal.is_some() {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "a process that was not killed",
            "A signal ended the command before it could report a result.",
        );
    }
    let Some(code) = exec.exit_code else {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "an exit code",
            "The command did not end with an exit code, so it gave no result.",
        );
    };
    if code == CANNOT_EXECUTE || code == NOT_FOUND {
        return blocked(
            BlockedCode::ToolUnavailable,
            "the program of the command",
            "The program of the command is not in the verify image, so the gate could not run.",
        );
    }
    if code != 0 {
        return failed_with_exit_code(role, code, reading);
    }
    if role.expects_tests() {
        return tests_ran(exec, reading);
    }
    Verdict::Passed
}

fn blocked(code: BlockedCode, missing: &'static str, reason: &'static str) -> Verdict {
    Verdict::Blocked(Why {
        code,
        missing,
        reason,
    })
}

fn failed_with_exit_code(role: Role, code: i32, reading: &Reading<'_>) -> Verdict {
    let mut failures = vec![Fail {
        check: "exit-code",
        message: format!(
            "The command ended with exit code {code}, and the gate needs exit code 0."
        ),
    }];
    let outcomes = reading.outcomes().filter(|_| role.expects_tests());
    if let Some(outcomes) = outcomes.filter(Outcomes::is_consistent) {
        failures.extend(
            outcomes
                .ids(Status::Failed)
                .into_iter()
                .take(MOST_NAMED)
                .map(|id| Fail {
                    check: "test-failed",
                    message: format!("The test {id} failed."),
                }),
        );
    }
    Verdict::Failed(failures)
}

/// A test command that exited with code 0 passes only if its test report shows tests that ran.
fn tests_ran(exec: &ExecResult, reading: &Reading<'_>) -> Verdict {
    const UNREADABLE: &str =
        "The output of the test command could not be read, so the gate cannot show that tests ran.";
    let cut = match reading {
        Reading::Unreadable => {
            return blocked(
                BlockedCode::ToolProbeFailed,
                "readable test output",
                UNREADABLE,
            );
        }
        Reading::NoReport => {
            return blocked(
                BlockedCode::ToolProbeFailed,
                "the test report file",
                "The test report file that the project manifest names could not be read after the test command ended, so the gate cannot show that tests ran.",
            );
        }
        Reading::Read { .. } => exec.stdout_truncated || exec.stderr_truncated,
        Reading::Report { cut, .. } => *cut,
    };
    if cut {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "complete test output",
            "The output of the test command was cut at the size limit, so the gate cannot show that tests ran.",
        );
    }
    let Some(outcomes) = reading.outcomes() else {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "readable test output",
            UNREADABLE,
        );
    };
    if let Some(problem) = outcomes.problem() {
        let missing = match reading {
            Reading::Report { .. } => "a test report that can be trusted",
            _ => "test output that adds up",
        };
        return blocked(BlockedCode::ToolProbeFailed, missing, problem);
    }
    if !outcomes.ran_something() {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "at least one test that ran",
            "The test command ran no test, and a test gate with no test shows nothing.",
        );
    }
    if outcomes.count(Status::Failed) > 0 {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "test output that matches the exit code",
            "The test command exited with code 0 but its output lists a failed test, so it is not accepted as evidence.",
        );
    }
    Verdict::Passed
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::contracts::ArtifactRef;
    use factory_domain::values::{MediaType, Sha256Digest, Timestamp};

    fn exec(code: Option<i32>) -> ExecResult {
        let log = ArtifactRef {
            sha256: Sha256Digest::of(b""),
            media_type: MediaType::parse("text/plain").expect("a media type"),
            size_bytes: None,
        };
        let at = Timestamp::parse("2026-10-28T08:00:00Z").expect("a timestamp");
        ExecResult {
            exit_code: code,
            signal: None,
            timed_out: false,
            oom_killed: false,
            stdout: log.clone(),
            stderr: log,
            stdout_truncated: false,
            stderr_truncated: false,
            started_at: at,
            finished_at: at,
        }
    }

    const OUT: &str = include_str!("../../../tests/validation/fixtures/cargo_test_passing.stdout");
    const ERR: &str = include_str!("../../../tests/validation/fixtures/cargo_test_passing.stderr");

    fn read<'a>(out: &'a str, err: &'a str) -> Reading<'a> {
        Reading::Read {
            stdout: out,
            stderr: err,
        }
    }

    #[test]
    fn exit_zero_passes_a_gate_that_needs_no_tests() {
        for role in [Role::Format, Role::Lint, Role::Build, Role::Other] {
            assert_eq!(
                interpret(role, &exec(Some(0)), &Reading::Unreadable),
                Verdict::Passed
            );
        }
    }

    #[test]
    fn a_nonzero_exit_fails_and_a_missing_program_blocks() {
        assert!(matches!(
            interpret(Role::Lint, &exec(Some(1)), &Reading::Unreadable),
            Verdict::Failed(_)
        ));
        for code in [126, 127] {
            assert!(matches!(
                interpret(Role::Lint, &exec(Some(code)), &Reading::Unreadable),
                Verdict::Blocked(Why {
                    code: BlockedCode::ToolUnavailable,
                    ..
                })
            ));
        }
    }

    #[test]
    fn a_timeout_a_signal_a_memory_kill_and_no_exit_code_each_block() {
        let mut timed = exec(None);
        timed.timed_out = true;
        let mut signalled = exec(None);
        signalled.signal = Some(9);
        let mut oom = exec(None);
        oom.oom_killed = true;
        for observation in [timed, signalled, oom, exec(None)] {
            assert!(matches!(
                interpret(Role::Build, &observation, &Reading::Unreadable),
                Verdict::Blocked(_)
            ));
        }
    }

    #[test]
    fn a_timeout_blocks_even_when_an_exit_code_is_present() {
        let mut timed = exec(Some(0));
        timed.timed_out = true;
        assert!(matches!(
            interpret(Role::Build, &timed, &Reading::Unreadable),
            Verdict::Blocked(_)
        ));
    }

    #[test]
    fn a_test_gate_passes_only_with_readable_output_that_shows_tests() {
        assert_eq!(
            interpret(Role::Tests, &exec(Some(0)), &read(OUT, ERR)),
            Verdict::Passed
        );
        assert!(matches!(
            interpret(Role::Tests, &exec(Some(0)), &Reading::Unreadable),
            Verdict::Blocked(_)
        ));
        assert!(matches!(
            interpret(Role::Tests, &exec(Some(0)), &read("", "")),
            Verdict::Blocked(_)
        ));
        let mut cut = exec(Some(0));
        cut.stdout_truncated = true;
        assert!(matches!(
            interpret(Role::Tests, &cut, &read(OUT, ERR)),
            Verdict::Blocked(_)
        ));
    }

    #[test]
    fn a_test_gate_with_exit_zero_and_a_failed_test_line_is_not_accepted() {
        let failing = include_str!("../../../tests/validation/fixtures/cargo_test_failing.stdout");
        let err = include_str!("../../../tests/validation/fixtures/cargo_test_failing.stderr");
        assert!(matches!(
            interpret(Role::Tests, &exec(Some(0)), &read(failing, err)),
            Verdict::Blocked(_)
        ));
    }

    /// A JUnit report with these test cases and totals that add up.
    fn junit(cases: &[(&str, &str)]) -> String {
        let count = |child: &str| cases.iter().filter(|(_, c)| *c == child).count();
        let listed: String = cases
            .iter()
            .map(|(name, child)| {
                format!("<testcase classname=\"tests.test_wc\" name=\"{name}\">{child}</testcase>")
            })
            .collect();
        format!(
            "<testsuites><testsuite name=\"pytest\" tests=\"{}\" failures=\"{}\" errors=\"0\" skipped=\"{}\">{listed}</testsuite></testsuites>",
            cases.len(),
            count("<failure/>"),
            count("<skipped/>"),
        )
    }

    fn report(kind: ReportKind, text: &str) -> Reading<'_> {
        Reading::Report {
            kind,
            text,
            cut: false,
        }
    }

    fn blocked_for(verdict: &Verdict) -> (&'static str, &'static str) {
        match verdict {
            Verdict::Blocked(why) => (why.missing, why.reason),
            other => panic!("the gate is not blocked: {other:?}"),
        }
    }

    #[test]
    fn a_test_gate_passes_on_a_junit_report_and_on_a_tap_report_that_show_tests() {
        let xml = junit(&[("test_a", ""), ("test_b", "<skipped/>")]);
        assert_eq!(
            interpret(
                Role::Tests,
                &exec(Some(0)),
                &report(ReportKind::JunitXml, &xml)
            ),
            Verdict::Passed
        );
        assert_eq!(
            interpret(
                Role::Tests,
                &exec(Some(0)),
                &report(ReportKind::Tap, "1..2\nok 1 - a\nok 2 - b # SKIP\n")
            ),
            Verdict::Passed
        );
    }

    #[test]
    fn a_missing_report_file_blocks_a_test_gate_that_exited_with_code_zero() {
        let verdict = interpret(Role::Tests, &exec(Some(0)), &Reading::NoReport);
        assert_eq!(blocked_for(&verdict).0, "the test report file");
    }

    #[test]
    fn a_report_that_is_cut_blocks_even_when_what_is_left_reads_well() {
        let xml = junit(&[("test_a", "")]);
        let cut = Reading::Report {
            kind: ReportKind::JunitXml,
            text: &xml,
            cut: true,
        };
        let verdict = interpret(Role::Tests, &exec(Some(0)), &cut);
        assert_eq!(blocked_for(&verdict).0, "complete test output");
    }

    #[test]
    fn a_report_that_cannot_be_trusted_blocks_with_its_own_reason() {
        let whole = junit(&[("test_a", "")]);
        let wrong_totals = whole.replace("tests=\"1\"", "tests=\"9\"");
        let truncated = &whole[..whole.len() - 20];
        for (kind, text, part_of_reason) in [
            (ReportKind::JunitXml, "", "is empty"),
            (ReportKind::JunitXml, "plain text", "not well-formed"),
            (ReportKind::JunitXml, truncated, "ends before"),
            (ReportKind::JunitXml, wrong_totals.as_str(), "totals"),
            (
                ReportKind::JunitXml,
                "<!DOCTYPE x><testsuites/>",
                "document type",
            ),
            (ReportKind::Tap, "", "no plan"),
            (
                ReportKind::Tap,
                "1..2\nok 1 - a\n",
                "disagree with its plan",
            ),
            (ReportKind::Tap, "1..1\nok 1 - a\nBail out!\n", "bailed out"),
        ] {
            let verdict = interpret(Role::Tests, &exec(Some(0)), &report(kind, text));
            let (missing, reason) = blocked_for(&verdict);
            assert_eq!(missing, "a test report that can be trusted", "{text}");
            assert!(reason.contains(part_of_reason), "{text}: {reason}");
        }
    }

    #[test]
    fn a_report_with_no_test_that_ran_blocks_whatever_the_format() {
        let only_skipped = junit(&[("test_a", "<skipped/>")]);
        for reading in [
            report(ReportKind::JunitXml, "<testsuites></testsuites>"),
            report(ReportKind::JunitXml, &only_skipped),
            report(ReportKind::Tap, "1..0\n"),
            report(ReportKind::Tap, "1..1\nok 1 - a # SKIP\n"),
        ] {
            let verdict = interpret(Role::Tests, &exec(Some(0)), &reading);
            assert_eq!(blocked_for(&verdict).0, "at least one test that ran");
        }
    }

    #[test]
    fn exit_code_zero_with_a_failed_test_in_the_report_is_not_accepted_whatever_the_format() {
        let xml = junit(&[("test_a", ""), ("test_b", "<failure/>")]);
        for reading in [
            report(ReportKind::JunitXml, &xml),
            report(ReportKind::Tap, "1..2\nok 1 - a\nnot ok 2 - b\n"),
        ] {
            let verdict = interpret(Role::Tests, &exec(Some(0)), &reading);
            assert_eq!(
                blocked_for(&verdict).0,
                "test output that matches the exit code"
            );
        }
    }

    #[test]
    fn a_failed_run_names_the_failed_tests_of_a_report_and_fails_without_one() {
        let xml = junit(&[("test_a", ""), ("test_fr_002_empty", "<failure/>")]);
        let Verdict::Failed(failures) = interpret(
            Role::Tests,
            &exec(Some(1)),
            &report(ReportKind::JunitXml, &xml),
        ) else {
            panic!("a failed test run is FAILED");
        };
        assert!(
            failures.iter().any(|f| f.check == "test-failed"
                && f.message.contains("tests.test_wc::test_fr_002_empty"))
        );

        let Verdict::Failed(failures) = interpret(
            Role::Tests,
            &exec(Some(1)),
            &report(
                ReportKind::Tap,
                "1..2\nok 1 - a\nnot ok 2 - counts nothing\n",
            ),
        ) else {
            panic!("a failed test run is FAILED");
        };
        assert!(
            failures
                .iter()
                .any(|f| f.message.contains("counts nothing"))
        );

        for reading in [
            Reading::NoReport,
            report(ReportKind::JunitXml, "<testsuites"),
            Reading::Unreadable,
        ] {
            let Verdict::Failed(failures) = interpret(Role::Tests, &exec(Some(1)), &reading) else {
                panic!("a non-zero exit code is FAILED with or without a report");
            };
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].check, "exit-code");
        }
    }

    #[test]
    fn a_failed_test_run_names_the_failed_test() {
        let failing = include_str!("../../../tests/validation/fixtures/cargo_test_failing.stdout");
        let err = include_str!("../../../tests/validation/fixtures/cargo_test_failing.stderr");
        let Verdict::Failed(failures) =
            interpret(Role::Tests, &exec(Some(101)), &read(failing, err))
        else {
            panic!("a failed test run is FAILED");
        };
        assert!(
            failures
                .iter()
                .any(|f| f.check == "test-failed" && f.message.contains("fr_002_failing_case"))
        );
    }
}
