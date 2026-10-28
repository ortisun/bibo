//! What the supervisor's observation of a command means for its gate.
//!
//! The only evidence of a command gate is what the supervisor saw: how the process ended, when,
//! and the redacted text it wrote. [`interpret`] maps that to one of three answers:
//!
//! | The supervisor saw | The gate is |
//! |---|---|
//! | Exit code 0, and for a test gate the output shows tests that ran | `PASSED` |
//! | Another exit code from a tool that ran | `FAILED` |
//! | The tool missing (126, 127), a timeout, a signal, an out-of-memory kill, no exit code, an output that is cut or cannot be read, or a test gate that ran no test | `BLOCKED` |
//!
//! `NOT_APPLICABLE` is not an answer of this function: only a rule that is recorded with its
//! inputs may say that a gate does not apply (policy `gate_integrity.missing_evidence_is`).
//! There is no path from a missing observation to `PASSED`.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_ports::sandbox::ExecResult;

use super::definition::Role;
use super::libtest::{Outcomes, Status};

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
    /// Both streams were read.
    Read {
        /// Standard output.
        stdout: &'a str,
        /// Standard error.
        stderr: &'a str,
    },
    /// The artifact store could not give the output back, or it was not text.
    Unreadable,
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
    if let (true, Reading::Read { stdout, stderr }) = (role.expects_tests(), reading) {
        let outcomes = Outcomes::parse(stdout, stderr);
        if outcomes.is_consistent() {
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
    }
    Verdict::Failed(failures)
}

/// A test command that exited with code 0 passes only if its output shows tests that ran.
fn tests_ran(exec: &ExecResult, reading: &Reading<'_>) -> Verdict {
    let Reading::Read { stdout, stderr } = reading else {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "readable test output",
            "The output of the test command could not be read, so the gate cannot show that tests ran.",
        );
    };
    if exec.stdout_truncated || exec.stderr_truncated {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "complete test output",
            "The output of the test command was cut at the size limit, so the gate cannot show that tests ran.",
        );
    }
    let outcomes = Outcomes::parse(stdout, stderr);
    if !outcomes.is_consistent() {
        return blocked(
            BlockedCode::ToolProbeFailed,
            "test output that adds up",
            "The output of the test command does not add up, so it is not accepted as evidence.",
        );
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
