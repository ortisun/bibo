//! The contract suite for the `ProcessRunner` port: the one funnel through which the factory
//! starts a host process.
//!
//! The requests differ between a fake and a real runner: a real one runs `git` or `docker`, so the
//! subject builds each request (a child that prints its environment, one that exits with a code,
//! one that runs until it is killed). The suite then asserts only what the port promises: a cleared
//! environment, secrets that stay out of `Debug`, exit codes returned and not raised, a cap on
//! output, and a group killed before the call returns after a timeout or a cancel.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use factory_ports::process::{
    EnvValue, ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest,
};

use super::{Check, Report, check_list, ensure, ensure_eq, ensure_err, run_checks, skip};
use crate::clock::FakeCancel;

/// What the suite needs beyond the `ProcessRunner` port itself.
#[async_trait]
pub trait ProcessSubject: Send + Sync {
    /// The runner under test.
    fn runner(&self) -> &dyn ProcessRunner;

    /// A request for a child that prints its whole environment as `NAME=value` lines on standard
    /// output and exits 0. `env` is the request's environment.
    fn print_environment(&self, env: Vec<(String, EnvValue)>) -> SpawnRequest;

    /// A request for a child that exits with `code`.
    fn exit_with(&self, code: i32) -> SpawnRequest;

    /// A request for a child that copies standard input to standard output, with `bytes` as input.
    fn echo_stdin(&self, bytes: Vec<u8>) -> SpawnRequest;

    /// A request for a child that writes `stdout_bytes` to standard output and `stderr_bytes` to
    /// standard error, with the output cap set to `cap`.
    fn print(&self, stdout_bytes: u64, stderr_bytes: u64, cap: u64) -> SpawnRequest;

    /// A request for a child that runs until it is killed, with this timeout.
    fn run_until_killed(&self, timeout: Duration) -> SpawnRequest;

    /// A request whose arguments include one with a NUL byte.
    fn with_a_nul_byte(&self) -> SpawnRequest;

    /// Makes `program` unavailable on this host. False when the subject cannot do that.
    fn make_unavailable(&self, program: Program) -> bool;

    /// How many children are still running. `None` when the subject cannot count them.
    fn children_alive(&self) -> Option<usize>;

    /// How many processes were started since the subject was made. `None` when it cannot count.
    fn processes_started(&self) -> Option<usize>;
}

/// A check of the process runner contract.
pub type ProcessCheck = Check<dyn ProcessSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: ProcessSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn ProcessSubject>
    })
    .await
}

/// Every check of the process runner contract.
#[must_use]
pub fn checks() -> Vec<ProcessCheck> {
    check_list![dyn ProcessSubject;
        the_child_environment_is_the_request_and_a_fixed_path,
        a_secret_reaches_the_child_and_stays_out_of_debug_output,
        an_exit_code_is_reported_not_raised,
        standard_input_reaches_the_child,
        output_is_cut_at_the_cap_and_marked_truncated,
        a_timeout_kills_the_process_group_before_the_call_returns,
        a_cancel_kills_the_process_group_before_the_call_returns,
        a_cancel_that_is_already_set_starts_no_process,
        an_argument_with_a_nul_byte_is_refused,
        a_missing_program_is_reported_by_name,
        each_call_runs_the_program_again,
    ]
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[super::Waiver] = &[];

async fn run_once(
    subject: &dyn ProcessSubject,
    request: SpawnRequest,
) -> Result<SpawnOutput, SpawnError> {
    subject.runner().run(request, &FakeCancel::new()).await
}

fn environment_of(output: &SpawnOutput) -> Vec<(String, String)> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

async fn the_child_environment_is_the_request_and_a_fixed_path(
    subject: &dyn ProcessSubject,
) -> Result<(), String> {
    let env = vec![
        (
            "GIT_AUTHOR_NAME".to_owned(),
            EnvValue::Plain("Factory".to_owned()),
        ),
        (
            "GIT_TERMINAL_PROMPT".to_owned(),
            EnvValue::Plain("0".to_owned()),
        ),
    ];
    let output = run_once(subject, subject.print_environment(env))
        .await
        .map_err(|error| format!("the environment dump failed: {error:?}"))?;
    let seen = environment_of(&output);
    let mut names: Vec<&str> = seen.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    ensure_eq!(
        names,
        vec!["GIT_AUTHOR_NAME", "GIT_TERMINAL_PROMPT", "PATH"],
        "the child sees the requested names and a path, and nothing inherited"
    );
    ensure!(
        seen.iter()
            .any(|(name, value)| name == "GIT_AUTHOR_NAME" && value == "Factory"),
        "a requested value did not arrive: {seen:?}"
    );
    Ok(())
}

async fn a_secret_reaches_the_child_and_stays_out_of_debug_output(
    subject: &dyn ProcessSubject,
) -> Result<(), String> {
    // Built at run time so that no credential-shaped literal sits in the source.
    let secret = format!("{}-{}", "child", "credential-value");
    let request = subject.print_environment(vec![(
        "GIT_CREDENTIAL".to_owned(),
        EnvValue::Secret(secret.clone()),
    )]);
    let shown = format!("{request:?}");
    ensure!(
        !shown.contains(&secret),
        "the request shows its secret in Debug output: {shown}"
    );
    let output = run_once(subject, request)
        .await
        .map_err(|error| format!("the environment dump failed: {error:?}"))?;
    ensure!(
        environment_of(&output)
            .iter()
            .any(|(name, value)| name == "GIT_CREDENTIAL" && *value == secret),
        "the secret did not reach the child through its environment"
    );
    Ok(())
}

async fn an_exit_code_is_reported_not_raised(subject: &dyn ProcessSubject) -> Result<(), String> {
    let output = run_once(subject, subject.exit_with(3))
        .await
        .map_err(|error| format!("a process that exited with 3 was an error: {error:?}"))?;
    ensure_eq!(output.exit_code, Some(3), "the exit code");
    ensure_eq!(output.signal, None, "no signal ended it");
    let output = run_once(subject, subject.exit_with(0))
        .await
        .map_err(|error| format!("a process that exited with 0 failed: {error:?}"))?;
    ensure_eq!(output.exit_code, Some(0), "the exit code");
    Ok(())
}

async fn standard_input_reaches_the_child(subject: &dyn ProcessSubject) -> Result<(), String> {
    let output = run_once(
        subject,
        subject.echo_stdin(b"patch bytes\nsecond line\n".to_vec()),
    )
    .await
    .map_err(|error| format!("the echo failed: {error:?}"))?;
    ensure_eq!(
        output.stdout,
        b"patch bytes\nsecond line\n".to_vec(),
        "what the child read from standard input"
    );
    Ok(())
}

async fn output_is_cut_at_the_cap_and_marked_truncated(
    subject: &dyn ProcessSubject,
) -> Result<(), String> {
    let output = run_once(subject, subject.print(5_000, 3_000, 1_000))
        .await
        .map_err(|error| format!("the print failed: {error:?}"))?;
    ensure_eq!(
        output.stdout.len(),
        1_000,
        "standard output is cut at the cap"
    );
    ensure_eq!(
        output.stderr.len(),
        1_000,
        "standard error is cut at the cap"
    );
    ensure!(output.truncated, "a cut stream must set `truncated`");

    let small = run_once(subject, subject.print(10, 10, 1_000))
        .await
        .map_err(|error| format!("the small print failed: {error:?}"))?;
    ensure_eq!(small.stdout.len(), 10, "output under the cap is kept whole");
    ensure!(!small.truncated, "output under the cap is not truncated");
    Ok(())
}

async fn a_timeout_kills_the_process_group_before_the_call_returns(
    subject: &dyn ProcessSubject,
) -> Result<(), String> {
    ensure_err!(
        run_once(subject, subject.run_until_killed(Duration::from_millis(50))).await,
        SpawnError::Timeout,
        "a child that outlives its timeout"
    );
    match subject.children_alive() {
        Some(alive) => ensure_eq!(alive, 0, "children still running after the timeout"),
        None => skip!("the subject cannot count running children"),
    }
    Ok(())
}

async fn a_cancel_kills_the_process_group_before_the_call_returns(
    subject: &dyn ProcessSubject,
) -> Result<(), String> {
    let cancel = FakeCancel::new();
    let request = subject.run_until_killed(Duration::from_secs(600));
    let result = {
        let running = subject.runner().run(request, &cancel);
        let stop = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel.cancel();
        };
        let (result, ()) = tokio::join!(running, stop);
        result
    };
    ensure_err!(
        result,
        SpawnError::Cancelled,
        "a child whose caller cancelled"
    );
    match subject.children_alive() {
        Some(alive) => ensure_eq!(alive, 0, "children still running after the cancel"),
        None => skip!("the subject cannot count running children"),
    }
    Ok(())
}

async fn a_cancel_that_is_already_set_starts_no_process(
    subject: &dyn ProcessSubject,
) -> Result<(), String> {
    let cancel = FakeCancel::new();
    cancel.cancel();
    ensure_err!(
        subject.runner().run(subject.exit_with(0), &cancel).await,
        SpawnError::Cancelled,
        "a call made after the cancel"
    );
    match subject.processes_started() {
        Some(started) => ensure_eq!(started, 0, "processes started by a cancelled call"),
        None => skip!("the subject cannot count started processes"),
    }
    Ok(())
}

async fn an_argument_with_a_nul_byte_is_refused(
    subject: &dyn ProcessSubject,
) -> Result<(), String> {
    let result = run_once(subject, subject.with_a_nul_byte()).await;
    ensure!(
        result.is_err(),
        "a NUL byte in an argument was passed on: {result:?}"
    );
    Ok(())
}

async fn a_missing_program_is_reported_by_name(subject: &dyn ProcessSubject) -> Result<(), String> {
    if !subject.make_unavailable(Program::Git) {
        skip!("the subject cannot make a program unavailable");
    }
    ensure_err!(
        run_once(subject, subject.exit_with(0)).await,
        SpawnError::ProgramMissing(Program::Git),
        "a program that is not installed"
    );
    Ok(())
}

async fn each_call_runs_the_program_again(subject: &dyn ProcessSubject) -> Result<(), String> {
    let first = run_once(subject, subject.exit_with(0)).await;
    let second = run_once(subject, subject.exit_with(0)).await;
    ensure!(first.is_ok() && second.is_ok(), "both runs must work");
    match subject.processes_started() {
        Some(started) => ensure_eq!(started, 2, "processes started by two identical calls"),
        None => skip!("the subject cannot count started processes"),
    }
    Ok(())
}
