//! The retry of a `docker network create` that finds Docker's address pool full. These tests run
//! against a scripted runner, so they need no Docker. What they pin down: the one transient error
//! is retried, and nothing else is (a retry of a real failure would hide it).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest};
use factory_testkit::clock::FakeCancel;

use crate::harness::PoolRetryRunner;

const POOL_FULL: &str =
    "Error response from daemon: all predefined address pools have been fully subnetted";

/// Answers from a script, in order, and counts the calls.
struct Script {
    answers: Mutex<VecDeque<Result<SpawnOutput, SpawnError>>>,
    calls: AtomicUsize,
}

impl Script {
    fn new(answers: Vec<Result<SpawnOutput, SpawnError>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ProcessRunner for Script {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn run(
        &self,
        _req: SpawnRequest,
        _cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answers
            .lock()
            .expect("lock")
            .pop_front()
            .expect("the script has an answer for every call")
    }
}

fn failed(stderr: &str) -> Result<SpawnOutput, SpawnError> {
    Ok(SpawnOutput {
        exit_code: Some(1),
        signal: None,
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        truncated: false,
    })
}

fn succeeded() -> Result<SpawnOutput, SpawnError> {
    Ok(SpawnOutput {
        exit_code: Some(0),
        signal: None,
        stdout: b"net-id\n".to_vec(),
        stderr: Vec::new(),
        truncated: false,
    })
}

fn docker(words: &[&str]) -> SpawnRequest {
    SpawnRequest {
        program: Program::Docker,
        args: words.iter().map(|w| (*w).to_owned()).collect(),
        cwd: None,
        env: Vec::new(),
        stdin: None,
        timeout: Duration::from_secs(5),
        max_output_bytes: 4096,
    }
}

fn runner_over(script: &Arc<Script>, tries_after_the_first: usize) -> PoolRetryRunner {
    PoolRetryRunner::with_backoff(
        Arc::clone(script) as Arc<dyn ProcessRunner>,
        vec![Duration::from_millis(1); tries_after_the_first],
    )
}

#[tokio::test]
async fn a_network_create_that_finds_the_pool_full_is_tried_again_until_it_works() {
    let script = Script::new(vec![
        failed(POOL_FULL),
        failed(POOL_FULL),
        failed(POOL_FULL),
        succeeded(),
    ]);
    let out = runner_over(&script, 5)
        .run(
            docker(&["network", "create", "--internal", "sf-net-x"]),
            &FakeCancel::new(),
        )
        .await
        .expect("the runner answers");
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(script.calls(), 4);
}

#[tokio::test]
async fn a_pool_that_stays_full_returns_the_daemons_own_error_after_the_last_try() {
    let script = Script::new(vec![
        failed(POOL_FULL),
        failed(POOL_FULL),
        failed(POOL_FULL),
    ]);
    let out = runner_over(&script, 2)
        .run(
            docker(&["network", "create", "sf-net-x"]),
            &FakeCancel::new(),
        )
        .await
        .expect("the runner answers");
    assert_eq!(out.exit_code, Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("fully subnetted"));
    assert_eq!(script.calls(), 3, "the first try and two retries");
}

#[tokio::test]
async fn any_other_failure_of_a_network_create_is_returned_after_one_try() {
    for stderr in [
        "Error response from daemon: network with name sf-net-x already exists",
        "Error response from daemon: invalid pool request: Pool overlaps with other one on this address space",
        "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
    ] {
        let script = Script::new(vec![failed(stderr)]);
        let out = runner_over(&script, 5)
            .run(
                docker(&["network", "create", "sf-net-x"]),
                &FakeCancel::new(),
            )
            .await
            .expect("the runner answers");
        assert_eq!(out.exit_code, Some(1), "{stderr}");
        assert_eq!(script.calls(), 1, "{stderr}");
    }
}

#[tokio::test]
async fn the_pool_message_from_any_other_command_is_not_retried() {
    // Only a network create makes a network. A container create that happens to print the same
    // words is a different failure and keeps the one try it always had.
    for words in [
        vec!["create", "--name", "sf-x", "image"],
        vec!["network", "rm", "sf-net-x"],
        vec!["network", "ls"],
        vec!["inspect", "sf-x"],
    ] {
        let script = Script::new(vec![failed(POOL_FULL)]);
        let out = runner_over(&script, 5)
            .run(docker(&words), &FakeCancel::new())
            .await
            .expect("the runner answers");
        assert_eq!(out.exit_code, Some(1), "{words:?}");
        assert_eq!(script.calls(), 1, "{words:?}");
    }
}

#[tokio::test]
async fn a_failure_to_start_the_process_is_not_retried() {
    let script = Script::new(vec![Err(SpawnError::ProgramMissing(Program::Docker))]);
    let outcome = runner_over(&script, 5)
        .run(
            docker(&["network", "create", "sf-net-x"]),
            &FakeCancel::new(),
        )
        .await;
    assert_eq!(outcome, Err(SpawnError::ProgramMissing(Program::Docker)));
    assert_eq!(script.calls(), 1);
}
