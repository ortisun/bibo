//! Deliberate breaks: a container that is built weaker than its spec must be caught by the posture
//! check, on a real daemon, before it starts. Each test makes the `docker create` of the sandbox
//! really different (a flag dropped, a capability added, the daemon socket mounted) and requires
//! `PostureMismatch`, no start, and nothing left behind.
//!
//! The other three breaks of the work package (skip the posture check, ignore cancellation, forget
//! the token file removal) change this crate's own code, so they are run by editing the source
//! and are reported with the work package, not kept as tests.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{ProcessRunner, SpawnError, SpawnOutput, SpawnRequest};
use factory_ports::sandbox::{SandboxError, SandboxProfile};
use factory_sandbox::SystemProcessRunner;

use crate::harness::Lab;

type Edit = Box<dyn Fn(&mut Vec<String>) + Send + Sync>;

/// Edits the `docker create` of the sandbox container (not of the sidecar) and records which
/// containers were started.
struct BreakRunner {
    inner: SystemProcessRunner,
    edit: Edit,
    started: Mutex<Vec<String>>,
}

#[async_trait]
impl ProcessRunner for BreakRunner {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn run(
        &self,
        mut req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        let first = req.args.first().cloned();
        let first = first.as_deref();
        if first == Some("create") && !req.args.iter().any(|a| a == "--network-alias") {
            (self.edit)(&mut req.args);
        }
        if first == Some("start") {
            self.started
                .lock()
                .expect("lock")
                .push(req.args.get(1).cloned().unwrap_or_default());
        }
        self.inner.run(req, cancel).await
    }
}

async fn assert_caught(edit: Edit, profile: SandboxProfile, field: &'static str) {
    let runner = Arc::new(BreakRunner {
        inner: SystemProcessRunner::new(),
        edit,
        started: Mutex::new(Vec::new()),
    });
    let lab = Lab::with_runner(true, Some(Arc::clone(&runner) as Arc<dyn ProcessRunner>));
    let outcome = lab
        .create(lab.spec(profile, 1, std::time::Duration::from_secs(60)))
        .await;
    match outcome {
        Err(SandboxError::PostureMismatch(diff)) => assert!(
            diff.fields.contains(&field),
            "expected {field} in {:?}",
            diff.fields
        ),
        Err(other) => panic!("expected PostureMismatch, got {other:?}"),
        Ok(_) => panic!("a container built weaker than its spec was returned"),
    }
    let started = runner.started.lock().expect("lock").clone();
    assert!(
        started.iter().all(|name| name.starts_with("sf-side-")),
        "the weaker container was started: {started:?}"
    );
    lab.world.provider.finish_background_cleanups().await;
    assert!(lab.leftovers().is_empty(), "{:?}", lab.leftovers());
    assert_eq!(lab.token_files(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn break_dropping_read_only_is_caught_before_the_start() {
    assert_caught(
        Box::new(|args| args.retain(|a| a != "--read-only")),
        SandboxProfile::Verify,
        "read_only_rootfs",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn break_adding_a_capability_is_caught_before_the_start() {
    assert_caught(
        Box::new(|args| {
            let at = args
                .iter()
                .position(|a| a == "--cap-drop")
                .expect("cap-drop");
            args.splice(at..at, ["--cap-add".to_owned(), "NET_ADMIN".to_owned()]);
        }),
        SandboxProfile::Verify,
        "cap_add",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn break_mounting_the_docker_socket_is_caught_before_the_start() {
    assert_caught(
        Box::new(|args| {
            let image = args
                .iter()
                .position(|a| a.contains("@sha256:"))
                .expect("image");
            args.splice(
                image..image,
                [
                    "--mount".to_owned(),
                    "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock".to_owned(),
                ],
            );
        }),
        SandboxProfile::Agent,
        "mounts",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn break_a_privileged_container_is_caught_before_the_start() {
    assert_caught(
        Box::new(|args| {
            let at = args
                .iter()
                .position(|a| a == "--cap-drop")
                .expect("cap-drop");
            args.insert(at, "--privileged".to_owned());
        }),
        SandboxProfile::Verify,
        "privileged",
    )
    .await;
}
