//! Deliberate breaks that the guards must catch.
//!
//! A guard that has never failed is not known to work. These breaks change how host git is
//! started, on its way to the spawn recorder, and each test requires the guard of the hostile
//! tests (`hostile::problems`) to name the fault. The breaks that change this crate's own code
//! (skip the audit, follow a link, let a protected edit through, treat `.GIT` as ordinary, read
//! without a bound) are run by editing the source, and are reported with the work package.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{ProcessRunner, SpawnError, SpawnOutput, SpawnRequest};
use factory_ports::workspace::Workspace;
use factory_testkit::clock::FakeCancel;

use crate::hostile::{Recording, problems};
use crate::world::{Options, World, commit_request};

type Edit = Box<dyn Fn(&mut SpawnRequest) + Send + Sync>;

/// Edits every git call before it reaches the recorder.
struct EditingRunner {
    inner: Arc<dyn ProcessRunner>,
    edit: Edit,
}

#[async_trait]
impl ProcessRunner for EditingRunner {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn run(
        &self,
        mut req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        (self.edit)(&mut req);
        self.inner.run(req, cancel).await
    }
}

/// Runs a whole flow (fetch, create, edit, ingest, commit) under `edit` and returns what the
/// guard says about the recorded calls.
async fn broken_flow(edit: Edit, writable: Arc<Mutex<Option<PathBuf>>>) -> Vec<String> {
    let recording = Recording::new();
    let runner = Arc::new(EditingRunner {
        inner: Arc::clone(&recording.runner) as Arc<dyn ProcessRunner>,
        edit,
    });
    let world = World::with(Options {
        runner: Some(runner),
        ..Options::default()
    })
    .await;
    let (ws, _) = world.open(1).await;
    let checkout = ws.mounts().workspace;
    *writable.lock().expect("lock") = Some(checkout.clone());
    std::fs::write(checkout.join("src/new.rs"), "pub fn new() {}\n").expect("a file");
    let change = ws.ingest(&FakeCancel::new()).await.expect("ingest");
    ws.commit(&change, commit_request("A change"))
        .await
        .expect("commit");
    problems(&recording.records(), &[&checkout])
}

#[tokio::test(flavor = "multi_thread")]
async fn a_break_that_drops_the_hook_and_monitor_disabling_is_caught() {
    let edit: Edit = Box::new(|req| {
        let mut kept = Vec::new();
        let mut args = req.args.iter().peekable();
        while let Some(arg) = args.next() {
            let drops = arg == "-c"
                && args.peek().is_some_and(|next| {
                    next.starts_with("core.hooksPath=") || next.starts_with("core.fsmonitor=")
                });
            if drops {
                args.next();
            } else {
                kept.push(arg.clone());
            }
        }
        req.args = kept;
    });
    let found = broken_flow(edit, Arc::new(Mutex::new(None))).await;
    assert!(
        found.iter().any(|p| p.contains("core.hooksPath")),
        "the guard must name the missing hook disabling: {found:?}"
    );
    assert!(
        found.iter().any(|p| p.contains("core.fsmonitor")),
        "{found:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_break_that_runs_git_inside_the_writable_tree_is_caught() {
    let writable: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&writable);
    let edit: Edit = Box::new(move |req| {
        if let Some(tree) = seen.lock().expect("lock").clone() {
            req.cwd = Some(tree.clone());
            req.args
                .insert(0, format!("--work-tree={}", tree.display()));
        }
    });
    let found = broken_flow(edit, writable).await;
    assert!(
        found.iter().any(|p| p.contains("ran in the writable tree")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|p| p.contains("names the writable tree")),
        "{found:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_break_that_adds_an_ownership_override_to_the_command_line_is_caught() {
    let edit: Edit = Box::new(|req| {
        // The override is assembled from pieces, as the fixtures do.
        req.args.insert(0, ["safe.", "dir=elsewhere"].concat());
        req.args.insert(0, "-c".to_owned());
    });
    let found = broken_flow(edit, Arc::new(Mutex::new(None))).await;
    assert!(
        found
            .iter()
            .any(|p| p.contains("signs or overrides the ownership check")),
        "{found:?}"
    );
}
