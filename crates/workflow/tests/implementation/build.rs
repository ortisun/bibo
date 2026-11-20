//! The implementation stage: tasks in order, commits on the host, the sandbox as the only place
//! the builder runs, and a restart that resumes where it stopped.

use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::retry::AttemptDisposition;
use factory_domain::state::{StageRunStatus, TaskNodeStatus};
use factory_domain::vocabulary::StageKind;
use factory_ports::agent::{AgentRunError, ExitInfo};
use factory_ports::sandbox::SandboxProfile;
use factory_testkit::agent::AdversarialScript;
use factory_workflow::engine::AttemptOutcome;
use factory_workflow::stages::implementation::{GRANTED_TOOLS, WorkspaceAccess};
use serde_json::json;

use crate::rig::{Rig, builder_manifest, done, lock, path, write};

/// The position of the first event that starts with `prefix` at or after `from`.
fn at(events: &[String], prefix: &str, from: usize) -> usize {
    events[from..]
        .iter()
        .position(|e| e.starts_with(prefix))
        .map(|p| p + from)
        .unwrap_or_else(|| panic!("no event `{prefix}` after {from} in {events:?}"))
}

#[tokio::test]
async fn commits_happen_on_the_host() {
    let rig = Rig::new().await;
    rig.run_until_implementation().await;
    rig.builder_does_the_plan();
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, StageKind::Implementation);
    assert_eq!(outcome, AttemptOutcome::Succeeded);

    // The tasks ran in the order of the plan: the formatter, the error test, the documentation.
    let runs = rig.events_of("ledger.start:");
    assert_eq!(
        runs,
        [
            "ledger.start:add-json-output-formatter",
            "ledger.start:cover-unreadable-file-error",
            "ledger.start:document-json-flag"
        ]
    );

    // For every task: the workspace, the sandbox, the builder, the end of the sandbox, and only
    // then the audit, the commit by the factory's own identity, and the record of the commit.
    let events = rig.events();
    let mut cursor = 0;
    for _task in 0..3 {
        let create = at(&events, "workspace.create:", cursor);
        let sandbox = at(&events, "sandbox.create:agent", create);
        let run = at(&events, "runtime.run:builder", sandbox);
        let removed = at(&events, "sandbox.removed", run);
        let ingest = at(&events, "workspace.ingest", removed);
        let commit = at(&events, "workspace.commit:Factory", ingest);
        let finish = at(&events, "ledger.finish:", commit);
        assert!(create < sandbox && sandbox < run && run < removed);
        assert!(removed < ingest && ingest < commit && commit < finish);
        cursor = finish;
    }
    // Nothing ran in the sandbox but the builder, and nothing ran after it ended.
    assert!(rig.events_of("sandbox.exec").is_empty());

    // The commits are a chain: each task is built on the commit of the task before it.
    let evidence = rig
        .deliverable(StageKind::Implementation, "implementation-evidence")
        .await
        .expect("the evidence manifest");
    let tasks = evidence["tasks"].as_array().expect("tasks");
    assert_eq!(tasks.len(), 3);
    assert_eq!(tasks[0]["built_on"], rig.base.as_str());
    assert_eq!(tasks[1]["built_on"], tasks[0]["commit"]);
    assert_eq!(tasks[2]["built_on"], tasks[1]["commit"]);
    assert_eq!(evidence["head_commit"], tasks[2]["commit"]);
    assert_eq!(evidence["base_commit"], rig.base.as_str());
    // The paths and the statistics are the host's own measurements.
    let first = &tasks[0];
    assert_eq!(first["changes"].as_array().expect("changes").len(), 3);
    assert!(
        first["diff_stats"]["additions"]
            .as_u64()
            .expect("additions")
            > 10
    );
    // What the builder said is kept apart and marked as not evidence.
    assert_eq!(
        first["reported_by_builder"]["commands"][0]["argv"][0],
        "cargo"
    );
    assert!(
        first["reported_by_builder"]["note"]
            .as_str()
            .expect("note")
            .contains("not evidence")
    );
    // The result the validation and review stages read names the same two commits.
    let result = rig
        .world
        .links(rig.run_of(StageKind::Implementation).await)
        .await;
    assert!(result.len() >= 2, "{result:?}");
    let run = rig.run_of(StageKind::Implementation).await;
    assert!(
        rig.ledger
            .statuses(run)
            .iter()
            .all(|(_, status)| *status == TaskNodeStatus::Succeeded)
    );
    assert_eq!(rig.ledger.commits(run).len(), 3);
    // Every commit is the factory's, by its own fixed identity, and the stage run passed.
    let view = rig.world.view(rig.job).await;
    assert_eq!(
        view.newest(StageKind::Implementation)
            .expect("a run")
            .status,
        StageRunStatus::Passed
    );
}

#[tokio::test]
async fn tasks_run_in_dependency_order_even_when_the_plan_lists_them_otherwise() {
    // The plan lists the two tasks that depend on the formatter before the formatter.
    let mut plan: serde_json::Value = serde_json::from_str(crate::rig::PLAN).expect("JSON");
    plan["tasks"].as_array_mut().expect("tasks").reverse();
    let rig = Rig::build(crate::rig::Options {
        plan: plan.to_string(),
        ..crate::rig::Options::default()
    })
    .await;
    rig.run_until_implementation().await;
    // Among the tasks that are ready together, the plan's own order decides: the documentation
    // task is listed before the error test, so it runs second.
    rig.builder_will(
        vec![
            write("src/main.rs", crate::rig::MAIN),
            write("src/output.rs", crate::rig::OUTPUT),
            write("tests/json_output.rs", crate::rig::JSON_TEST),
        ],
        done(
            "add-json-output-formatter",
            &["src/main.rs", "src/output.rs", "tests/json_output.rs"],
        ),
    );
    rig.builder_will(
        vec![write("README.md", "# Word count\n\nUse --json.\n")],
        done("document-json-flag", &["README.md"]),
    );
    rig.builder_will(
        vec![write("tests/errors.rs", crate::rig::ERRORS_TEST)],
        done("cover-unreadable-file-error", &["tests/errors.rs"]),
    );
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(
        rig.events_of("ledger.start:"),
        [
            "ledger.start:add-json-output-formatter",
            "ledger.start:document-json-flag",
            "ledger.start:cover-unreadable-file-error"
        ]
    );
}

#[tokio::test]
async fn commits_happen_on_the_host_and_a_planted_hook_blocks_the_attempt() {
    // A hook lives in a git directory. The builder plants one inside its tree, together with a
    // legitimate change. The audit finds the nested git directory, so nothing is committed, and
    // nothing runs on the host after the builder's sandbox is gone.
    let rig = Rig::new().await;
    rig.run_until_implementation().await;
    rig.builder_will(
        vec![
            write("src/main.rs", crate::rig::MAIN),
            factory_testkit::contracts::workspace::TreeEdit::NestedGit(path("src/vendor")),
        ],
        done("add-json-output-formatter", &["src/main.rs"]),
    );
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert!(rig.events_of("workspace.commit").is_empty());
    assert!(rig.events_of("sandbox.exec").is_empty());
    let evidence = rig
        .deliverable(StageKind::Implementation, "implementation-evidence")
        .await
        .expect("the evidence manifest");
    assert_eq!(evidence["refusal"]["code"], "nested-git");
    assert_eq!(evidence["refusal"]["paths"][0]["path"], "src/vendor");
    assert_eq!(evidence["head_commit"], rig.base.as_str());
    assert!(evidence["tasks"].as_array().expect("tasks").is_empty());
    let view = rig.world.view(rig.job).await;
    assert_eq!(
        view.newest(StageKind::Implementation)
            .expect("a run")
            .status,
        StageRunStatus::Blocked
    );
}

#[tokio::test]
async fn agent_runs_only_in_the_sandbox() {
    // The contract grants the builder the tools of its manifest and nothing else.
    let builder = builder_manifest();
    let mut manifest: Vec<&str> = builder
        .allowed_tools
        .as_slice()
        .iter()
        .map(|tool| tool.name.as_str())
        .collect();
    let mut granted: Vec<&str> = GRANTED_TOOLS.to_vec();
    granted.sort_unstable();
    manifest.sort_unstable();
    assert_eq!(granted, manifest);

    // A spec for any other profile is refused before a sandbox exists, and so is a spec that
    // mounts another workspace or the wrong access. The builder does not run.
    for sabotage in 0..3 {
        let rig = Rig::new().await;
        rig.run_until_implementation().await;
        match sabotage {
            0 => *lock(&rig.specs.profile) = Some(SandboxProfile::Verify),
            1 => *lock(&rig.specs.read_only) = Some(true),
            _ => *lock(&rig.specs.other_workspace) = true,
        }
        rig.builder_does_the_plan();
        let (_, outcome) = rig.run_next().await;
        assert!(
            matches!(
                outcome,
                AttemptOutcome::Failed {
                    class: FailureClass::PolicyDenied,
                    ..
                }
            ),
            "{sabotage}: {outcome:?}"
        );
        assert!(
            rig.events_of("sandbox.create").is_empty(),
            "{sabotage}: no sandbox was made"
        );
        // The stage refuses a spec for another profile, or one that mounts something other than
        // the workspace it made, itself, before it asks the sandbox port.
        assert!(
            rig.events_of("sandbox.attempt").is_empty(),
            "{sabotage}: the stage asked the port for a sandbox it should have refused"
        );
        assert!(
            rig.events_of("runtime.run").is_empty(),
            "{sabotage}: the builder did not run"
        );
        assert!(rig.events_of("workspace.commit").is_empty());
        let view = rig.world.view(rig.job).await;
        assert_eq!(
            view.newest(StageKind::Implementation)
                .expect("a run")
                .status,
            StageRunStatus::Blocked,
            "{sabotage}"
        );
    }
    // And the usual case asks for a writable checkout in the agent profile.
    let rig = Rig::new().await;
    rig.run_until_implementation().await;
    rig.builder_does_the_plan();
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let seen = lock(&rig.specs.seen).clone();
    assert_eq!(seen.len(), 3);
    assert!(seen.iter().all(
        |(profile, read_only, access)| *profile == SandboxProfile::Agent
            && !read_only
            && *access == WorkspaceAccess::Edit
    ));
}

#[tokio::test]
async fn resume_after_crash() {
    let rig = Rig::new().await;
    rig.run_until_implementation().await;
    // The first task works. The second one's builder dies, and the process dies with it before it
    // can write that the task failed: the ledger keeps the task as RUNNING.
    rig.builder_will(
        vec![
            write("src/main.rs", crate::rig::MAIN),
            write("src/output.rs", crate::rig::OUTPUT),
            write("tests/json_output.rs", crate::rig::JSON_TEST),
        ],
        done(
            "add-json-output-formatter",
            &["src/main.rs", "src/output.rs", "tests/json_output.rs"],
        ),
    );
    rig.runtime
        .inner
        .queue(
            AdversarialScript::returning(json!({})).failing_with(AgentRunError::ProcessFailed(
                ExitInfo {
                    code: Some(137),
                    signal: None,
                },
            )),
        );
    rig.ledger.skip_next_fail();
    // The skip applies to the first `fail`, which is the one of the second task.
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed {
                class: FailureClass::ToolError,
                then: AttemptDisposition::Retry
            }
        ),
        "{outcome:?}"
    );
    let run = rig.run_of(StageKind::Implementation).await;
    let statuses = rig.ledger.statuses(run);
    assert_eq!(statuses[0].1, TaskNodeStatus::Succeeded);
    assert_eq!(statuses[1].1, TaskNodeStatus::Running);
    assert_eq!(statuses[2].1, TaskNodeStatus::Pending);
    let after_first_task = rig.ledger.commits(run)[0].clone();

    // The next attempt resumes at the first task that is not SUCCEEDED, on the commit of the one
    // before it, and does not build the first task again.
    rig.builder_will(
        vec![write("tests/errors.rs", crate::rig::ERRORS_TEST)],
        done("cover-unreadable-file-error", &["tests/errors.rs"]),
    );
    rig.builder_will(
        vec![write("README.md", "# Word count\n\nUse --json.\n")],
        done("document-json-flag", &["README.md"]),
    );
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(
        rig.events_of("ledger.start:"),
        [
            "ledger.start:add-json-output-formatter",
            "ledger.start:cover-unreadable-file-error",
            "ledger.start:cover-unreadable-file-error",
            "ledger.start:document-json-flag",
        ]
    );
    assert_eq!(rig.runtime.runs("builder"), 4);
    let creates = rig.events_of("workspace.create:");
    assert!(
        creates[2].ends_with(after_first_task.as_str()),
        "the resumed task is built on the commit of the first: {creates:?}"
    );
    let evidence = rig
        .deliverable(StageKind::Implementation, "implementation-evidence")
        .await
        .expect("the evidence manifest");
    let tasks = evidence["tasks"].as_array().expect("tasks");
    assert_eq!(tasks.len(), 3);
    assert_eq!(tasks[0]["commit"], after_first_task.as_str());
    assert_eq!(tasks[1]["built_on"], after_first_task.as_str());
    // The first task was not built in this attempt, so the builder's statements are not there,
    // and the host's measurements are.
    assert!(
        tasks[0]["reported_by_builder"]["commands"]
            .as_array()
            .expect("commands")
            .is_empty()
    );
    assert_eq!(tasks[0]["changes"].as_array().expect("changes").len(), 3);
}

#[tokio::test]
async fn resume_after_crash_with_every_task_done_still_proves_a_sandbox() {
    // The attempt finishes the last task and then loses the artifact store before it writes its
    // output. The next attempt has nothing to build. The engine fails a stage that declares a
    // sandbox and never reports one, so the stage makes one sandbox, checks it, and removes it.
    let rig = Rig::new().await;
    rig.run_until_implementation().await;
    rig.builder_does_the_plan();
    let artifacts = rig.artifacts.clone();
    rig.runtime.hook("builder", || {});
    rig.runtime.hook("builder", || {});
    rig.runtime
        .hook("builder", move || artifacts.fail_next_get());
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed {
                class: FailureClass::ToolError,
                then: AttemptDisposition::Retry
            }
        ),
        "{outcome:?}"
    );
    let run = rig.run_of(StageKind::Implementation).await;
    assert!(
        rig.ledger
            .statuses(run)
            .iter()
            .all(|(_, status)| *status == TaskNodeStatus::Succeeded)
    );
    let builder_runs = rig.runtime.runs("builder");
    let sandboxes = rig.events_of("sandbox.create").len();
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(rig.runtime.runs("builder"), builder_runs, "no builder ran");
    assert_eq!(rig.events_of("sandbox.create").len(), sandboxes + 1);
    assert!(rig.events_of("workspace.commit").len() == 3);
    let evidence = rig
        .deliverable(StageKind::Implementation, "implementation-evidence")
        .await
        .expect("the evidence manifest");
    assert_eq!(evidence["tasks"].as_array().expect("tasks").len(), 3);
}

#[tokio::test]
async fn a_builder_that_fails_is_classified_like_every_other_agent() {
    // A provider outage is retried, a refused credential is not, and a missing output is a tool
    // error. The mapping is the one every stage uses.
    let table = [
        (
            AgentRunError::ProviderUnavailable,
            FailureClass::ProviderError,
        ),
        (
            AgentRunError::AuthenticationRequired,
            FailureClass::PolicyDenied,
        ),
        (AgentRunError::OutputMissing, FailureClass::ToolError),
        (AgentRunError::BudgetRefused, FailureClass::BudgetExhausted),
    ];
    for (error, class) in table {
        let rig = Rig::new().await;
        rig.run_until_implementation().await;
        rig.runtime
            .inner
            .queue(AdversarialScript::returning(json!({})).failing_with(error.clone()));
        let (_, outcome) = rig.run_next().await;
        match outcome {
            AttemptOutcome::Failed { class: found, .. } => assert_eq!(found, class, "{error:?}"),
            other => panic!("{error:?}: {other:?}"),
        }
        assert!(rig.events_of("workspace.commit").is_empty());
        assert!(
            rig.events_of("workspace.ingest").is_empty(),
            "nothing is read from a failed run"
        );
        let run = rig.run_of(StageKind::Implementation).await;
        assert_eq!(rig.ledger.statuses(run)[0].1, TaskNodeStatus::Failed);
    }
}

/// The settings `.factory/repository.json` of a project that asked for Conventional Commits.
const GIT_SETTINGS: &str = r#"{"schema":"factory-repository-settings/1","repository":{"owner":"example-org","name":"fixture"},"project_board":null,"commits":{"convention":"conventional-commits","types":["build","chore","ci","docs","feat","fix","perf","refactor","revert","style","test"],"scopes":[],"require_scope":false,"header_max_length":100},"gitflow":{"closing_mode":"develop","main_branch":"main","develop_branch":"develop","prefixes":{"feature":["feature/","factory/"],"bugfix":["bugfix/"],"release":["release/"],"hotfix":["hotfix/"],"support":["support/"]},"additional_flows":[]}}"#;

/// A project with git settings gets Conventional Commits headers, typed by the kind of each task;
/// a project without them keeps the plain titles.
#[tokio::test]
async fn commit_messages_follow_the_projects_git_conventions() {
    let mut files = crate::rig::base_files();
    files.push((
        ".factory/repository.json".to_owned(),
        GIT_SETTINGS.to_owned(),
    ));
    let rig = Rig::build(crate::rig::Options {
        files,
        ..crate::rig::Options::default()
    })
    .await;
    rig.run_until_implementation().await;
    rig.builder_does_the_plan();
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(
        rig.events_of("commit.header:"),
        [
            "commit.header:feat: Print counts as JSON when the flag is given",
            "commit.header:test: Show a clear error when the input file cannot be read",
            "commit.header:docs: Document the JSON option and its key order",
        ]
    );

    let plain = Rig::new().await;
    plain.run_until_implementation().await;
    plain.builder_does_the_plan();
    let (_, outcome) = plain.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(
        plain.events_of("commit.header:")[0],
        "commit.header:Print counts as JSON when the flag is given"
    );
}
