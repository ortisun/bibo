//! The live-adapters run: the factory driven through the REAL adapters, with only the model's
//! answers and GitHub's server faked (both labelled), and the part of the run that needs the Docker
//! daemon.
//!
//! The rig, and what is real and what is fake, are in `live/mod.rs`. Every test here that needs
//! Docker panics with `BLOCKED:` when the daemon or an image is missing, which is never a pass. They
//! are ignored in the default suite, as `crates/composition/tests/docker_sandbox.rs` is, because
//! they need the daemon and the pinned images, and they share the daemon with other stacks: they
//! hold the cross-process lock of the sandbox tests, label everything `factory.test=true`, and remove
//! only what carries their own labels. Run them one at a time:
//!
//! ```text
//! cargo nextest run -p factory-api --run-ignored only --test live_run
//! ```

#[allow(dead_code, unused_imports)]
#[path = "../../../crates/workflow/tests/validation/cargo.rs"]
mod cargo;
mod full;
mod live;
#[allow(dead_code)]
mod playbook;
mod support;

use std::sync::Arc;

use factory_composition::external::ProbeReport;
use factory_domain::vocabulary::StageKind;
use factory_ports::agent::Capability;
use live::{Lab, build_world};
use playbook::Playbook;
use support::Env;

/// Runs the body with the telemetry pipeline of the factory as the subscriber, so that the
/// warnings of the sandbox and of the stages (a failed teardown, a refused posture) show in the log
/// of the test. `LIVE_LOG` replaces the filter.
fn live(body: impl std::future::Future<Output = ()>) {
    let policies = factory_composition::startup::load_policy(&live::root(), &[]).expect("policies");
    let redactor = Arc::new(
        factory_composition::redaction::redactor_from_policy(&policies.security)
            .expect("a redactor"),
    );
    let filter = std::env::var("LIVE_LOG").unwrap_or_else(|_| "warn".to_owned());
    let telemetry = factory_composition::telemetry::config_for(
        "factory-live-test",
        "0.0.0",
        factory_composition::profile::Profile::Test,
        &factory_composition::config::TelemetryConfig {
            otlp_endpoint: None,
            log_filter: Some(filter),
        },
        &redactor,
    )
    .expect("a telemetry configuration");
    let pipeline = factory_observability::telemetry::build_pipeline(&telemetry, std::io::stderr)
        .expect("a pipeline");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    pipeline.in_scope(|| runtime.block_on(body));
}

/// The lab, the environment and the fakes around the world, with the real providers.
struct Setup {
    lab: Lab,
    github: live::github::GitHub,
    registry: factory_testkit::fx::http::HttpServer,
    world: live::World,
    env: Env,
}

/// `extra` is appended to the configuration, for a break that changes it.
async fn setup(extra: &str) -> Setup {
    setup_with(extra, |_| {}).await
}

/// Like [`setup`], and `tweak` changes the playbook before the provider starts: how a deliberate
/// break puts a wrong model answer on the wire.
async fn setup_with(extra: &str, tweak: impl FnOnce(&Playbook)) -> Setup {
    let playbook = Playbook::word_count(&live::root());
    tweak(&playbook);
    // The real sandbox can fail an attempt for a reason of the machine (the daemon not yet seeing a
    // directory), and the engine then runs the stage again from its start. The playbook has one
    // answer for each entry and refuses a second ask by design; here a second ask is a retry of the
    // same call and gets the same answer.
    playbook.allow_repeats(&[
        "intake-classifier",
        "specification-writer.specify",
        "specification-writer.checklist",
        "specification-reviewer",
        "architect",
        "planner",
        "builder.write-json-formatter",
        "builder.read-json-option",
        "code-reviewer",
        "documentation-writer",
        "documentation-reviewer",
    ]);
    let lab = Lab::start(Arc::clone(&playbook));
    let env = Env::start().await;
    // The remote the workspaces clone from and push to: a bare repository with the fixture, the
    // Spec Kit installation and the constitution a person owns.
    let files = full::fixture_files(&playbook);
    let (bare, _main) =
        live::github::make_remote(&lab.scratch.join("remote"), &env.a.full_name, &files);
    let github = live::github::GitHub::start(
        &env.a.full_name,
        env.a.installation,
        bare,
        &[
            ("requester-one", env.a.requester.github_id),
            ("approver-one", env.a.approver.github_id),
        ],
        Arc::new(factory_composition::system::SystemClock),
    );
    let registry = live::registry_server();
    let text = format!(
        "{}{extra}",
        lab.config_text(
            &env,
            &github.base_url(),
            &registry.base_url(),
            github.fake.app().id
        )
    );
    let logins = env.db.server.logins().await;
    let store: Arc<dyn factory_ports::store::Store> = Arc::new(
        factory_storage::pg::PgStore::connect(factory_composition::database::pools(
            support::small_pool(env.db.url(&logins.worker)),
            support::small_pool(env.db.url(&logins.engine)),
        ))
        .await
        .expect("the worker store becomes ready"),
    );
    let artifacts: Arc<dyn factory_ports::artifact::ArtifactStore> = Arc::new(
        factory_storage::artifact_fs::LocalFsArtifactStore::open(
            env.artifacts_root.clone(),
            64 * 1024 * 1024,
            Arc::new(
                factory_storage::pg::PgStore::connect(factory_composition::database::pools(
                    support::small_pool(env.db.url(&logins.worker)),
                    support::small_pool(env.db.url(&logins.engine)),
                ))
                .await
                .expect("the worker store becomes ready"),
            ),
        )
        .expect("the artifact root opens"),
    );
    let skills = factory_composition::spec_skills::bundle_for_writer(
        &lab.root,
        &lab.root,
        &lab.policies.security,
        "specification-writer",
    )
    .expect("the skills of the specification writer");
    let world = build_world(&lab, &env, &text, store, artifacts, Some(skills)).await;
    Setup {
        lab,
        github,
        registry,
        world,
        env,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Docker daemon, the pinned images and the shared network lock; see the head of the file"]
async fn the_start_up_probe_reads_the_version_of_each_tool_in_the_real_agent_image() {
    let set = setup("").await;
    assert!(set.world.blocked.is_empty(), "{:?}", set.world.blocked);
    let ProbeReport::Probed(found) = &set.world.probe else {
        panic!(
            "the probe did not run in the real sandbox: {:?}",
            set.world.probe
        );
    };
    let claude = &found.0[&factory_ports::agent::RuntimeId::new("claude-code-cli").expect("id")];
    let codex = &found.0[&factory_ports::agent::RuntimeId::new("codex-cli").expect("id")];
    println!(
        "PROBE claude-code-cli {} / codex-cli {}",
        claude.runtime_version, codex.runtime_version
    );
    // The versions the image pins (infra/sandbox-images/images.json), read from the tools.
    assert_eq!(claude.runtime_version, "2.1.311");
    assert_eq!(codex.runtime_version, "0.163.0");
    // What the stages need of a runtime is supported by both tools.
    for runtime in [claude, codex] {
        for capability in [
            Capability::HeadlessMultiTurn,
            Capability::SkillInvocation,
            Capability::BaseUrlOverride,
            Capability::CredentialFromFile,
            Capability::StructuredStream,
        ] {
            assert!(
                runtime.supports(capability),
                "{capability:?} {}",
                runtime.runtime_version
            );
        }
        // Neither tool reports `JsonSchemaOutput`, on purpose (the engine validates the bytes), so
        // a stage that asked the router for it could be routed to no runtime at all. That was the
        // case until this work; `crates/composition/tests/stage_needs_match_real_probes.rs` guards it.
        assert!(!runtime.supports(Capability::JsonSchemaOutput));
    }
    // Nothing is left in the daemon, and no model request was made by a version probe.
    assert!(
        set.lab.provider.seen().is_empty(),
        "{:?}",
        set.lab.provider.seen()
    );
    let _ = (&set.github, &set.registry, &set.env, StageKind::Intake);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Docker daemon, the pinned images and the shared network lock; see the head of the file"]
async fn break_a_probe_of_a_tool_that_is_not_in_the_image_blocks_the_worker_and_names_it() {
    // The configuration points the Claude Code tool at a path the image does not have: the same
    // thing as an image built without the tool. The probe runs in the real sandbox, finds nothing
    // to run, and the worker does not get its capabilities from anywhere else.
    let set =
        setup("runtimes:\n  claude_code: { binary: /usr/local/bin/not-in-this-image }\n").await;
    assert!(
        matches!(set.world.probe, ProbeReport::Blocked(ref why) if why.contains("claude-code-cli")),
        "{:?}",
        set.world.probe
    );
    assert!(
        set.world.built.is_none(),
        "no port is built on a probe that failed"
    );
    assert_eq!(set.world.blocked.len(), 1, "{:?}", set.world.blocked);
    assert!(
        set.world.blocked[0].starts_with("CapabilityProbes: runtimes: claude-code-cli"),
        "{:?}",
        set.world.blocked
    );
}

// ---- the whole job ----------------------------------------------------------------------------

/// The signed webhook that says a person labelled the issue. It carries no text.
async fn label_the_issue(env: &Env, number: u64) {
    let body = serde_json::to_vec(&serde_json::json!({
        "action": "labeled",
        "installation": {"id": env.a.installation},
        "repository": {"id": env.a.github_repository, "full_name": env.a.full_name},
        "sender": {"id": env.a.requester.github_id, "login": "requester-one", "type": "User"},
        "issue": {"number": number, "node_id": "I_live", "updated_at": "2026-10-28T10:00:00Z"},
        "label": {"name": "factory"},
    }))
    .expect("json");
    let reply = env
        .send(env.delivery("issues", "0190a3b2-7c4d-4e5f-8a6b-0000000000aa", &body))
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
}

fn status_of(
    view: &factory_workflow::engine::JobView,
    kind: StageKind,
) -> Option<factory_domain::state::StageRunStatus> {
    view.newest(kind).map(|run| run.status)
}

#[test]
#[ignore = "needs the Docker daemon, the pinned images and the shared network lock; see the head of the file"]
fn a_labelled_issue_goes_through_the_real_adapters_to_a_draft_pull_request_and_an_approval() {
    live(the_whole_job());
}

async fn the_whole_job() {
    use factory_domain::state::{JobStatus, StageRunStatus, Status as _};
    let Setup {
        lab,
        github,
        registry,
        world,
        env,
    } = setup("").await;
    let requester = full::token_from_file(&env, "requester", &env.a.requester.token.clone());
    let approver = full::token_from_file(&env, "approver", &env.a.approver.token.clone());
    let repo = env.a.full_name.clone();
    let issue = github.fake.add_issue(
        &repo,
        "Add a --json flag",
        "Please add a --json flag to the word count tool so other programs can read the counts.",
        "requester-one",
        &["factory"],
    );
    let main_before = github.tip("main").expect("main exists");
    let rig = live::LiveRig::start(&lab, env, world, &github).await;
    label_the_issue(&rig.env, issue).await;
    let job = full::job_of(&rig.env, &requester).await;
    let started = std::time::Instant::now();

    // 1. To the first question: the specification draft waits for a person.
    let view = rig
        .drive(job, 1500, |view| {
            status_of(view, StageKind::Specification) == Some(StageRunStatus::WaitingForHuman)
                || full::stopped(view)
        })
        .await
        .expect("a view of the job");
    full::print_states("first question", &view);
    if status_of(&view, StageKind::Specification) != Some(StageRunStatus::WaitingForHuman) {
        rig.dump(job).await;
        println!("PROVIDER {:#?}", lab.provider.seen());
    }
    assert_eq!(
        status_of(&view, StageKind::Specification),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );

    // 2. The approver approves the draft through the API.
    rig.dump(job).await;
    println!("PROVIDER {:#?}", lab.provider.seen());
    let run = full::stage_run_of(&view, StageKind::Specification);
    let head = rig.spec_draft_commit(job, run).await;
    let evidence = rig.ledger_head(job, StageKind::Specification, run).await;
    let reply = full::decide(
        &rig.env,
        &approver,
        job,
        "approve-specification-1",
        serde_json::json!({
            "verb": "approve", "stage_run_id": run.as_text(), "head": head,
            "evidence": evidence.as_str(),
            "reason": "The specification says what the issue asked for.",
        }),
    )
    .await;
    assert_eq!(reply.status, 202, "{}", reply.text());

    // 3. To the second question: the pull request waits for a person.
    let view = rig
        .drive(job, 2400, |view| {
            status_of(view, StageKind::Approval) == Some(StageRunStatus::WaitingForHuman)
                || (full::stopped(view)
                    && status_of(view, StageKind::Specification)
                        != Some(StageRunStatus::WaitingForHuman))
        })
        .await
        .expect("a view of the job");
    full::print_states("second question", &view);
    if status_of(&view, StageKind::Approval) != Some(StageRunStatus::WaitingForHuman) {
        rig.dump(job).await;
        println!("PROVIDER {:#?}", lab.provider.seen());
    }
    assert_eq!(
        status_of(&view, StageKind::Approval),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );

    // 4. The approver approves the pull request, naming the head they saw.
    use factory_workflow::stages::approval::ApprovalSources as _;
    let run = full::stage_run_of(&view, StageKind::Approval);
    let request = rig
        .approvals
        .request(rig.tenant, run)
        .await
        .expect("the approval stage stored its request");
    let evidence = rig.ledger_head(job, StageKind::Approval, run).await;
    let reply = full::decide(
        &rig.env,
        &approver,
        job,
        "approve-pull-request-1",
        serde_json::json!({
            "verb": "approve", "stage_run_id": run.as_text(),
            "head": request.pr_head.as_str(), "evidence": evidence.as_str(),
            "reason": "The change does what the issue asked.",
        }),
    )
    .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let view = rig
        .drive(job, 600, |view| {
            view.status == JobStatus::Completed || view.status.is_terminal()
        })
        .await
        .expect("a view of the job");
    full::print_states("after the second approval", &view);
    if view.status != JobStatus::Completed {
        rig.dump(job).await;
    }
    assert_eq!(view.status, JobStatus::Completed, "{view:#?}");
    let took = started.elapsed();

    // ---- what the run left ----------------------------------------------------------------
    // One open draft pull request on the (fake) GitHub, whose head is the commit the worker's own
    // git pushed, above the base, and nothing merged.
    let pulls = github.fake.pull_numbers(&repo);
    assert_eq!(pulls.len(), 1, "{pulls:?}");
    let pull = github
        .fake
        .pull_json(&repo, pulls[0])
        .expect("the pull request");
    assert_eq!(pull["draft"], serde_json::json!(true));
    assert_eq!(pull["state"], serde_json::json!("open"));
    assert_eq!(pull["merged"], serde_json::json!(false));
    let head_branch = pull["head"]["ref"].as_str().expect("a head branch");
    assert!(head_branch.starts_with("factory/"), "{head_branch}");
    let pushed = github
        .tip(head_branch)
        .expect("the branch was pushed to the remote");
    assert_eq!(
        request.pr_head.as_str(),
        pushed,
        "the approval named the pushed head"
    );
    assert_eq!(
        github.tip("main"),
        Some(main_before),
        "the base branch did not move"
    );
    assert!(
        github.fake.merge_attempts().is_empty(),
        "nothing tried to merge"
    );

    // Only the model's answers and GitHub's server were faked: the report says what ran.
    // The reviewer is another family than the builder, on the wire: the provider saw the code
    // reviewer on the other runtime, and the builder on Claude Code.
    let seen = lab.provider.seen();
    let model_of = |agent: &str| {
        seen.iter()
            .find(|request| request.agent == agent)
            .map(|request| request.model.clone())
            .unwrap_or_else(|| panic!("the provider saw no request of {agent}"))
    };
    assert_eq!(model_of("builder"), "claude-sonnet-5-5");
    assert_eq!(model_of("code-reviewer"), "gpt-6.1-sol");
    assert_eq!(model_of("documentation-reviewer"), "gpt-6.1-sol");
    assert!(
        lab.playbook.misses().is_empty(),
        "the playbook answered every call it was asked: {:?}",
        lab.playbook.misses()
    );

    // The tokens of the (fake) GitHub: each narrowed to the one repository, none holding a
    // permission the policy forbids, and all revoked once the job is over.
    for mint in github.fake.mints() {
        assert_eq!(
            mint.requested_repositories.as_deref().map(<[String]>::len),
            Some(1),
            "{mint:?}"
        );
        for forbidden in [
            "organization_administration",
            "workflows",
            "secrets",
            "environments",
        ] {
            assert!(
                !mint.granted_permissions.contains_key(forbidden),
                "{forbidden} in {mint:?}"
            );
        }
        // `administration: read` is allowed since 2026-11-12, for the classic protection read
        // only; never a higher level.
        assert!(
            mint.granted_permissions
                .get("administration")
                .is_none_or(|level| level == "read"),
            "{mint:?}"
        );
    }
    rig.revoke_ended_jobs().await;
    let live_tokens: Vec<_> = github
        .fake
        .tokens()
        .into_iter()
        .filter(|token| token.revoked_at.is_none())
        .collect();
    assert!(live_tokens.is_empty(), "tokens left live: {live_tokens:?}");
    // Both checks of the factory were published by the App on the head the approval named.
    let checks = github.checks();
    for name in ["factory-validation", "factory-review"] {
        assert!(
            checks.iter().any(|check| check.name == name
                && check.head_sha == pushed
                && check.conclusion.as_deref() == Some("success")),
            "{name}: {checks:?}"
        );
    }

    println!("LIVE-RUN took {took:.1?}");
    for (stage, took) in rig.durations() {
        println!("LIVE-RUN stage {stage}: {took:.1?}");
    }
    println!("LIVE-RUN provider requests: {:#?}", lab.provider.seen());
    println!(
        "LIVE-RUN create retries: {}",
        live::CREATE_RETRIES.load(std::sync::atomic::Ordering::SeqCst)
    );
    println!("LIVE-RUN check runs: {:#?}", github.checks());
    let _ = (&registry, StageRunStatus::Passed);
}

#[test]
#[ignore = "needs the Docker daemon, the pinned images and the shared network lock; see the head of the file"]
fn break_a_model_answer_outside_the_recorded_shape_stops_the_job_at_the_stage_that_asked() {
    live(async {
        use factory_domain::state::StageRunStatus;
        // The classifier's answer is a document the schema does not describe. It travels the whole
        // wire: the fake provider, the real broker, the sidecar, the real tool in the real
        // container, the adapter, the engine's schema check.
        let set = setup_with("", |playbook| {
            playbook.replace(
                "intake-classifier",
                playbook::Reply {
                    entry: "intake-classifier".to_owned(),
                    output: serde_json::json!({"unexpected": true, "classification": "yes"}),
                    writes: Vec::new(),
                    script: None,
                },
            );
        })
        .await;
        let Setup {
            lab,
            github,
            registry,
            world,
            env,
        } = set;
        let requester = full::token_from_file(&env, "requester", &env.a.requester.token.clone());
        let issue = github.fake.add_issue(
            &env.a.full_name,
            "Add a --json flag",
            "Please add a --json flag to the word count tool.",
            "requester-one",
            &["factory"],
        );
        let rig = live::LiveRig::start(&lab, env, world, &github).await;
        label_the_issue(&rig.env, issue).await;
        let job = full::job_of(&rig.env, &requester).await;
        let view = rig
            .drive(job, 300, full::stopped)
            .await
            .expect("a view of the job");
        let intake = status_of(&view, StageKind::Intake);
        println!("BREAK intake {intake:?}, job {:?}", view.status);
        assert_ne!(intake, Some(StageRunStatus::Passed), "{view:#?}");
        for later in [
            StageKind::RepositoryIntelligence,
            StageKind::Specification,
            StageKind::Implementation,
            StageKind::Delivery,
        ] {
            assert_ne!(
                status_of(&view, later),
                Some(StageRunStatus::Passed),
                "{later:?} ran after a classifier answer the schema refuses"
            );
        }
        // The wrong answer reached the engine over the real wire, and nothing was published.
        let seen = lab.provider.seen();
        assert!(
            seen.iter()
                .any(|request| request.agent == "intake-classifier")
        );
        assert!(github.fake.pull_numbers(&github_repo(&rig)).is_empty());
        let _ = &registry;
    });
}

fn github_repo(rig: &live::LiveRig) -> String {
    rig.env.a.full_name.clone()
}
