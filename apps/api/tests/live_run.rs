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
    let playbook = Playbook::word_count(&live::root());
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
    let world = build_world(&lab, &env, &text, store, artifacts, None).await;
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
