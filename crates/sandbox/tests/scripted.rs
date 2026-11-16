//! The supervisor against a scripted `docker` (no daemon, no process). These tests pin the
//! decisions the supervisor makes: what it sends, what it refuses, and what it removes.

mod support;

use std::sync::Arc;
use std::time::Duration;

use factory_ports::clock::CancelSignal;
use factory_ports::process::{ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest};
use factory_ports::sandbox::{
    Confinement, ImageDigest, Namespace, NetworkAttachment, ProvisionStage, SandboxError,
    SandboxProfile, SandboxProvider, SandboxSpec, TeardownReason,
};
use factory_sandbox::container::args::{CreatePlan, allowed_binds, create_args};
use factory_sandbox::container::names::{Kind, SandboxNames, labels};
use factory_sandbox::container::posture::denied_flag_in_allowing;
use factory_testkit::clock::FakeCancel;
use factory_testkit::fx::rng::FxRng;
use serde_json::{Value, json};
use support::sim::Sim;
use support::{Scratch, World, attempt, config, host_workspace, images_json_with_stand_in_sidecar};

const WALL: Duration = Duration::from_secs(120);

struct Rig {
    sim: Arc<Sim>,
    world: World,
    tokens: Scratch,
}

fn rig_with(images_json: &str, apparmor_ok: bool) -> Rig {
    let sim = Sim::new();
    let tokens = Scratch::new("tokens");
    let world = support::provider(
        config(
            images_json,
            tokens.path().join("root"),
            vec![("owner.test".to_owned(), "scripted".to_owned())],
            apparmor_ok,
        ),
        Arc::clone(&sim) as Arc<dyn ProcessRunner>,
    );
    Rig { sim, world, tokens }
}

fn new_rig() -> Rig {
    rig_with(&images_json_with_stand_in_sidecar(), false)
}

fn make_spec(profile: SandboxProfile) -> (SandboxSpec, support::HostWorkspace) {
    let host = host_workspace(profile == SandboxProfile::Verify, &[".github"]);
    let catalog = support::catalog(&images_json_with_stand_in_sidecar());
    let spec = support::spec(profile, &catalog, &host.mounts, attempt(1), WALL);
    (spec, host)
}

fn token_dir_entries(rig: &Rig) -> usize {
    std::fs::read_dir(rig.tokens.path().join("root")).map_or(0, Iterator::count)
}

async fn create(
    rig: &Rig,
    spec: SandboxSpec,
) -> Result<Box<dyn factory_ports::sandbox::SandboxSession>, SandboxError> {
    rig.world
        .provider
        .create_verified(spec, &FakeCancel::new())
        .await
}

// ---- spawn plumbing: arrays through the port, nothing else ----------------------------------

#[tokio::test]
async fn every_docker_call_goes_through_the_port_as_an_argument_array() {
    let rig = new_rig();
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    let session = create(&rig, spec).await.expect("a sandbox");
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    let calls = rig.sim.calls();
    assert!(calls.len() >= 6, "{} calls", calls.len());
    for call in &calls {
        assert_eq!(call.program, Program::Docker);
        assert!(call.cwd.is_none());
        assert!(
            call.args.iter().all(|a| !a.contains('\0')),
            "a NUL in {:?}",
            call.args
        );
    }
    let create_call = calls
        .iter()
        .find(|c| c.args[0] == "create")
        .expect("a create");
    for flag in ["--read-only", "--init"] {
        assert!(create_call.args.iter().any(|a| a == flag), "{flag}");
    }
    let at = create_call
        .args
        .iter()
        .position(|a| a == "--cap-drop")
        .expect("cap-drop");
    assert_eq!(
        create_call.args[at + 1],
        "ALL",
        "the value is its own argument"
    );
}

#[test]
fn only_process_rs_names_a_spawning_path() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    let mut offenders = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name().is_some_and(|n| n != "process.rs")
            {
                let text = std::fs::read_to_string(&path).expect("read");
                if [
                    "tokio::process",
                    "std::process::Command",
                    "std::process::Child",
                    "std::process::Stdio",
                    "std::os::unix::process",
                ]
                .iter()
                .any(|needle| text.contains(needle))
                {
                    offenders.push(path);
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "spawning paths outside process.rs: {offenders:?}"
    );
}

// ---- denied_flags_are_never_emitted -----------------------------------------------------------

/// Every flag the builder may write. Anything else in a vector is a defect.
const ALLOWED_FLAGS: &[&str] = &[
    "--pull=never",
    "--name",
    "--label",
    "--user",
    "--read-only",
    "--cap-drop",
    "--security-opt",
    "--init",
    "--ipc",
    "--pids-limit",
    "--memory",
    "--memory-swap",
    "--cpus",
    "--ulimit",
    "--network",
    "--log-driver",
    "--stop-timeout",
    "--restart",
    "--workdir",
    "--env",
    "--tmpfs",
    "--mount",
];

fn random_spec(rng: &mut FxRng, base: &SandboxSpec) -> SandboxSpec {
    let mut spec = base.clone();
    let h = &mut spec.hardening;
    if rng.below(24) == 0 {
        h.privileged = true;
    }
    if rng.below(24) == 0 {
        h.cap_add.push("SYS_ADMIN".to_owned());
    }
    if rng.below(24) == 0 {
        h.cap_drop_all = false;
    }
    if rng.below(24) == 0 {
        h.uid = 0;
    }
    if rng.below(24) == 0 {
        h.gid = 0;
    }
    if rng.below(24) == 0 {
        h.read_only_rootfs = false;
    }
    if rng.below(24) == 0 {
        h.no_new_privileges = false;
    }
    if rng.below(24) == 0 {
        h.seccomp = Confinement::Unconfined;
    }
    if rng.below(24) == 0 {
        h.apparmor = [Confinement::Unconfined, Confinement::NotAvailable][rng.below(2)];
    }
    let namespaces = [Namespace::Private, Namespace::None, Namespace::Host];
    if rng.below(24) == 0 {
        h.pid = namespaces[rng.below(3)];
    }
    if rng.below(24) == 0 {
        h.ipc = namespaces[rng.below(3)];
    }
    if rng.below(24) == 0 {
        h.uts = namespaces[rng.below(3)];
    }
    if rng.below(24) == 0 {
        h.userns = namespaces[rng.below(3)];
    }
    if rng.below(24) == 0 {
        h.devices.push("/dev/kvm".to_owned());
    }
    if rng.below(24) == 0 {
        h.sysctls.push("net.ipv4.ip_forward=1".to_owned());
    }
    if rng.below(24) == 0 {
        h.init = false;
    }
    if rng.below(24) == 0 {
        h.log_driver_none = false;
    }
    // Hostile text in the places that become mount and label values.
    let hostile = [
        ",readonly=false",
        "a\"b",
        "x\ny",
        "../..",
        "/var/run/docker.sock",
        " --privileged",
    ];
    if rng.below(12) == 0 {
        let path = format!("/Users/test/{}", hostile[rng.below(hostile.len())]);
        spec.mounts.workspace.workspace = path.into();
    }
    if rng.below(12) == 0 {
        let value = format!("v{}", hostile[rng.below(hostile.len())]);
        spec.env =
            factory_ports::sandbox::FixedEnv::new(vec![("HOME".to_owned(), value)]).expect("env");
    }
    spec
}

#[test]
fn denied_flags_are_never_emitted() {
    let catalog = support::catalog(&images_json_with_stand_in_sidecar());
    let host = host_workspace(false, &[".github"]);
    let base = support::spec(
        SandboxProfile::Agent,
        &catalog,
        &host.mounts,
        attempt(1),
        WALL,
    );
    let policy = support::policy(true);
    let token = base.job_token.is_some();
    let mut rng = FxRng::from_seed(0x5eed);
    let (mut built, mut refused, mut policy_refused_and_built) = (0, 0, 0);
    for _ in 0..4000 {
        let spec = random_spec(&mut rng, &base);
        let names = SandboxNames::from_suffix("0a1b2c3d-4e5f6a7b-89abcdef");
        let spec_labels = labels(Kind::Sandbox, &spec, Some("egress"), &[]);
        let token_path = std::path::PathBuf::from("/Users/test/token");
        let plan = CreatePlan {
            container: &names.container,
            image: spec.image.reference(),
            network: Some(&names.network),
            labels: &spec_labels,
            token_file: token.then_some(token_path.as_path()),
            cache_dirs: &[],
        };
        match create_args(&spec, &plan) {
            Ok(args) => {
                built += 1;
                assert_eq!(
                    denied_flag_in_allowing(&args, &allowed_binds(&spec, &plan)),
                    None,
                    "{args:?}"
                );
                for arg in args.iter().filter(|a| a.starts_with('-')) {
                    let flag = arg.split('=').next().unwrap_or(arg);
                    assert!(
                        ALLOWED_FLAGS.contains(&arg.as_str()) || ALLOWED_FLAGS.contains(&flag),
                        "a flag outside the allow list: {arg}"
                    );
                }
                // A vector that was built is never one the policy would have refused for a
                // weaker hardening setting.
                if spec.validate(&policy).is_err() {
                    policy_refused_and_built += 1;
                    let h = &spec.hardening;
                    assert!(
                        !h.privileged
                            && h.cap_add.is_empty()
                            && h.cap_drop_all
                            && h.read_only_rootfs
                            && h.no_new_privileges
                            && h.seccomp == Confinement::RuntimeDefault
                            && h.uid != 0
                            && h.gid != 0
                            && h.devices.is_empty()
                            && h.sysctls.is_empty()
                            && h.init
                            && h.log_driver_none
                            && h.pid == Namespace::Private
                            && h.uts == Namespace::Private
                            && h.userns == Namespace::Private
                            && h.ipc != Namespace::Host
                            && h.apparmor != Confinement::Unconfined,
                        "the builder translated a weaker spec: {h:?}"
                    );
                }
            }
            Err(_) => refused += 1,
        }
    }
    assert!(
        built > 100 && refused > 100,
        "built {built}, refused {refused}"
    );
    // Policy-refused specs that still build are those that differ only in places the policy
    // checks and the builder does not translate (limits, paths the policy forbids); the flags
    // they produce are still clean.
    let _ = policy_refused_and_built;
}

// ---- NT-SBX-01: the posture verifier rejects each forbidden setting ---------------------------

type Edit = fn(&mut Value);

fn host_config(doc: &mut Value) -> &mut Value {
    &mut doc["HostConfig"]
}

#[tokio::test]
async fn negative_nt_sbx_01_each_forbidden_setting_is_refused_before_the_start() {
    let cases: Vec<(&str, Edit, &str)> = vec![
        (
            "privileged",
            |d| host_config(d)["Privileged"] = true.into(),
            "privileged",
        ),
        (
            "a capability added",
            |d| host_config(d)["CapAdd"] = json!(["NET_ADMIN"]),
            "cap_add",
        ),
        (
            "capabilities kept",
            |d| host_config(d)["CapDrop"] = Value::Null,
            "cap_drop_all",
        ),
        (
            "seccomp unconfined",
            |d| host_config(d)["SecurityOpt"] = json!(["no-new-privileges", "seccomp=unconfined"]),
            "seccomp",
        ),
        (
            "apparmor unconfined",
            |d| d["AppArmorProfile"] = "unconfined".into(),
            "apparmor",
        ),
        (
            "another apparmor profile",
            |d| d["AppArmorProfile"] = "my-profile".into(),
            "apparmor",
        ),
        (
            "host network",
            |d| {
                host_config(d)["NetworkMode"] = "host".into();
                d["NetworkSettings"]["Networks"] = json!({"host": {}});
            },
            "network",
        ),
        (
            "default bridge",
            |d| {
                host_config(d)["NetworkMode"] = "bridge".into();
                d["NetworkSettings"]["Networks"] = json!({"bridge": {}});
            },
            "network",
        ),
        (
            "host pid",
            |d| host_config(d)["PidMode"] = "host".into(),
            "pid",
        ),
        (
            "host ipc",
            |d| host_config(d)["IpcMode"] = "host".into(),
            "ipc",
        ),
        (
            "host user namespace",
            |d| host_config(d)["UsernsMode"] = "host".into(),
            "userns",
        ),
        (
            "host uts",
            |d| host_config(d)["UTSMode"] = "host".into(),
            "uts",
        ),
        (
            "a device",
            |d| host_config(d)["Devices"] = json!([{"PathOnHost": "/dev/kvm"}]),
            "devices",
        ),
        (
            "a sysctl",
            |d| host_config(d)["Sysctls"] = json!({"net.ipv4.ip_forward": "1"}),
            "sysctls",
        ),
        (
            "the daemon socket mounted",
            |d| {
                d["Mounts"].as_array_mut().expect("mounts").push(
            json!({"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": true}))
            },
            "mounts",
        ),
        (
            "/etc mounted",
            |d| {
                d["Mounts"].as_array_mut().expect("mounts").push(
            json!({"Type": "bind", "Source": "/etc", "Destination": "/host-etc", "RW": false}))
            },
            "mounts",
        ),
        (
            "a writable mask",
            |d| {
                for m in d["Mounts"].as_array_mut().expect("mounts") {
                    if m["Destination"] == "/workspace/.git" {
                        m["RW"] = true.into();
                    }
                }
            },
            "mounts",
        ),
        ("user root", |d| d["Config"]["User"] = "0:0".into(), "uid"),
        (
            "an unnamed user",
            |d| d["Config"]["User"] = "agent".into(),
            "uid",
        ),
        (
            "a writable root",
            |d| host_config(d)["ReadonlyRootfs"] = false.into(),
            "read_only_rootfs",
        ),
        (
            "privilege escalation allowed",
            |d| host_config(d)["SecurityOpt"] = json!([]),
            "no_new_privileges",
        ),
        (
            "restart always",
            |d| host_config(d)["RestartPolicy"]["Name"] = "always".into(),
            "restart_policy",
        ),
        (
            "auto remove",
            |d| host_config(d)["AutoRemove"] = true.into(),
            "auto_remove",
        ),
        (
            "log driver json-file",
            |d| host_config(d)["LogConfig"]["Type"] = "json-file".into(),
            "log_driver_none",
        ),
        ("no init", |d| host_config(d)["Init"] = false.into(), "init"),
        (
            "no pids limit",
            |d| host_config(d)["PidsLimit"] = 0.into(),
            "limits",
        ),
        (
            "no memory limit",
            |d| host_config(d)["Memory"] = 0.into(),
            "limits",
        ),
        (
            "a different pids limit",
            |d| host_config(d)["PidsLimit"] = 999.into(),
            "limits",
        ),
        (
            "no nofile limit",
            |d| host_config(d)["Ulimits"] = json!([]),
            "limits",
        ),
        (
            "the process limit is soft only",
            |d| {
                for u in host_config(d)["Ulimits"].as_array_mut().expect("u") {
                    if u["Name"] == "nofile" {
                        u["Hard"] = 99_999.into();
                    }
                }
            },
            "limits",
        ),
        (
            "a writable, executable scratch",
            |d| host_config(d)["Tmpfs"]["/tmp"] = "rw,size=64m".into(),
            "mounts",
        ),
        (
            "LD_PRELOAD in the environment",
            |d| {
                d["Config"]["Env"]
                    .as_array_mut()
                    .expect("env")
                    .push("LD_PRELOAD=/x.so".into())
            },
            "env",
        ),
        (
            "RUSTFLAGS in the environment",
            |d| {
                d["Config"]["Env"]
                    .as_array_mut()
                    .expect("env")
                    .push("RUSTFLAGS=-Cx".into())
            },
            "env",
        ),
        (
            "a name outside the list",
            |d| {
                d["Config"]["Env"]
                    .as_array_mut()
                    .expect("env")
                    .push("EXTRA=1".into())
            },
            "env",
        ),
        (
            "a published port",
            |d| host_config(d)["PortBindings"] = json!({"80/tcp": [{"HostPort": "80"}]}),
            "port_bindings",
        ),
        (
            "system paths unmasked",
            |d| host_config(d)["MaskedPaths"] = json!([]),
            "masked_paths",
        ),
        (
            "volumes from another container",
            |d| host_config(d)["VolumesFrom"] = json!(["other"]),
            "volumes_from",
        ),
        (
            "a different image",
            |d| {
                d["Config"]["Image"] =
                    format!("factory-sandbox/verify@sha256:{}", "e".repeat(64)).into()
            },
            "image",
        ),
        (
            "the image id is not the catalog's",
            |d| d["Image"] = "sha256:00".into(),
            "image",
        ),
        (
            "the container already runs",
            |d| d["State"]["Status"] = "running".into(),
            "state",
        ),
    ];
    for (what, edit, field) in cases {
        let rig = new_rig();
        rig.sim.mutate(move |doc, kind| {
            if kind == "sandbox" {
                edit(doc);
            }
        });
        let (spec, _host) = make_spec(SandboxProfile::Verify);
        let outcome = create(&rig, spec).await;
        match outcome {
            Err(SandboxError::PostureMismatch(diff)) => assert!(
                diff.fields.contains(&field),
                "{what}: expected {field} in {:?}",
                diff.fields
            ),
            Err(other) => panic!("{what}: expected PostureMismatch, got {other:?}"),
            Ok(_) => panic!("{what}: the supervisor returned a sandbox"),
        }
        assert!(
            rig.sim.started().is_empty(),
            "{what}: a container was started: {:?}",
            rig.sim.started()
        );
        assert!(
            rig.sim.removed().iter().any(|n| n.starts_with("sf-")),
            "{what}: the container was not removed: {:?}",
            rig.sim.removed()
        );
    }
}

#[tokio::test]
async fn negative_nt_sbx_01_a_container_the_policy_allows_is_started_after_the_inspect() {
    let rig = new_rig();
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    let session = create(&rig, spec).await.expect("a sandbox");
    let name = session.id().as_str().to_owned();
    assert!(
        rig.sim.inspected_before_started(&name),
        "inspected while still created"
    );
    assert!(rig.sim.started().contains(&name));
    let verbs = rig.sim.verbs();
    let at = |verb: &str| verbs.iter().position(|v| v == verb).expect(verb);
    assert!(
        at("create") < at("inspect") && at("inspect") < at("start") && at("start") < at("exec")
    );
}

// ---- NT-SBX-02: the runtime self-check ---------------------------------------------------------

#[tokio::test]
async fn negative_nt_sbx_02_each_bad_runtime_value_keeps_the_workload_from_starting() {
    let good = support::sim::good_status(10_001);
    let cases = [
        ("no seccomp", good.replace("Seccomp:\t2", "Seccomp:\t0")),
        (
            "privileges can grow",
            good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ),
        (
            "capabilities remain",
            good.replace("CapEff:\t0000000000000000", "CapEff:\t00000000a80425fb"),
        ),
        (
            "root",
            good.replace("Uid:\t10001\t10001\t10001\t10001", "Uid:\t0\t0\t0\t0"),
        ),
        ("nothing printed", String::new()),
    ];
    for (what, text) in cases {
        let rig = new_rig();
        rig.sim.self_check_prints(&text);
        let (spec, _host) = make_spec(SandboxProfile::Verify);
        match create(&rig, spec).await {
            Err(SandboxError::PostureMismatch(diff)) => {
                assert_eq!(diff.fields, vec!["self_check"], "{what}")
            }
            other => panic!("{what}: {:?}", other.map(|_| ())),
        }
        assert!(
            rig.sim.removed().iter().any(|n| n.starts_with("sf-")),
            "{what}: the container was not removed"
        );
    }
}

// ---- NT-SUP-05: images run only by digest --------------------------------------------------------

#[tokio::test]
async fn negative_nt_sup_05_a_tag_an_unknown_digest_or_a_missing_image_is_refused() {
    assert!(ImageDigest::parse("factory-sandbox/verify:latest").is_err());
    assert!(ImageDigest::parse("factory-sandbox/verify").is_err());

    // A digest the catalog does not list.
    let rig = new_rig();
    let (mut spec, _host) = make_spec(SandboxProfile::Verify);
    spec.image = ImageDigest::parse(&format!("factory-sandbox/verify@sha256:{}", "d".repeat(64)))
        .expect("digest");
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::ImageUnavailable)
    );
    assert!(!rig.sim.verbs().contains(&"create".to_owned()));

    // A listed image on the wrong profile.
    let rig = new_rig();
    let (mut spec, _host) = make_spec(SandboxProfile::Agent);
    let catalog = support::catalog(&images_json_with_stand_in_sidecar());
    spec.image = catalog
        .reference_for(SandboxProfile::Verify)
        .expect("verify")
        .clone();
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::ImageUnavailable)
    );

    // A listed image that is not on this host.
    let rig = new_rig();
    rig.sim.image_missing();
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::ImageUnavailable)
    );
    assert!(
        !rig.sim.verbs().contains(&"create".to_owned()),
        "nothing is created for a missing image"
    );
}

// ---- NT-SBX-14: fail closed ----------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_sbx_14_a_stopped_daemon_a_bad_catalog_and_a_failed_sidecar_run_nothing() {
    let rig = new_rig();
    rig.sim.daemon_down();
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::DaemonUnavailable)
    );
    assert!(rig.sim.created().is_empty());

    let rig = rig_with("{ not json", false);
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::ImageUnavailable)
    );
    assert!(rig.sim.created().is_empty());

    // A skeleton sidecar (the real catalog with its sidecar put back to the skeleton state)
    // blocks an agent before anything is made.
    let skeleton = support::images_json_with_skeleton_sidecar();
    let rig = rig_with(&skeleton, false);
    let host = host_workspace(false, &[]);
    let spec = support::spec(
        SandboxProfile::Agent,
        &support::catalog(&skeleton),
        &host.mounts,
        attempt(1),
        WALL,
    );
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::ProvisionFailed(ProvisionStage::Network))
    );
    assert!(
        !rig.sim
            .verbs()
            .iter()
            .any(|v| v == "network create" || v == "create"),
        "{:?}",
        rig.sim.verbs()
    );
    assert_eq!(token_dir_entries(&rig), 0);

    // A sidecar that fails to start removes what was made, the token file included.
    let rig = new_rig();
    rig.sim.sidecar_start_fails();
    let (spec, _host) = make_spec(SandboxProfile::Agent);
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::ProvisionFailed(ProvisionStage::Network))
    );
    assert!(rig.sim.started().is_empty());
    let removed = rig.sim.removed();
    assert!(
        removed.iter().any(|n| n.starts_with("sf-side-")),
        "{removed:?}"
    );
    assert!(
        removed.iter().any(|n| n.starts_with("sf-net-")),
        "{removed:?}"
    );
    assert_eq!(token_dir_entries(&rig), 0);
}

// ---- posture covers every part -------------------------------------------------------------------

#[tokio::test]
async fn posture_is_compared_in_every_part_and_apparmor_only_by_policy() {
    // Network: an agent whose container sits on the wrong network.
    let rig = new_rig();
    rig.sim.mutate(|doc, kind| {
        if kind == "sandbox" {
            doc["HostConfig"]["NetworkMode"] = "none".into();
            doc["NetworkSettings"]["Networks"] = json!({"none": {}});
        }
    });
    let (spec, _host) = make_spec(SandboxProfile::Agent);
    match create(&rig, spec).await {
        Err(SandboxError::PostureMismatch(diff)) => assert!(diff.fields.contains(&"network")),
        other => panic!("{:?}", other.map(|_| ())),
    }
    // A daemon without AppArmor: refused on a production policy, accepted where the policy
    // allows it, for a sandbox alone and for one with a sidecar.
    for profile in [SandboxProfile::Verify, SandboxProfile::Agent] {
        for (allowed, accepted) in [(false, false), (true, true)] {
            let rig = rig_with(&images_json_with_stand_in_sidecar(), allowed);
            rig.sim.daemon_without_apparmor();
            let (spec, _host) = make_spec(profile);
            match create(&rig, spec).await {
                Ok(_) => assert!(accepted, "{profile:?}: policy allows {allowed}"),
                Err(SandboxError::PostureMismatch(diff)) => {
                    assert!(!accepted, "{profile:?}: policy allows {allowed}");
                    assert_eq!(diff.fields, vec!["apparmor"], "{profile:?}");
                }
                Err(other) => panic!("{profile:?}: {other:?}"),
            }
        }
    }
}

// ---- AppArmor: the daemon says whether a profile is enforced ----------------------------------------

#[tokio::test]
async fn an_empty_profile_after_the_create_on_a_daemon_with_apparmor_is_accepted_on_production() {
    // Docker 29 on Ubuntu 24.04 reports no profile until the start and applies `docker-default`
    // then. A production policy must accept that, for the sandbox and for the sidecar.
    for profile in [SandboxProfile::Verify, SandboxProfile::Agent] {
        let rig = rig_with(&images_json_with_stand_in_sidecar(), false);
        rig.sim.mutate(|doc, _| doc["AppArmorProfile"] = "".into());
        let (spec, _host) = make_spec(profile);
        let session = create(&rig, spec).await.expect("a sandbox");
        assert_eq!(
            session.posture().observed.apparmor,
            Confinement::RuntimeDefault,
            "{profile:?}"
        );
        session
            .stop_and_remove(TeardownReason::Completed)
            .await
            .expect("teardown");
    }
}

#[tokio::test]
async fn docker_default_reported_by_a_daemon_without_apparmor_is_not_confinement() {
    // Docker Desktop echoes the profile a create named although nothing enforces it.
    let rig = rig_with(&images_json_with_stand_in_sidecar(), false);
    rig.sim.daemon_without_apparmor();
    rig.sim
        .mutate(|doc, _| doc["AppArmorProfile"] = "docker-default".into());
    let (spec, _host) = make_spec(SandboxProfile::Agent);
    match create(&rig, spec).await {
        Err(SandboxError::PostureMismatch(diff)) => assert_eq!(diff.fields, vec!["apparmor"]),
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert!(rig.sim.started().is_empty(), "{:?}", rig.sim.started());
}

#[tokio::test]
async fn the_daemon_is_asked_about_apparmor_once_and_before_anything_is_created() {
    let rig = new_rig();
    for _ in 0..2 {
        let (spec, _host) = make_spec(SandboxProfile::Verify);
        create(&rig, spec)
            .await
            .expect("a sandbox")
            .stop_and_remove(TeardownReason::Completed)
            .await
            .expect("teardown");
    }
    let verbs = rig.sim.verbs();
    let infos: Vec<usize> = (0..verbs.len()).filter(|i| verbs[*i] == "info").collect();
    assert_eq!(infos.len(), 1, "{verbs:?}");
    let first_create = verbs.iter().position(|v| v == "create").expect("a create");
    assert!(infos[0] < first_create, "{verbs:?}");
    let info = &rig.sim.calls()[infos[0]];
    assert_eq!(info.args, ["info", "--format", "{{json .SecurityOptions}}"]);
}

#[tokio::test]
async fn an_unreadable_or_failed_answer_about_apparmor_fails_closed_before_anything_is_created() {
    for answer in [
        "",
        "name=apparmor",
        "{\"name\": \"apparmor\"}",
        "[name=apparmor]",
    ] {
        // The development policy too: an unknown daemon is not a daemon without AppArmor.
        for allowed in [false, true] {
            let rig = rig_with(&images_json_with_stand_in_sidecar(), allowed);
            rig.sim.daemon_security_options(answer);
            let (spec, _host) = make_spec(SandboxProfile::Agent);
            assert_eq!(
                create(&rig, spec).await.err(),
                Some(SandboxError::DaemonUnavailable),
                "{answer:?}"
            );
            assert!(
                !rig.sim
                    .verbs()
                    .iter()
                    .any(|v| v == "create" || v == "network create"),
                "{answer:?}: {:?}",
                rig.sim.verbs()
            );
        }
    }
    let rig = new_rig();
    rig.sim
        .info_fails("Error response from daemon: an internal error");
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::DaemonUnavailable)
    );
    assert!(!rig.sim.verbs().contains(&"create".to_owned()));
    // The failure is not remembered: a later answer is read again.
    rig.sim.info_recovers();
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    create(&rig, spec)
        .await
        .expect("a sandbox once the daemon answers")
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
}

// ---- cancellation, teardown and the token file ------------------------------------------------------

struct CancelOnVerb {
    inner: Arc<Sim>,
    verb: &'static str,
    cancel: Arc<FakeCancel>,
}

#[async_trait::async_trait]
impl ProcessRunner for CancelOnVerb {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        if req.args.first().map(String::as_str) == Some(self.verb) {
            self.cancel.cancel();
        }
        self.inner.run(req, cancel).await
    }
}

#[tokio::test]
async fn a_cancel_during_provisioning_removes_everything_it_made() {
    for verb in ["network", "create", "start"] {
        let sim = Sim::new();
        let tokens = Scratch::new("tokens");
        let cancel = Arc::new(FakeCancel::new());
        let world = support::provider(
            config(
                &images_json_with_stand_in_sidecar(),
                tokens.path().join("root"),
                vec![],
                false,
            ),
            Arc::new(CancelOnVerb {
                inner: Arc::clone(&sim),
                verb,
                cancel: Arc::clone(&cancel),
            }),
        );
        let (spec, _host) = make_spec(SandboxProfile::Agent);
        let outcome = world.provider.create_verified(spec, cancel.as_ref()).await;
        assert_eq!(
            outcome.err(),
            Some(SandboxError::Cancelled),
            "cancel at {verb}"
        );
        let removed = sim.removed();
        assert!(
            removed.iter().any(|n| n.starts_with("sf-net-")),
            "{verb}: {removed:?}"
        );
        assert_eq!(
            std::fs::read_dir(tokens.path().join("root")).map_or(0, Iterator::count),
            0,
            "{verb}"
        );
    }
}

#[tokio::test]
async fn a_cancel_that_is_already_set_makes_no_docker_call_for_the_create() {
    let rig = new_rig();
    let cancel = FakeCancel::new();
    cancel.cancel();
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    let outcome = rig.world.provider.create_verified(spec, &cancel).await;
    assert_eq!(outcome.err(), Some(SandboxError::Cancelled));
    assert!(rig.sim.created().is_empty());
}

#[tokio::test]
async fn teardown_removes_the_container_the_sidecar_the_network_and_the_token_file() {
    let rig = new_rig();
    let (spec, _host) = make_spec(SandboxProfile::Agent);
    let session = create(&rig, spec).await.expect("a sandbox");
    assert_eq!(
        token_dir_entries(&rig),
        1,
        "the token file exists while the sandbox lives"
    );
    let report = session
        .stop_and_remove(TeardownReason::Failed)
        .await
        .expect("teardown");
    assert_eq!(report.reason, TeardownReason::Failed);
    let removed = rig.sim.removed();
    for prefix in ["sf-net-", "sf-side-"] {
        assert!(
            removed.iter().any(|n| n.starts_with(prefix)),
            "{prefix}: {removed:?}"
        );
    }
    assert!(removed.iter().any(|n| n == report.sandbox.as_str()));
    assert_eq!(token_dir_entries(&rig), 0, "the token file is gone");
}

#[tokio::test]
async fn a_token_the_container_cannot_read_stops_the_workload() {
    let rig = new_rig();
    rig.sim.token_reads_as(b"");
    let (spec, _host) = make_spec(SandboxProfile::Agent);
    assert_eq!(
        create(&rig, spec).await.err(),
        Some(SandboxError::ProvisionFailed(ProvisionStage::TokenFile))
    );
    assert_eq!(token_dir_entries(&rig), 0);
}

// ---- NT-SEC-09: nothing secret in what is spawned ------------------------------------------------------

#[tokio::test]
async fn negative_nt_sec_09_no_argument_or_environment_holds_the_job_token() {
    use factory_testkit::fx::canary::{Canary, CanaryKind, CanarySet, Sweeper};
    let mut rng = FxRng::from_seed(9);
    let canary = Canary::generate(CanaryKind::JobToken, &mut rng);
    let mut spec_for = {
        let (spec, host) = make_spec(SandboxProfile::Agent);
        (spec, host)
    };
    spec_for.0.job_token = Some(factory_ports::sandbox::JobTokenMount {
        secret: factory_ports::agent::JobTokenSecret::new(canary.value().to_owned()),
    });
    let rig = new_rig();
    rig.sim.token_reads_as(canary.value().as_bytes());
    let session = create(&rig, spec_for.0).await.expect("a sandbox");
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    let sweeper = Sweeper::new(&CanarySet::generate().with(canary));
    for (index, call) in rig.sim.calls().iter().enumerate() {
        let mut text = call.args.join("\u{1f}");
        for (name, value) in &call.env {
            text.push_str(&format!("\u{1f}{name}={value:?}"));
        }
        let hits = sweeper.scan(&format!("spawn {index}"), text.as_bytes());
        assert!(
            hits.is_empty(),
            "call {index} holds the job token: {:?}",
            call.args
        );
    }
}

#[tokio::test]
async fn the_job_token_is_registered_with_the_redactor_only_while_the_job_lives() {
    // A job that fails closed leaves nothing registered.
    let rig = new_rig();
    rig.sim.mutate(|doc, kind| {
        if kind == "sandbox" {
            doc["HostConfig"]["Privileged"] = true.into();
        }
    });
    let (spec, _host) = make_spec(SandboxProfile::Agent);
    assert!(matches!(
        create(&rig, spec).await,
        Err(SandboxError::PostureMismatch(_))
    ));
    assert_eq!(rig.world.redactor.registered_count(), 0);

    // A job that runs has it registered, and the end of the job forgets it.
    let rig = new_rig();
    let (spec, _host) = make_spec(SandboxProfile::Agent);
    let session = create(&rig, spec).await.expect("a sandbox");
    assert_eq!(rig.world.redactor.registered_count(), 1);
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    assert_eq!(rig.world.redactor.registered_count(), 0);
}

#[test]
fn a_spec_that_names_a_network_for_the_wrong_profile_is_refused_before_any_call() {
    let rig = new_rig();
    let (mut spec, _host) = make_spec(SandboxProfile::Verify);
    spec.network = NetworkAttachment::JobInternal {
        sidecar: "x".to_owned(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let outcome = runtime.block_on(create(&rig, spec));
    assert!(matches!(outcome, Err(SandboxError::PolicyViolation(_))));
    assert!(
        rig.sim.calls().is_empty(),
        "the policy check runs before any docker call"
    );
}

// ---- SBX-3: a disk that cannot be measured is not a disk under its cap -------------------------

fn true_command() -> factory_ports::sandbox::ExecRequest {
    factory_ports::sandbox::ExecRequest {
        argv: factory_ports::sandbox::ExecArgv::new(vec!["true".to_owned()]).expect("argv"),
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(5),
        max_output_bytes: 1024,
    }
}

/// SBX-3. A process that holds the process table full makes every `docker exec` fail, the
/// watchdog's `du` included. The watchdog used to skip a failed measurement for ever, so the disk
/// cap went unenforced while the table was held. Now three failed polls in a row, in a container
/// that is still running, kill it and end the attempt as a resource failure. The control is the
/// same sandbox with a `du` that works: it is not touched.
#[tokio::test]
async fn sbx_3_a_disk_that_keeps_failing_to_be_measured_ends_the_attempt_as_a_resource_failure() {
    let rig = new_rig();
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    let mut session = create(&rig, spec).await.expect("a sandbox");
    rig.sim.du_cannot_start();
    // The watchdog polls every 500 ms in this rig: the third failure comes after about 1.5 s.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let ended = session.exec(true_command(), &FakeCancel::new()).await;
    assert_eq!(
        ended.err(),
        Some(SandboxError::ResourceExceeded(
            factory_ports::sandbox::Resource::Disk
        ))
    );
    assert!(
        rig.sim.verbs().iter().any(|verb| verb == "kill"),
        "the container must have been killed: {:?}",
        rig.sim.verbs()
    );
    let _ = session.stop_and_remove(TeardownReason::Failed).await;
}

#[tokio::test]
async fn sbx_3_control_a_disk_that_is_measured_leaves_the_sandbox_alone() {
    let rig = new_rig();
    let (spec, _host) = make_spec(SandboxProfile::Verify);
    let mut session = create(&rig, spec).await.expect("a sandbox");
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let ran = session.exec(true_command(), &FakeCancel::new()).await;
    assert!(ran.is_ok(), "{ran:?}");
    assert!(
        !rig.sim.verbs().iter().any(|verb| verb == "kill"),
        "{:?}",
        rig.sim.verbs()
    );
    let _ = session.stop_and_remove(TeardownReason::Completed).await;
}
