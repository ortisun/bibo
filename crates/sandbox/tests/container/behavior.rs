//! Adapter-only tests against the real daemon: each hardening setting is in effect inside the
//! container, the networks reach what they should and nothing else, the supervisor enforces the
//! wall clock and the disk cap, teardown and the janitor leave nothing behind, and the token file
//! lives and dies as documented.

use std::sync::Arc;
use std::time::{Duration, Instant};

use factory_ports::sandbox::{
    ExecArgv, ExecRequest, ProvisionStage, Resource, SandboxError, SandboxProfile, SandboxProvider,
    TeardownReason,
};
use factory_sandbox::SystemProcessRunner;
use factory_sandbox::container::images::ImageCatalog;
use factory_testkit::clock::FakeCancel;
use factory_testkit::contracts::sandbox::DriftPart;
use factory_testkit::fx::canary::{Canary, CanaryKind, CanarySet, Sweeper};
use factory_testkit::fx::rng::FxRng;
use factory_testkit::fx::spawn::{Behavior, SpawnPolicy, SpawnRecorder};

use crate::harness::{DriftRunner, Lab, daemon_lacks_apparmor};
use crate::support::{self, Scratch, attempt};

const WALL: Duration = Duration::from_secs(120);

fn agent_words(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_owned()).collect()
}

fn exec_request(words: &[&str], timeout: Duration) -> ExecRequest {
    ExecRequest {
        argv: ExecArgv::new(agent_words(words)).expect("argv"),
        cwd: None,
        stdin: None,
        timeout,
        max_output_bytes: 1024 * 1024,
    }
}

// ---- NT-SBX-06: every hardening setting is in effect inside the container --------------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_06_read_only_root_tmpfs_capabilities_and_masked_paths_hold() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Verify, 1, WALL))
        .await
        .expect("a verify sandbox");

    let status = lab.run(&mut *session, &["cat", "/proc/self/status"]).await;
    let (text, _) = lab.text(&status).await;
    for (field, wanted) in [
        ("Uid:", "10001\t10001\t10001\t10001"),
        ("NoNewPrivs:", "1"),
        ("Seccomp:", "2"),
        ("CapEff:", "0000000000000000"),
        ("CapBnd:", "0000000000000000"),
    ] {
        let line = text
            .lines()
            .find(|l| l.starts_with(field))
            .unwrap_or("<missing>");
        assert_eq!(line[field.len()..].trim(), wanted, "{field} in {text}");
    }

    // A write outside the allowed paths fails; the scratch tmpfs works but cannot execute.
    for path in ["/x", "/usr/x", "/etc/x", "/home/x"] {
        let attempt = lab.run(&mut *session, &["touch", path]).await;
        let (_, err) = lab.text(&attempt).await;
        assert_ne!(attempt.exit_code, Some(0), "{path}");
        assert!(err.contains("Read-only file system"), "{path}: {err}");
    }
    assert_eq!(
        lab.run(&mut *session, &["touch", "/tmp/ok"])
            .await
            .exit_code,
        Some(0)
    );
    assert_eq!(
        lab.run(&mut *session, &["cp", "/bin/true", "/tmp/t"])
            .await
            .exit_code,
        Some(0)
    );
    let exec_from_tmp = lab.run(&mut *session, &["/tmp/t"]).await;
    // The docker client prints the runtime's refusal on standard output.
    let (out, err) = lab.text(&exec_from_tmp).await;
    assert_eq!(exec_from_tmp.exit_code, Some(126), "{out}{err}");
    assert!(
        format!("{out}{err}")
            .to_ascii_lowercase()
            .contains("permission denied"),
        "{out}{err}"
    );

    // No capability: chown and mknod are refused although the user owns the file.
    for words in [
        &["chown", "0", "/tmp/ok"][..],
        &["mknod", "/tmp/n", "c", "1", "3"][..],
    ] {
        let result = lab.run(&mut *session, words).await;
        let (_, err) = lab.text(&result).await;
        assert_ne!(result.exit_code, Some(0), "{words:?}");
        assert!(err.contains("Operation not permitted"), "{words:?}: {err}");
    }
    // Kernel paths are masked: the file exists and reads as empty.
    let kcore = lab
        .run(&mut *session, &["head", "-c", "16", "/proc/kcore"])
        .await;
    assert!(
        lab.read(&kcore.stdout).await.is_empty(),
        "/proc/kcore is masked"
    );

    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    assert!(lab.leftovers().is_empty(), "{:?}", lab.leftovers());
}

// ---- NT-SBX-07: limits are in effect; the disk poll kills a writer over the cap -----------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_07_resource_limits_are_in_effect_and_a_memory_hog_is_killed() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Verify, 1, WALL))
        .await
        .expect("a verify sandbox");
    for (path, wanted) in [
        ("/sys/fs/cgroup/pids.max", "128"),
        ("/sys/fs/cgroup/memory.max", "268435456"),
        ("/sys/fs/cgroup/memory.swap.max", "0"),
        ("/sys/fs/cgroup/cpu.max", "100000 100000"),
    ] {
        let result = lab.run(&mut *session, &["cat", path]).await;
        assert_eq!(lab.text(&result).await.0.trim(), wanted, "{path}");
    }
    let limits = lab.run(&mut *session, &["cat", "/proc/self/limits"]).await;
    let (text, _) = lab.text(&limits).await;
    for needle in [
        "Max open files            1024",
        "Max file size             67108864",
        "Max core file size        0",
    ] {
        assert!(text.contains(needle), "{needle} not in {text}");
    }

    // A file above the per-file limit stops its writer with SIGXFSZ.
    let big = lab
        .run(
            &mut *session,
            &["dd", "if=/dev/zero", "of=/out/big", "bs=1M", "count=100"],
        )
        .await;
    assert_eq!(big.signal, Some(25), "SIGXFSZ, got {big:?}");

    // `tail` keeps the last line, and /dev/zero has none: its memory grows until the kernel
    // kills it. The limit is 256 MiB with no swap.
    let hog = lab
        .run_with(
            &mut *session,
            &["tail", "-n", "1", "/dev/zero"],
            Duration::from_secs(60),
            1024,
        )
        .await;
    assert_eq!(hog.signal, Some(9), "{hog:?}");
    assert!(hog.oom_killed, "the kernel killed it for memory: {hog:?}");

    session
        .stop_and_remove(TeardownReason::Failed)
        .await
        .expect("teardown");
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_07_the_disk_poll_kills_a_writer_that_passes_its_cap() {
    let lab = Lab::new(true);
    let mut spec = lab.spec(SandboxProfile::Verify, 1, WALL);
    spec.limits.workspace_disk_mb = support::n(8);
    let mut session = lab.create(spec).await.expect("a verify sandbox");
    // 40 MiB is under the per-file limit and over the 8 MiB cap.
    let wrote = lab
        .run(
            &mut *session,
            &["dd", "if=/dev/zero", "of=/out/fill", "bs=1M", "count=40"],
        )
        .await;
    assert_eq!(wrote.exit_code, Some(0), "{wrote:?}");
    let started = Instant::now();
    let next = session
        .exec(
            exec_request(&["sleep", "60"], Duration::from_secs(120)),
            &FakeCancel::new(),
        )
        .await;
    assert_eq!(
        next.err(),
        Some(SandboxError::ResourceExceeded(Resource::Disk))
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
    // The session stays over: no later command runs.
    let again = session
        .exec(
            exec_request(&["true"], Duration::from_secs(10)),
            &FakeCancel::new(),
        )
        .await;
    assert_eq!(
        again.err(),
        Some(SandboxError::ResourceExceeded(Resource::Disk))
    );
    session
        .stop_and_remove(TeardownReason::Failed)
        .await
        .expect("teardown");
    assert!(lab.leftovers().is_empty());
}

// ---- NT-SBX-08: the wall clock ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_08_the_supervisor_kills_the_container_at_the_wall_clock() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Verify, 1, Duration::from_secs(5)))
        .await
        .expect("a verify sandbox");
    let name = session.id().to_string();
    let started = Instant::now();
    let outcome = session
        .exec(
            exec_request(&["sleep", "600"], Duration::from_secs(600)),
            &FakeCancel::new(),
        )
        .await;
    let elapsed = started.elapsed();
    assert_eq!(outcome.err(), Some(SandboxError::Timeout));
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(9),
        "killed after {elapsed:?}"
    );
    let state = lab
        .scope
        .cli()
        .run(&[
            "inspect",
            "--format",
            "{{.State.Running}} {{.State.ExitCode}}",
            &name,
        ])
        .expect("inspect");
    assert_eq!(state.stdout.trim(), "false 137", "killed, not stopped");
    session
        .stop_and_remove(TeardownReason::TimedOut)
        .await
        .expect("teardown");
}

// ---- NT-SBX-03 and NT-SBX-04: networks --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_03_the_verify_profile_has_no_network() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Verify, 1, WALL))
        .await
        .expect("a verify sandbox");
    let devices = lab.run(&mut *session, &["cat", "/proc/net/dev"]).await;
    let (text, _) = lab.text(&devices).await;
    let names: Vec<&str> = text
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next())
        .map(str::trim)
        .collect();
    assert!(names.contains(&"lo"), "{names:?}");
    assert!(
        names.iter().all(|n| *n == "lo"
            || n.starts_with("tunl")
            || n.starts_with("sit")
            || n.starts_with("ip6tnl")
            || n.starts_with("gre")
            || n.starts_with("ip_vti")
            || n.starts_with("ip6_vti")
            || n.starts_with("ip6gre")
            || n.starts_with("erspan")),
        "an interface a network would have: {names:?}"
    );
    let routes = lab.run(&mut *session, &["cat", "/proc/net/route"]).await;
    let (table, _) = lab.text(&routes).await;
    assert_eq!(
        table.lines().count(),
        1,
        "only the header: no route at all\n{table}"
    );
    assert_eq!(
        session.posture().network,
        factory_ports::sandbox::NetworkAttachment::None
    );
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
}

fn connect_attempt(host: &str, port: u16) -> Vec<String> {
    // `bash` is in the agent image only. Its /dev/tcp is the network client.
    agent_words(&[
        "timeout",
        "10",
        "bash",
        "-c",
        &format!("exec 3<>/dev/tcp/{host}/{port}"),
    ])
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_04_an_agent_on_its_job_network_reaches_no_other_job_no_external_address_and_no_metadata_address()
 {
    let lab = Lab::new(true);
    let mut a = lab
        .create(lab.spec(SandboxProfile::Agent, 1, WALL))
        .await
        .expect("job A");
    let b = lab
        .create(lab.spec(SandboxProfile::Agent, 2, WALL))
        .await
        .expect("job B");
    // Job B's address on its own network, as Docker reports it.
    let b_ip = lab
        .scope
        .cli()
        .run(&[
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &b.id().to_string(),
        ])
        .expect("inspect B")
        .stdout
        .trim()
        .to_owned();
    assert!(!b_ip.is_empty(), "job B has an address");

    let mut refused = Vec::new();
    for (what, host, port) in [
        ("an external address", "1.1.1.1".to_owned(), 443),
        ("the metadata address", "169.254.169.254".to_owned(), 80),
        ("another job's container", b_ip.clone(), 80),
        ("an external name", "example.com".to_owned(), 80),
    ] {
        let words = connect_attempt(&host, port);
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let result = lab
            .run_with(&mut *a, &refs, Duration::from_secs(30), 4096)
            .await;
        let (_, err) = lab.text(&result).await;
        assert_ne!(result.exit_code, Some(0), "{what} was reached from job A");
        refused.push((what, err));
    }
    // The control: A's own sidecar resolves and answers (refused: the stand-in listens on nothing),
    // which is different from "unreachable".
    let words = connect_attempt(support::SIDECAR_ALIAS, 80);
    let refs: Vec<&str> = words.iter().map(String::as_str).collect();
    let own = lab
        .run_with(&mut *a, &refs, Duration::from_secs(30), 4096)
        .await;
    let (_, own_err) = lab.text(&own).await;
    assert!(
        own_err.contains("Connection refused"),
        "A reaches its own sidecar: {own_err}"
    );
    for (what, err) in &refused {
        assert!(!err.contains("Connection refused"), "{what}: {err}");
    }

    a.stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown A");
    b.stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown B");
    assert!(lab.leftovers().is_empty(), "{:?}", lab.leftovers());
}

// ---- NT-SBX-12 and NT-SBX-13: no daemon, no credential -------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_12_no_daemon_socket_is_reachable_and_none_can_be_mounted() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Verify, 1, WALL))
        .await
        .expect("a verify sandbox");
    for path in ["/var/run/docker.sock", "/run/docker.sock"] {
        let result = lab.run(&mut *session, &["ls", path]).await;
        assert_ne!(result.exit_code, Some(0), "{path} exists in the sandbox");
    }
    let mounts = lab.run(&mut *session, &["cat", "/proc/self/mounts"]).await;
    assert!(!lab.text(&mounts).await.0.contains("docker.sock"));
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");

    // A workspace that is the socket is refused before any container exists.
    let mut spec = lab.spec(SandboxProfile::Verify, 2, WALL);
    spec.mounts.workspace.workspace = "/var/run/docker.sock".into();
    assert!(matches!(
        lab.create(spec).await,
        Err(SandboxError::PolicyViolation(_))
    ));
    assert!(lab.leftovers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_13_the_job_token_is_a_file_and_no_other_credential_is_anywhere() {
    let lab = Lab::new(true);
    let mut rng = FxRng::from_seed(13);
    let token = Canary::generate(CanaryKind::JobToken, &mut rng);
    let others = CanarySet::generate_with(&mut rng);
    let mut spec = lab.spec(SandboxProfile::Agent, 1, WALL);
    spec.job_token = Some(factory_ports::sandbox::JobTokenMount {
        secret: factory_ports::agent::JobTokenSecret::new(token.value().to_owned()),
    });
    let mut session = lab.create(spec).await.expect("an agent sandbox");

    let mut sweeper = Sweeper::new(&others);
    sweeper.add(&token);
    let name = session.id().to_string();
    let mut sinks: Vec<(String, String)> = Vec::new();
    for (kind, object) in [
        ("container", name.clone()),
        (
            "network",
            format!("sf-net-{}", name.trim_start_matches("sf-")),
        ),
    ] {
        let doc = lab
            .scope
            .cli()
            .run(&["inspect", "--type", kind, &object])
            .expect("inspect");
        sinks.push((format!("inspect {kind}"), doc.stdout));
    }
    let sidecar = format!("sf-side-{}", name.trim_start_matches("sf-"));
    let doc = lab
        .scope
        .cli()
        .run(&["inspect", "--type", "container", &sidecar])
        .expect("inspect sidecar");
    sinks.push(("inspect sidecar".to_owned(), doc.stdout));
    for words in [
        &["env"][..],
        &["cat", "/proc/1/environ"][..],
        &["cat", "/proc/self/mounts"][..],
    ] {
        let result = lab.run(&mut *session, words).await;
        sinks.push((format!("{words:?}"), lab.text(&result).await.0));
    }
    for (sink, text) in &sinks {
        let hits = sweeper.scan(sink, text.as_bytes());
        assert!(hits.is_empty(), "a credential in {sink}: {hits:?}");
    }
    // The token is there once, as a file, and the container reads it: the supervisor already
    // compared its bytes from inside before it released the workload. What a command prints of it
    // is redacted before it is stored, so the stored text is the marker and not the secret.
    let size = lab
        .run(&mut *session, &["wc", "-c", "/run/factory/job-token"])
        .await;
    assert!(
        lab.text(&size)
            .await
            .0
            .starts_with(&token.value().len().to_string()),
        "the file holds the secret and nothing else"
    );
    let file = lab
        .run(&mut *session, &["cat", "/run/factory/job-token"])
        .await;
    assert_eq!(lab.read(&file.stdout).await, b"[REDACTED:job_token]");
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
}

// ---- NT-SBX-14 and NT-SUP-05: fail closed -------------------------------------------------------------

fn lab_with(docker_env: Vec<(String, String)>, images_json: &str) -> Lab {
    let lab = Lab::new(true);
    let mut config = support::config(
        images_json,
        lab.token_root.clone(),
        vec![(
            factory_testkit::fx::docker::RUN_LABEL_KEY.to_owned(),
            lab.scope.label().value().to_owned(),
        )],
        true,
    );
    config.docker.env = docker_env;
    let world = support::provider(config, Arc::new(SystemProcessRunner::new()));
    Lab {
        world,
        images_json: images_json.to_owned(),
        ..lab
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_14_a_stopped_daemon_a_missing_image_and_a_skeleton_sidecar_run_nothing() {
    // The daemon cannot be reached: the client is pointed at a socket nobody listens on.
    let lab = lab_with(
        vec![(
            "DOCKER_HOST".to_owned(),
            "unix:///nonexistent/docker.sock".to_owned(),
        )],
        &support::images_json_with_stand_in_sidecar(),
    );
    let outcome = lab.create(lab.spec(SandboxProfile::Verify, 1, WALL)).await;
    assert_eq!(outcome.err(), Some(SandboxError::DaemonUnavailable));

    // The docker program is not installed.
    let config = support::config(
        &support::images_json_with_stand_in_sidecar(),
        lab.token_root.clone(),
        vec![],
        true,
    );
    let world = support::provider(
        config,
        Arc::new(
            SystemProcessRunner::new().with_programs("/nonexistent/docker".into(), "git".into()),
        ),
    );
    let spec = lab.spec(SandboxProfile::Verify, 2, WALL);
    assert_eq!(
        world
            .provider
            .create_verified(spec, &FakeCancel::new())
            .await
            .err(),
        Some(SandboxError::DaemonUnavailable)
    );

    // A skeleton sidecar (the real catalog with its sidecar put back to the skeleton state): an
    // agent job is blocked before anything is made.
    // One lab at a time: the first one goes before the second is made.
    drop(lab);
    let lab = lab_with(vec![], &support::images_json_with_skeleton_sidecar());
    let outcome = lab.create(lab.spec(SandboxProfile::Agent, 3, WALL)).await;
    assert_eq!(
        outcome.err(),
        Some(SandboxError::ProvisionFailed(ProvisionStage::Network))
    );
    assert!(lab.leftovers().is_empty(), "{:?}", lab.leftovers());
    assert_eq!(lab.token_files(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sup_05_an_image_that_is_listed_but_not_on_this_host_is_refused() {
    // A digest that no host has, listed as the verify image.
    let fake = format!("sha256:{}", "ab".repeat(32));
    let mut root: serde_json::Value = serde_json::from_str(support::IMAGES_JSON).expect("json");
    let entry = &mut root["platforms"][support::PLATFORM]["images"]["verify"];
    entry["reference"] = format!("factory-sandbox/verify@{fake}").into();
    entry["digest"] = fake.into();
    let lab = lab_with(vec![], &root.to_string());
    let outcome = lab.create(lab.spec(SandboxProfile::Verify, 1, WALL)).await;
    assert_eq!(outcome.err(), Some(SandboxError::ImageUnavailable));
    assert!(lab.leftovers().is_empty());
}

// ---- NT-TOOL: the same payload in the agent sandbox ----------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_tool_01_shell_metacharacters_are_literals_and_a_payload_runs_unprivileged() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Agent, 1, WALL))
        .await
        .expect("agent");
    let literal = lab
        .run(
            &mut *session,
            &["echo", "a;b", "$(id)", "`id`", "&&", "|", "*", ">", "x"],
        )
        .await;
    assert_eq!(lab.text(&literal).await.0, "a;b $(id) `id` && | * > x\n");
    assert!(
        !std::path::Path::new("x").exists(),
        "no redirect happened on the host"
    );

    // A hostile payload run through the shell the agent image has, as the agent would run it.
    let payload = "id -u; grep CapEff /proc/self/status; echo m > /workspace/marker; \
                   echo m > /etc/marker 2>&1 || echo etc-refused; echo m > /host-marker 2>&1 || echo root-refused";
    let ran = lab.run(&mut *session, &["bash", "-c", payload]).await;
    let (out, _) = lab.text(&ran).await;
    assert!(out.starts_with("10001\n"), "non-root: {out}");
    assert!(
        out.contains("CapEff:\t0000000000000000"),
        "no capability: {out}"
    );
    assert!(
        out.contains("etc-refused") && out.contains("root-refused"),
        "{out}"
    );
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_tool_04_writes_outside_the_writable_mounts_and_protected_paths_are_refused() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Agent, 1, WALL))
        .await
        .expect("agent");
    // The checkout is writable, the protected overlay and the pointer mask are not.
    assert_eq!(
        lab.run(&mut *session, &["touch", "/workspace/new.txt"])
            .await
            .exit_code,
        Some(0)
    );
    for words in [
        &["touch", "/workspace/.github/new.txt"][..],
        &["rm", "/workspace/.github/protected.txt"][..],
        &["rm", "/workspace/.git"][..],
        &["mv", "/workspace/.github", "/workspace/.github2"][..],
        &["touch", "/etc/new.txt"][..],
        &["touch", "/run/factory/new.txt"][..],
    ] {
        let result = lab.run(&mut *session, words).await;
        assert_ne!(result.exit_code, Some(0), "{words:?} succeeded");
    }
    // The mask is still a mask: the pointer file reads empty.
    let pointer = lab.run(&mut *session, &["cat", "/workspace/.git"]).await;
    assert!(lab.read(&pointer.stdout).await.is_empty());
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_tool_05_argument_injection_changes_nothing_outside_the_sandbox() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Verify, 1, WALL))
        .await
        .expect("verify");
    for words in [
        &[
            "find",
            "/workspace",
            "-maxdepth",
            "0",
            "-fprint",
            "/etc/injected",
        ][..],
        &[
            "find",
            "/workspace",
            "-maxdepth",
            "0",
            "-exec",
            "touch",
            "/etc/injected",
            ";",
        ][..],
        &["tee", "/etc/injected"][..],
        &["cp", "/bin/true", "/etc/injected"][..],
    ] {
        lab.run(&mut *session, words).await;
        // The option that runs a command reports success when that command failed, so the proof
        // is that the file was never made.
        let looked = lab.run(&mut *session, &["ls", "/etc/injected"]).await;
        assert_ne!(
            looked.exit_code,
            Some(0),
            "{words:?} wrote outside the sandbox"
        );
    }
    // An option-looking argument stays an argument.
    let help = lab
        .run(&mut *session, &["echo", "--help", "-n", "--"])
        .await;
    assert_eq!(lab.text(&help).await.0, "--help -n --\n");
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
}

// ---- posture covers every part, on real containers --------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn posture_covers_every_part() {
    let scope_probe = Lab::new(true);
    let lacks_apparmor = daemon_lacks_apparmor(&scope_probe.scope);
    drop(scope_probe);
    let cases = [
        (DriftPart::Limits, SandboxProfile::Verify, "limits"),
        (DriftPart::Network, SandboxProfile::Agent, "network"),
        (DriftPart::ExtraMount, SandboxProfile::Verify, "mounts"),
        (DriftPart::WritableMount, SandboxProfile::Verify, "mounts"),
        (DriftPart::Env, SandboxProfile::Verify, "env"),
        (DriftPart::Image, SandboxProfile::Verify, "image"),
        (DriftPart::Hardening, SandboxProfile::Verify, "cap_drop_all"),
    ];
    for (part, profile, field) in cases {
        let spare = Scratch::new("spare");
        let drift = Arc::new(DriftRunner::new(
            SystemProcessRunner::new(),
            spare.path().to_path_buf(),
        ));
        let lab = Lab::with_runner(
            true,
            Some(Arc::clone(&drift) as Arc<dyn factory_ports::process::ProcessRunner>),
        );
        drift.arm(part);
        let outcome = lab.create(lab.spec(profile, 1, WALL)).await;
        match outcome {
            Err(SandboxError::PostureMismatch(diff)) => assert!(
                diff.fields.contains(&field),
                "{part:?}: expected {field} in {:?}",
                diff.fields
            ),
            other => panic!("{part:?}: {:?}", other.map(|_| "a sandbox")),
        }
        lab.world.provider.finish_background_cleanups().await;
        assert!(
            lab.leftovers().is_empty(),
            "{part:?}: {:?}",
            lab.leftovers()
        );
    }
    if lacks_apparmor {
        // A daemon without AppArmor: refused by a production policy, accepted by a development one.
        let production = Lab::new(false);
        let outcome = production
            .create(production.spec(SandboxProfile::Verify, 1, WALL))
            .await;
        match outcome {
            Err(SandboxError::PostureMismatch(diff)) => {
                assert!(diff.fields.contains(&"apparmor"), "{diff:?}")
            }
            other => panic!("{:?}", other.map(|_| "a sandbox")),
        }
        // One lab at a time: the production lab goes before the development lab is made.
        production.world.provider.finish_background_cleanups().await;
        drop(production);
        let development = Lab::new(true);
        let session = development
            .create(development.spec(SandboxProfile::Verify, 1, WALL))
            .await;
        session
            .expect("accepted")
            .stop_and_remove(TeardownReason::Completed)
            .await
            .expect("teardown");
    }
}

// ---- the token file's life ------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn token_file_lifecycle() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Agent, 1, WALL))
        .await
        .expect("agent");
    let secret = support::token_secret("spec");

    // Inside: the fixed path, mode 0400, owned by the sandbox user, read-only mount.
    let listing = lab
        .run(&mut *session, &["ls", "-ln", "/run/factory/job-token"])
        .await;
    let (line, _) = lab.text(&listing).await;
    assert!(line.starts_with("-r--------"), "{line}");
    assert!(line.contains("10001 10001"), "{line}");
    let content = lab
        .run(&mut *session, &["cat", "/run/factory/job-token"])
        .await;
    assert_eq!(lab.read(&content.stdout).await, b"[REDACTED:job_token]");
    let size = lab
        .run(&mut *session, &["wc", "-c", "/run/factory/job-token"])
        .await;
    assert!(
        lab.text(&size)
            .await
            .0
            .starts_with(&secret.expose().len().to_string()),
        "the file holds the secret and nothing else"
    );
    let write = lab
        .run(&mut *session, &["tee", "/run/factory/job-token"])
        .await;
    assert_ne!(write.exit_code, Some(0), "the token file is not writable");
    // On the host: 0400 in a 0700 directory while the sandbox lives.
    assert_eq!(lab.token_files(), 1);
    use std::os::unix::fs::PermissionsExt;
    let dir = std::fs::read_dir(&lab.token_root)
        .expect("dir")
        .next()
        .expect("one")
        .expect("entry")
        .path();
    let mode =
        |p: &std::path::Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(&dir.join("job-token")), 0o400);
    assert_eq!(mode(&dir), 0o700);
    // It never shows in Debug output of the posture or the session.
    assert!(!format!("{:?}", session.posture()).contains(secret.expose()));
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");
    assert_eq!(lab.token_files(), 0, "absent after completion");

    // Failure, timeout and cancellation end the same way.
    let mut failed = lab
        .create(lab.spec(SandboxProfile::Agent, 2, WALL))
        .await
        .expect("agent");
    let result = lab.run(&mut *failed, &["false"]).await;
    assert_eq!(result.exit_code, Some(1));
    failed
        .stop_and_remove(TeardownReason::Failed)
        .await
        .expect("teardown");
    assert_eq!(lab.token_files(), 0, "absent after failure");

    let mut timed = lab
        .create(lab.spec(SandboxProfile::Agent, 3, Duration::from_secs(4)))
        .await
        .expect("agent");
    let outcome = timed
        .exec(
            exec_request(&["sleep", "300"], Duration::from_secs(300)),
            &FakeCancel::new(),
        )
        .await;
    assert_eq!(outcome.err(), Some(SandboxError::Timeout));
    timed
        .stop_and_remove(TeardownReason::TimedOut)
        .await
        .expect("teardown");
    assert_eq!(lab.token_files(), 0, "absent after the wall clock");

    let mut cancelled = lab
        .create(lab.spec(SandboxProfile::Agent, 4, WALL))
        .await
        .expect("agent");
    let cancel = FakeCancel::new();
    let run = cancelled.exec(
        exec_request(&["sleep", "300"], Duration::from_secs(300)),
        &cancel,
    );
    let stop = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(run, stop);
    assert_eq!(outcome.err(), Some(SandboxError::Cancelled));
    cancelled
        .stop_and_remove(TeardownReason::Cancelled)
        .await
        .expect("teardown");
    assert_eq!(lab.token_files(), 0, "absent after cancellation");
    assert!(lab.leftovers().is_empty(), "{:?}", lab.leftovers());
}

// ---- teardown, drop and the janitor ----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_session_and_a_dropped_create_are_removed_by_the_guard() {
    let lab = Lab::new(true);
    let session = lab
        .create(lab.spec(SandboxProfile::Agent, 1, WALL))
        .await
        .expect("agent");
    assert!(!lab.leftovers().is_empty());
    drop(session);
    lab.world.provider.finish_background_cleanups().await;
    assert!(
        lab.leftovers().is_empty(),
        "after a dropped session: {:?}",
        lab.leftovers()
    );
    assert_eq!(lab.token_files(), 0);

    // A create future dropped half way: a timeout is the caller giving up.
    // The give-up times differ so that the future is dropped at different steps. A create that
    // happens to finish first is dropped as a session, which the first half already covered.
    let mut interrupted = 0;
    for (n, give_up_ms) in [100_u64, 250, 400, 550, 700, 900].into_iter().enumerate() {
        let spec = lab.spec(SandboxProfile::Agent, 10 + n as u128, WALL);
        let cancel = FakeCancel::new();
        let outcome = tokio::time::timeout(
            Duration::from_millis(give_up_ms),
            lab.world.provider.create_verified(spec, &cancel),
        )
        .await;
        interrupted += usize::from(outcome.is_err());
        drop(outcome);
        lab.world.provider.finish_background_cleanups().await;
        assert!(
            lab.leftovers().is_empty(),
            "after a create dropped at {give_up_ms} ms: {:?}",
            lab.leftovers()
        );
        assert_eq!(lab.token_files(), 0, "dropped at {give_up_ms} ms");
    }
    assert!(
        interrupted >= 2,
        "only {interrupted} creates were interrupted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn janitor_removes_orphans() {
    let lab = Lab::new(true);
    let one = lab
        .create(lab.spec(SandboxProfile::Agent, 1, WALL))
        .await
        .expect("one");
    let two = lab
        .create(lab.spec(SandboxProfile::Agent, 2, WALL))
        .await
        .expect("two");
    let (id_one, id_two) = (one.id().clone(), two.id().clone());
    // A crash: nothing runs the drop guard and nobody calls stop_and_remove.
    std::mem::forget(one);
    std::mem::forget(two);

    // A crash between making the network and the container leaves a network and a token directory.
    // The name carries this lab's own number, so no other run can make or sweep the same one.
    let stray = format!(
        "aaaaaaaa-bbbbbbbb-{:08x}",
        lab.scope
            .label()
            .value()
            .bytes()
            .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)))
    );
    let stray = stray.as_str();
    let label = lab.scope.label();
    lab.scope
        .cli()
        .run(&[
            "network",
            "create",
            "--internal",
            "--label",
            "sf.sandbox=network",
            "--label",
            &format!("factory.attempt_id={}", attempt(9)),
            "--label",
            &label.assignment(),
            &format!("sf-net-{stray}"),
        ])
        .expect("a stray network");
    std::fs::create_dir_all(lab.token_root.join(stray)).expect("a stray token directory");
    std::fs::write(lab.token_root.join(stray).join("job-token"), b"stray").expect("a stray token");

    // A network that carries the marker but not this provider's owner label is not touched.
    let foreign = format!("sf-net-ffffffff-ffffffff-{:08x}", std::process::id());
    lab.scope
        .cli()
        .run(&[
            "network",
            "create",
            "--internal",
            "--label",
            "sf.sandbox=network",
            &foreign,
        ])
        .expect("a foreign network");
    // The janitor must leave this one alone, so the lab's cleanup (by owner label) cannot remove it
    // either. This guard removes it, whether the test passes or fails.
    struct RemoveNetwork(factory_testkit::fx::docker::DockerCli, String);
    impl Drop for RemoveNetwork {
        fn drop(&mut self) {
            let _ = self.0.run(&["network", "rm", &self.1]);
        }
    }
    let _foreign_guard = RemoveNetwork(lab.scope.cli().clone(), foreign.clone());

    // Attempt 1 is live: only attempt 2 and the stray are removed.
    let removed = lab
        .world
        .provider
        .sweep_orphans(&[attempt(1)])
        .await
        .expect("sweep");
    assert_eq!(removed, vec![id_two.clone()], "{removed:?}");
    let left = lab.leftovers();
    assert!(
        left.iter().any(|n| n == id_one.as_str()),
        "the live sandbox stays: {left:?}"
    );
    assert!(
        !left.iter().any(|n| n.contains(stray)),
        "the stray network is gone: {left:?}"
    );
    assert!(
        !lab.token_root.join(stray).exists(),
        "the stray token directory is gone"
    );
    let foreign_left = lab
        .scope
        .cli()
        .run(&[
            "network",
            "ls",
            "--filter",
            &format!("name={foreign}"),
            "--format",
            "{{.Name}}",
        ])
        .expect("ls");
    assert!(
        foreign_left.stdout.contains(&foreign),
        "a network without the owner label is not ours to remove"
    );

    // Nothing is live now: the rest goes, and a second sweep finds nothing.
    let removed = lab.world.provider.sweep_orphans(&[]).await.expect("sweep");
    assert_eq!(removed, vec![id_one]);
    assert!(
        lab.world
            .provider
            .sweep_orphans(&[])
            .await
            .expect("again")
            .is_empty()
    );
    assert!(lab.leftovers().is_empty(), "{:?}", lab.leftovers());
    assert_eq!(lab.token_files(), 0);
    lab.scope
        .cli()
        .run(&["network", "rm", &foreign])
        .expect("remove the foreign network");
    lab.world.provider.finish_background_cleanups().await;
}

// ---- NT-SEC-09: what the spawn recorder sees ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sec_09_the_recorded_processes_hold_no_secret_and_start_no_shell() {
    let real_docker = std::env::var("PATH")
        .expect("a PATH")
        .split(':')
        .map(|dir| std::path::Path::new(dir).join("docker"))
        .find(|candidate| candidate.is_file())
        .expect("docker on the PATH");
    let mut recorder = SpawnRecorder::new(SpawnPolicy::docker_and_git()).expect("a recorder");
    recorder
        .install("docker", &Behavior::Passthrough(real_docker))
        .expect("a docker shim");
    recorder.install_shell_traps().expect("shell traps");
    let runner =
        SystemProcessRunner::new().with_path(recorder.path_env().to_string_lossy().into_owned());

    let mut rng = FxRng::from_seed(9);
    let token = Canary::generate(CanaryKind::JobToken, &mut rng);
    let lab = Lab::with_runner(true, Some(Arc::new(runner)));
    let mut spec = lab.spec(SandboxProfile::Agent, 1, WALL);
    spec.job_token = Some(factory_ports::sandbox::JobTokenMount {
        secret: factory_ports::agent::JobTokenSecret::new(token.value().to_owned()),
    });
    let mut session = lab.create(spec).await.expect("agent");
    let echoed = lab.run(&mut *session, &["echo", "hello"]).await;
    assert_eq!(echoed.exit_code, Some(0));
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .expect("teardown");

    let records = recorder.records().expect("records");
    assert!(records.len() > 8, "{} processes recorded", records.len());
    let sweeper = Sweeper::new(&CanarySet::generate_with(&mut rng).with(token));
    for record in &records {
        assert_eq!(record.program, "docker", "{}", record.summary());
        let hits = sweeper.scan("spawn record", record.to_json().to_string().as_bytes());
        assert!(
            hits.is_empty(),
            "a secret in {}: {hits:?}",
            record.summary()
        );
    }
    assert!(
        recorder.violations().is_empty(),
        "{:?}",
        recorder.violations()
    );
    recorder.assert_clean();
}

// ---- sanity: the catalog the tests run is the one the image build wrote --------------------------------------------------

#[test]
fn a_catalog_with_a_skeleton_sidecar_refuses_it() {
    let json = support::images_json_with_skeleton_sidecar();
    let catalog = ImageCatalog::from_json(&json, support::PLATFORM).expect("catalog");
    assert!(
        catalog.sidecar().is_err(),
        "a sidecar without its program must be refused"
    );
}

#[test]
fn the_real_catalog_lists_a_ready_sidecar_and_the_other_images() {
    let catalog =
        ImageCatalog::from_json(support::IMAGES_JSON, support::PLATFORM).expect("catalog");
    assert!(
        catalog.sidecar().is_ok(),
        "the egress sidecar has its program and is listed as ready"
    );
    for profile in [
        SandboxProfile::Agent,
        SandboxProfile::Verify,
        SandboxProfile::FetchDeps,
    ] {
        let image = catalog.reference_for(profile).expect("listed");
        assert!(
            catalog.check_spec_image(profile, image).is_ok(),
            "{profile:?}"
        );
    }
}
