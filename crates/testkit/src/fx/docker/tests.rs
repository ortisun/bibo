use std::os::unix::fs::PermissionsExt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::fx::spawn::{Behavior, Reply, SpawnPolicy, SpawnRecorder};
use crate::fx::tmpdir::FxTempDir;

/// A `docker` that is a scripted shim. The recorder keeps what the code under test ran.
fn scripted(rules: Vec<(&str, Reply)>, default: Reply) -> (SpawnRecorder, DockerCli) {
    let mut recorder = SpawnRecorder::new(SpawnPolicy::allowing(&["docker"])).unwrap();
    recorder
        .install(
            "docker",
            &Behavior::ByArguments {
                rules: rules
                    .into_iter()
                    .map(|(prefix, reply)| (prefix.to_owned(), reply))
                    .collect(),
                default,
            },
        )
        .unwrap();
    let cli = DockerCli::with_program(recorder.bin_dir().join("docker"));
    (recorder, cli)
}

fn panic_message(result: std::thread::Result<impl std::fmt::Debug>) -> String {
    let payload = result.expect_err("expected a panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default()
}

#[test]
fn docker_guard_blocks_and_cleans() {
    // ---- Part 1: with no daemon the test is BLOCKED, and BLOCKED is not PASSED. -------------

    // No client at all.
    let guard = DockerGuard::new(DockerCli::with_program("/nonexistent/place/docker"));
    let DockerStatus::Absent { reason } = guard.status() else {
        panic!("a missing client must be reported as absent");
    };
    assert!(reason.contains("not installed"), "{reason}");
    let blocked = guard.require().unwrap_err();
    assert!(blocked.to_string().starts_with("BLOCKED: "), "{blocked}");

    // The test body is not run, and the status says BLOCKED, not PASSED.
    let mut ran = false;
    let status = guard.run_if_available(|_| ran = true);
    assert!(!ran, "a blocked test must not run its body");
    assert!(matches!(&status, TestStatus::Blocked(r) if r.contains("not installed")));
    assert!(!status.is_passed());

    // `require_or_block` ends the test with a message that starts with BLOCKED.
    let message = panic_message(catch_unwind(AssertUnwindSafe(|| guard.require_or_block())));
    assert!(message.starts_with("BLOCKED: "), "{message}");

    // A client with no daemon behind it: the reason is what the client said.
    let (_recorder, cli) = scripted(
        vec![(
            "version",
            Reply::fail(
                1,
                "Cannot connect to the Docker daemon. Is the docker daemon running?\n",
            ),
        )],
        Reply::fail(9, "unexpected"),
    );
    let stopped = DockerGuard::new(cli);
    assert!(matches!(
        stopped.status(),
        DockerStatus::Absent { reason } if reason.contains("Cannot connect")
    ));
    assert!(stopped.require().is_err());

    // A client that answers but names no server version is not a daemon either.
    let (_recorder, cli) = scripted(
        vec![("version", Reply::ok("\n"))],
        Reply::fail(9, "unexpected"),
    );
    assert!(matches!(
        DockerGuard::new(cli).status(),
        DockerStatus::Absent { .. }
    ));

    // A client that hangs is cut off.
    let dir = FxTempDir::new("fx-hang").unwrap();
    let hang = dir.join("docker");
    std::fs::write(&hang, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
    std::fs::set_permissions(&hang, std::fs::Permissions::from_mode(0o755)).unwrap();
    let started = Instant::now();
    let hung =
        DockerGuard::new(DockerCli::with_program(&hang).with_timeout(Duration::from_millis(400)));
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(matches!(
        hung.status(),
        DockerStatus::Absent { reason } if reason.contains("did not answer")
    ));

    // ---- Part 2: cleanup uses the run's label and nothing else. ------------------------------
    let label = "factory.test_run=run-b";
    let (recorder, cli) = scripted(
        vec![
            ("version", Reply::ok("29.9.2\n")),
            (
                &format!("ps -aq --filter label={label}"),
                Reply::ok("c0ffee000001\nc0ffee000002\n"),
            ),
            (
                &format!("network ls -q --filter label={label}"),
                Reply::ok("beef00000001\n"),
            ),
            (
                &format!("volume ls -q --filter label={label}"),
                Reply::ok(""),
            ),
            (
                &format!("image ls -q --filter label={label}"),
                Reply::ok(""),
            ),
            ("rm -f -v c0ffee000001 c0ffee000002", Reply::ok("")),
            ("network rm beef00000001", Reply::ok("")),
        ],
        Reply::fail(9, "an unscripted command was run"),
    );
    let guard = DockerGuard::with_label(cli, RunLabel::new("run-b"));
    assert_eq!(
        guard.status(),
        &DockerStatus::Available {
            server_version: "29.9.2".to_owned()
        }
    );
    let scope = guard.require().unwrap();
    // The scripted daemon keeps listing the objects after "removing" them, which is what a
    // container that cannot be removed looks like. The cleanup must say so, not hide it.
    let problem = scope.cleanup().unwrap_err();
    assert!(problem.contains("still there after cleanup"), "{problem}");
    assert!(problem.contains("c0ffee000001"), "{problem}");
    std::mem::forget(scope);

    let commands: Vec<Vec<String>> = recorder
        .records()
        .unwrap()
        .into_iter()
        .map(|r| r.argv)
        .collect();
    let removals: Vec<String> = commands
        .iter()
        .filter(|c| c[0] == "rm" || (c[0] == "network" && c[1] == "rm"))
        .map(|c| c.join(" "))
        .collect();
    assert_eq!(
        removals,
        [
            "rm -f -v c0ffee000001 c0ffee000002",
            "network rm beef00000001"
        ],
        "only the listed ids are removed"
    );
    // Every listing carries the run's label, and nothing prunes or reaches into other objects.
    for command in &commands {
        let joined = command.join(" ");
        assert!(!joined.contains("prune"), "{joined}");
        assert!(!joined.contains("system"), "{joined}");
        assert!(command[0] != "kill" && command[0] != "stop", "{joined}");
        if joined.contains(" ls ") || joined.starts_with("ps ") {
            assert!(
                joined.contains(&format!("--filter label={label}")),
                "{joined}"
            );
        }
    }

    // ---- Part 3: against the real daemon, only this run's objects go. ------------------------
    let guard = DockerGuard::from_environment();
    let scope = guard.require_or_block();
    let suffix = format!("{:08x}", FxRng::from_entropy().next_u64() as u32);
    let run = |args: &[&str]| {
        let output = scope.cli().run(args).expect("docker runs");
        assert!(output.success(), "docker {args:?}: {}", output.stderr);
        output
    };
    let assignment = scope.label().assignment();
    let image = format!("fx-guard-empty-{suffix}:test");
    let container = format!("fx-guard-c-{suffix}");
    let network = format!("fx-guard-n-{suffix}");
    let volume = format!("fx-guard-v-{suffix}");

    // An image with nothing in it, made offline, so a container can be created without a pull.
    let imported = scope
        .cli()
        .run_with_input(
            &[
                "import",
                "--change",
                &format!("LABEL {assignment}"),
                "-",
                &image,
            ],
            &[0u8; 1024],
        )
        .expect("docker runs");
    assert!(imported.success(), "docker import: {}", imported.stderr);
    run(&[
        "create",
        "--label",
        &assignment,
        "--name",
        &container,
        &image,
        "/nothing",
    ]);
    run(&["network", "create", "--label", &assignment, &network]);
    run(&["volume", "create", "--label", &assignment, &volume]);

    // A neighbour from another run, with a different label. It must survive.
    let other_guard = DockerGuard::from_environment();
    let other_scope = other_guard.require_or_block();
    let other_network = format!("fx-guard-other-{suffix}");
    let other_assignment = other_scope.label().assignment();
    run(&[
        "network",
        "create",
        "--label",
        &other_assignment,
        &other_network,
    ]);

    let report = scope.cleanup().expect("cleanup removes this run's objects");
    assert_eq!(report.containers.len(), 1, "{report:?}");
    assert_eq!(report.networks.len(), 1, "{report:?}");
    assert_eq!(report.volumes.len(), 1, "{report:?}");
    assert_eq!(report.images.len(), 1, "{report:?}");

    let present = |kind: &[&str], name: &str| -> bool {
        let mut args = kind.to_vec();
        let name_filter = format!("name={name}");
        args.extend(["--filter", &name_filter, "-q"]);
        !run(&args).stdout.trim().is_empty()
    };
    assert!(
        !present(&["ps", "-a"], &container),
        "the container is still there"
    );
    assert!(
        !present(&["network", "ls"], &network),
        "the network is still there"
    );
    assert!(
        !present(&["volume", "ls"], &volume),
        "the volume is still there"
    );
    assert!(
        run(&[
            "image",
            "ls",
            "-q",
            "--filter",
            &format!("label={assignment}")
        ])
        .stdout
        .trim()
        .is_empty(),
        "the image is still there"
    );
    assert!(
        present(&["network", "ls"], &other_network),
        "the cleanup removed a network that belongs to another run"
    );

    // Dropping a scope cleans up too, with no call to cleanup().
    let drop_guard = DockerGuard::from_environment();
    let dropped_network = format!("fx-guard-dropped-{suffix}");
    {
        let drop_scope = drop_guard.require_or_block();
        let created = drop_scope
            .cli()
            .run(&[
                "network",
                "create",
                "--label",
                &drop_scope.label().assignment(),
                &dropped_network,
            ])
            .unwrap();
        assert!(created.success(), "{}", created.stderr);
        assert!(present(&["network", "ls"], &dropped_network));
    }
    assert!(
        !present(&["network", "ls"], &dropped_network),
        "dropping the scope left the network behind"
    );
    // `other_scope` goes out of scope here and removes its own network.
}

#[test]
fn a_listing_that_is_not_ids_removes_nothing() {
    let (recorder, cli) = scripted(
        vec![
            ("version", Reply::ok("29.9.2\n")),
            // A hostile or broken answer: a flag that `docker rm` would take as an option.
            ("ps -aq", Reply::ok("--all\n")),
        ],
        Reply::ok(""),
    );
    let guard = DockerGuard::with_label(cli, RunLabel::new("run-c"));
    let scope = guard.require().unwrap();
    let problem = scope.cleanup().unwrap_err();
    assert!(problem.contains("not an object id"), "{problem}");
    std::mem::forget(scope);
    assert!(
        recorder
            .records()
            .unwrap()
            .iter()
            .all(|r| r.argv[0] != "rm"),
        "nothing may be removed when the listing is not ids"
    );
}

#[test]
fn ids_are_checked_before_they_reach_a_remove_command() {
    for good in [
        "c0ffee000001",
        "0123456789abcdef0123456789abcdef",
        "fx_volume-1.a",
        "sha256:abc",
    ] {
        assert!(looks_like_an_id(good), "{good}");
    }
    for bad in [
        "",
        "--all",
        "-f",
        ".hidden",
        "a b",
        "a;b",
        "$(id)",
        "a/b",
        &"x".repeat(129),
    ] {
        assert!(!looks_like_an_id(bad), "{bad:?}");
    }
}

#[test]
fn every_guard_gets_its_own_label_and_the_forms_are_right() {
    let a = RunLabel::unique();
    let b = RunLabel::unique();
    assert_ne!(a, b);
    let label = RunLabel::new("abc");
    assert_eq!(label.assignment(), "factory.test_run=abc");
    assert_eq!(label.filter(), "label=factory.test_run=abc");
    let guard = DockerGuard::with_label(
        DockerCli::with_program("/nonexistent/docker"),
        RunLabel::new("abc"),
    );
    assert_eq!(guard.label_args(), ["--label", "factory.test_run=abc"]);
}

#[test]
fn a_blocked_status_is_never_a_pass() {
    let status = TestStatus::Blocked("no daemon".to_owned());
    assert!(!status.is_passed());
    assert!(TestStatus::Passed.is_passed());
    assert_eq!(Blocked { reason: "x".into() }.to_string(), "BLOCKED: x");
    let message = panic_message(catch_unwind(|| blocked("for the test")));
    assert_eq!(message, "BLOCKED: for the test");
}
