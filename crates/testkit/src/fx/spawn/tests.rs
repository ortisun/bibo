use std::collections::BTreeSet;
use std::process::{Command, Output};

use super::*;

/// Starts `program` the way the code under test would, with a `PATH` that holds only the shims.
fn run(recorder: &SpawnRecorder, program: &str, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", recorder.path_env());
    for (name, value) in envs {
        command.env(name, value);
    }
    command.output().expect("the shim starts")
}

fn recorder() -> SpawnRecorder {
    SpawnRecorder::new(SpawnPolicy::docker_and_git()).unwrap()
}

#[test]
fn fx_spawn_records_argv_and_environment_exactly() {
    let mut rec = recorder();
    rec.install("docker", &Behavior::Record).unwrap();
    let out = run(
        &rec,
        "docker",
        &["run", "--rm", "two words", "line\nbreak", "", ";", "$(id)"],
        &[("TOKEN_NAME", "value with spaces"), ("EMPTY", "")],
    );
    assert!(out.status.success());

    let records = rec.records().unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.seq, 1);
    assert_eq!(record.program, "docker");
    // Shell metacharacters, spaces, a line break and an empty argument survive untouched.
    assert_eq!(
        record.argv,
        ["run", "--rm", "two words", "line\nbreak", "", ";", "$(id)"]
    );
    assert_eq!(record.env["TOKEN_NAME"], "value with spaces");
    assert_eq!(record.env["EMPTY"], "");
    let names: BTreeSet<&str> = record.env.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        BTreeSet::from(["PATH", "TOKEN_NAME", "EMPTY"]),
        "the record holds what the caller passed and nothing the shell added"
    );
    assert!(!record.cwd.is_empty());
}

#[test]
fn a_start_with_no_arguments_has_an_empty_argument_list() {
    let mut rec = recorder();
    rec.install("git", &Behavior::Record).unwrap();
    run(&rec, "git", &[], &[]);
    assert_eq!(rec.records().unwrap()[0].argv, Vec::<String>::new());
}

#[test]
fn starts_are_numbered_in_order_even_when_made_at_once() {
    let mut rec = recorder();
    rec.install("docker", &Behavior::Record).unwrap();
    run(&rec, "docker", &["first"], &[]);
    run(&rec, "docker", &["second"], &[]);
    let records = rec.records().unwrap();
    assert_eq!(
        records
            .iter()
            .map(|r| r.argv[0].as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );

    // Twenty-four starts together: none is lost, and no number is used twice.
    let rec = std::sync::Arc::new(rec);
    let handles: Vec<_> = (0..24)
        .map(|n| {
            let rec = std::sync::Arc::clone(&rec);
            std::thread::spawn(move || run(&rec, "docker", &[&format!("n{n}")], &[]))
        })
        .collect();
    for handle in handles {
        assert!(handle.join().unwrap().status.success());
    }
    let records = rec.records().unwrap();
    assert_eq!(records.len(), 26);
    let numbers: BTreeSet<u64> = records.iter().map(|r| r.seq).collect();
    assert_eq!(numbers, (1..=26).collect());
    let arguments: BTreeSet<&str> = records.iter().map(|r| r.argv[0].as_str()).collect();
    assert_eq!(arguments.len(), 26, "every start has its own record");
}

#[test]
fn allowed_programs_pass_the_policy() {
    let mut rec = recorder();
    rec.install("docker", &Behavior::Record).unwrap();
    rec.install("git", &Behavior::Record).unwrap();
    run(&rec, "docker", &["ps"], &[]);
    run(&rec, "git", &["status"], &[]);
    assert!(rec.violations().is_empty());
    rec.assert_clean();
}

#[test]
fn a_shell_start_is_caught_as_a_violation() {
    // Deliberate break: the code under test starts `sh -c`. The recorder must see it, the trap
    // must stop it from running, and the policy must name it.
    let mut rec = recorder();
    rec.install("docker", &Behavior::Record).unwrap();
    rec.install_shell_traps().unwrap();
    let marker = rec.bin_dir().join("did-the-shell-run");
    let out = run(
        &rec,
        "sh",
        &["-c", &format!("touch {}", marker.display())],
        &[],
    );
    assert_eq!(
        out.status.code(),
        Some(127),
        "the trap answers, not a shell"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("FX-SPAWN"));
    assert!(!marker.exists(), "the shell command must not have run");

    let violations = rec.violations();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(matches!(&violations[0], SpawnViolation::Shell { program, .. } if program == "sh"));
    rec.disarm();
}

#[test]
fn a_launcher_asked_to_run_a_shell_is_caught() {
    let mut rec = recorder();
    rec.install_shell_traps().unwrap();
    run(&rec, "env", &["bash", "-c", "id"], &[]);
    let violations = rec.violations();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(matches!(
        &violations[0],
        SpawnViolation::ShellThroughLauncher { program, shell, .. }
            if program == "env" && shell == "bash"
    ));
    rec.disarm();
}

#[test]
fn a_program_outside_the_allowed_set_is_caught() {
    let mut rec = recorder();
    rec.install("curl", &Behavior::Record).unwrap();
    run(&rec, "curl", &["http://attacker.test/x"], &[]);
    let violations = rec.violations();
    assert_eq!(violations.len(), 1);
    assert!(
        matches!(&violations[0], SpawnViolation::NotAllowed { program, .. } if program == "curl")
    );
    rec.disarm();
}

#[test]
fn the_policy_can_allow_other_programs() {
    let mut rec = SpawnRecorder::new(SpawnPolicy::allowing(&["docker", "git", "claude"])).unwrap();
    rec.install("claude", &Behavior::Record).unwrap();
    run(&rec, "claude", &["--version"], &[]);
    rec.assert_clean();
}

#[test]
fn the_recorder_panics_when_dropped_after_a_forbidden_start() {
    let outcome = std::panic::catch_unwind(|| {
        let mut rec = recorder();
        rec.install_shell_traps().unwrap();
        run(&rec, "sh", &["-c", "true"], &[]);
        // `rec` is dropped here without a look at the result and without disarm().
    });
    let payload = outcome.expect_err("the trap must fire at drop");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(message.contains("FX-SPAWN"), "{message}");
    assert!(message.contains("the shell sh"), "{message}");
}

#[test]
fn a_disarmed_recorder_does_not_panic_at_drop() {
    let mut rec = recorder();
    rec.install_shell_traps().unwrap();
    run(&rec, "sh", &["-c", "true"], &[]);
    rec.disarm();
    drop(rec);
}

#[test]
fn replies_follow_the_argument_prefix_and_never_a_glob() {
    let mut rec = recorder();
    rec.install(
        "docker",
        &Behavior::ByArguments {
            rules: vec![
                (
                    "ps -aq".to_owned(),
                    Reply::ok("aaaaaaaaaaaa\nbbbbbbbbbbbb\n"),
                ),
                (
                    "info".to_owned(),
                    Reply::fail(1, "Cannot connect to the Docker daemon\n"),
                ),
                ("run *".to_owned(), Reply::ok("matched the star\n")),
            ],
            default: Reply::fail(2, "not scripted\n"),
        },
    )
    .unwrap();

    let ps = run(&rec, "docker", &["ps", "-aq", "--filter", "label=x"], &[]);
    assert_eq!(
        String::from_utf8_lossy(&ps.stdout),
        "aaaaaaaaaaaa\nbbbbbbbbbbbb\n"
    );
    assert_eq!(ps.status.code(), Some(0));

    let info = run(&rec, "docker", &["info"], &[]);
    assert_eq!(info.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&info.stderr).contains("Cannot connect"));

    // A prefix is compared as text: `run *` matches only a literal star, not any argument.
    let other = run(&rec, "docker", &["run", "anything"], &[]);
    assert_eq!(other.status.code(), Some(2));
    let literal = run(&rec, "docker", &["run", "*"], &[]);
    assert!(String::from_utf8_lossy(&literal.stdout).contains("matched the star"));

    // A word that merely contains the prefix does not match.
    let infix = run(&rec, "docker", &["xps", "-aq"], &[]);
    assert_eq!(infix.status.code(), Some(2));
    rec.assert_clean();
}

#[test]
fn passthrough_hands_the_call_to_the_real_program_and_still_records_it() {
    let mut rec = SpawnRecorder::new(SpawnPolicy::allowing(&["echo"])).unwrap();
    rec.install("echo", &Behavior::Passthrough(PathBuf::from("/bin/echo")))
        .unwrap();
    let out = run(&rec, "echo", &["hello", "world"], &[]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello world\n");
    let records = rec.records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].argv, ["hello", "world"]);
}

#[test]
fn a_start_by_absolute_path_does_not_use_the_path_and_is_invisible() {
    // The limit, on purpose: a program started as `/usr/bin/true` never meets a shim. The static
    // scan (ST-03) is what covers this, and this test keeps the limit written down.
    let mut rec = recorder();
    rec.install_shell_traps().unwrap();
    let status = Command::new("/usr/bin/true")
        .env_clear()
        .env("PATH", rec.path_env())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(rec.records().unwrap().is_empty());

    // And a name that is neither shimmed nor trapped fails to start at all.
    let missing = Command::new("not-a-shimmed-program")
        .env_clear()
        .env("PATH", rec.path_env())
        .output();
    assert!(missing.is_err());
}

#[test]
fn git_is_checked_for_the_fixed_environment() {
    let mut rec = recorder();
    rec.install("git", &Behavior::Record).unwrap();

    run(&rec, "git", &["status"], &[]);
    let bare = &rec.records().unwrap()[0];
    let missing = bare.missing_git_hardening();
    assert_eq!(missing.len(), 4, "{missing:?}");

    run(
        &rec,
        "git",
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "status",
        ],
        &[
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ],
    );
    assert!(rec.records().unwrap()[1].missing_git_hardening().is_empty());

    // The same two settings through GIT_CONFIG_COUNT are accepted too.
    run(
        &rec,
        "git",
        &["status"],
        &[
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_COUNT", "2"),
            ("GIT_CONFIG_KEY_0", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_0", "/dev/null"),
            ("GIT_CONFIG_KEY_1", "core.fsmonitor"),
            ("GIT_CONFIG_VALUE_1", "false"),
        ],
    );
    assert!(rec.records().unwrap()[2].missing_git_hardening().is_empty());

    // Only one of the two settings: the other is reported.
    run(
        &rec,
        "git",
        &["-c", "core.hooksPath=/dev/null", "status"],
        &[
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ],
    );
    assert_eq!(
        rec.records().unwrap()[3].missing_git_hardening(),
        ["-c core.fsmonitor=false"]
    );

    // A program that is not git has nothing to check.
    rec.record_direct("docker", &["ps"], &[]).unwrap();
    assert!(rec.records().unwrap()[4].missing_git_hardening().is_empty());
}

#[test]
fn a_url_with_a_password_in_an_argument_is_found() {
    let mut rec = recorder();
    rec.install("git", &Behavior::Record).unwrap();
    // Built from parts, so this file holds no URL with a password in it for the repository's own
    // secret scan to find.
    let scheme = "https";
    let with_password = format!("{scheme}://x-access-token:abc123@github.com/o/r.git");
    let database = format!("{}://u:p@h/db", "postgres");
    run(
        &rec,
        "git",
        &[
            "clone",
            &with_password,
            "https://github.com/o/r.git",
            "https://user@host/path",
            &database,
            "a://b",
            "see https://u:p@h and more",
        ],
        &[],
    );
    let record = &rec.records().unwrap()[0];
    assert_eq!(record.arguments_with_url_credentials(), [1, 4, 6]);
}

#[test]
fn records_are_labelled_fake_and_hold_no_environment_values() {
    let mut rec = recorder();
    rec.install("docker", &Behavior::Record).unwrap();
    run(
        &rec,
        "docker",
        &["ps"],
        &[("SECRETISH", "do-not-print-this")],
    );
    let json = rec.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert_eq!(json["records"][0]["fidelity"], "fake");
    assert!(
        json["records"][0]["env_names"]
            .to_string()
            .contains("SECRETISH")
    );
    assert!(!json.to_string().contains("do-not-print-this"));
}

#[test]
fn the_shim_file_says_it_is_fake() {
    let mut rec = recorder();
    rec.install("docker", &Behavior::Record).unwrap();
    let script = fs::read_to_string(rec.bin_dir().join("docker")).unwrap();
    assert!(script.starts_with("#!/bin/sh\n"));
    assert!(script.contains("FAKE"));
}

#[test]
fn unsafe_program_names_and_paths_are_refused() {
    let mut rec = recorder();
    for bad in ["", "../x", "a b", ".hidden", "a/b", "q'uote", "semi;colon"] {
        assert!(
            rec.install(bad, &Behavior::Record).is_err(),
            "{bad:?} must be refused"
        );
    }
    assert!(
        rec.install("x", &Behavior::Passthrough(PathBuf::from("/bin/ec'ho")))
            .is_err()
    );
    assert!(
        rec.install("y", &Behavior::Passthrough(PathBuf::from("relative/echo")))
            .is_err()
    );
}

#[test]
fn a_direct_record_joins_the_sequence() {
    let mut rec = recorder();
    rec.install("docker", &Behavior::Record).unwrap();
    run(&rec, "docker", &["one"], &[]);
    let seq = rec.record_direct("git", &["two"], &[("K", "v")]).unwrap();
    assert_eq!(seq, 2);
    let records = rec.records().unwrap();
    assert_eq!(records[1].program, "git");
    assert_eq!(records[1].env["K"], "v");
}
