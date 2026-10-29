//! Every program of the adapters' command chain is execute-only, and a hostile process that already
//! runs when the chain starts cannot forge a line into its output (finding RR-14 of
//! docs/reviews/isolation-core-security-rereview.md, the part of SBX-4 the first fix left open).
//!
//! The adapters run `env -i ... timeout ... <tool>` through one `docker exec`, and the event stream
//! they trust is the output pipe of that exec. The kernel closes `/proc/<pid>/fd/1` of a process that
//! started from a file nobody can read. But the pipe is held by `env`, then `timeout`, then the tool,
//! one after the other, and a descriptor opened while the pipe was held by a READABLE program stays
//! open across the `execve` calls that follow. So the whole chain must be unreadable, not only the
//! tool. `infra/sandbox-images/lib/execute-only.txt` is the one list of those programs: `harden.sh`
//! applies it to the image, rule `TOOLS-EXECUTE-ONLY` of `test.sh` checks the built image against it,
//! and this file checks two things:
//!
//! 1. (no Docker) every program that `crates/runtime/src/command.rs` puts in a command vector is on
//!    the list, and `harden.sh` reads the list and keeps none of its own;
//! 2. (Docker) on a container of the agent image with the modes of the list applied, a racer that
//!    exists BEFORE the exec and loops over `/proc` forges nothing into the output of the real
//!    wrapper chain; and, as the control without which the test would show nothing, with `env` left
//!    readable the same racer does forge.
//!
//! The Docker test makes one container with no network, labelled `factory.test=true` and with the
//! run label, takes the machine-wide Docker lock, and removes the container when it ends. Without a
//! daemon or without the image it panics with `BLOCKED:`; it never passes without Docker. The
//! hostile code runs only inside that container, as the sandbox user, never on the host.
//!
//! The image may be built before or after the recipe: the test sets the modes itself. The control
//! first reopens `env` (mode 0755, as an image built before the recipe has it), and the protected
//! case then applies the modes of the list, as `harden.sh` does at build time. On an image built with
//! the recipe the second step changes nothing, and the control is what shows that the race is real.
//! `test.sh` rule `TOOLS-EXECUTE-ONLY` proves the built image.

mod support;

use std::path::PathBuf;
use std::time::Duration;

use factory_runtime::ClaudeCodeConfig;
use factory_runtime::CodexConfig;
use factory_runtime::command::{EnvName, TIMEOUT_PROGRAM, ToolCommand, ToolEnv};
use factory_testkit::fx::docker::{DockerGuard, DockerScope, blocked};

use support::docker::docker_lock::DockerLock;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The programs of `lib/execute-only.txt`, in file order.
fn listed() -> Vec<String> {
    let path = repo_root().join("infra/sandbox-images/lib/execute-only.txt");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn command(program: &str, args: &[&str]) -> ToolCommand {
    let env = ToolEnv::new()
        .set(EnvName::Home, "/home/agent")
        .and_then(|e| e.set(EnvName::Path, "/usr/local/bin:/usr/bin:/bin"))
        .and_then(|e| e.set(EnvName::AnthropicBaseUrl, "http://127.0.0.1:9"))
        .and_then(|e| e.set(EnvName::ClaudeDisableNonessentialTraffic, "1"))
        .and_then(|e| e.set(EnvName::ClaudeMaxRetries, "0"))
        .expect("a closed environment");
    ToolCommand {
        env,
        soft_deadline_seconds: 20,
        program: program.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
    }
}

/// The programs a command vector asks the sandbox to start, in order of the process chain: the first
/// element, then every absolute path after the `env` options and `NAME=value` assignments, up to and
/// including the tool. Read from the vector, so a program added to `into_argv` is seen.
fn chain_of(argv: &[String], tool: &str) -> Vec<String> {
    let mut chain = vec![argv[0].clone()];
    let mut i = 1;
    while i < argv.len() && (argv[i].starts_with('-') || argv[i].contains('=')) {
        i += 1;
    }
    while i < argv.len() {
        if argv[i].starts_with('/') {
            chain.push(argv[i].clone());
            if argv[i] == tool {
                break;
            }
        }
        i += 1;
    }
    chain
}

#[test]
fn the_list_names_absolute_paths_without_duplicates() {
    let programs = listed();
    assert!(programs.len() >= 5, "{programs:?}");
    for p in &programs {
        assert!(p.starts_with('/') && !p.contains(' '), "{p}");
    }
    let mut sorted = programs.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), programs.len(), "a duplicate in {programs:?}");
}

#[test]
fn every_program_the_adapters_put_in_a_command_vector_is_execute_only() {
    let programs = listed();
    let claude = ClaudeCodeConfig::default().binary;
    let codex = CodexConfig::default().binary;
    for tool in [claude, codex] {
        for argv in [
            command(&tool, &["--version"]).into_argv(),
            command(&tool, &["--version"]).into_probe_argv(),
        ] {
            let chain = chain_of(&argv, &tool);
            assert!(
                chain.len() >= 2,
                "the chain was not read from {argv:?}: {chain:?}"
            );
            assert_eq!(chain.last().map(String::as_str), Some(tool.as_str()));
            for program in &chain {
                assert!(
                    programs.contains(program),
                    "{program} runs in the command chain {argv:?} and is not on lib/execute-only.txt, \
                     so a hostile process that already runs can take the exec's output pipe from it \
                     (RR-14): {programs:?}"
                );
            }
        }
    }
    // The helper of Codex that holds the same pipe when the tool starts it.
    assert!(
        programs.contains(&"/opt/codex/bin/codex-code-mode-host".to_owned()),
        "{programs:?}"
    );
}

#[test]
fn the_chain_reader_sees_a_program_added_to_the_vector() {
    let argv: Vec<String> = [
        "/usr/bin/env",
        "-i",
        "HOME=/h",
        "/usr/local/bin/factory-wrap",
        "/usr/bin/timeout",
        "-s",
        "INT",
        "-k",
        "10",
        "20",
        "/usr/local/bin/claude",
        "--version",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let chain = chain_of(&argv, "/usr/local/bin/claude");
    assert!(
        chain.contains(&"/usr/local/bin/factory-wrap".to_owned()),
        "{chain:?}"
    );
    assert!(
        chain.contains(&"/usr/local/bin/claude".to_owned()),
        "{chain:?}"
    );
}

#[test]
fn harden_sh_reads_the_list_and_keeps_none_of_its_own() {
    let text = std::fs::read_to_string(repo_root().join("infra/sandbox-images/lib/harden.sh"))
        .expect("harden.sh");
    assert!(
        text.contains("execute-only.txt"),
        "harden.sh ignores the list"
    );
    for program in listed() {
        assert!(
            !text.lines().any(|l| {
                let l = l.trim();
                !l.starts_with('#') && l.contains(&program)
            }),
            "harden.sh names {program} itself instead of reading the list"
        );
    }
}

// ---- the race, on a real container ----------------------------------------------------------------

/// Removes what the test made, whatever way it ends.
struct Cleanup<'a> {
    scope: &'a DockerScope,
    name: String,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let _ = self.scope.cli().run(&["rm", "--force", &self.name]);
    }
}

fn exec(
    scope: &DockerScope,
    name: &str,
    user: &str,
    argv: &[&str],
) -> (Option<i32>, String, String) {
    let mut words = vec!["exec", "--user", user, name];
    words.extend_from_slice(argv);
    let out = scope.cli().run(&words).expect("docker exec");
    (out.code, out.stdout, out.stderr)
}

/// What one trial saw.
struct Trial {
    forged_lines: usize,
    chain_ran: bool,
    racer_opened: bool,
    racer_tries: u64,
}

/// One trial: the racer starts first and is already looping when the real chain starts.
fn trial(scope: &DockerScope, name: &str, forged: &str, argv: &[String]) -> Trial {
    let racer_args = ["/bin/bash", "/usr/local/share/pipe_racer.sh", "5", forged];
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    std::thread::scope(|s| {
        let racer = s.spawn(|| exec(scope, name, "10001:10001", &racer_args));
        // The racer is already looping, as a background job of an earlier tool call would be.
        std::thread::sleep(Duration::from_secs(2));
        let (_, stdout, _) = exec(scope, name, "10001:10001", &argv_refs);
        let (_, _, racer_err) = racer.join().expect("the racer thread");
        let racer_tries = racer_err
            .lines()
            .find_map(|l| l.strip_prefix("RACER: no descriptor: "))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        Trial {
            forged_lines: stdout.lines().filter(|l| *l == forged).count(),
            chain_ran: stdout.contains("\"type\":\"system\""),
            racer_opened: racer_err.contains("RACER: opened"),
            racer_tries,
        }
    })
}

#[test]
fn a_hostile_process_that_exists_before_the_exec_cannot_forge_a_line_through_the_chain() {
    let guard = DockerGuard::from_environment();
    let scope = guard.require_or_block();
    let image = support::agent_image();
    let found = scope
        .cli()
        .run(&["image", "inspect", "--format", "{{.Id}}", image.reference()]);
    if !found.is_ok_and(|out| out.success()) {
        blocked(&format!(
            "the image {} is not on this host; build the sandbox images with infra/sandbox-images/build.sh",
            image.reference()
        ));
    }
    let lock = DockerLock::take();
    lock.register_label(scope.label().value());

    let name = format!("rr14-{}", scope.label().value());
    let labels = scope.label_args();
    // A container with no network and no capability. The user is root only so that the modes can be
    // applied, as harden.sh applies them as root at build time; the racer and the chain run as the
    // sandbox user, as the adapters' commands do.
    let started = scope
        .cli()
        .run(&[
            "run",
            "--detach",
            "--pull=never",
            "--name",
            &name,
            &labels[0],
            &labels[1],
            "--label",
            "factory.test=true",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--init",
            "--pids-limit",
            "256",
            "--memory",
            "1g",
            "--log-driver",
            "none",
            "--user",
            "0:0",
            "--tmpfs",
            "/home/agent:rw,mode=0700,uid=10001,gid=10001,size=64m",
            "--tmpfs",
            "/tmp:rw,mode=1777,size=64m",
            "--entrypoint",
            "sleep",
            image.reference(),
            "600",
        ])
        .expect("docker run");
    assert!(
        started.success(),
        "the container did not start: {}",
        started.stderr
    );
    let _cleanup = Cleanup {
        scope: &scope,
        name: name.clone(),
    };

    // The racer script, readable and executable by the sandbox user.
    let racer = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/pipe_racer.sh"),
    )
    .expect("the racer script");
    let installed = scope
        .cli()
        .run_with_input(
            &[
                "exec",
                "-i",
                "--user",
                "0:0",
                &name,
                "/bin/bash",
                "-c",
                "cat > /usr/local/share/pipe_racer.sh && chmod 0755 /usr/local/share/pipe_racer.sh",
            ],
            &racer,
        )
        .expect("docker exec");
    assert!(installed.success(), "{}", installed.stderr);

    let programs = listed();
    let apply = |only: &[String]| {
        let mut words = vec!["exec", "--user", "0:0", name.as_str(), "/bin/chmod", "0711"];
        words.extend(only.iter().map(String::as_str));
        let done = scope.cli().run(&words).expect("docker exec chmod");
        assert!(done.success(), "chmod: {}", done.stderr);
    };

    // The wrapper chain exactly as the adapters build it, around the real tool. It needs no
    // credential and no network: it starts, prints its init event and an error result, and ends.
    let argv = command(
        "/usr/local/bin/claude",
        &["-p", "hi", "--output-format", "stream-json", "--verbose"],
    )
    .into_argv();
    assert_eq!(argv[0], "/usr/bin/env");
    assert!(argv.contains(&TIMEOUT_PROGRAM.to_owned()));
    let forged = "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"terminal_reason\":\"completed\",\"result\":\"FORGED-BY-RACER\",\"usage\":{}}";

    // The control: everything on the list is execute-only EXCEPT `env`, which is what the first fix
    // left readable. The racer must win. Without this the clean result below would show nothing.
    let without_env: Vec<String> = programs
        .iter()
        .filter(|p| *p != "/usr/bin/env")
        .cloned()
        .collect();
    // An image built with the recipe already has `env` at 0711: the control makes it readable again.
    {
        let done = scope
            .cli()
            .run(&[
                "exec",
                "--user",
                "0:0",
                name.as_str(),
                "/bin/chmod",
                "0755",
                "/usr/bin/env",
            ])
            .expect("docker exec chmod");
        assert!(done.success(), "chmod env readable: {}", done.stderr);
    }
    apply(&without_env);
    let mut control = Vec::new();
    for _ in 0..6 {
        let t = trial(&scope, &name, forged, &argv);
        let won = t.forged_lines > 0;
        control.push((t.forged_lines, t.chain_ran, t.racer_opened));
        if won {
            break;
        }
    }
    assert!(
        control
            .iter()
            .any(|(forged_lines, ran, opened)| *forged_lines > 0 && *ran && *opened),
        "the control failed: with /usr/bin/env readable the racer must forge a line into the \
         output of the chain, or this test shows nothing: (forged lines, chain ran, racer opened) \
         per trial = {control:?}"
    );

    // The recipe: every program of the list, as harden.sh applies it.
    apply(&programs);
    let mut results = Vec::new();
    for _ in 0..4 {
        results.push(trial(&scope, &name, forged, &argv));
    }
    for (i, t) in results.iter().enumerate() {
        assert!(
            t.chain_ran,
            "trial {i}: the chain did not run, so nothing was shown"
        );
        assert!(
            !t.racer_opened && t.forged_lines == 0,
            "trial {i}: a process that existed before the exec forged {} line(s) into the output of the \
             chain although every program of lib/execute-only.txt is mode 0711 (RR-14)",
            t.forged_lines
        );
        assert!(
            t.racer_tries > 1000,
            "trial {i}: the racer made only {} attempts, so it did not really race",
            t.racer_tries
        );
    }
    println!(
        "RR-14: control forged on trial {} (lines {:?}); recipe: {} trials, attempts per trial {:?}, forged 0",
        control.len(),
        control.last(),
        results.len(),
        results.iter().map(|t| t.racer_tries).collect::<Vec<_>>()
    );
    drop(lock);
}
