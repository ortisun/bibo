//! Security review of the sandbox adapter (docs/reviews/isolation-core-security-review.md).
//!
//! Tests marked `#[ignore = "confirmed defect ..."]` fail today and show a defect; they pass when
//! the defect is fixed. Tests without `#[ignore]` pin something the review tried to break and could
//! not. Run the defect tests with:
//!
//! ```text
//! CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
//!   cargo test -p factory-sandbox --test security_review -- --ignored
//! ```
//!
//! The Docker tests take the machine-wide Docker lock of the sandbox suite, label everything they
//! create with the run label (`factory.test_run`) and remove it when they end. Without a daemon or
//! without the images they panic with a message that starts `BLOCKED:`; they never pass without
//! Docker. All hostile code runs inside the adapter's own hardened container (the `agent` image,
//! profile `agent` on a job network with a stand-in sidecar, because the `verify` image has no shell), never on the host. The two host-side tests (`sbx_1`, `sbx_2`)
//! only call pure functions and walk a scratch directory that holds empty files.

#![allow(dead_code, unused_imports)]

#[path = "../container/harness.rs"]
mod harness;
#[path = "../support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use factory_ports::paths::RepoPath;
use factory_ports::sandbox::{
    ExecArgv, ExecRequest, SandboxProfile, SandboxSession, TeardownReason,
};
use factory_sandbox::container::posture::denied_flag_in;
use factory_sandbox::workspace::{AuditKind, AuditLimits, audit_output};
use harness::Lab;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{ProcessRunner, SpawnError, SpawnOutput, SpawnRequest};
use factory_sandbox::SystemProcessRunner;

/// Passes every call to the real runner and writes down what the disk watchdog's `du` returned, so
/// a test can tell a poll that measured from a poll that failed.
struct WatchdogLog {
    inner: SystemProcessRunner,
    started: Instant,
    lines: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl ProcessRunner for WatchdogLog {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        let is_du = req.args.iter().any(|a| a == "du");
        let result = self.inner.run(req, cancel).await;
        if is_du {
            let at = self.started.elapsed().as_secs_f32();
            let line = match &result {
                Ok(out) => format!(
                    "t={at:.1}s exit={:?} stdout={:?} stderr={:?}",
                    out.exit_code,
                    String::from_utf8_lossy(&out.stdout).trim(),
                    String::from_utf8_lossy(&out.stderr)
                        .trim()
                        .chars()
                        .take(90)
                        .collect::<String>(),
                ),
                Err(error) => format!("t={at:.1}s error={error:?}"),
            };
            self.lines.lock().expect("lock").push(line);
        }
        result
    }
}

fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_owned()).collect()
}

// ---- SBX-1: the second layer of the argument deny list ---------------------------------------

/// SBX-1, FIXED. The deny list is the second look at a `docker create` vector ("a later edit of
/// the builder cannot start a weaker container without this check failing"). It used to read only
/// `--flag=value` and `--flag value`, not the spellings Docker also accepts, so a builder that was
/// edited to write one of them would have passed both layers. It now reads the vector the way
/// Docker does and checks what each flag means (`container/posture_args.rs`).
///
/// Each vector below was accepted by `docker create` (Docker 29.9.2) in the review.
#[test]
fn sbx_1_the_deny_list_reads_the_spellings_docker_accepts() {
    let vectors: &[&[&str]] = &[
        &["create", "-v/private/tmp:/h:ro"],
        &["create", "-p8080:80"],
        &["create", "--mount", "type=bind,source=/,target=/h"],
        &["create", "--mount", "type=bind,source=/etc,target=/h"],
        &["create", "--mount=type=bind,source=/proc,target=/h"],
        &["create", "--security-opt", "seccomp:unconfined"],
        &["create", "--cgroupns", "host"],
        &["create", "--cgroupns=host"],
        &["create", "--pids-limit", "-1"],
        &["create", "--pids-limit=0"],
        &["create", "--memory", "0"],
    ];
    let missed: Vec<&&[&str]> = vectors
        .iter()
        .filter(|v| denied_flag_in(&strings(v)).is_none())
        .collect();
    assert!(
        missed.is_empty(),
        "{} of {} vectors pass the deny list: {missed:?}",
        missed.len(),
        vectors.len()
    );
}

// ---- SBX-2: names that a reader cannot read ----------------------------------------------------

/// SBX-2, FIXED for the audit walk. The audit used to reject control characters (Unicode category
/// Cc) and a backslash in a name, and accept the characters that reorder or hide text
/// (bidirectional controls, line and paragraph separators, zero width characters, tag characters,
/// the Hangul filler). It now rejects the whole category Cf, Zl and Zp, the tag block and the
/// fillers (`hides_text` in `workspace/audit.rs`), and a name in any script still passes.
const HOSTILE_NAMES: [&str; 8] = [
    "gpj.\u{202E}rs",
    "a\u{2028}b.rs",
    "a\u{2029}b.rs",
    "a\u{200B}b.rs",
    "a\u{FEFF}b.rs",
    "a\u{2066}b.rs",
    "a\u{E0041}b.rs",
    "a\u{3164}b.rs",
];

#[test]
fn sbx_2_the_audit_refuses_names_that_hide_or_reorder_text() {
    let scratch = support::Scratch::new("sbx2");
    let mut accepted = Vec::new();
    for name in HOSTILE_NAMES {
        let dir = scratch.path().join(format!("case-{}", accepted.len()));
        std::fs::create_dir_all(&dir).expect("a case directory");
        std::fs::write(dir.join(name), b"").expect("an empty file");
        let stop = AtomicBool::new(false);
        match audit_output(&dir, &AuditLimits::default(), &stop) {
            Ok(files) if !files.is_empty() => accepted.push(name),
            _ => {}
        }
    }
    assert!(
        accepted.is_empty(),
        "the audit accepted these names: {accepted:?}"
    );
    // The control: names in other scripts, with accents, with an emoji, still pass.
    for (i, name) in [
        "caf\u{e9}.rs",
        "\u{65e5}\u{672c}\u{8a9e}.md",
        "\u{444}\u{430}\u{439}\u{43b}.txt",
        "smile\u{1F600}.png",
    ]
    .iter()
    .enumerate()
    {
        let dir = scratch.path().join(format!("ok-{i}"));
        std::fs::create_dir_all(&dir).expect("a case directory");
        std::fs::write(dir.join(name), b"").expect("an empty file");
        let stop = AtomicBool::new(false);
        let files = audit_output(&dir, &AuditLimits::default(), &stop)
            .unwrap_or_else(|e| panic!("{name:?} must pass the audit: {e:?}"));
        assert_eq!(files.len(), 1, "{name:?}");
    }
}

/// SBX-2, second half, NOT FIXED here. `RepoPath` (the type every changed path goes through) is in
/// the ports crate, which this change may not edit. It still accepts these names. The audit
/// refuses them before a path is built from the sandbox, so the sandbox cannot produce one; a
/// `RepoPath` made from any other text (a webhook, a model's output) is still not checked. The
/// architect owns the change: reject the same class of characters in `check_text`
/// (`crates/ports/src/paths.rs`).
#[test]
#[ignore = "open gap SBX-2 (low), needs the ports crate: RepoPath::new accepts bidi, line separator, zero width and tag characters; fix in crates/ports/src/paths.rs check_text; run: cargo test -p factory-sandbox --test security_review -- --ignored sbx_2"]
fn sbx_2_repo_path_refuses_names_that_hide_or_reorder_text() {
    for name in HOSTILE_NAMES {
        assert!(
            RepoPath::new(&format!("src/{name}")).is_err(),
            "RepoPath accepts {name:?}"
        );
    }
}

/// What held. The names git or the filesystem treat as the repository's own metadata, in the
/// spellings that HFS+ and NTFS ignore, are all refused, and so is every control character.
#[test]
fn held_git_directory_aliases_and_control_names_are_refused() {
    for name in [
        ".git",
        ".GIT",
        ".Git ",
        ".git.",
        "git~1",
        "GIT~1",
        ".g\u{200C}it",
        ".gi\u{202E}t",
        ".git\u{FEFF}",
    ] {
        assert!(
            RepoPath::new(&format!("a/{name}/config")).is_err(),
            "{name:?}"
        );
    }
    for name in ["a\nb", "a\0b", "a\x1bb", "a\u{85}b", "a\\b", "a\u{7f}b"] {
        assert!(RepoPath::new(&format!("a/{name}")).is_err(), "{name:?}");
    }
}

// ---- Docker: the watchdog and the event stream --------------------------------------------------

fn running(lab: &Lab, container: &str) -> bool {
    lab.scope
        .cli()
        .run(&["inspect", "--format", "{{.State.Running}}", container])
        .map(|out| out.stdout.trim() == "true")
        .unwrap_or(false)
}

/// A shell script that brings the process count of the cgroup to its limit with sleeping children,
/// using only builtins (a `cat` or a command substitution would need a process of its own). The
/// children keep the count at the limit for `hold` seconds after the shell has gone.
fn exhaust_pids(hold: u32) -> String {
    format!(
        "while :; do \
           read cur < /sys/fs/cgroup/pids.current; read max < /sys/fs/cgroup/pids.max; \
           [ \"$cur\" -ge \"$max\" ] && break; \
           sleep {hold} > /dev/null 2>&1 & \
         done"
    )
}

/// Writes `files` files of 1 MiB under /out with builtins only.
fn write_files(files: u32) -> String {
    format!(
        "i=0; while [ $i -lt {files} ]; do \
           {{ j=0; while [ $j -lt 1024 ]; do printf '%1024s' x; j=$((j+1)); done; }} > /out/fill-$i; \
           i=$((i+1)); \
         done"
    )
}

/// Held (hypothesis SBX-3 not reproduced). The disk cap is enforced by a poll that runs `du` inside
/// the container with `docker exec`, and a poll that cannot be made is skipped. The review asked
/// whether process-table pressure makes the poll fail often enough to matter. In this environment
/// (Docker Desktop 29.9.2, one run, a Linux VM) the poll still measured and stopped the container
/// while the process table was at its limit. Whether a poll can fail at all under pressure depends
/// on the runtime and kernel, which a macOS host cannot settle; the finding stays a hypothesis
/// about a bounded overshoot (one poll interval of writes), and this test pins today's behaviour.
#[tokio::test(flavor = "multi_thread")]
async fn held_the_disk_cap_is_enforced_while_the_process_table_is_at_its_limit() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let lab = Lab::with_runner(
        true,
        Some(Arc::new(WatchdogLog {
            inner: SystemProcessRunner::new(),
            started: Instant::now(),
            lines: Arc::clone(&lines),
        })),
    );
    let mut spec = lab.spec(SandboxProfile::Agent, 1, Duration::from_secs(120));
    spec.limits.workspace_disk_mb = support::n(8);
    spec.limits.pids = support::n(24);
    let mut session = lab.create(spec).await.expect("an agent sandbox");
    let container = session.id().as_str().to_owned();

    // The control: the limit the exploit relies on is the one in force.
    let max = lab
        .run(&mut *session, &["cat", "/sys/fs/cgroup/pids.max"])
        .await;
    assert_eq!(lab.text(&max).await.0.trim(), "24");

    let script = format!("{}; {}; exit 0", exhaust_pids(25), write_files(40));
    let request = ExecRequest {
        argv: ExecArgv::new(strings(&["bash", "-c", &script])).expect("argv"),
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(60),
        max_output_bytes: 64 * 1024,
    };
    let began = Instant::now();
    let wrote = session
        .exec(request, &factory_testkit::clock::FakeCancel::new())
        .await;
    let exec_took = began.elapsed();
    let stopped_by_exec = matches!(
        wrote,
        Err(factory_ports::sandbox::SandboxError::ResourceExceeded(
            factory_ports::sandbox::Resource::Disk
        ))
    );

    // If the exec returned normally, the container must not be left running over its cap.
    let mut stopped_later = None;
    if !stopped_by_exec {
        let waited = Instant::now();
        while waited.elapsed() < Duration::from_secs(8) {
            if !running(&lab, &container) {
                stopped_later = Some(waited.elapsed());
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let out_bytes: u64 = std::fs::read_dir(lab_out_dir(&lab))
        .map(|dir| {
            dir.filter_map(Result::ok)
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0);
    let polls = lines.lock().expect("lock").join("\n  ");
    let _ = session.stop_and_remove(TeardownReason::Failed).await;
    assert!(
        stopped_by_exec || stopped_later.is_some(),
        "the container ran on over its disk cap: exec = {:?} after {exec_took:?}, {out_bytes} bytes \
         in /out (cap 8 MiB); watchdog polls:\n  {polls}",
        wrote
            .as_ref()
            .map(|r| r.exit_code)
            .map_err(|e| format!("{e:?}")),
    );
    eprintln!(
        "polls:\n  {polls}\nexec after {exec_took:?}, stopped_by_exec = {stopped_by_exec}, {out_bytes} bytes"
    );
}

fn lab_out_dir(lab: &Lab) -> std::path::PathBuf {
    lab.workspaces
        .lock()
        .expect("lock")
        .last()
        .expect("a workspace")
        .mounts
        .out
        .clone()
}

/// SBX-4. Standard output of `docker exec` is the pipe of the first process. Any process of the
/// same user in the container can open `/proc/<pid>/fd/1` of that process and write into the pipe,
/// whatever its own standard output is connected to. The agent adapters read the tool's event
/// stream from this pipe, and `classify` takes the last `result` line as the outcome. A tool
/// child can therefore add lines the tool did not write. This test shows the mechanism with a
/// parent and a child: the child's own output is captured by the parent, and a line still arrives
/// on the exec's output.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "residual SBX-4 (medium), true for any READABLE program such as bash: the stdout pipe of an exec is reachable through /proc/PPID/fd/1; the installed tools are made execute-only by the image (sbx_4_a_tool_that_nobody_can_read_has_a_stdout_that_proc_does_not_open shows the mechanism, infra/sandbox-images/lib/harden.sh installs it); run: cargo test -p factory-sandbox --test security_review -- --ignored sbx_4_a_child"]
async fn sbx_4_a_child_cannot_write_into_the_stdout_pipe_of_its_parent() {
    let lab = Lab::new(true);
    let mut session = lab
        .create(lab.spec(SandboxProfile::Agent, 2, Duration::from_secs(120)))
        .await
        .expect("an agent sandbox");
    let forged = "FORGED-EVENT-LINE";
    // The inner shell's output is captured by the command substitution of the outer shell. The
    // inner shell writes to the outer shell's file descriptor 1 through /proc instead.
    let script = format!(
        "me=$$; captured=$(bash -c \"echo {forged} > /proc/$me/fd/1; echo inner-own-output\"); \
         echo \"captured=$captured\""
    );
    let ran = lab
        .run_with(
            &mut *session,
            &["bash", "-c", &script],
            Duration::from_secs(30),
            64 * 1024,
        )
        .await;
    let (out, err) = lab.text(&ran).await;
    let _ = session.stop_and_remove(TeardownReason::Completed).await;
    assert_eq!(ran.exit_code, Some(0), "{out}{err}");
    assert!(
        out.contains("captured=inner-own-output"),
        "the control failed: {out}{err}"
    );
    assert!(
        !out.lines().any(|line| line == forged),
        "a child wrote a line into its parent's stdout pipe: {out:?}"
    );
}

/// SBX-4, the fix, shown with the mechanism. The kernel clears the dumpable flag of a process that
/// was started from a file nobody can read. The `/proc/<pid>/fd` of such a process belongs to root,
/// so the sandbox user, and anything it starts, cannot open the standard output pipe of the exec
/// through it. The image installs `claude`, `codex`, `codex-code-mode-host` and `timeout` this way
/// (mode 0711, `infra/sandbox-images/lib/harden.sh`); the real tools were run that way, a full turn
/// through the broker, as the image README records.
///
/// This test needs a place where a file can be executable and unreadable, which a bind mount from
/// a macOS host is not (its permission bits are those of the host file). So it uses a container
/// made by hand with the agent image, the same hardening flags and no network, and an executable
/// tmpfs. The stand-in for the tool is an execute-only copy of bash, the first process of the exec,
/// as the tool is.
///
/// The control runs the same attack against the readable bash: the forged line arrives. A test
/// without the control would show nothing.
#[tokio::test(flavor = "multi_thread")]
async fn sbx_4_a_tool_that_nobody_can_read_has_a_stdout_that_proc_does_not_open() {
    let lab = Lab::new(true);
    let image = lab
        .spec(SandboxProfile::Agent, 2, Duration::from_secs(120))
        .image
        .reference()
        .to_owned();
    let cli = lab.scope.cli();
    let name = format!("sbx4-{}", lab.scope.label().value());
    let labels = lab.scope.label_args();
    let started = cli
        .run(&[
            "run",
            "--detach",
            "--pull=never",
            "--name",
            &name,
            &labels[0],
            &labels[1],
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--init",
            "--user",
            "10001:10001",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--log-driver",
            "none",
            "--tmpfs",
            "/w:rw,exec,nosuid,nodev,size=32m,mode=1777",
            &image,
            "sleep",
            "120",
        ])
        .expect("docker run");
    assert!(
        started.success(),
        "the container did not start: {}",
        started.stderr
    );

    let forged = "FORGED-EVENT-LINE";
    // `$me` is the first process of the exec, the one whose stdout is the exec's pipe. A child
    // tries to write into it through /proc; its own output is captured by the parent.
    let attack = |tool: &str| {
        format!(
            "me=$$; captured=$({tool} -c \"echo {forged} > /proc/$me/fd/1; echo inner-own-output\" 2>&1); \
             echo \"captured=$captured\""
        )
    };
    let exec = |argv: &[&str]| {
        let mut words = vec!["exec", name.as_str()];
        words.extend_from_slice(argv);
        cli.run(&words).expect("docker exec")
    };
    let made = exec(&[
        "bash",
        "-c",
        "cp /bin/bash /w/tool && chmod 0111 /w/tool && ! cat /w/tool >/dev/null 2>&1",
    ]);
    // The control: the readable program is forged through.
    let readable = exec(&["bash", "-c", &attack("bash")]);
    // The program that cannot be read, as the first process of the exec.
    let closed = exec(&["/w/tool", "-c", &attack("/w/tool")]);
    let _ = cli.run(&["rm", "--force", &name]);

    assert!(
        made.success(),
        "the stand-in could not be made: {}",
        made.stderr
    );
    assert!(readable.success(), "{}{}", readable.stdout, readable.stderr);
    assert!(
        readable.stdout.lines().any(|line| line == forged),
        "the control failed: the readable program must be forgeable, or this test shows nothing: {:?}",
        readable.stdout
    );
    assert!(closed.success(), "{}{}", closed.stdout, closed.stderr);
    assert!(
        closed.stdout.contains("captured=") && closed.stdout.contains("inner-own-output"),
        "the attack did not run: {}{}",
        closed.stdout,
        closed.stderr
    );
    assert!(
        !closed.stdout.lines().any(|line| line == forged),
        "a child wrote a line into the stdout pipe of a program that nobody can read: {:?}",
        closed.stdout
    );
    assert!(
        closed.stdout.contains("Permission denied"),
        "the write must have been refused by /proc: {:?}",
        closed.stdout
    );
}

/// What held (control for SBX-3 and a regression guard for NT-SBX-07): with free process slots the
/// same over-cap write is measured and the container is killed at once.
#[tokio::test(flavor = "multi_thread")]
async fn held_an_over_cap_write_with_free_pids_is_killed_within_seconds() {
    let lab = Lab::new(true);
    let mut spec = lab.spec(SandboxProfile::Agent, 3, Duration::from_secs(120));
    spec.limits.workspace_disk_mb = support::n(8);
    let mut session = lab.create(spec).await.expect("an agent sandbox");
    let container = session.id().as_str().to_owned();
    let script = format!("{}; exit 0", write_files(40));
    let request = ExecRequest {
        argv: ExecArgv::new(strings(&["bash", "-c", &script])).expect("argv"),
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(60),
        max_output_bytes: 64 * 1024,
    };
    // The poll may kill the container while the writer runs; either answer is fine here.
    let _ = session
        .exec(request, &factory_testkit::clock::FakeCancel::new())
        .await;
    let started = Instant::now();
    let mut stopped_after = None;
    while started.elapsed() < Duration::from_secs(12) {
        if !running(&lab, &container) {
            stopped_after = Some(started.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = session.stop_and_remove(TeardownReason::Failed).await;
    assert!(
        stopped_after.is_some_and(|t| t < Duration::from_secs(8)),
        "stopped_after = {stopped_after:?}"
    );
}

// ---- the agent profile's network: what an agent can see around its own sidecar ------------------

async fn attempt(lab: &Lab, session: &mut dyn SandboxSession, what: &str, script: &str) -> String {
    let result = lab
        .run_with(
            session,
            &["timeout", "10", "bash", "-c", script],
            Duration::from_secs(30),
            8 * 1024,
        )
        .await;
    let (out, err) = lab.text(&result).await;
    format!(
        "{what}: exit={:?} signal={:?} out={:?} err={:?}",
        result.exit_code,
        result.signal,
        out.trim(),
        err.trim()
    )
}

/// What held (NT-SBX-04, the parts the repository's own test does not cover). From an agent
/// sandbox: there is no default route and no gateway address on the job network; the embedded
/// resolver answers for the sidecar's name and for nothing else (an external name, the Docker
/// Desktop host name and the gateway name all fail to resolve, so a name cannot carry data out);
/// the VM host address, the default bridge gateway and an IPv6 address are unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn held_an_agent_sandbox_has_no_route_no_gateway_and_no_external_name_resolution() {
    let lab = Lab::new(true);
    let mut a = lab
        .create(lab.spec(SandboxProfile::Agent, 5, Duration::from_secs(120)))
        .await
        .expect("an agent sandbox");
    let container = a.id().as_str().to_owned();
    let inspected = lab
        .scope
        .cli()
        .run(&[
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}gw={{.Gateway}} v6={{.GlobalIPv6Address}}{{end}}",
            &container,
        ])
        .map(|o| o.stdout)
        .unwrap_or_default();
    let gateway_is_unset = inspected
        .split_whitespace()
        .find_map(|p| p.strip_prefix("gw="))
        .is_none_or(|gw| gw.is_empty() || gw == "invalid");

    let routes = attempt(&lab, &mut *a, "routes", "cat /proc/net/route").await;
    let external = attempt(
        &lab,
        &mut *a,
        "dns-external",
        "getent hosts example.com; echo rc=$?",
    )
    .await;
    let host = attempt(
        &lab,
        &mut *a,
        "dns-host",
        "getent hosts host.docker.internal; echo rc=$?",
    )
    .await;
    let own = attempt(
        &lab,
        &mut *a,
        "dns-sidecar",
        "getent hosts egress; echo rc=$?",
    )
    .await;
    let mut unreachable = Vec::new();
    for target in ["192.168.65.254/80", "192.168.65.254/2375", "172.17.0.1/80"] {
        let script = format!("exec 3<>/dev/tcp/{target}");
        let line = attempt(&lab, &mut *a, target, &script).await;
        unreachable.push(line);
    }
    let _ = a.stop_and_remove(TeardownReason::Completed).await;

    assert!(
        gateway_is_unset,
        "the job network has a gateway: {inspected}"
    );
    // Only the on-link route of the job network: no destination 00000000 (a default route).
    let default_routes = routes
        .split("\\n")
        .filter(|line| line.contains("eth0") && line.contains("\\t00000000\\t00000000\\t0003"))
        .count();
    assert_eq!(default_routes, 0, "a default route exists: {routes}");
    assert!(
        external.contains("rc=2"),
        "an external name resolved: {external}"
    );
    assert!(
        host.contains("rc=2"),
        "the Docker Desktop host name resolved: {host}"
    );
    assert!(
        own.contains("egress") && own.contains("rc=0"),
        "the control failed, the sidecar name does not resolve: {own}"
    );
    for line in &unreachable {
        assert!(
            line.contains("Network is unreachable") || line.contains("exit=Some(124)"),
            "{line}"
        );
        assert!(!line.contains("Connection refused"), "{line}");
    }
}
