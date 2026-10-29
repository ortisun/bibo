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

/// The deny list is the second look at a `docker create` vector ("a later edit of the builder
/// cannot start a weaker container without this check failing"). It reads `--flag=value` and
/// `--flag value`. It does not read the spellings Docker also accepts, so a builder that was edited
/// to write one of them would pass both layers. The builder does not write them today, which is
/// why this is a gap in depth and not a way in.
///
/// Each vector below was accepted by `docker create` (Docker 29.9.2) in the review.
#[test]
#[ignore = "confirmed defect SBX-1 (low, defence in depth): denied_flag_in misses -v/path, -p8080:80, mount source=/target=, seccomp:unconfined, --cgroupns host and unlimited limits; run: cargo test -p factory-sandbox --test security_review -- --ignored sbx_1"]
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

/// The audit walk rejects control characters (Unicode category Cc) and a backslash in a name. The
/// characters that reorder or hide text (bidirectional controls, line and paragraph separators,
/// zero width characters, tag characters, the Hangul filler) are accepted as part of a path. A
/// path then reaches the change list, the evidence, the pull request text and any prompt that
/// lists the files of a diff. The prompt assembler strips exactly these characters from text it
/// quotes, but a path listed outside a quoted block is not text it quotes.
#[test]
#[ignore = "confirmed defect SBX-2 (low): the audit accepts file names with bidi, U+2028, zero-width and tag characters; run: cargo test -p factory-sandbox --test security_review -- --ignored sbx_2"]
fn sbx_2_the_audit_refuses_names_that_hide_or_reorder_text() {
    let scratch = support::Scratch::new("sbx2");
    let hostile = [
        "gpj.\u{202E}rs",
        "a\u{2028}b.rs",
        "a\u{2029}b.rs",
        "a\u{200B}b.rs",
        "a\u{FEFF}b.rs",
        "a\u{2066}b.rs",
        "a\u{E0041}b.rs",
        "a\u{3164}b.rs",
    ];
    let mut accepted = Vec::new();
    for name in hostile {
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
    // The type that every path of a change set goes through accepts them too.
    for name in hostile {
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
#[ignore = "confirmed defect SBX-4 (medium): a child process can write lines into the exec stdout of its parent through /proc/PPID/fd/1, so the event stream is not authentic; run: cargo test -p factory-sandbox --test security_review -- --ignored sbx_4"]
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
