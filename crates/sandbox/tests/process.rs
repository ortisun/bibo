//! The real process runner against the shared `ProcessRunner` contract suite.
//!
//! The runner starts only `docker` and `git`, so the test points both at one small shim script (a
//! test fixture, the way the spawn recorder of the security harness does). The script is the
//! "program": it prints its environment, exits with a code, copies standard input, prints a
//! number of bytes, or sleeps in a child of its own. Everything the contract asserts about the
//! runner (cleared environment, secrets, caps, group kill, cancel) is therefore asserted on real
//! processes. Each deliberate break below must make the suite fail.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{
    EnvValue, ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest,
};
use factory_sandbox::SystemProcessRunner;
use factory_testkit::contracts::process::{self, ProcessSubject};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("process-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).expect("a scratch directory");
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The shim: one script for both programs. It counts its starts in `started`, and the sleeper
/// records the pid of its child in `childpid`.
fn write_shim(dir: &Path) -> PathBuf {
    let script = format!(
        r#"#!/bin/sh
echo started >> "{dir}/started"
case "$1" in
  env) /usr/bin/env | /usr/bin/grep -v -E '^(PWD|OLDPWD|SHLVL|_)=' ;;
  exit) exit "$2" ;;
  cat) exec /bin/cat ;;
  print) /usr/bin/head -c "$2" /dev/zero | /usr/bin/tr '\0' 'o'; /usr/bin/head -c "$3" /dev/zero | /usr/bin/tr '\0' 'e' >&2 ;;
  hang) /bin/sleep 600 & echo $! > "{dir}/childpid"; wait ;;
esac
"#,
        dir = dir.display()
    );
    let path = dir.join("shim");
    fs::write(&path, script).expect("write the shim");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("make it executable");
    path
}

/// A runner whose `git` can be made to vanish.
struct Switchable {
    runner: Mutex<SystemProcessRunner>,
    shim: PathBuf,
}

#[async_trait]
impl ProcessRunner for Switchable {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        let runner = self.runner.lock().expect("the lock").clone();
        runner.run(req, cancel).await
    }
}

struct RealSubject {
    scratch: Scratch,
    runner: Switchable,
}

impl RealSubject {
    fn new() -> Self {
        let scratch = Scratch::new();
        let shim = write_shim(&scratch.0);
        let runner = Switchable {
            runner: Mutex::new(
                SystemProcessRunner::new().with_programs(shim.clone(), shim.clone()),
            ),
            shim,
        };
        Self { scratch, runner }
    }

    fn request(&self, args: &[&str], timeout: Duration, cap: u64) -> SpawnRequest {
        SpawnRequest {
            program: Program::Git,
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            cwd: None,
            env: Vec::new(),
            stdin: None,
            timeout,
            max_output_bytes: cap,
        }
    }
}

#[async_trait]
impl ProcessSubject for RealSubject {
    fn runner(&self) -> &dyn ProcessRunner {
        &self.runner
    }

    fn print_environment(&self, env: Vec<(String, EnvValue)>) -> SpawnRequest {
        SpawnRequest {
            env,
            ..self.request(&["env"], Duration::from_secs(20), 64 * 1024)
        }
    }

    fn exit_with(&self, code: i32) -> SpawnRequest {
        self.request(&["exit", &code.to_string()], Duration::from_secs(20), 1024)
    }

    fn echo_stdin(&self, bytes: Vec<u8>) -> SpawnRequest {
        SpawnRequest {
            stdin: Some(bytes),
            ..self.request(&["cat"], Duration::from_secs(20), 64 * 1024)
        }
    }

    fn print(&self, stdout_bytes: u64, stderr_bytes: u64, cap: u64) -> SpawnRequest {
        self.request(
            &[
                "print",
                &stdout_bytes.to_string(),
                &stderr_bytes.to_string(),
            ],
            Duration::from_secs(20),
            cap,
        )
    }

    fn run_until_killed(&self, timeout: Duration) -> SpawnRequest {
        // The shim needs a moment to start its child. A timeout shorter than that would end the
        // call before there is a grandchild to kill, and the check would pass without proving it.
        self.request(&["hang"], timeout.max(Duration::from_millis(800)), 1024)
    }

    fn with_a_nul_byte(&self) -> SpawnRequest {
        self.request(&["exit", "0\0"], Duration::from_secs(20), 1024)
    }

    fn make_unavailable(&self, program: Program) -> bool {
        if program != Program::Git {
            return false;
        }
        let gone = self.scratch.0.join("no-such-git");
        *self.runner.runner.lock().expect("the lock") =
            SystemProcessRunner::new().with_programs(self.runner.shim.clone(), gone);
        true
    }

    fn children_alive(&self) -> Option<usize> {
        // No file means the call ended before the shim started its child: nothing is alive.
        let Ok(pid) = fs::read_to_string(self.scratch.0.join("childpid")) else {
            return Some(0);
        };
        let alive = std::process::Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .output()
            .ok()?
            .status
            .success();
        Some(usize::from(alive))
    }

    fn processes_started(&self) -> Option<usize> {
        let text = fs::read_to_string(self.scratch.0.join("started")).unwrap_or_default();
        Some(text.lines().count())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_real_runner_passes_the_process_contract() {
    let report = process::run(|| async { RealSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), process::checks().len());
}

/// A runner with one break: it leaves the child alone after a timeout or a cancel.
struct LeavesChild(RealSubject);

#[async_trait]
impl ProcessRunner for LeavesChild {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        // Starts the child detached in its own session and reports a timeout without killing it.
        if req.args.first().map(String::as_str) == Some("hang") {
            let child = std::process::Command::new("/bin/sh")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .arg("-c")
                .arg(format!(
                    "/bin/sleep 20 & echo $! > '{}/childpid'",
                    self.0.scratch.0.display()
                ))
                .spawn()
                .map_err(|_| SpawnError::Os(factory_ports::process::SpawnStep::Start))?;
            drop(child);
            tokio::time::sleep(Duration::from_millis(200)).await;
            return Err(if cancel.is_cancelled() {
                SpawnError::Cancelled
            } else {
                SpawnError::Timeout
            });
        }
        self.0.runner.run(req, cancel).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runner_that_leaves_the_child_running_fails_the_contract() {
    struct Broken(Arc<LeavesChild>);
    #[async_trait]
    impl ProcessSubject for Broken {
        fn runner(&self) -> &dyn ProcessRunner {
            &*self.0
        }
        fn print_environment(&self, env: Vec<(String, EnvValue)>) -> SpawnRequest {
            self.0.0.print_environment(env)
        }
        fn exit_with(&self, code: i32) -> SpawnRequest {
            self.0.0.exit_with(code)
        }
        fn echo_stdin(&self, bytes: Vec<u8>) -> SpawnRequest {
            self.0.0.echo_stdin(bytes)
        }
        fn print(&self, so: u64, se: u64, cap: u64) -> SpawnRequest {
            self.0.0.print(so, se, cap)
        }
        fn run_until_killed(&self, timeout: Duration) -> SpawnRequest {
            self.0.0.run_until_killed(timeout)
        }
        fn with_a_nul_byte(&self) -> SpawnRequest {
            self.0.0.with_a_nul_byte()
        }
        fn make_unavailable(&self, program: Program) -> bool {
            self.0.0.make_unavailable(program)
        }
        fn children_alive(&self) -> Option<usize> {
            self.0.0.children_alive()
        }
        fn processes_started(&self) -> Option<usize> {
            self.0.0.processes_started()
        }
    }
    let report = process::run(|| async { Broken(Arc::new(LeavesChild(RealSubject::new()))) }).await;
    assert!(
        report.failed_check("a_timeout_kills_the_process_group_before_the_call_returns"),
        "failed checks: {:?}",
        report.failed_names()
    );
    assert!(
        report.failed_check("a_cancel_kills_the_process_group_before_the_call_returns"),
        "failed checks: {:?}",
        report.failed_names()
    );
}
