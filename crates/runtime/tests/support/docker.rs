//! The real agent image in a real hardened container, with the spike's fake provider behind a
//! per-job network.
//!
//! **This is not `DockerSandboxProvider`.** The dependency rules (`crate-dependency-rules.json`,
//! DEP-01) allow `runtime` to name only `testkit` as a dev-dependency, so the sandbox crate cannot
//! be used from these tests. [`RealSession`] therefore creates the container itself, with the same
//! hardening the sandbox adapter applies (read-only root, all capabilities dropped,
//! `no-new-privileges`, `--init`, `--ipc none`, uid 10001, a `/tmp` tmpfs, the `.git` mask, the job
//! token file read-only at the ports constant, no network but the job's internal one), reads the
//! posture back from `docker inspect`, and runs the same runtime self-check. The adapter under
//! test then judges that posture with `VerifiedTarget::check`, exactly as it would judge the real
//! sandbox's. What is not exercised is the sandbox adapter's own code. A composition test that
//! wires both belongs in a crate that may depend on both.
//!
//! Everything it creates carries the run label of testkit's `DockerGuard`, and the scope removes it
//! when the test ends. A BLOCKED reason is a panic that starts with `BLOCKED:`, never a skip.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use factory_domain::redaction::Redactor;
use factory_domain::values::{MediaType, Timestamp};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{
    Confinement, ExecRequest, ExecResult, Hardening, JOB_TOKEN_TARGET, Namespace,
    NetworkAttachment, ObservedMount, PostureReport, SandboxError, SandboxId, SandboxLimits,
    SandboxSession, TeardownReason, TeardownReport,
};
use factory_testkit::fx::docker::{DockerGuard, DockerScope, blocked};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{GrantingStore, Harness, IMAGES_JSON, PLATFORM, agent_image, runtime_secret};

// The lock that keeps real-Docker tests from using Docker's network address pool at the same time.
// It is the sandbox crate's file, included here (the dependency rules keep `runtime` from naming
// the `sandbox` crate), so both crates take the same lock file in the system temporary directory
// and a sandbox run and a runtime run wait for each other.
#[path = "../../../sandbox/tests/support/docker_lock.rs"]
mod docker_lock;

use docker_lock::{DockerLock, is_network_pool_exhausted, retry_while_pool_exhausted};

/// The alias of the stand-in sidecar on the job network, as in the sandbox crate's tests.
pub const SIDECAR_ALIAS: &str = "egress";

/// The port the fake provider listens on.
pub const PROVIDER_PORT: u16 = 8080;

/// The public Python image that runs the fake provider. It is a test fixture, not part of the
/// factory's images.
const PROVIDER_IMAGE: &str = "python:3.13-alpine";

/// A directory under the target directory, removed when dropped. It is under `/Users`, so Docker
/// Desktop can mount it.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn open_to_all(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).expect("open it");
}

/// The host side of a workspace: a checkout, an output directory and a place for the token.
pub struct HostWorkspace {
    pub worktree: PathBuf,
    pub out: PathBuf,
    _scratch: Scratch,
}

impl HostWorkspace {
    /// A checkout holding `files` (path and text), the pointer file the `.git` mask needs, and an
    /// output directory. Both are open to the sandbox user.
    pub fn new(files: &[(&str, &str)]) -> Self {
        let scratch = Scratch::new("ws");
        let worktree = scratch.path().join("worktree");
        let out = scratch.path().join("out");
        std::fs::create_dir_all(&worktree).expect("worktree");
        std::fs::create_dir_all(&out).expect("out");
        std::fs::write(worktree.join(".git"), b"gitdir: /nonexistent\n").expect("pointer file");
        std::fs::write(worktree.join("README.md"), b"# a tiny project\n").expect("readme");
        for (path, text) in files {
            let full = worktree.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("parent directories");
                open_to_all(parent);
            }
            std::fs::write(&full, text).expect("a fixture file");
        }
        open_to_all(&worktree);
        open_to_all(&out);
        Self {
            worktree,
            out,
            _scratch: scratch,
        }
    }

    /// Makes a file of the checkout executable.
    pub fn make_executable(&self, relative: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            self.worktree.join(relative),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("an executable file");
    }

    /// True when a file exists in the checkout on the host.
    pub fn has(&self, relative: &str) -> bool {
        self.worktree.join(relative).exists()
    }
}

/// The world of one test: a job network, the fake provider on it, and the key it accepts.
pub struct Lab {
    scope: DockerScope,
    /// Held for the whole life of the lab, so nothing else makes a network meanwhile.
    _lock: DockerLock,
    network: String,
    provider: String,
    pub key: String,
    dirs: Scratch,
    names: AtomicU64,
}

impl Lab {
    /// Starts the world. BLOCKED (a panic) when Docker or an image is missing.
    pub fn start() -> Self {
        let guard = DockerGuard::from_environment();
        let scope = guard.require_or_block();
        let agent = agent_image();
        for reference in [agent.reference(), PROVIDER_IMAGE] {
            let found = scope
                .cli()
                .run(&["image", "inspect", "--format", "{{.Id}}", reference]);
            if !found.is_ok_and(|out| out.success()) {
                blocked(&format!(
                    "the image {reference} is not on this host; build the sandbox images with infra/sandbox-images/build.sh"
                ));
            }
        }
        // Docker hands out an address block to every network from a small pool. Tests that make
        // a network run one at a time on the whole machine, whatever the process or the crate,
        // and a test that holds the lock for too long is ended (see `docker_lock`).
        let lock = DockerLock::take();
        lock.register_label(scope.label().value());

        let dirs = Scratch::new("lab");
        let key = runtime_secret("FAKE");
        let keys = dirs.path().join("keys");
        let out = dirs.path().join("provider");
        std::fs::create_dir_all(&keys).expect("keys");
        std::fs::create_dir_all(&out).expect("provider out");
        std::fs::write(keys.join("key"), &key).expect("the fake key");
        open_to_all(&keys);
        open_to_all(&out);

        let unique = scope.label().value().to_owned();
        let network = format!("rt-net-{unique}");
        let provider = format!("rt-fake-{unique}");
        let labels = scope.label_args();
        // A full address pool is the one transient error of this command, and the only one retried.
        let created = retry_while_pool_exhausted(
            || {
                scope.cli().run(&[
                    "network",
                    "create",
                    "--internal",
                    &labels[0],
                    &labels[1],
                    &network,
                ])
            },
            |result| {
                result
                    .as_ref()
                    .is_ok_and(|out| !out.success() && is_network_pool_exhausted(&out.stderr))
            },
            std::thread::sleep,
        )
        .expect("docker network create");
        assert!(created.success(), "network create: {}", created.stderr);

        let fake_dir = repo_root().join("fixtures/recordings/agent-cli/fake");
        let ext_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support");
        let mounts = [
            format!("{}:/fake/spike:ro", fake_dir.display()),
            format!("{}:/fake/ext:ro", ext_dir.display()),
            format!("{}:/keys:ro", keys.display()),
            format!("{}:/out", out.display()),
        ];
        let port = PROVIDER_PORT.to_string();
        let started = scope
            .cli()
            .run(&[
                "run",
                "-d",
                "--name",
                &provider,
                &labels[0],
                &labels[1],
                "--network",
                &network,
                "--network-alias",
                SIDECAR_ALIAS,
                "-v",
                &mounts[0],
                "-v",
                &mounts[1],
                "-v",
                &mounts[2],
                "-v",
                &mounts[3],
                PROVIDER_IMAGE,
                "python3",
                "/fake/ext/runtime_fake_provider.py",
                "--port",
                &port,
                "--log",
                "/out/requests.jsonl",
                "--key-file",
                "/keys/key",
            ])
            .expect("docker run");
        assert!(started.success(), "the fake provider: {}", started.stderr);
        let lab = Self {
            scope,
            _lock: lock,
            network,
            provider,
            key,
            dirs,
            names: AtomicU64::new(0),
        };
        lab.wait_for_provider();
        lab
    }

    fn wait_for_provider(&self) {
        for _ in 0..50 {
            let logs = self
                .scope
                .cli()
                .run(&["logs", &self.provider])
                .map(|o| format!("{}{}", o.stdout, o.stderr))
                .unwrap_or_default();
            if logs.contains("listening on") {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("the fake provider did not start");
    }

    /// The broker address the tools are given.
    pub fn broker_url(&self) -> String {
        format!("http://{SIDECAR_ALIAS}:{PROVIDER_PORT}")
    }

    /// Every request the fake provider logged, oldest first.
    pub fn provider_requests(&self) -> Vec<Value> {
        let path = self.dirs.path().join("provider/requests.jsonl");
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// The requests that were model calls (a POST to a messages or responses route).
    pub fn model_requests(&self) -> Vec<Value> {
        self.provider_requests()
            .into_iter()
            .filter(|r| r["method"] == "POST" && r["handler"] == "post")
            .collect()
    }

    /// Creates a hardened agent container on the job network, with the key as the job token.
    pub async fn session(&self, h: &Harness, ws: &HostWorkspace) -> RealSession {
        self.session_with(h, ws, &self.key.clone(), Vec::new())
            .await
    }

    /// Like [`session`](Self::session), with another token value and extra `docker create`
    /// arguments (for a test that needs a weaker container to prove the check refuses it).
    pub async fn session_with(
        &self,
        h: &Harness,
        ws: &HostWorkspace,
        token: &str,
        extra: Vec<String>,
    ) -> RealSession {
        let n = self.names.fetch_add(1, Ordering::SeqCst);
        let name = format!("rt-agent-{}-{n}", self.scope.label().value());
        let token_path = self.dirs.path().join(format!("token-{n}"));
        std::fs::write(&token_path, token).expect("the token file");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644))
                .expect("readable token");
        }
        let image = agent_image();
        let labels = self.scope.label_args();
        let mut args: Vec<String> = [
            "create",
            "--name",
            &name,
            &labels[0],
            &labels[1],
            "--pull=never",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--init",
            "--ipc",
            "none",
            "--pids-limit",
            "256",
            "--memory",
            "2g",
            "--memory-swap",
            "2g",
            "--cpus",
            "2",
            "--user",
            "10001:10001",
            "--workdir",
            "/workspace",
            "--network",
            &self.network,
            "--log-driver",
            "none",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
            "--env",
            "HOME=/tmp",
        ]
        .map(String::from)
        .to_vec();
        for mount in [
            format!("type=bind,src={},dst=/workspace", ws.worktree.display()),
            "type=bind,src=/dev/null,dst=/workspace/.git,readonly".to_owned(),
            format!("type=bind,src={},dst=/out", ws.out.display()),
            format!(
                "type=bind,src={},dst={JOB_TOKEN_TARGET},readonly",
                token_path.display()
            ),
        ] {
            args.extend(["--mount".to_owned(), mount]);
        }
        args.extend(extra);
        args.extend([
            image.reference().to_owned(),
            "sleep".to_owned(),
            "infinity".to_owned(),
        ]);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let created = self.scope.cli().run(&refs).expect("docker create");
        assert!(created.success(), "docker create: {}", created.stderr);
        let started = self
            .scope
            .cli()
            .run(&["start", &name])
            .expect("docker start");
        assert!(started.success(), "docker start: {}", started.stderr);
        let inspected = self
            .scope
            .cli()
            .run(&["inspect", "--type", "container", &name])
            .expect("docker inspect");
        assert!(inspected.success(), "docker inspect: {}", inspected.stderr);
        let document: Value = serde_json::from_str(&inspected.stdout).expect("inspect JSON");
        let mut session = RealSession {
            name: name.clone(),
            id: SandboxId::new(name),
            posture: posture_of(&document[0], image),
            store: h.store.clone(),
            redactor: h.redactor.clone(),
            dead: None,
            seen: Vec::new(),
        };
        let status = session
            .exec_text(&["/usr/bin/cat", "/proc/self/status"])
            .await
            .1;
        session.posture.self_check_passed = status.contains("Seccomp:\t2")
            && status.contains("NoNewPrivs:\t1")
            && status.contains("CapEff:\t0000000000000000");
        session
    }

    /// Names of containers of this run that still exist (running or not).
    pub fn leftover_containers(&self) -> Vec<String> {
        let filter = self.scope.label().filter();
        self.scope
            .cli()
            .run(&["ps", "-a", "--filter", &filter, "--format", "{{.Names}}"])
            .map(|o| o.stdout.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// Writes the control file the fake provider reads on every request.
    pub fn script(&self, value: &Value) {
        let path = self.dirs.path().join("provider/script.json");
        std::fs::write(path, value.to_string()).expect("the provider script");
    }

    /// Removes the control file.
    pub fn clear_script(&self) {
        let _ = std::fs::remove_file(self.dirs.path().join("provider/script.json"));
    }

    /// An empty directory for a read-only overlay, and the `--mount` argument pair that puts it
    /// over `target` inside the container, as the sandbox does for a protected or hidden path.
    pub fn overlay_args(&self, target: &str) -> Vec<String> {
        let n = self.names.fetch_add(1, Ordering::SeqCst);
        let dir = self.dirs.path().join(format!("empty-{n}"));
        std::fs::create_dir_all(&dir).expect("an empty directory");
        vec![
            "--mount".to_owned(),
            format!("type=bind,src={},dst={target},readonly", dir.display()),
        ]
    }

    /// The run label's value, for assertions about the names of what was made.
    pub fn run_label(&self) -> String {
        self.scope.label().value().to_owned()
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The posture of a created container, read from its `docker inspect` document.
fn posture_of(doc: &Value, image: factory_ports::sandbox::ImageDigest) -> PostureReport {
    let host = &doc["HostConfig"];
    let user = doc["Config"]["User"].as_str().unwrap_or("0:0");
    let (uid, gid) = user.split_once(':').map_or((0, 0), |(u, g)| {
        (u.parse().unwrap_or(0), g.parse().unwrap_or(0))
    });
    let options: Vec<&str> = host["SecurityOpt"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let namespace = |value: &Value| match value.as_str().unwrap_or("") {
        "host" => Namespace::Host,
        "none" => Namespace::None,
        _ => Namespace::Private,
    };
    let apparmor = match doc["AppArmorProfile"].as_str().unwrap_or("") {
        "" => Confinement::NotAvailable,
        "unconfined" => Confinement::Unconfined,
        _ => Confinement::RuntimeDefault,
    };
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let observed = Hardening {
        privileged: host["Privileged"].as_bool().unwrap_or(true),
        uid,
        gid,
        read_only_rootfs: host["ReadonlyRootfs"].as_bool().unwrap_or(false),
        cap_drop_all: strings(&host["CapDrop"]).iter().any(|c| c == "ALL"),
        cap_add: strings(&host["CapAdd"]),
        no_new_privileges: options.iter().any(|o| o.starts_with("no-new-privileges")),
        seccomp: if options.iter().any(|o| o.starts_with("seccomp=unconfined")) {
            Confinement::Unconfined
        } else {
            Confinement::RuntimeDefault
        },
        apparmor,
        pid: namespace(&host["PidMode"]),
        ipc: namespace(&host["IpcMode"]),
        uts: namespace(&host["UTSMode"]),
        userns: namespace(&host["UsernsMode"]),
        devices: host["Devices"]
            .as_array()
            .map(|a| a.iter().map(|d| d.to_string()).collect())
            .unwrap_or_default(),
        sysctls: host["Sysctls"]
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default(),
        init: host["Init"].as_bool().unwrap_or(false),
        log_driver_none: host["LogConfig"]["Type"] == "none",
    };
    let mounts = doc["Mounts"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|m| ObservedMount {
                    target: m["Destination"].as_str().unwrap_or_default().to_owned(),
                    read_only: !m["RW"].as_bool().unwrap_or(true),
                    source: m["Source"].as_str().unwrap_or_default().to_owned(),
                })
                .collect()
        })
        .unwrap_or_default();
    let env = doc["Config"]["Env"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(|e| e.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        })
        .unwrap_or_default();
    let n = |v: u32| std::num::NonZeroU32::new(v).expect("non-zero");
    PostureReport {
        observed,
        image,
        limits: SandboxLimits {
            cpu_millis: n(2000),
            memory_mb: n(2048),
            memory_swap_mb: n(2048),
            pids: n(256),
            nofile: n(1024),
            max_file_mb: n(64),
            tmpfs_mb: n(512),
            workspace_disk_mb: n(512),
            wall_clock: Duration::from_secs(600),
        },
        network: NetworkAttachment::JobInternal {
            sidecar: SIDECAR_ALIAS.to_owned(),
        },
        mounts,
        env,
        self_check_passed: false,
        verified_at: Timestamp::parse("2026-10-27T10:00:00Z").expect("a time"),
    }
}

/// A session over a real container.
pub struct RealSession {
    name: String,
    id: SandboxId,
    pub posture: PostureReport,
    store: Arc<GrantingStore>,
    redactor: Arc<Redactor>,
    dead: Option<SandboxError>,
    /// Every argument vector the session was asked to run, in order.
    pub seen: Vec<Vec<String>>,
}

/// Reads at most `cap` bytes, then drains the rest so the writer never blocks.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    cap: usize,
) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(kept.len());
                if n > room {
                    truncated = true;
                }
                kept.extend_from_slice(&buffer[..n.min(room)]);
            }
        }
    }
    (kept, truncated)
}

impl RealSession {
    /// The container's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Runs a command and returns its exit code and standard output as text. For assertions.
    pub async fn exec_text(&mut self, argv: &[&str]) -> (Option<i32>, String) {
        let request = ExecRequest {
            argv: factory_ports::sandbox::ExecArgv::new(
                argv.iter().map(|a| (*a).to_owned()).collect(),
            )
            .expect("a command"),
            cwd: None,
            stdin: None,
            timeout: Duration::from_secs(30),
            max_output_bytes: 1 << 20,
        };
        let result = self
            .exec(request, &factory_runtime::probe::NeverCancelled)
            .await
            .expect("the command ran");
        let reference = result.stdout.clone();
        let bytes = self
            .store
            .get(
                &factory_domain::scope::TenantScope::new(self.tenant()),
                &reference,
            )
            .await
            .expect("stdout");
        (
            result.exit_code,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    /// Runs a command and returns the sandbox's own answer, for a test that expects the session to
    /// be over.
    pub async fn exec_text_result(&mut self, argv: &[&str]) -> Result<Option<i32>, SandboxError> {
        let request = ExecRequest {
            argv: factory_ports::sandbox::ExecArgv::new(
                argv.iter().map(|a| (*a).to_owned()).collect(),
            )
            .expect("a command"),
            cwd: None,
            stdin: None,
            timeout: Duration::from_secs(30),
            max_output_bytes: 1 << 20,
        };
        self.exec(request, &factory_runtime::probe::NeverCancelled)
            .await
            .map(|result| result.exit_code)
    }

    fn tenant(&self) -> factory_domain::ids::TenantId {
        self.store.tenant()
    }

    fn kill(&self) {
        let _ = std::process::Command::new("docker")
            .args(["kill", &self.name])
            .output();
    }

    async fn keep(&self, bytes: Vec<u8>) -> factory_domain::contracts::ArtifactRef {
        let mut stream = self.redactor.stream();
        let mut clean = Vec::with_capacity(bytes.len());
        for chunk in bytes.chunks(8192) {
            stream.push(chunk, &mut clean).expect("redaction");
        }
        stream.finish(&mut clean).expect("redaction end");
        self.store
            .put(clean, MediaType::parse("text/plain").expect("a media type"))
            .await
            .expect("stored")
    }
}

#[async_trait]
impl SandboxSession for RealSession {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn posture(&self) -> &PostureReport {
        &self.posture
    }

    async fn exec(
        &mut self,
        req: ExecRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<ExecResult, SandboxError> {
        self.seen.push(req.argv.as_slice().to_vec());
        if let Some(dead) = &self.dead {
            return Err(dead.clone());
        }
        if cancel.is_cancelled() {
            return Err(SandboxError::Cancelled);
        }
        let mut command = tokio::process::Command::new("docker");
        command.arg("exec").arg("-i");
        command.arg(&self.name);
        command.args(req.argv.as_slice());
        command
            .stdin(if req.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| SandboxError::DaemonUnavailable)?;
        if let (Some(input), Some(mut stdin)) = (req.stdin.clone(), child.stdin.take()) {
            tokio::spawn(async move {
                let _ = stdin.write_all(&input).await;
                let _ = stdin.shutdown().await;
            });
        }
        let cap = usize::try_from(req.max_output_bytes).unwrap_or(usize::MAX);
        let stdout_pipe = child.stdout.take().expect("piped stdout");
        let stderr_pipe = child.stderr.take().expect("piped stderr");
        let out_task = tokio::spawn(read_capped(stdout_pipe, cap));
        let err_task = tokio::spawn(read_capped(stderr_pipe, cap));
        enum End {
            Exited(std::io::Result<std::process::ExitStatus>),
            TimedOut,
            Cancelled,
        }
        let end = tokio::select! {
            status = child.wait() => End::Exited(status),
            () = tokio::time::sleep(req.timeout) => End::TimedOut,
            () = cancel.cancelled() => End::Cancelled,
        };
        match &end {
            End::Exited(_) => {}
            End::TimedOut | End::Cancelled => {
                // The real sandbox ends the whole session when a command is cut short.
                self.kill();
                let _ = child.kill().await;
            }
        }
        let (stdout, stdout_truncated) = tokio::time::timeout(Duration::from_secs(10), out_task)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        let (stderr, stderr_truncated) = tokio::time::timeout(Duration::from_secs(10), err_task)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        let now = Timestamp::parse("2026-10-27T10:00:00Z").expect("a time");
        match end {
            End::Cancelled => {
                self.dead = Some(SandboxError::Cancelled);
                Err(SandboxError::Cancelled)
            }
            End::TimedOut => {
                self.dead = Some(SandboxError::Timeout);
                Ok(ExecResult {
                    exit_code: None,
                    signal: Some(9),
                    timed_out: true,
                    oom_killed: false,
                    stdout: self.keep(stdout).await,
                    stderr: self.keep(stderr).await,
                    stdout_truncated,
                    stderr_truncated,
                    started_at: now,
                    finished_at: now,
                })
            }
            End::Exited(status) => {
                let status = status.map_err(|_| SandboxError::DaemonUnavailable)?;
                Ok(ExecResult {
                    exit_code: status.code(),
                    signal: None,
                    timed_out: false,
                    oom_killed: false,
                    stdout: self.keep(stdout).await,
                    stderr: self.keep(stderr).await,
                    stdout_truncated,
                    stderr_truncated,
                    started_at: now,
                    finished_at: now,
                })
            }
        }
    }

    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        let removed = std::process::Command::new("docker")
            .args(["rm", "-f", "-v", &self.name])
            .output()
            .map_err(|_| SandboxError::TeardownFailed { leaked: true })?;
        if !removed.status.success() {
            return Err(SandboxError::TeardownFailed { leaked: true });
        }
        Ok(TeardownReport {
            sandbox: self.id.clone(),
            reason,
            oom_killed: false,
        })
    }
}

/// The agent image reference, for tests that want to name it.
pub fn image_reference() -> String {
    let root: Value = serde_json::from_str(IMAGES_JSON).expect("images.json");
    root["platforms"][PLATFORM]["images"]["agent"]["reference"]
        .as_str()
        .expect("a reference")
        .to_owned()
}
