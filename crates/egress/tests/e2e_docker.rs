//! End to end, in real containers: the real Claude Code and Codex command line tools, in the hardened
//! `agent` container profile on a per-job internal network, reach a labelled fake provider only
//! through the real sidecar program and the real broker, with a job token and no real key.
//!
//! WHAT IS REAL: the agent image (digest from `infra/sandbox-images/images.json`), the two tools,
//! the sidecar program (the image built by `egress-sidecar/build.sh`), the broker listener and core
//! (this crate), the internal network and the container posture flags. WHAT IS FAKE: the model
//! provider (the spike's `fake_provider.py`, a container on the default bridge), the keys (made at
//! run time), the clock (a fake clock that never moves). WHAT IS NOT USED: the sandbox crate's
//! provider and the runtime crate's adapters. This crate may not depend on either (DEP-01), so the
//! container flags and the tool command lines are written out here from `sandbox/src/container/
//! args.rs` and `runtime/src/{claude,codex}/argv.rs`. Wiring through those crates is the job of the
//! composition root and of the integration tests that follow this package.
//!
//! A missing Docker daemon or image is BLOCKED: a failing test whose message starts `BLOCKED:`.
//! The tests share the daemon's small network pool, so they run one at a time across processes, and
//! everything they create carries the run label and is removed at the end.

mod support;

use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use factory_egress::broker::{CapPolicy, ModelPrice, PriceTable, Provider, TokenCounts};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, ServerLimits, UpstreamConfig,
};
use factory_ports::agent::{
    CostMicroUsd, IssuedJobToken, JobTokenRequest, ModelSelection, RuntimeId,
};
use factory_testkit::fx::canary::{Canary, CanarySet, Sweeper};
use factory_testkit::fx::docker::{DockerGuard, DockerScope, blocked};
use serde_json::Value;
use support::{Rig, made_up_key};

const CLAUDE_MODEL: &str = "claude-sonnet-5-5";
const CODEX_MODEL: &str = "gpt-fake";
const SIDECAR_PORT: u16 = 8443;
const ALIAS: &str = "egress";
const PROVIDER_IMAGE: &str = "python:3.13-alpine";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The reference of an image in the catalog, or BLOCKED when it is not ready.
fn catalog_reference(key: &str) -> String {
    let text = fs::read_to_string(repo().join("infra/sandbox-images/images.json"))
        .unwrap_or_else(|_| blocked("infra/sandbox-images/images.json cannot be read"));
    let doc: Value = serde_json::from_str(&text).expect("images.json is JSON");
    let image = &doc["platforms"]["linux/arm64"]["images"][key];
    if image["status"] != "ready" {
        blocked(&format!(
            "the {key} image is not ready in images.json (status {}); build it with infra/sandbox-images",
            image["status"]
        ));
    }
    image["reference"].as_str().expect("a reference").to_owned()
}

fn open_to_all(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o777));
}

/// A directory that is removed when it goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "e2e-{label}-{}-{}",
            std::process::id(),
            made_up_key("")[..8].to_owned()
        ));
        fs::create_dir_all(&dir).expect("a scratch directory");
        open_to_all(&dir);
        Self(dir)
    }
    fn sub(&self, name: &str) -> PathBuf {
        let dir = self.0.join(name);
        fs::create_dir_all(&dir).expect("a directory");
        open_to_all(&dir);
        dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Lab {
    scope: DockerScope,
    _permit: fs::File,
    net: String,
    sidecar: String,
    agent_image: String,
    broker: BrokerServer,
    rig: Rig,
    key: String,
    host_ip: String,
    dirs: Scratch,
    runs: AtomicUsize,
}

fn docker(scope: &DockerScope, args: &[String]) -> factory_testkit::fx::docker::CliOutput {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    scope
        .cli()
        .run(&refs)
        .unwrap_or_else(|e| panic!("docker {args:?} failed to run: {e}"))
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_owned()).collect()
}

impl Lab {
    fn start(caps: CapPolicy) -> Self {
        let scope = DockerGuard::from_environment().require_or_block();
        let agent_image = catalog_reference("agent");
        let sidecar_image = catalog_reference("egress-sidecar");
        for image in [agent_image.as_str(), sidecar_image.as_str(), PROVIDER_IMAGE] {
            let found = scope
                .cli()
                .run(&["image", "inspect", "--format", "{{.Id}}", image]);
            if !found.is_ok_and(|out| out.success()) {
                blocked(&format!("the image {image} is not on this host"));
            }
        }
        // The daemon's pool of network blocks is small and shared: one lab at a time.
        let lock = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("egress-e2e-docker.lock");
        let permit = fs::File::create(lock).expect("a lock file");
        permit.lock().expect("the lock");

        let unique = scope.label().value().to_owned();
        let dirs = Scratch::new("lab");
        let labels = scope.label_args();
        // The run label goes right after the sub-command, before any image or command.
        let label = |mut args: Vec<String>| -> Vec<String> {
            let at = if args.first().is_some_and(|a| a == "network") {
                2
            } else {
                1
            };
            args.insert(at, labels[1].clone());
            args.insert(at, labels[0].clone());
            args
        };

        // The key of the broker is also the key the fake provider expects.
        let key = made_up_key("provider-test-key-");
        let keys = dirs.sub("keys");
        fs::write(keys.join("key"), &key).expect("the key file");
        let provider_out = dirs.sub("provider");

        // The fake provider, on the default bridge, published on the host's loopback address.
        let provider = format!("e2e-fake-{unique}");
        let fake_dir = repo().join("fixtures/recordings/agent-cli/fake");
        let started = docker(
            &scope,
            &label(strings(&[
                "run",
                "-d",
                "--pull=never",
                "--name",
                &provider,
                "-p",
                "127.0.0.1::8080",
                "-v",
                &format!("{}:/fake:ro", fake_dir.display()),
                "-v",
                &format!("{}:/keys:ro", keys.display()),
                "-v",
                &format!("{}:/out", provider_out.display()),
                PROVIDER_IMAGE,
                "python3",
                "/fake/fake_provider.py",
                "--port",
                "8080",
                "--log",
                "/out/requests.jsonl",
                "--key-file",
                "/keys/key",
            ])),
        );
        assert!(started.success(), "the fake provider: {}", started.stderr);
        let published = docker(&scope, &strings(&["port", &provider, "8080/tcp"]));
        let provider_port: u16 = published
            .stdout
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or_else(|| panic!("no published port: {}", published.stdout));

        // The broker, on the host, in front of it.
        let prices = PriceTable::new()
            .with_model(Provider::Anthropic, CLAUDE_MODEL, price())
            .with_model(Provider::OpenAi, CODEX_MODEL, price());
        let rig = Rig::with_prices(caps, Arc::new(prices));
        let base = format!("http://127.0.0.1:{provider_port}");
        let broker = BrokerServer::start(
            BrokerServerConfig {
                listen: "0.0.0.0:0".parse().expect("an address"),
                upstreams: vec![
                    UpstreamConfig::new(
                        Provider::Anthropic,
                        &base,
                        ProviderKey::new(key.clone()).expect("a key"),
                    )
                    .expect("an upstream"),
                    UpstreamConfig::new(
                        Provider::OpenAi,
                        &base,
                        ProviderKey::new(key.clone()).expect("a key"),
                    )
                    .expect("an upstream"),
                ],
                expected_job: None,
                limits: ServerLimits::default(),
            },
            rig.core.clone(),
        )
        .expect("the broker starts");
        let broker_port = broker.local_addr().port();

        // Where the host is, as a container on the bridge sees it.
        let resolved = docker(
            &scope,
            &label(strings(&[
                "run",
                "--rm",
                "--pull=never",
                PROVIDER_IMAGE,
                "python3",
                "-c",
                "import socket;print(socket.gethostbyname('host.docker.internal'))",
            ])),
        );
        assert!(
            resolved.success(),
            "host.docker.internal: {}",
            resolved.stderr
        );
        let host_ip = resolved.stdout.trim().to_owned();

        // The job network and the sidecar, as the sandbox adapter builds them: an internal
        // network, a sidecar with the strict posture on it under an alias and also on the
        // default bridge, and the broker as the only upstream.
        let net = format!("e2e-net-{unique}");
        let created = docker(
            &scope,
            &label(strings(&["network", "create", "--internal", &net])),
        );
        assert!(created.success(), "network create: {}", created.stderr);
        let sidecar = format!("e2e-side-{unique}");
        let upstream = format!("{host_ip}:{broker_port}");
        let create = docker(
            &scope,
            &label(strings(&[
                "create",
                "--pull=never",
                "--name",
                &sidecar,
                "--user",
                "10003:10003",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--init",
                "--ipc",
                "private",
                "--pids-limit",
                "256",
                "--memory",
                "256m",
                "--memory-swap",
                "256m",
                "--cpus",
                "1.000",
                "--ulimit",
                "core=0",
                "--network",
                &net,
                "--network-alias",
                ALIAS,
                "--stop-timeout",
                "10",
                "--restart",
                "no",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
                &sidecar_image,
                "--mode",
                "broker",
                "--listen",
                &format!("0.0.0.0:{SIDECAR_PORT}"),
                "--upstream",
                &upstream,
                "--job",
                "e2e-job",
            ])),
        );
        assert!(create.success(), "sidecar create: {}", create.stderr);
        let attached = docker(
            &scope,
            &strings(&["network", "connect", "bridge", &sidecar]),
        );
        assert!(attached.success(), "network connect: {}", attached.stderr);
        let start = docker(&scope, &strings(&["start", &sidecar]));
        assert!(start.success(), "sidecar start: {}", start.stderr);
        let lab = Self {
            scope,
            _permit: permit,
            net,
            sidecar,
            agent_image,
            broker,
            rig,
            key,
            host_ip,
            dirs,
            runs: AtomicUsize::new(0),
        };
        lab.wait_for_sidecar();
        lab
    }

    fn wait_for_sidecar(&self) {
        for _ in 0..50 {
            if self.sidecar_log().contains("\"event\":\"ready\"") {
                return;
            }
            thread::sleep(Duration::from_millis(200));
        }
        panic!("the sidecar never said ready: {}", self.sidecar_log());
    }

    fn sidecar_log(&self) -> String {
        let out = docker(&self.scope, &strings(&["logs", &self.sidecar]));
        format!("{}{}", out.stdout, out.stderr)
    }

    fn provider_log(&self) -> Vec<Value> {
        fs::read_to_string(self.dirs.0.join("provider/requests.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn model_requests(&self) -> Vec<Value> {
        self.provider_log()
            .into_iter()
            .filter(|r| r["method"] == "POST" && r["handler"] == "post")
            .collect()
    }

    fn token(&self, ceiling: CostMicroUsd) -> IssuedJobToken {
        self.token_for(self.rig.ids.job(), ceiling)
    }

    fn token_for(&self, job: factory_domain::ids::JobId, ceiling: CostMicroUsd) -> IssuedJobToken {
        self.rig
            .core
            .issue_token(JobTokenRequest {
                tenant: self.rig.ids.tenant(),
                job,
                stage: factory_domain::vocabulary::StageKind::Implementation,
                cost_ceiling: ceiling,
                allowed_models: vec![
                    ModelSelection {
                        runtime: RuntimeId::new("claude-code-cli").expect("a slug"),
                        model: factory_domain::values::NonEmptyString::parse(CLAUDE_MODEL)
                            .expect("a name"),
                    },
                    ModelSelection {
                        runtime: RuntimeId::new("codex-cli").expect("a slug"),
                        model: factory_domain::values::NonEmptyString::parse(CODEX_MODEL)
                            .expect("a name"),
                    },
                ],
                ttl: Duration::from_secs(3600),
            })
            .expect("a token")
    }

    /// The job token as a file on a host directory, to be mounted read-only.
    fn token_file(&self, token: &IssuedJobToken) -> PathBuf {
        let dir = self.dirs.sub(&format!(
            "token-{}",
            self.runs.fetch_add(1, Ordering::SeqCst)
        ));
        let path = dir.join("job-token");
        fs::write(&path, token.secret.expose()).expect("the token file");
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o444));
        }
        path
    }

    /// `docker run` of the agent image in the `agent` profile posture on the job network. The
    /// container is kept (no `--rm`) so it can be inspected; the run label removes it later.
    fn agent_args(
        &self,
        name: &str,
        token_file: &Path,
        workspace: &Path,
        command: &[&str],
    ) -> Vec<String> {
        let labels = self.scope.label_args();
        let mut args = strings(&[
            "run",
            "--name",
            name,
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
            "4g",
            "--memory-swap",
            "4g",
            "--cpus",
            "2",
            "--ulimit",
            "nofile=4096:4096",
            "--ulimit",
            "core=0",
            "--user",
            "10001:10001",
            "--workdir",
            "/workspace",
            "--network",
            &self.net,
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
            "--tmpfs",
            "/home/agent:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700",
            "--env",
            "HOME=/home/agent",
        ]);
        args.extend(strings(&[&labels[0], &labels[1]]));
        args.extend([
            "--mount".to_owned(),
            format!("type=bind,src={},dst=/workspace", workspace.display()),
            "--mount".to_owned(),
            format!(
                "type=bind,src={},dst=/run/factory/job-token,readonly",
                token_file.display()
            ),
        ]);
        args.push(self.agent_image.clone());
        args.extend(command.iter().map(|s| (*s).to_owned()));
        args
    }

    fn broker_url(&self) -> String {
        format!("http://{ALIAS}:{SIDECAR_PORT}")
    }

    /// Runs Claude Code once with the given prompt. The flag set is that of
    /// `runtime/src/claude/argv.rs` (non-specification), with the environment that the runtime's
    /// `ToolEnv` allows.
    fn run_claude(&self, token: &IssuedJobToken, prompt: &str) -> Run {
        let n = self.runs.fetch_add(1, Ordering::SeqCst);
        let name = format!("e2e-claude-{}-{n}", self.scope.label().value());
        let workspace = self.dirs.sub(&format!("ws-claude-{n}"));
        let token_file = self.token_file(token);
        let base = format!("ANTHROPIC_BASE_URL={}", self.broker_url());
        let args = self.agent_args(
            &name,
            &token_file,
            &workspace,
            &[
                "/usr/bin/env",
                "-i",
                "HOME=/home/agent",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                &base,
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
                "CLAUDE_CODE_MAX_RETRIES=2",
                "claude",
                "-p",
                "--output-format=stream-json",
                "--verbose",
                "--no-session-persistence",
                "--setting-sources=user",
                "--strict-mcp-config",
                "--settings={\"apiKeyHelper\":\"/usr/bin/cat /run/factory/job-token\"}",
                &format!("--model={CLAUDE_MODEL}"),
                "--max-turns=6",
                "--max-budget-usd=5.0000",
                "--tools=Bash",
                "--disable-slash-commands",
                "--dangerously-skip-permissions",
                prompt,
            ],
        );
        self.finish(name, args, workspace)
    }

    /// Runs Codex once. The flag set is that of `runtime/src/codex/argv.rs`.
    fn run_codex(&self, token: &IssuedJobToken, prompt: &str) -> Run {
        let n = self.runs.fetch_add(1, Ordering::SeqCst);
        let name = format!("e2e-codex-{}-{n}", self.scope.label().value());
        let workspace = self.dirs.sub(&format!("ws-codex-{n}"));
        let token_file = self.token_file(token);
        let provider = format!(
            "model_providers.broker={{name=\"Broker\", base_url=\"{}/v1\", auth={{command=\"/usr/bin/cat\", args=[\"/run/factory/job-token\"]}}, wire_api=\"responses\", supports_websockets=false, request_max_retries=1, stream_max_retries=1}}",
            self.broker_url()
        );
        let args = self.agent_args(
            &name,
            &token_file,
            &workspace,
            &[
                "/usr/bin/env",
                "-i",
                "HOME=/home/agent",
                "PATH=/opt/codex/bin:/usr/local/bin:/usr/bin:/bin",
                "codex",
                "exec",
                "--json",
                "--ephemeral",
                "--skip-git-repo-check",
                "-C",
                "/workspace",
                "--ignore-user-config",
                "--ignore-rules",
                "--disable",
                "unbounded_connection_retries",
                "-c",
                "project_doc_max_bytes=0",
                "-c",
                "skills.bundled.enabled=false",
                "-m",
                CODEX_MODEL,
                "--dangerously-bypass-approvals-and-sandbox",
                "-c",
                "model_provider=\"broker\"",
                "-c",
                &provider,
                "--disable",
                "plugins",
                "--disable",
                "apps",
                "--disable",
                "remote_plugin",
                "--disable",
                "tool_suggest",
                "--disable",
                "image_generation",
                "--disable",
                "plugin_sharing",
                "-c",
                "web_search=\"disabled\"",
                "-c",
                "analytics.enabled=false",
                "-c",
                "feedback.enabled=false",
                "-c",
                "check_for_update_on_startup=false",
                prompt,
            ],
        );
        self.finish(name, args, workspace)
    }

    fn finish(&self, name: String, args: Vec<String>, workspace: PathBuf) -> Run {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let cli =
            factory_testkit::fx::docker::DockerCli::new().with_timeout(Duration::from_secs(240));
        let out = cli
            .run(&refs)
            .unwrap_or_else(|e| panic!("the agent run: {e}"));
        let inspect = docker(&self.scope, &strings(&["inspect", &name])).stdout;
        Run {
            stdout: out.stdout,
            stderr: out.stderr,
            inspect,
            workspace,
            exit: out.code,
        }
    }

    /// Everything a leak could be seen in, as named byte sinks.
    fn sinks(&self, run: &Run) -> Vec<(String, Vec<u8>)> {
        let mut sinks = vec![
            ("agent stdout".to_owned(), run.stdout.clone().into_bytes()),
            ("agent stderr".to_owned(), run.stderr.clone().into_bytes()),
            (
                "agent docker inspect (env, args, mounts)".to_owned(),
                run.inspect.clone().into_bytes(),
            ),
            (
                "sidecar docker inspect".to_owned(),
                docker(&self.scope, &strings(&["inspect", &self.sidecar]))
                    .stdout
                    .into_bytes(),
            ),
            ("sidecar log".to_owned(), self.sidecar_log().into_bytes()),
            (
                "provider request log".to_owned(),
                fs::read(self.dirs.0.join("provider/requests.jsonl")).unwrap_or_default(),
            ),
        ];
        // The files the agent left on its writable mounts.
        let mut files = Vec::new();
        collect_files(&run.workspace, &mut files);
        for file in files {
            sinks.push((
                format!("file {}", file.display()),
                fs::read(&file).unwrap_or_default(),
            ));
        }
        // The environment a process in this container profile sees.
        let env = self.hostile_probe_env();
        sinks.push((
            "environment of a process in the profile".to_owned(),
            env.into_bytes(),
        ));
        sinks
    }

    fn hostile_probe_env(&self) -> String {
        let token = self.token(CostMicroUsd(1_000_000));
        let file = self.token_file(&token);
        let workspace = self.dirs.sub("ws-probe");
        let name = format!("e2e-env-{}", self.runs.fetch_add(1, Ordering::SeqCst));
        let args = self.agent_args(&name, &file, &workspace, &["/usr/bin/env"]);
        let out = docker(&self.scope, &args);
        let mut text = out.stdout;
        // And the environment of PID 1, as a model's shell would read /proc/1/environ.
        let args = self.agent_args(
            &format!("{name}-proc"),
            &file,
            &workspace,
            &["/usr/bin/cat", "/proc/1/environ"],
        );
        text.push_str(&docker(&self.scope, &args).stdout);
        text
    }
}

fn price() -> ModelPrice {
    ModelPrice {
        input: 1_000_000,
        cache_write: 1_250_000,
        cache_read: 100_000,
        output: 5_000_000,
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

struct Run {
    stdout: String,
    stderr: String,
    inspect: String,
    workspace: PathBuf,
    exit: Option<i32>,
}

impl Run {
    /// The text of the `result` event of Claude Code, and whether it was an error.
    fn claude_result(&self) -> (bool, String) {
        for line in self.stdout.lines().rev() {
            if let Ok(event) = serde_json::from_str::<Value>(line)
                && event["type"] == "result"
            {
                return (
                    event["is_error"].as_bool().unwrap_or(true),
                    event["result"].as_str().unwrap_or("").to_owned(),
                );
            }
        }
        (true, String::new())
    }

    fn codex_failed(&self) -> bool {
        self.stdout.contains("turn.failed") || self.exit != Some(0)
    }
}

fn sweeper(lab: &Lab) -> Sweeper {
    let set = CanarySet::generate().with(Canary::custom("provider_key", &lab.key));
    Sweeper::new(&set)
}

fn assert_no_real_key(lab: &Lab, run: &Run) {
    let sweeper = sweeper(lab);
    for (name, bytes) in lab.sinks(run) {
        let hits = sweeper.scan(&name, &bytes);
        assert!(
            hits.is_empty(),
            "the real provider key leaked into {name}: {hits:?}"
        );
    }
    // The control: the sweep does find the key where it legitimately is, the file the fake
    // provider reads it from, so a clean sweep elsewhere means something.
    let file = fs::read(lab.dirs.0.join("keys/key")).expect("the key file");
    assert!(!sweeper.scan("the provider's key file", &file).is_empty());
}

// ---- the tests --------------------------------------------------------------------------------

#[test]
fn e2e_claude_code_reaches_the_fake_provider_only_through_the_sidecar_and_the_broker() {
    let lab = Lab::start(CapPolicy::default());
    let token = lab.token(CostMicroUsd(5_000_000));
    let run = lab.run_claude(&token, "Say something short.");
    let (is_error, text) = run.claude_result();
    assert!(
        !is_error && text.contains("FAKE-PROVIDER-REPLY"),
        "exit {:?}\nstdout: {}\nstderr: {}\nsidecar: {}",
        run.exit,
        run.stdout,
        run.stderr,
        lab.sidecar_log()
    );
    // Every model request reached the provider with the broker's key, none with the job token.
    let requests = lab.model_requests();
    assert!(!requests.is_empty(), "the provider saw no model request");
    assert!(
        requests
            .iter()
            .all(|r| r["client_credential"]["matches_expected_fake_key"] == true),
        "a request reached the provider without the broker's key: {requests:?}"
    );
    // The broker metered the run from the streamed usage.
    let standing = lab.rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(standing.usage.requests as usize, requests.len());
    assert!(
        standing.usage.input_tokens > 0 && standing.usage.output_tokens > 0,
        "{standing:?}"
    );
    // The sidecar decided once per connection and only about the broker.
    let log = lab.sidecar_log();
    assert!(log.contains("\"decision\":\"allow\""), "{log}");
    assert!(!log.contains("\"decision\":\"deny\""), "{log}");
    assert_no_real_key(&lab, &run);
    let _ = TokenCounts::default();
}

#[test]
fn e2e_codex_reaches_the_fake_provider_only_through_the_sidecar_and_the_broker() {
    let lab = Lab::start(CapPolicy::default());
    let token = lab.token(CostMicroUsd(5_000_000));
    let run = lab.run_codex(&token, "Say something short.");
    assert!(
        !run.codex_failed() && run.stdout.contains("FAKE-PROVIDER-REPLY"),
        "exit {:?}\nstdout: {}\nstderr: {}\nsidecar: {}",
        run.exit,
        run.stdout,
        run.stderr,
        lab.sidecar_log()
    );
    let requests = lab.model_requests();
    assert!(!requests.is_empty(), "the provider saw no model request");
    assert!(
        requests
            .iter()
            .all(|r| r["client_credential"]["matches_expected_fake_key"] == true),
        "{requests:?}"
    );
    let standing = lab.rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(standing.usage.requests as usize, requests.len());
    assert!(standing.usage.output_tokens > 0, "{standing:?}");
    assert_no_real_key(&lab, &run);
}

/// A listener on every interface of the host, to see whether anything reaches it.
struct Bait {
    tcp_hits: Arc<AtomicUsize>,
    udp_hits: Arc<AtomicUsize>,
    tcp_port: u16,
    udp_port: u16,
}

impl Bait {
    fn start() -> Self {
        let tcp = TcpListener::bind("0.0.0.0:0").expect("bind tcp");
        let udp = UdpSocket::bind("0.0.0.0:0").expect("bind udp");
        let (tcp_port, udp_port) = (
            tcp.local_addr().expect("addr").port(),
            udp.local_addr().expect("addr").port(),
        );
        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let udp_hits = Arc::new(AtomicUsize::new(0));
        let counter = tcp_hits.clone();
        thread::spawn(move || {
            for _ in tcp.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        let counter = udp_hits.clone();
        thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            while udp.recv_from(&mut buffer).is_ok() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        Self {
            tcp_hits,
            udp_hits,
            tcp_port,
            udp_port,
        }
    }
}

/// NT-SBX-05 in the real network position of the agent: a hostile process in the `agent` profile
/// network can reach the sidecar and nothing else. The bait listens on every interface of the
/// host and counts what reaches it. The control is the same probe on the default bridge, which
/// does reach the bait.
#[test]
fn e2e_a_process_in_the_agent_network_reaches_the_sidecar_and_nothing_else() {
    let lab = Lab::start(CapPolicy::default());
    let bait = Bait::start();
    let broker_port = lab.broker.local_addr().port();
    let script = format!(
        r#"
import json, socket
res = {{}}
def tcp(name, host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        res[name] = "connected"
    except Exception as e:
        res[name] = type(e).__name__
def dns(name, host):
    try:
        res[name] = socket.gethostbyname(host)
    except Exception as e:
        res[name] = type(e).__name__
tcp("sidecar", "{alias}", {sidecar_port})
tcp("sidecar_other_port", "{alias}", {other_port})
tcp("bait_tcp", "{host}", {bait_tcp})
tcp("broker_direct", "{host}", {broker})
tcp("public_ip", "1.1.1.1", 80)
tcp("metadata_ip", "169.254.169.254", 80)
dns("external_name", "example.com")
dns("flipping_name", "rebind.test")
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    u.sendto(b"x", ("{host}", {bait_udp}))
    res["bait_udp_sent"] = "sent"
except Exception as e:
    res["bait_udp_sent"] = type(e).__name__
print(json.dumps(res))
"#,
        alias = ALIAS,
        sidecar_port = SIDECAR_PORT,
        other_port = SIDECAR_PORT + 1,
        host = lab.host_ip,
        bait_tcp = bait.tcp_port,
        bait_udp = bait.udp_port,
        broker = broker_port,
    );
    let probe = |network: &str, name: &str| -> Value {
        let labels = lab.scope.label_args();
        let args = strings(&[
            "run",
            "--rm",
            "--pull=never",
            "--name",
            name,
            &labels[0],
            &labels[1],
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--network",
            network,
            PROVIDER_IMAGE,
            "python3",
            "-c",
            &script,
        ]);
        let out = docker(&lab.scope, &args);
        serde_json::from_str(out.stdout.lines().last().unwrap_or("{}"))
            .unwrap_or_else(|_| panic!("the probe printed no JSON: {} {}", out.stdout, out.stderr))
    };
    let inside = probe(
        &lab.net,
        &format!("e2e-probe-in-{}", lab.scope.label().value()),
    );
    assert_eq!(inside["sidecar"], "connected", "{inside}");
    for name in [
        "sidecar_other_port",
        "bait_tcp",
        "broker_direct",
        "public_ip",
        "metadata_ip",
        "external_name",
        "flipping_name",
    ] {
        assert_ne!(
            inside[name], "connected",
            "{name} was reachable from the agent network: {inside}"
        );
        assert!(
            !inside[name]
                .as_str()
                .is_some_and(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit())),
            "{name} resolved from the agent network: {inside}"
        );
    }
    assert_eq!(
        bait.tcp_hits.load(Ordering::SeqCst),
        0,
        "the bait listener was reached"
    );
    assert_eq!(
        bait.udp_hits.load(Ordering::SeqCst),
        0,
        "the bait socket got a packet"
    );

    // The control: the same probe on the default bridge does reach the bait.
    let outside = probe(
        "bridge",
        &format!("e2e-probe-out-{}", lab.scope.label().value()),
    );
    assert_eq!(
        outside["bait_tcp"], "connected",
        "the control must reach the bait: {outside}"
    );
    assert!(bait.tcp_hits.load(Ordering::SeqCst) >= 1);
}

/// A cap stops the run, and revocation at job end works. Claude Code is told by the fake
/// provider to keep calling a tool; the broker allows three requests and refuses the fourth with
/// 402, on which Claude Code gives up. Revoking the job then refuses even a new run at once.
#[test]
fn e2e_a_request_cap_stops_a_looping_run_and_revocation_at_job_end_refuses_the_next_one() {
    let lab = Lab::start(CapPolicy {
        max_requests: Some(3),
        ..CapPolicy::default()
    });
    let job = lab.rig.ids.job();
    let token = lab.token_for(job, CostMicroUsd(5_000_000));
    let run = lab.run_claude(
        &token,
        "FAKE:LOOP 50 Bash {\"command\": \"true\", \"description\": \"loop\"}",
    );
    let requests = lab.model_requests();
    assert_eq!(
        requests.len(),
        3,
        "the provider must see exactly the three requests the cap allows\nstdout: {}\nsidecar: {}",
        run.stdout,
        lab.sidecar_log()
    );
    let (is_error, _) = run.claude_result();
    assert!(
        is_error,
        "the run must end in an error once the broker refuses: {}",
        run.stdout
    );
    let standing = lab.rig.core.token_usage(&token.id).expect("usage");
    assert_eq!(standing.state, factory_ports::agent::TokenState::Revoked);
    assert_eq!(standing.usage.requests, 3);
    assert_eq!(
        lab.rig.core.revoke_reason(&token.id),
        Some(factory_egress::broker::RevokeReason::RequestCap)
    );

    // Job end: every token of the job is revoked, and a second token of the same job is refused
    // at once, so a run that starts after the end of the job cannot spend.
    let second = lab.token_for(job, CostMicroUsd(5_000_000));
    lab.rig.core.revoke_job(job);
    let before = lab.model_requests().len();
    let run = lab.run_codex(&second, "Say something short.");
    assert!(
        run.codex_failed(),
        "the run with a revoked token must fail: {}",
        run.stdout
    );
    assert_eq!(
        lab.model_requests().len(),
        before,
        "a revoked token reached the provider"
    );
}
