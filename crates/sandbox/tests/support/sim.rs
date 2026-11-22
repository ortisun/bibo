//! A scripted `docker`: a process runner that answers the commands the supervisor sends and
//! starts nothing. It keeps a small model of what was created, so `docker inspect` returns what a
//! correct daemon would return for the arguments of `docker create`. A test then mutates that
//! document to play a daemon that ignored a setting, or fails a command to play a broken one.
//!
//! This is how every unit test of the supervisor runs without a daemon. The tests that need the
//! real daemon use the real runner and are in `tests/container`.
//!
//! The simulated daemon is a Linux host with AppArmor, as a production host is: `docker info`
//! lists `name=apparmor`, and a created container reports an empty `AppArmorProfile` (Docker
//! applies `docker-default` only at the start), unless `--security-opt apparmor=<profile>` named
//! one. [`Sim::daemon_without_apparmor`] plays Docker Desktop instead.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::process::{ProcessRunner, SpawnError, SpawnOutput, SpawnRequest};
use serde_json::{Value, json};

type Mutation = Box<dyn Fn(&mut Value, &str) + Send + Sync>;

/// What `docker info --format '{{json .SecurityOptions}}'` prints on Docker 29 on Ubuntu 24.04.
pub const SECURITY_OPTIONS_WITH_APPARMOR: &str =
    r#"["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"]"#;

/// The same on Docker Desktop, which has no AppArmor.
pub const SECURITY_OPTIONS_WITHOUT_APPARMOR: &str =
    r#"["name=seccomp,profile=builtin","name=cgroupns"]"#;

#[derive(Default)]
struct State {
    calls: Vec<SpawnRequest>,
    creates: BTreeMap<String, Vec<String>>,
    extra_networks: BTreeMap<String, Vec<String>>,
    started: Vec<String>,
    removed: Vec<String>,
    daemon_down: bool,
    image_missing: bool,
    sidecar_start_fails: bool,
    du_fails: bool,
    status_text: Option<String>,
    token_content: Option<Vec<u8>>,
    inspect_before_start: Vec<String>,
    /// What `docker info` prints for the security options; `None` is a daemon with AppArmor.
    security_options: Option<String>,
    /// When set, `docker info` fails with this text.
    info_fails: Option<String>,
}

pub struct Sim {
    state: Mutex<State>,
    mutation: Mutex<Option<Mutation>>,
}

/// The `/proc/self/status` of a process inside a correctly hardened container.
pub fn good_status(uid: u32) -> String {
    format!(
        "Name:\tcat\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapInh:\t0000000000000000\n\
         CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n\
         CapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
    )
}

impl Sim {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            mutation: Mutex::new(None),
        })
    }

    /// Changes every inspect document before it is returned. The second argument is the kind of
    /// container, `sandbox` or `sidecar`.
    pub fn mutate(&self, f: impl Fn(&mut Value, &str) + Send + Sync + 'static) {
        *self.mutation.lock().expect("lock") = Some(Box::new(f));
    }

    /// Makes every `du` that the watchdog runs inside a container fail the way a `docker exec`
    /// does when the container has no free process slot (finding SBX-3).
    pub fn du_cannot_start(&self) {
        self.state.lock().expect("lock").du_fails = true;
    }

    /// Plays a daemon without AppArmor (Docker Desktop).
    pub fn daemon_without_apparmor(&self) {
        self.daemon_security_options(SECURITY_OPTIONS_WITHOUT_APPARMOR);
    }

    /// Makes `docker info` print `answer` for the security options.
    pub fn daemon_security_options(&self, answer: &str) {
        self.state.lock().expect("lock").security_options = Some(answer.to_owned());
    }

    /// Makes `docker info` fail with `stderr`.
    pub fn info_fails(&self, stderr: &str) {
        self.state.lock().expect("lock").info_fails = Some(stderr.to_owned());
    }

    /// Makes `docker info` answer again after [`Sim::info_fails`].
    pub fn info_recovers(&self) {
        self.state.lock().expect("lock").info_fails = None;
    }

    pub fn daemon_down(&self) {
        self.state.lock().expect("lock").daemon_down = true;
    }

    pub fn image_missing(&self) {
        self.state.lock().expect("lock").image_missing = true;
    }

    pub fn sidecar_start_fails(&self) {
        self.state.lock().expect("lock").sidecar_start_fails = true;
    }

    pub fn self_check_prints(&self, text: &str) {
        self.state.lock().expect("lock").status_text = Some(text.to_owned());
    }

    pub fn token_reads_as(&self, bytes: &[u8]) {
        self.state.lock().expect("lock").token_content = Some(bytes.to_vec());
    }

    pub fn calls(&self) -> Vec<SpawnRequest> {
        self.state.lock().expect("lock").calls.clone()
    }

    /// The first word of each call, then the second: `create`, `network create`, ...
    pub fn verbs(&self) -> Vec<String> {
        self.calls()
            .iter()
            .map(|call| match call.args.first().map(String::as_str) {
                Some("network" | "image") => call.args[..2.min(call.args.len())].join(" "),
                Some(first) => first.to_owned(),
                None => String::new(),
            })
            .collect()
    }

    pub fn created(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("lock")
            .creates
            .keys()
            .cloned()
            .collect()
    }

    pub fn started(&self) -> Vec<String> {
        self.state.lock().expect("lock").started.clone()
    }

    pub fn removed(&self) -> Vec<String> {
        self.state.lock().expect("lock").removed.clone()
    }

    /// True when a container was inspected and started after it, never the other way round.
    pub fn inspected_before_started(&self, container: &str) -> bool {
        let state = self.state.lock().expect("lock");
        state
            .inspect_before_start
            .iter()
            .any(|name| name == container)
    }
}

fn ok(stdout: &str) -> Result<SpawnOutput, SpawnError> {
    Ok(SpawnOutput {
        exit_code: Some(0),
        signal: None,
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
        truncated: false,
    })
}

fn fail(stderr: &str) -> Result<SpawnOutput, SpawnError> {
    Ok(SpawnOutput {
        exit_code: Some(1),
        signal: None,
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        truncated: false,
    })
}

fn bytes_of(size: &str) -> u64 {
    let lower = size.to_ascii_lowercase();
    let digits: String = lower.chars().filter(char::is_ascii_digit).collect();
    let base: u64 = digits.parse().unwrap_or(0);
    match lower.trim_start_matches(|c: char| c.is_ascii_digit()) {
        "m" => base * 1024 * 1024,
        "g" => base * 1024 * 1024 * 1024,
        "k" => base * 1024,
        _ => base,
    }
}

/// What a correct daemon reports for `docker create <args>`.
fn derive(args: &[String], extra_networks: &[String]) -> Value {
    let mut doc = json!({
        "State": {"Status": "created", "OOMKilled": false},
        "AppArmorProfile": "",
        "Config": {"User": "", "Env": ["PATH=/opt/rust/bin:/usr/bin:/bin"], "Labels": {}, "Image": ""},
        "Image": "",
        "Mounts": [],
        "NetworkSettings": {"Networks": {}},
        "HostConfig": {
            "Privileged": false, "ReadonlyRootfs": false, "CapAdd": null, "CapDrop": null,
            "SecurityOpt": [], "PidsLimit": 0, "Memory": 0, "MemorySwap": 0, "NanoCpus": 0,
            "NetworkMode": "default", "IpcMode": "private", "PidMode": "", "UsernsMode": "",
            "UTSMode": "", "Init": false, "LogConfig": {"Type": "json-file", "Config": {}},
            "Devices": [], "Ulimits": [], "Tmpfs": {}, "RestartPolicy": {"Name": "no"},
            "AutoRemove": false, "Sysctls": null, "PortBindings": {}, "VolumesFrom": null,
            "ExtraHosts": null, "MaskedPaths": ["/proc/kcore"], "OomKillDisable": false
        }
    });
    let mut alias: Option<String> = None;
    let mut network = String::from("default");
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = args.get(i + 1).cloned().unwrap_or_default();
        match flag {
            "--label" => {
                if let Some((k, v)) = value.split_once('=') {
                    doc["Config"]["Labels"][k] = v.into();
                }
            }
            "--user" => doc["Config"]["User"] = value.into(),
            "--read-only" => {
                doc["HostConfig"]["ReadonlyRootfs"] = true.into();
                i -= 1;
            }
            "--cap-drop" => doc["HostConfig"]["CapDrop"] = json!([value]),
            "--security-opt" => {
                if let Some(profile) = value.strip_prefix("apparmor=") {
                    doc["AppArmorProfile"] = profile.into();
                }
                doc["HostConfig"]["SecurityOpt"]
                    .as_array_mut()
                    .expect("array")
                    .push(value.into());
            }
            "--init" => {
                doc["HostConfig"]["Init"] = true.into();
                i -= 1;
            }
            "--ipc" => doc["HostConfig"]["IpcMode"] = value.into(),
            "--pids-limit" => {
                doc["HostConfig"]["PidsLimit"] = value.parse::<i64>().unwrap_or(0).into()
            }
            "--memory" => doc["HostConfig"]["Memory"] = bytes_of(&value).into(),
            "--memory-swap" => doc["HostConfig"]["MemorySwap"] = bytes_of(&value).into(),
            "--cpus" => {
                let cpus: f64 = value.parse().unwrap_or(0.0);
                doc["HostConfig"]["NanoCpus"] = ((cpus * 1_000_000_000.0).round() as i64).into();
            }
            "--ulimit" => {
                let (name, limit) = value.split_once('=').unwrap_or(("", "0"));
                let soft: i64 = limit.split(':').next().unwrap_or("0").parse().unwrap_or(0);
                doc["HostConfig"]["Ulimits"]
                    .as_array_mut()
                    .expect("array")
                    .push(json!({"Name": name, "Hard": soft, "Soft": soft}));
            }
            "--network" => network = value.clone(),
            "--network-alias" => alias = Some(value.clone()),
            "--log-driver" => doc["HostConfig"]["LogConfig"]["Type"] = value.into(),
            "--restart" => doc["HostConfig"]["RestartPolicy"]["Name"] = value.into(),
            "--env" => doc["Config"]["Env"]
                .as_array_mut()
                .expect("array")
                .push(value.into()),
            "--tmpfs" => {
                if let Some((target, options)) = value.split_once(':') {
                    doc["HostConfig"]["Tmpfs"][target] = options.into();
                }
            }
            "--mount" => {
                let mut source = String::new();
                let mut target = String::new();
                let mut read_only = false;
                for part in value.split(',') {
                    match part.split_once('=') {
                        Some(("src", v)) => source = v.to_owned(),
                        Some(("dst", v)) => target = v.to_owned(),
                        None if part == "readonly" => read_only = true,
                        _ => {}
                    }
                }
                doc["Mounts"].as_array_mut().expect("array").push(json!({
                    "Type": "bind", "Source": source, "Destination": target, "RW": !read_only
                }));
            }
            _ => {
                if flag.contains("@sha256:") {
                    doc["Config"]["Image"] = flag.into();
                    let digest = flag.split_once('@').map_or("", |(_, d)| d);
                    doc["Image"] = digest.into();
                }
                // A flag with no value (`--pull=never`, `--init`) was handled above; the rest
                // of the arguments are values already consumed or positional words.
                i += 1;
                continue;
            }
        }
        i += 2;
    }
    doc["HostConfig"]["NetworkMode"] = network.clone().into();
    let mut networks = serde_json::Map::new();
    let mut endpoint = json!({});
    if let Some(alias) = alias {
        endpoint["Aliases"] = json!([alias]);
    }
    networks.insert(network, endpoint);
    for extra in extra_networks {
        networks.insert(extra.clone(), json!({}));
    }
    doc["NetworkSettings"]["Networks"] = Value::Object(networks);
    doc
}

/// What a container would read at a token path: the host file bind-mounted there. When the
/// supervisor handed the `0400` file to the sandbox user (the test process is root or holds
/// `CAP_CHOWN`, as a Linux worker does, ADR 0035), the container user can read it and the test
/// process cannot; the sim then takes the file back for the read and hands it over again, which
/// the same capability allows.
fn token_from_mount(args: &[String], target: &str) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let mount = args
        .windows(2)
        .find(|w| w[0] == "--mount" && w[1].contains(&format!("dst={target},")))?;
    let source = std::path::Path::new(
        mount[1]
            .split(',')
            .find_map(|part| part.strip_prefix("src="))?,
    );
    match std::fs::read(source) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let owner = std::fs::metadata(source).ok()?;
            let writer = std::fs::metadata(source.parent()?).ok()?;
            std::os::unix::fs::chown(source, Some(writer.uid()), Some(writer.gid())).ok()?;
            let bytes = std::fs::read(source).ok();
            std::os::unix::fs::chown(source, Some(owner.uid()), Some(owner.gid())).ok()?;
            bytes
        }
        Err(_) => None,
    }
}

fn name_of(args: &[String]) -> String {
    args.iter()
        .position(|a| a == "--name")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_default()
}

#[async_trait]
impl ProcessRunner for Sim {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        if cancel.is_cancelled() {
            return Err(SpawnError::Cancelled);
        }
        let mut state = self.state.lock().expect("lock");
        state.calls.push(req.clone());
        if state.daemon_down {
            return fail(
                "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
            );
        }
        let args = req.args.clone();
        let word = |i: usize| args.get(i).map_or("", String::as_str);
        match word(0) {
            "version" => ok("linux/arm64\n"),
            "info" => match &state.info_fails {
                Some(stderr) => fail(stderr),
                None => ok(&format!(
                    "{}\n",
                    state
                        .security_options
                        .as_deref()
                        .unwrap_or(SECURITY_OPTIONS_WITH_APPARMOR)
                )),
            },
            "image" => {
                if state.image_missing {
                    return fail("Error response from daemon: No such image: x");
                }
                let reference = word(args.len() - 1);
                ok(&format!(
                    "{}\n",
                    reference.split_once('@').map_or("", |(_, d)| d)
                ))
            }
            "network" => match word(1) {
                "connect" => {
                    state
                        .extra_networks
                        .entry(word(3).to_owned())
                        .or_default()
                        .push(word(2).to_owned());
                    ok("")
                }
                "rm" => {
                    state.removed.push(word(2).to_owned());
                    ok("")
                }
                _ => ok("net-id\n"),
            },
            "create" => {
                state.creates.insert(name_of(&args), args.clone());
                ok("0123456789abcdef\n")
            }
            "inspect" => {
                let kind = word(2);
                let name = word(3).to_owned();
                if kind == "network" {
                    return ok(&json!([{"Name": name, "Internal": true}]).to_string());
                }
                let Some(create) = state.creates.get(&name).cloned() else {
                    return fail("Error: No such container: x");
                };
                let extra = state.extra_networks.get(&name).cloned().unwrap_or_default();
                let mut doc = derive(&create, &extra);
                if !state.started.contains(&name) {
                    state.inspect_before_start.push(name.clone());
                }
                let kind = doc["Config"]["Labels"]["sf.sandbox"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned();
                drop(state);
                if let Some(mutation) = self.mutation.lock().expect("lock").as_ref() {
                    mutation(&mut doc, &kind);
                }
                ok(&json!([doc]).to_string())
            }
            "start" => {
                let name = word(1).to_owned();
                if state.sidecar_start_fails && name.starts_with("sf-side-") {
                    return fail("Error response from daemon: failed to create task");
                }
                state.started.push(name);
                ok("")
            }
            "exec" => {
                let rest: Vec<&str> = args[1..].iter().map(String::as_str).collect();
                let command = rest
                    .iter()
                    .position(|w| w.starts_with("sf-"))
                    .map_or(0, |i| i + 1);
                match &rest[command..] {
                    ["cat", "/proc/self/status"] => {
                        let text = state
                            .status_text
                            .clone()
                            .unwrap_or_else(|| good_status(10_001));
                        ok(&text)
                    }
                    ["cat", target]
                        if target.ends_with("job-token") || target.ends_with("mcp-token") =>
                    {
                        let container = rest[command - 1];
                        let bytes = state
                            .token_content
                            .clone()
                            .or_else(|| {
                                state
                                    .creates
                                    .get(container)
                                    .and_then(|a| token_from_mount(a, target))
                            })
                            .unwrap_or_default();
                        Ok(SpawnOutput {
                            exit_code: Some(0),
                            signal: None,
                            stdout: bytes,
                            stderr: Vec::new(),
                            truncated: false,
                        })
                    }
                    ["du", ..] if state.du_fails => fail(
                        "OCI runtime exec failed: exec failed: unable to start container process: \
                         error executing setns process: exit status 1: resource temporarily unavailable",
                    ),
                    ["du", ..] => ok("1\t/workspace\n1\t/out\n"),
                    _ => ok(""),
                }
            }
            "rm" => {
                state.removed.push(word(args.len() - 1).to_owned());
                ok("")
            }
            _ => ok(""),
        }
    }
}
