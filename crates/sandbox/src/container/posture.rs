//! The posture verifier: what a created container looks like, read from `docker inspect`, and the
//! rules that no argument vector may break (sandbox-policy.md sections 3.3 and 9).
//!
//! Three pieces, all pure:
//!
//! * [`observe`] turns the inspect document of a container that has been created and not started
//!   into a [`PostureReport`] plus the deviations the report has no field for. The ports crate
//!   compares the report with the spec ([`PostureReport::differences`]); this module only reads.
//!   A part that cannot be read is a deviation, never a default.
//! * [`evaluate_self_check`] decides the runtime self-check from the text of `/proc/self/status`
//!   of a process inside the started container (NT-SBX-02).
//! * [`denied_flag_in`] is the deny list. The argument builder never writes a denied flag, and
//!   the supervisor checks every vector it is about to run against this list once more, so a
//!   later edit of the builder cannot start a weaker container without this check failing.
//!
//! Dangerous flag spellings (`--privileged`, `--cap-add`, `docker.sock`, the unconfined profiles)
//! appear in the source of this crate only here (check ST-04).

use std::num::NonZeroU32;
use std::time::Duration;

use factory_domain::values::Timestamp;
use factory_ports::sandbox::{
    Confinement, ExpectedMount, Hardening, ImageDigest, Namespace, NetworkAttachment,
    ObservedMount, PostureDiff, PostureReport, SCRATCH_TARGET, SandboxLimits, TMPFS_SOURCE,
};
use serde_json::Value;

use super::names::{DISK_MB_LABEL, WALL_MS_LABEL};

/// Flags that may never appear in an argument vector the supervisor runs.
pub const DENIED_FLAGS: &[&str] = &[
    "--privileged",
    "--cap-add",
    "--device",
    "--device-cgroup-rule",
    "--sysctl",
    "--volumes-from",
    "--volume",
    "-v",
    "--publish",
    "--publish-all",
    "-p",
    "-P",
    "--add-host",
    "--env-file",
    "--cgroup-parent",
    "--oom-kill-disable",
    "--rm",
    "--gpus",
    "--runtime",
    "--link",
    "--ip",
    "--dns",
    "--entrypoint",
];

/// Values that make an otherwise allowed flag weaker. Each is the text after `--security-opt`.
const DENIED_SECURITY_OPTIONS: &[&str] = &[
    "seccomp=unconfined",
    "apparmor=unconfined",
    "systempaths=unconfined",
    "label=disable",
    "no-new-privileges=false",
];

/// Flags whose value must not name the host or another container.
const NAMESPACE_FLAGS: &[&str] = &["--network", "--net", "--pid", "--ipc", "--uts", "--userns"];

/// Substrings of a mount or env argument that name the daemon socket or a host root.
const DENIED_FRAGMENTS: &[&str] = &["docker.sock", "src=/,", "src=/etc", "src=/proc", "src=/sys"];

/// The first rule an argument vector breaks, as short text for a log or a test. `None` means the
/// vector is clean.
#[must_use]
pub fn denied_flag_in(args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with('-') => (flag, Some(value)),
            _ => (arg, None),
        };
        if DENIED_FLAGS.contains(&flag) {
            return Some(format!("denied flag {flag}"));
        }
        let value = inline.or_else(|| args.get(index + 1).map(String::as_str));
        if flag == "--security-opt"
            && let Some(value) = value
        {
            if DENIED_SECURITY_OPTIONS.contains(&value) {
                return Some(format!("denied security option {value}"));
            }
            if value.starts_with("seccomp=") || value.starts_with("apparmor=") {
                return Some(format!("custom confinement {value}"));
            }
        }
        if NAMESPACE_FLAGS.contains(&flag)
            && let Some(value) = value
            && (value == "host" || value.starts_with("container:") || value == "bridge")
        {
            return Some(format!("{flag} {value}"));
        }
        if flag == "--user" && value.is_none_or(|v| v.split(':').next() == Some("0")) {
            return Some("root user".to_owned());
        }
        if flag == "--restart" && value != Some("no") {
            return Some("restart policy".to_owned());
        }
        if flag == "--pull" && value != Some("never") {
            return Some("pull policy".to_owned());
        }
        if flag == "--log-driver" && value != Some("none") {
            return Some("log driver".to_owned());
        }
        if flag == "--read-only" && inline == Some("false") {
            return Some("writable root file system".to_owned());
        }
        if (flag == "--mount" || flag == "--env" || flag == "-e")
            && let Some(fragment) = DENIED_FRAGMENTS
                .iter()
                .find(|f| value.is_some_and(|v| v.contains(**f)))
        {
            return Some(format!("{flag} names {fragment}"));
        }
        index += 1;
    }
    None
}

/// What was read from an inspect document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspected {
    /// The report, with `self_check_passed` still false: the container has not started.
    pub report: PostureReport,
    /// Deviations that [`PostureReport`] has no field for. Static names, no values.
    pub extra: Vec<&'static str>,
}

/// What `observe` needs besides the document.
#[derive(Debug, Clone)]
pub struct ObserveInput<'a> {
    /// The first object of `docker inspect <container>`.
    pub document: &'a Value,
    /// The image id the catalog lists for the image, `sha256:...`.
    pub expected_image_id: &'a str,
    /// The per-job network the container must be on, when its spec has one.
    pub job_network: Option<&'a str>,
    /// The sidecar alias observed on that network (read from the sidecar's own inspect).
    pub observed_sidecar: Option<&'a str>,
    /// When the posture is being verified.
    pub verified_at: Timestamp,
}

fn text<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut at = value;
    for key in path {
        at = at.get(*key)?;
    }
    at.as_str()
}

fn number(value: &Value, path: &[&str]) -> Option<i64> {
    let mut at = value;
    for key in path {
        at = at.get(*key)?;
    }
    at.as_i64()
}

fn flag(value: &Value, path: &[&str]) -> bool {
    let mut at = value;
    for key in path {
        match at.get(*key) {
            Some(next) => at = next,
            None => return false,
        }
    }
    at.as_bool().unwrap_or(false)
}

fn strings(value: &Value, path: &[&str]) -> Vec<String> {
    let mut at = value;
    for key in path {
        match at.get(*key) {
            Some(next) => at = next,
            None => return Vec::new(),
        }
    }
    at.as_array()
        .map(|list| {
            list.iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn namespace(mode: &str) -> Namespace {
    match mode {
        "" | "private" => Namespace::Private,
        "none" => Namespace::None,
        // `host`, `shareable`, `container:<id>`, `ns:<path>`: not the container's own.
        _ => Namespace::Host,
    }
}

fn user_ids(user: &str) -> (u32, u32) {
    let mut parts = user.split(':');
    let uid = parts.next().and_then(|p| p.parse().ok());
    let gid = parts.next().and_then(|p| p.parse().ok());
    // A name, an empty user and a missing group are all unknown, and unknown reads as root.
    match (uid, gid) {
        (Some(uid), Some(gid)) => (uid, gid),
        (Some(uid), None) => (uid, 0),
        _ => (0, 0),
    }
}

fn hardening(document: &Value) -> Hardening {
    let host = document.get("HostConfig").unwrap_or(&Value::Null);
    let options = strings(host, &["SecurityOpt"]);
    let has = |wanted: &str| options.iter().any(|o| o == wanted);
    let (uid, gid) = user_ids(text(document, &["Config", "User"]).unwrap_or(""));
    let seccomp = if options.iter().any(|o| o.starts_with("seccomp=")) {
        // A profile that is named is a profile this supervisor did not ask for and cannot judge.
        Confinement::Unconfined
    } else {
        Confinement::RuntimeDefault
    };
    let apparmor = match text(document, &["AppArmorProfile"]) {
        _ if options
            .iter()
            .any(|o| o.starts_with("apparmor=") && o != "apparmor=docker-default") =>
        {
            Confinement::Unconfined
        }
        None | Some("") => Confinement::NotAvailable,
        Some("docker-default") => Confinement::RuntimeDefault,
        Some(_) => Confinement::Unconfined,
    };
    Hardening {
        privileged: flag(host, &["Privileged"]),
        uid,
        gid,
        read_only_rootfs: flag(host, &["ReadonlyRootfs"]),
        cap_drop_all: strings(host, &["CapDrop"])
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case("ALL")),
        cap_add: strings(host, &["CapAdd"]),
        no_new_privileges: has("no-new-privileges")
            || has("no-new-privileges=true")
            || has("no-new-privileges:true"),
        seccomp,
        apparmor,
        pid: namespace(text(host, &["PidMode"]).unwrap_or("")),
        ipc: namespace(text(host, &["IpcMode"]).unwrap_or("")),
        uts: namespace(text(host, &["UTSMode"]).unwrap_or("")),
        userns: namespace(text(host, &["UsernsMode"]).unwrap_or("")),
        devices: host
            .get("Devices")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|d| text(d, &["PathOnHost"]).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        sysctls: host
            .get("Sysctls")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
                    .collect()
            })
            .unwrap_or_default(),
        init: flag(host, &["Init"]),
        log_driver_none: text(host, &["LogConfig", "Type"]) == Some("none"),
    }
}

/// Parses a size such as `64m`, `1g`, `4096k` or `67108864` into bytes.
fn size_bytes(text: &str) -> Option<u64> {
    let lower = text.to_ascii_lowercase();
    let (digits, unit): (String, String) = lower.chars().partition(char::is_ascii_digit);
    let base: u64 = digits.parse().ok()?;
    let factor = match unit.as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return None,
    };
    base.checked_mul(factor)
}

fn mib(bytes: i64) -> Option<NonZeroU32> {
    u64::try_from(bytes)
        .ok()
        .map(|b| b / (1024 * 1024))
        .and_then(|m| u32::try_from(m).ok())
        .and_then(NonZeroU32::new)
}

fn ulimit(host: &Value, name: &str) -> Option<i64> {
    let list = host.get("Ulimits")?.as_array()?;
    let entry = list.iter().find(|u| text(u, &["Name"]) == Some(name))?;
    let soft = number(entry, &["Soft"])?;
    let hard = number(entry, &["Hard"])?;
    // A soft limit below the hard one lets the process raise it: only equal limits are read.
    (soft == hard).then_some(soft)
}

fn label_number(document: &Value, key: &str) -> Option<u64> {
    text(document, &["Config", "Labels", key])?.parse().ok()
}

/// The limits Docker reports, with the two the supervisor itself holds (the wall clock and the
/// disk cap) read from the labels it wrote. `None` when any part is missing or unlimited.
fn limits(document: &Value) -> Option<SandboxLimits> {
    let host = document.get("HostConfig")?;
    let nano_cpus = number(host, &["NanoCpus"]).filter(|n| *n > 0)?;
    let tmpfs_options = host.get("Tmpfs")?.get(SCRATCH_TARGET)?.as_str()?;
    let tmpfs_bytes = tmpfs_options
        .split(',')
        .find_map(|option| option.strip_prefix("size="))
        .and_then(size_bytes)?;
    Some(SandboxLimits {
        cpu_millis: NonZeroU32::new(u32::try_from(nano_cpus / 1_000_000).ok()?)?,
        memory_mb: mib(number(host, &["Memory"])?)?,
        memory_swap_mb: mib(number(host, &["MemorySwap"])?)?,
        pids: NonZeroU32::new(u32::try_from(number(host, &["PidsLimit"])?).ok()?)?,
        nofile: NonZeroU32::new(u32::try_from(ulimit(host, "nofile")?).ok()?)?,
        max_file_mb: mib(ulimit(host, "fsize")?)?,
        tmpfs_mb: mib(i64::try_from(tmpfs_bytes).ok()?)?,
        workspace_disk_mb: NonZeroU32::new(
            u32::try_from(label_number(document, DISK_MB_LABEL)?).ok()?,
        )?,
        wall_clock: Duration::from_millis(label_number(document, WALL_MS_LABEL)?),
    })
}

fn network(document: &Value, input: &ObserveInput<'_>) -> NetworkAttachment {
    let mode = text(document, &["HostConfig", "NetworkMode"]).unwrap_or("");
    let attached: Vec<&str> = document
        .get("NetworkSettings")
        .and_then(|n| n.get("Networks"))
        .and_then(Value::as_object)
        .map(|map| map.keys().map(String::as_str).collect())
        .unwrap_or_default();
    if mode == "none" && attached.iter().all(|name| *name == "none") {
        return NetworkAttachment::None;
    }
    let on_job_network = input.job_network == Some(mode) && attached == [mode];
    match (on_job_network, input.observed_sidecar) {
        (true, Some(alias)) => NetworkAttachment::JobInternal {
            sidecar: alias.to_owned(),
        },
        // Any other network (the default bridge, the host, another container's), or a job
        // network with no sidecar on it, is named so that it cannot equal the spec's.
        _ => NetworkAttachment::JobInternal {
            sidecar: format!("<unexpected network {mode}>"),
        },
    }
}

fn mounts(document: &Value) -> Vec<ObservedMount> {
    let mut all: Vec<ObservedMount> = document
        .get("Mounts")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|m| ObservedMount {
                    target: text(m, &["Destination"]).unwrap_or("").to_owned(),
                    read_only: !flag(m, &["RW"]),
                    source: text(m, &["Source"]).unwrap_or("").to_owned(),
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(tmpfs) = document
        .get("HostConfig")
        .and_then(|h| h.get("Tmpfs"))
        .and_then(Value::as_object)
    {
        for (target, options) in tmpfs {
            let options = options.as_str().unwrap_or("");
            all.push(ObservedMount {
                target: target.clone(),
                read_only: options.split(',').any(|o| o == "ro"),
                source: TMPFS_SOURCE.to_owned(),
            });
        }
    }
    all
}

fn environment(document: &Value) -> Vec<(String, String)> {
    strings(document, &["Config", "Env"])
        .into_iter()
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (name.to_owned(), value.to_owned()),
            None => (pair, String::new()),
        })
        .collect()
}

/// Deviations that the report has no field for.
fn extra_deviations(document: &Value, expected_image_id: &str) -> Vec<&'static str> {
    let host = document.get("HostConfig").unwrap_or(&Value::Null);
    let mut extra = Vec::new();
    if text(document, &["State", "Status"]) != Some("created") {
        extra.push("state");
    }
    if text(document, &["Image"]) != Some(expected_image_id) {
        extra.push("image");
    }
    if host
        .get("PortBindings")
        .and_then(Value::as_object)
        .is_some_and(|map| !map.is_empty())
    {
        extra.push("port_bindings");
    }
    if !strings(host, &["VolumesFrom"]).is_empty() {
        extra.push("volumes_from");
    }
    if !strings(host, &["ExtraHosts"]).is_empty() {
        extra.push("extra_hosts");
    }
    if strings(host, &["MaskedPaths"]).is_empty() {
        // `systempaths=unconfined` removes the masks over /proc and /sys.
        extra.push("masked_paths");
    }
    if flag(host, &["OomKillDisable"]) {
        extra.push("oom_kill_disable");
    }
    if text(host, &["RestartPolicy", "Name"]).is_some_and(|name| name != "no" && !name.is_empty()) {
        extra.push("restart_policy");
    }
    if flag(host, &["AutoRemove"]) {
        extra.push("auto_remove");
    }
    // The scratch tmpfs must not be executable, setuid or a device node source.
    let scratch = host
        .get("Tmpfs")
        .and_then(|t| t.get(SCRATCH_TARGET))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !["noexec", "nosuid", "nodev"]
        .iter()
        .all(|wanted| scratch.split(',').any(|o| o == *wanted))
    {
        extra.push("mounts");
    }
    extra
}

/// Reads the posture of a created container.
///
/// # Errors
/// A [`PostureDiff`] naming the parts that could not be read (an unlimited or missing limit, an
/// image reference that is not a digest). Nothing is guessed: such a container is refused.
pub fn observe(input: &ObserveInput<'_>) -> Result<Inspected, PostureDiff> {
    let document = input.document;
    let image = text(document, &["Config", "Image"]).and_then(|r| ImageDigest::parse(r).ok());
    let limits = limits(document);
    let (Some(image), Some(limits)) = (image.as_ref(), limits.as_ref()) else {
        let mut fields = Vec::new();
        if image.is_none() {
            fields.push("image");
        }
        if limits.is_none() {
            fields.push("limits");
        }
        return Err(PostureDiff { fields });
    };
    let (image, limits) = (image.clone(), limits.clone());
    Ok(Inspected {
        report: PostureReport {
            observed: hardening(document),
            image,
            limits,
            network: network(document, input),
            mounts: mounts(document),
            env: environment(document),
            self_check_passed: false,
            verified_at: input.verified_at,
        },
        extra: extra_deviations(document, input.expected_image_id),
    })
}

/// Where Docker Desktop mounts the host's shared folders inside its virtual machine. It reports a
/// bind mount's source under this prefix for some mounts and not for others of the same job.
const FILE_SHARE_PREFIX: &str = "/host_mnt";

/// Puts an observed bind source back to the host path the spec named, when the daemon reported it
/// under [`FILE_SHARE_PREFIX`] and the path without the prefix is exactly what the spec asked for
/// at that target. Nothing else is changed: a source that is not the requested one stays as it
/// was, and the comparison in the ports crate then reports it.
pub fn normalize_file_share_sources(mounts: &mut [ObservedMount], expected: &[ExpectedMount]) {
    for mount in mounts {
        let Some(plain) = mount.source.strip_prefix(FILE_SHARE_PREFIX) else {
            continue;
        };
        let asked = expected
            .iter()
            .any(|want| want.target == mount.target && want.source.as_deref() == Some(plain));
        if asked {
            mount.source = plain.to_owned();
        }
    }
}

/// The alias the sidecar has on `network`: `expected` when the sidecar has it, otherwise its first
/// alias, otherwise nothing. The sandbox's own posture compares it with the spec.
#[must_use]
pub fn sidecar_alias(document: &Value, network: &str, expected: &str) -> Option<String> {
    let aliases = strings(
        document,
        &["NetworkSettings", "Networks", network, "Aliases"],
    );
    if aliases.iter().any(|alias| alias == expected) {
        Some(expected.to_owned())
    } else {
        aliases.into_iter().next()
    }
}

/// What differs between a created egress sidecar and its plan: the strict hardening, exactly the
/// job network and the default bridge, no mounts and no published ports, and the planned image.
#[must_use]
pub fn sidecar_deviations(
    document: &Value,
    ids: (u32, u32),
    job_network: &str,
    image_reference: &str,
    apparmor_may_be_unavailable: bool,
) -> Vec<&'static str> {
    let expected = Hardening::strict(ids.0, ids.1);
    let mut observed = hardening(document);
    if apparmor_may_be_unavailable && observed.apparmor == Confinement::NotAvailable {
        observed.apparmor = expected.apparmor;
    }
    let mut out = expected.differences(&observed).fields;
    let attached: std::collections::BTreeSet<&str> = document
        .get("NetworkSettings")
        .and_then(|n| n.get("Networks"))
        .and_then(Value::as_object)
        .map(|map| map.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let planned: std::collections::BTreeSet<&str> = [job_network, "bridge"].into_iter().collect();
    if attached != planned {
        out.push("network");
    }
    if text(document, &["Config", "Image"]) != Some(image_reference) {
        out.push("image");
    }
    if document
        .get("Mounts")
        .and_then(Value::as_array)
        .is_some_and(|list| !list.is_empty())
    {
        out.push("mounts");
    }
    let host = document.get("HostConfig").unwrap_or(&Value::Null);
    if host
        .get("PortBindings")
        .and_then(Value::as_object)
        .is_some_and(|map| !map.is_empty())
    {
        out.push("port_bindings");
    }
    out
}

/// What the runtime self-check found wrong, by the name of the `/proc/self/status` field.
pub type SelfCheckFailure = Vec<&'static str>;

fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        (name == key).then(|| rest.trim())
    })
}

/// Decides the runtime self-check (sandbox-policy.md section 9, step 5) from the text of
/// `/proc/self/status` of a process started inside the container: `Seccomp: 2`, `NoNewPrivs: 1`,
/// every capability set zero and the user ids equal to `uid`.
///
/// # Errors
/// The names of the fields that are wrong or missing.
pub fn evaluate_self_check(status: &str, uid: u32) -> Result<(), SelfCheckFailure> {
    let mut wrong = Vec::new();
    if status_field(status, "Seccomp") != Some("2") {
        wrong.push("Seccomp");
    }
    if status_field(status, "NoNewPrivs") != Some("1") {
        wrong.push("NoNewPrivs");
    }
    for set in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let zero = status_field(status, set)
            .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b == b'0'));
        if !zero {
            wrong.push(set);
        }
    }
    let user_ok = status_field(status, "Uid").is_some_and(|ids| {
        let ids: Vec<&str> = ids.split_whitespace().collect();
        ids.len() == 4 && ids.iter().all(|id| id.parse::<u32>().ok() == Some(uid))
    });
    if !user_ok {
        wrong.push("Uid");
    }
    if wrong.is_empty() { Ok(()) } else { Err(wrong) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn each_denied_flag_is_found_in_both_spellings() {
        for flag in DENIED_FLAGS {
            assert!(
                denied_flag_in(&args(&["create", flag, "x"])).is_some(),
                "{flag}"
            );
            assert!(
                denied_flag_in(&args(&["create", &format!("{flag}=x")])).is_some(),
                "{flag}="
            );
        }
    }

    #[test]
    fn weakening_values_of_allowed_flags_are_found() {
        for vector in [
            args(&["create", "--security-opt", "seccomp=unconfined"]),
            args(&["create", "--security-opt", "apparmor=unconfined"]),
            args(&["create", "--security-opt", "systempaths=unconfined"]),
            args(&["create", "--security-opt=seccomp=/tmp/p.json"]),
            args(&["create", "--network", "host"]),
            args(&["create", "--network=container:abc"]),
            args(&["create", "--network", "bridge"]),
            args(&["create", "--pid", "host"]),
            args(&["create", "--ipc=host"]),
            args(&["create", "--userns", "host"]),
            args(&["create", "--user", "0:0"]),
            args(&["create", "--restart", "always"]),
            args(&["create", "--pull", "always"]),
            args(&["create", "--log-driver", "json-file"]),
            args(&["create", "--read-only=false"]),
            args(&[
                "create",
                "--mount",
                "type=bind,src=/var/run/docker.sock,dst=/s",
            ]),
            args(&["create", "--mount", "type=bind,src=/etc,dst=/e"]),
        ] {
            assert!(denied_flag_in(&vector).is_some(), "{vector:?}");
        }
    }

    #[test]
    fn a_hardened_vector_is_clean() {
        let clean = args(&[
            "create",
            "--pull=never",
            "--user",
            "10001:10001",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--init",
            "--ipc",
            "private",
            "--network",
            "none",
            "--log-driver",
            "none",
            "--restart",
            "no",
        ]);
        assert_eq!(denied_flag_in(&clean), None);
    }

    #[test]
    fn the_self_check_accepts_the_canonical_status_and_names_each_bad_field() {
        let good = "Name:\tcat\nUid:\t10001\t10001\t10001\t10001\nCapInh:\t0000000000000000\n\
                    CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n\
                    CapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";
        assert_eq!(evaluate_self_check(good, 10001), Ok(()));
        assert_eq!(
            evaluate_self_check(&good.replace("Seccomp:\t2", "Seccomp:\t0"), 10001),
            Err(vec!["Seccomp"])
        );
        assert_eq!(
            evaluate_self_check(&good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), 10001),
            Err(vec!["NoNewPrivs"])
        );
        assert_eq!(
            evaluate_self_check(
                &good.replace("CapEff:\t0000000000000000", "CapEff:\t00000000a80425fb"),
                10001
            ),
            Err(vec!["CapEff"])
        );
        assert_eq!(evaluate_self_check(good, 0), Err(vec!["Uid"]));
        assert_eq!(
            evaluate_self_check(
                &good.replace("Uid:\t10001\t10001\t10001\t10001", "Uid:\t0\t0\t0\t0"),
                10001
            ),
            Err(vec!["Uid"])
        );
        // A missing field is a failure, not a pass.
        assert!(evaluate_self_check("", 10001).is_err());
    }

    #[test]
    fn a_file_share_prefix_is_removed_only_where_the_spec_asked_for_that_path() {
        let observed = |target: &str, source: &str| ObservedMount {
            target: target.to_owned(),
            read_only: false,
            source: source.to_owned(),
        };
        let expected = vec![
            ExpectedMount {
                target: "/out".to_owned(),
                read_only: false,
                source: Some("/Users/x/out".to_owned()),
            },
            ExpectedMount {
                target: "/workspace".to_owned(),
                read_only: false,
                source: Some("/Users/x/ws".to_owned()),
            },
        ];
        let mut mounts = vec![
            observed("/out", "/host_mnt/Users/x/out"),
            // The daemon reports another path than the one asked for: it must stay different.
            observed("/workspace", "/host_mnt/Users/y/ws"),
            observed("/elsewhere", "/host_mnt/Users/x/out"),
        ];
        normalize_file_share_sources(&mut mounts, &expected);
        assert_eq!(mounts[0].source, "/Users/x/out");
        assert_eq!(mounts[1].source, "/host_mnt/Users/y/ws");
        assert_eq!(mounts[2].source, "/host_mnt/Users/x/out");
    }

    #[test]
    fn a_size_is_read_in_bytes() {
        assert_eq!(size_bytes("64m"), Some(64 * 1024 * 1024));
        assert_eq!(size_bytes("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(size_bytes("67108864"), Some(67_108_864));
        assert_eq!(size_bytes("lots"), None);
    }
}
