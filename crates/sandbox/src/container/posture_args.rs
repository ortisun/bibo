//! The typed reading of an argument vector for the posture deny list ([`super::posture::denied_flag_in`]).
//!
//! The deny list is the second look at a `docker create` vector: "a later edit of the builder
//! cannot start a weaker container without this check failing". A scan for spellings misses the
//! spellings Docker also accepts, so this module reads the vector the way Docker's own flag parser
//! does and checks what each flag *means*:
//!
//! * `--flag value`, `--flag=value`, `-f value`, `-fvalue`, `-f=value` and clusters of boolean
//!   short flags (`-it`) are all read into `(flag, value)` pairs, with the short flag turned into
//!   its long name first;
//! * a flag that takes a value takes the next word when none is glued on, as Docker does;
//! * the checks are on values, not on text: a `--security-opt` is a key and a value joined by `=`
//!   or `:`; a `--mount` is a map of keys with aliases (`src`/`source`, `dst`/`destination`/
//!   `target`); a limit is a number that must be above zero; a user is a number that is not zero;
//! * what is not understood is refused when it could weaken the container (an unknown
//!   `--security-opt` key, a mount of a type that is not `bind`, a mount key this list does not
//!   know, a `--tmpfs` option that makes the scratch space executable);
//! * a `--mount` key is read the way Docker reads it: lower-cased with Go's `ToLower`, and the last
//!   `src`, `source`, `dst`, `destination`, `target` or `type` wins (finding RR-10: `SRC=/etc` after
//!   `src=/tmp/ok` mounts `/etc`);
//! * a bind mount is allowed only for a (source, destination) pair on the [`BindAllowlist`], the
//!   mounts the factory provisions (finding RR-11: a list of host roots to refuse is always one
//!   runtime behind the next, a list of the paths to allow is not). A short list of sensitive roots
//!   stays as a second line, for a pair that was allowed by mistake.
//!
//! This file is part of the posture verifier (check ST-04): dangerous flag spellings may appear
//! in the source of this crate only here and in `posture.rs`.

use super::posture::DENIED_FLAGS;

/// One flag of the vector, in its long name, with the value Docker would read for it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Given<'a> {
    /// The long name, such as `--volume`, or the word as written when it is not known.
    flag: String,
    /// The value glued to the flag or taken from the next word. `None` for a boolean flag.
    value: Option<&'a str>,
    /// True when the value was glued on (`--flag=value`, `-fvalue`).
    glued: bool,
}

/// The long name of a short flag of `docker create`, and whether it takes a value.
fn short(c: char) -> Option<(&'static str, bool)> {
    Some(match c {
        'a' => ("--attach", true),
        'c' => ("--cpu-shares", true),
        'e' => ("--env", true),
        'h' => ("--hostname", true),
        'i' => ("--interactive", false),
        'l' => ("--label", true),
        'm' => ("--memory", true),
        'p' => ("--publish", true),
        'P' => ("--publish-all", false),
        't' => ("--tty", false),
        'u' => ("--user", true),
        'v' => ("--volume", true),
        'w' => ("--workdir", true),
        _ => return None,
    })
}

/// Long flags that take no value. Every other long flag takes one.
const BOOLEAN: &[&str] = &[
    "--privileged",
    "--read-only",
    "--init",
    "--rm",
    "--interactive",
    "--tty",
    "--publish-all",
    "--oom-kill-disable",
    "--no-healthcheck",
    "--sig-proxy",
    "--quiet",
    "--disable-content-trust",
    "--help",
];

/// Reads the vector into flags and values. The first word is the sub-command (`create`). The flags
/// end at the first word that is neither a flag nor the value of one, as Docker reads `create`:
/// that word is the image, and everything after it is the command of the container, not a flag.
/// A `--` ends the flags too.
fn read(args: &[String]) -> Vec<Given<'_>> {
    let mut out = Vec::new();
    let mut index = usize::from(args.first().is_some_and(|word| !word.starts_with('-')));
    while index < args.len() {
        let word = args[index].as_str();
        index += 1;
        if word == "--" || word == "-" || !word.starts_with('-') {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let flag = format!("--{name}");
            let value = if glued.is_some() {
                glued
            } else if BOOLEAN.contains(&flag.as_str()) {
                None
            } else {
                let next = args.get(index).map(String::as_str);
                if next.is_some() {
                    index += 1;
                }
                next
            };
            out.push(Given {
                flag,
                value,
                glued: glued.is_some(),
            });
        } else if let Some(cluster) = word.strip_prefix('-').filter(|c| !c.is_empty()) {
            let chars = cluster.char_indices();
            for (at, c) in chars {
                let Some((long, takes)) = short(c) else {
                    out.push(Given {
                        flag: format!("-{c}"),
                        value: None,
                        glued: false,
                    });
                    continue;
                };
                if !takes {
                    out.push(Given {
                        flag: long.to_owned(),
                        value: None,
                        glued: false,
                    });
                    continue;
                }
                let rest = &cluster[at + c.len_utf8()..];
                let (value, glued) = if rest.is_empty() {
                    let next = args.get(index).map(String::as_str);
                    if next.is_some() {
                        index += 1;
                    }
                    (next, false)
                } else {
                    (Some(rest.strip_prefix('=').unwrap_or(rest)), true)
                };
                out.push(Given {
                    flag: long.to_owned(),
                    value,
                    glued,
                });
                break;
            }
        }
    }
    out
}

/// Flags whose value names a namespace of the host or of another container.
const NAMESPACE_FLAGS: &[&str] = &[
    "--network",
    "--net",
    "--pid",
    "--ipc",
    "--uts",
    "--userns",
    "--cgroupns",
];

/// Directories that no bind mount may start at or inside, whatever the allowlist says: the second
/// line, for a pair that was allowed by mistake. The first line is the allowlist.
const SENSITIVE_TREES: &[&str] = &[
    "/etc",
    "/private/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",
    // The runtime sockets and services under /run. The directory itself is not listed: on a Linux
    // host the token files live on a tmpfs under it, and a path there is refused unless it is the
    // token file of the sandbox being built.
    "/run/docker",
    "/run/containerd",
    "/run/podman",
    "/run/crio",
    "/run/systemd",
    "/run/dbus",
    "/var/run",
    "/private/var/run",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/kubelet",
    "/lib/modules",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
];

/// Directories that are too wide to mount as they stand, though a path inside them is fine: the
/// roots under which the factory's own directories live.
const SENSITIVE_ROOTS: &[&str] = &["/", "/home", "/Users", "/var", "/private", "/tmp", "/opt"];

/// The one device the builder binds: it masks the `.git` file of the workspace.
const MASK: (&str, &str) = (
    factory_ports::sandbox::MASK_SOURCE,
    factory_ports::sandbox::MASK_TARGET,
);

/// The only path a `--tmpfs` may name: the scratch space.
const TMPFS_PATH: &str = factory_ports::sandbox::SCRATCH_TARGET;

/// The bind mounts a vector may hold, as (host source, container destination) pairs. The factory
/// provisions a small, known set of them for a sandbox: the workspace and the paths inside it that
/// are masked or protected, the output directory, the caches and the job token file. A bind mount
/// of any other source, or of an allowed source at another destination, is refused, so a mount over
/// a tool of the image or over the token file is as impossible as a mount of the runtime's socket.
///
/// The paths are compared as read, with `//`, `.` and `..` resolved by reading them (no file system
/// is consulted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindAllowlist {
    pairs: Vec<(String, String)>,
}

impl BindAllowlist {
    /// No pair: the vector may bind nothing but the mask of the `.git` file.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Adds a pair.
    #[must_use]
    pub fn allow(mut self, source: &str, destination: &str) -> Self {
        self.pairs
            .push((lexical_path(source), lexical_path(destination)));
        self
    }

    fn contains(&self, source: &str, destination: &str) -> bool {
        let pair = (lexical_path(source), lexical_path(destination));
        pair == (MASK.0.to_owned(), MASK.1.to_owned()) || self.pairs.contains(&pair)
    }
}

/// The first rule the vector breaks, as short text. `None` means it is clean.
pub(super) fn first_denied(args: &[String], binds: &BindAllowlist) -> Option<String> {
    let given = read(args);
    let mut destinations: Vec<String> = Vec::new();
    for one in &given {
        if let Some(reason) = check(one, binds, &mut destinations) {
            return Some(reason);
        }
    }
    None
}

fn check(
    given: &Given<'_>,
    binds: &BindAllowlist,
    destinations: &mut Vec<String>,
) -> Option<String> {
    let flag = given.flag.as_str();
    if DENIED_FLAGS.contains(&flag) {
        return Some(format!("denied flag {flag}"));
    }
    let value = given.value;
    match flag {
        "--security-opt" => security_option(value),
        "--user" => user(value),
        "--restart" => (value != Some("no")).then(|| "restart policy".to_owned()),
        "--pull" => (value != Some("never")).then(|| "pull policy".to_owned()),
        "--log-driver" => (value != Some("none")).then(|| "log driver".to_owned()),
        "--read-only" => switched_off(given).then(|| "writable root file system".to_owned()),
        "--init" => switched_off(given).then(|| "no init process".to_owned()),
        "--mount" => mount(value, binds, destinations),
        "--tmpfs" => tmpfs(value, destinations),
        "--ulimit" => ulimit(value),
        "--env" => value
            .filter(|v| v.contains("docker.sock"))
            .map(|_| format!("{flag} names the daemon socket")),
        "--pids-limit" => {
            (!positive_integer(value)).then(|| "a process limit that is not above zero".to_owned())
        }
        "--memory" | "--memory-swap" => {
            (!positive_size(value)).then(|| format!("{flag} is not a size above zero"))
        }
        "--cpus" => {
            (!positive_decimal(value)).then(|| "a cpu limit that is not above zero".to_owned())
        }
        _ if NAMESPACE_FLAGS.contains(&flag) => namespace(flag, value),
        _ => None,
    }
}

fn namespace(flag: &str, value: Option<&str>) -> Option<String> {
    let value = value?;
    let lower = value.to_ascii_lowercase();
    let host_or_other = lower == "host"
        || lower.starts_with("container:")
        || lower.starts_with("ns:")
        || (matches!(flag, "--network" | "--net")
            && matches!(lower.as_str(), "bridge" | "default"));
    host_or_other.then(|| format!("{flag} {value}"))
}

/// A security option is a key and a value joined by `=` or `:`. The only one allowed is
/// `no-new-privileges`, on. Anything else is a way to leave the default confinement, or a key
/// this list does not know.
fn security_option(value: Option<&str>) -> Option<String> {
    let Some(value) = value else {
        return Some("a security option with no value".to_owned());
    };
    let (key, setting) = value.split_once(['=', ':']).unwrap_or((value, ""));
    let allowed = key == "no-new-privileges" && matches!(setting, "" | "true");
    (!allowed).then(|| format!("denied security option {key}"))
}

/// The user must be `UID` or `UID:GID`, numbers, and neither may be zero.
fn user(value: Option<&str>) -> Option<String> {
    let Some(value) = value else {
        return Some("root user".to_owned());
    };
    let (uid, gid) = match value.split_once(':') {
        Some((uid, gid)) => (uid, Some(gid)),
        None => (value, None),
    };
    let number = |text: &str| text.parse::<u32>().ok().filter(|n| *n != 0);
    let ok = number(uid).is_some() && gid.is_none_or(|g| number(g).is_some());
    (!ok).then(|| "root user".to_owned())
}

/// True for a boolean flag that was given a value other than a true one (`--read-only=false`).
fn switched_off(given: &Given<'_>) -> bool {
    given
        .glued
        .then_some(given.value)
        .flatten()
        .is_some_and(|v| !matches!(v, "true" | "TRUE" | "True" | "1" | "t" | "T"))
}

/// Go's `strings.ToLower` on a key, which is how Docker reads the keys of a `--mount` value: each
/// character goes to its simple lower-case form. Rust's `to_lowercase` differs in one place (the
/// capital I with a dot above, U+0130, which Go makes a plain `i` and Rust makes `i` and a combining
/// dot), so that one is spelled out.
fn go_lower(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c == '\u{130}' {
                vec!['i']
            } else {
                c.to_lowercase().collect::<Vec<char>>()
            }
        })
        .collect()
}

/// A `--mount` value: comma separated `key=value` words, read the way Docker reads them, and
/// checked by what they mount.
///
/// * The keys are lower-cased first, and the last `type`, `src`/`source` and `dst`/`destination`/
///   `target` wins (finding RR-10).
/// * A key this list does not know is refused (`bind-propagation`, `tmpfs-size`, `volume-opt`, a
///   key in quotes). Only `readonly` and `ro`, which the builder writes, are known besides the three
///   above.
/// * The type must be `bind`: a named volume is another job's data, and the builder makes its
///   scratch space with `--tmpfs`, not with a `tmpfs` mount.
/// * A bind mount must be a (source, destination) pair on the [`BindAllowlist`] (finding RR-11), and
///   no two mounts may share a destination (finding RR-12): a second mount over a path the builder
///   binds replaces it. The source must also be outside the sensitive trees.
fn mount(
    value: Option<&str>,
    binds: &BindAllowlist,
    destinations: &mut Vec<String>,
) -> Option<String> {
    let value = value?;
    if value.contains("docker.sock") {
        return Some("--mount names the daemon socket".to_owned());
    }
    // Docker reads the value as a line of CSV, where a quote changes what a comma means.
    if value.contains(['"', '\n', '\r', '\0']) {
        return Some("--mount with a quote or a line break".to_owned());
    }
    let mut kind = "volume".to_owned();
    let mut source: Option<&str> = None;
    let mut destination: Option<&str> = None;
    for word in value.split(',') {
        let (raw_key, setting) = word.split_once('=').unwrap_or((word, ""));
        match go_lower(raw_key).as_str() {
            "type" => kind = go_lower(setting),
            "src" | "source" => source = Some(setting),
            "dst" | "destination" | "target" => destination = Some(setting),
            "readonly" | "ro" => {}
            other => return Some(format!("--mount with the key {other}")),
        }
    }
    if kind != "bind" {
        return Some(format!("--mount of type {kind}"));
    }
    let Some(source) = source else {
        return Some("a bind mount with no source".to_owned());
    };
    let Some(destination) = destination else {
        return Some("a bind mount with no destination".to_owned());
    };
    let clean = lexical_path(source);
    let target = lexical_path(destination);
    if !binds.contains(source, destination) {
        return Some(format!(
            "--mount of {clean} at {target}, which the factory does not provision"
        ));
    }
    let is_mask = (clean.as_str(), target.as_str()) == MASK;
    let sensitive = !is_mask
        && (SENSITIVE_ROOTS.contains(&clean.as_str())
            || SENSITIVE_TREES.iter().any(|dir| {
                clean == *dir || clean.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
            }));
    if sensitive {
        return Some(format!("--mount of the host path {clean}"));
    }
    if destinations.contains(&target) {
        return Some(format!("two mounts at {target}"));
    }
    destinations.push(target);
    None
}

/// A `--tmpfs` value is `PATH` or `PATH:OPTIONS`. The only path is the scratch space, and the
/// options may not switch on what the builder switches off: `exec`, `suid` and `dev` (finding
/// RR-12). The builder's own value is `rw,noexec,nosuid,nodev,size=...,mode=1777`; the scratch
/// space needs no executable file, so nothing here allows `exec`.
fn tmpfs(value: Option<&str>, destinations: &mut Vec<String>) -> Option<String> {
    let value = value?;
    let (path, options) = value.split_once(':').unwrap_or((value, ""));
    let path = lexical_path(path);
    if path != TMPFS_PATH {
        return Some(format!("--tmpfs at {path}"));
    }
    for option in options.split(',') {
        let option = option.trim().to_ascii_lowercase();
        if matches!(option.as_str(), "exec" | "suid" | "dev") {
            return Some(format!("--tmpfs with the option {option}"));
        }
    }
    if destinations.contains(&path) {
        return Some(format!("two mounts at {path}"));
    }
    destinations.push(path);
    None
}

/// A `--ulimit` value is `NAME=SOFT` or `NAME=SOFT:HARD`, numbers. A negative number is "no limit"
/// to Docker (`core=-1`), and a word that is not a number is refused (finding RR-12).
fn ulimit(value: Option<&str>) -> Option<String> {
    let Some(value) = value else {
        return Some("a ulimit with no value".to_owned());
    };
    let Some((name, limits)) = value.split_once('=') else {
        return Some("a ulimit with no limit".to_owned());
    };
    let plain = limits
        .split(':')
        .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && n.len() < 19);
    (!plain || limits.split(':').count() > 2)
        .then(|| format!("a ulimit of {name} that is not a plain number"))
}

/// The path with `//`, `.` and `..` resolved by reading it, as a string that starts with `/`
/// when the input did. No file system is consulted.
fn lexical_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if path.starts_with('/') {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

fn positive_integer(value: Option<&str>) -> bool {
    value
        .and_then(|v| v.parse::<i64>().ok())
        .is_some_and(|n| n > 0)
}

/// A size such as `512`, `512m`, `2g` or `1024k`: digits and an optional unit, above zero.
fn positive_size(value: Option<&str>) -> bool {
    let Some(text) = value else {
        return false;
    };
    let digits = text.trim_end_matches(['b', 'B', 'k', 'K', 'm', 'M', 'g', 'G']);
    digits.len() + 1 >= text.len()
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits.parse::<u64>().ok().is_some_and(|n| n > 0)
}

fn positive_decimal(value: Option<&str>) -> bool {
    value
        .and_then(|v| v.parse::<f64>().ok())
        .is_some_and(|n| n.is_finite() && n > 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|w| (*w).to_owned()).collect()
    }

    fn denied(items: &[&str]) -> bool {
        first_denied(&words(items), &BindAllowlist::none()).is_some()
    }

    /// The mounts the factory provisions for a sandbox in these tests.
    fn provisioned() -> BindAllowlist {
        BindAllowlist::none()
            .allow("/Users/test/jobs/a/workspace", "/workspace")
            .allow("/Users/test/jobs/a/workspace/.github", "/workspace/.github")
            .allow("/var/folders/zz/job", "/out")
            .allow("/tmp/job/token", "/run/factory/job-token")
            .allow("/x/ws", "/workspace")
    }

    fn denied_with_mounts(items: &[&str]) -> bool {
        first_denied(&words(items), &provisioned()).is_some()
    }

    #[test]
    fn short_flags_are_read_glued_separate_and_in_clusters() {
        let read_one = |items: &[&str]| {
            let args = words(items);
            read(&args)
                .into_iter()
                .map(|g| (g.flag, g.value.map(str::to_owned)))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            read_one(&["create", "-v/tmp:/h:ro"]),
            vec![("--volume".to_owned(), Some("/tmp:/h:ro".to_owned()))]
        );
        assert_eq!(
            read_one(&["create", "-v", "/tmp:/h"]),
            vec![("--volume".to_owned(), Some("/tmp:/h".to_owned()))]
        );
        assert_eq!(
            read_one(&["create", "-v=/tmp:/h"]),
            vec![("--volume".to_owned(), Some("/tmp:/h".to_owned()))]
        );
        assert_eq!(
            read_one(&["create", "-itp8080:80"]),
            vec![
                ("--interactive".to_owned(), None),
                ("--tty".to_owned(), None),
                ("--publish".to_owned(), Some("8080:80".to_owned())),
            ]
        );
        // The image ends the flags: what follows is the command of the container, even when it
        // looks like a flag. A `--` ends the flags too.
        assert_eq!(
            read_one(&["create", "--init", "img", "sleep", "-p", "--", "-v"]),
            vec![("--init".to_owned(), None)]
        );
        assert_eq!(
            read_one(&["create", "--init", "--", "-v", "x"]),
            vec![("--init".to_owned(), None)]
        );
        // A value that looks like a flag is still the value of the flag before it.
        assert_eq!(
            read_one(&["create", "--workdir", "--init", "--read-only"]),
            vec![
                ("--workdir".to_owned(), Some("--init".to_owned())),
                ("--read-only".to_owned(), None)
            ]
        );
    }

    #[test]
    fn every_spelling_of_a_denied_flag_is_denied() {
        for vector in [
            &["create", "-v/private/tmp:/h:ro"][..],
            &["create", "-v", "/x:/y"],
            &["create", "-v=/x:/y"],
            &["create", "-p8080:80"],
            &["create", "-p", "8080:80"],
            &["create", "-P"],
            &["create", "-itP"],
            &["create", "--volume=/x:/y"],
            &["create", "--publish", "80"],
            &["create", "--privileged"],
            &["create", "--privileged=true"],
            &["create", "--cap-add=SYS_ADMIN"],
            &["create", "--cap-add", "ALL"],
            &["create", "--group-add", "docker"],
        ] {
            assert!(denied(vector), "{vector:?}");
        }
    }

    #[test]
    fn a_security_option_is_read_as_key_and_value_with_either_separator() {
        for bad in [
            "seccomp=unconfined",
            "seccomp:unconfined",
            "seccomp=/tmp/profile.json",
            "apparmor=unconfined",
            "apparmor:unconfined",
            "label=disable",
            "label:disable",
            "systempaths=unconfined",
            "no-new-privileges=false",
            "no-new-privileges:false",
            "no-new-privileges:0",
            "writable-cgroups=true",
            "something-new",
        ] {
            assert!(denied(&["create", "--security-opt", bad]), "{bad}");
            assert!(
                denied(&["create", &format!("--security-opt={bad}")]),
                "{bad}"
            );
        }
        for good in [
            "no-new-privileges",
            "no-new-privileges=true",
            "no-new-privileges:true",
        ] {
            assert!(!denied(&["create", "--security-opt", good]), "{good}");
        }
        assert!(denied(&["create", "--security-opt"]));
    }

    #[test]
    fn namespaces_of_the_host_or_of_another_container_are_denied_for_every_namespace_flag() {
        for flag in [
            "--network",
            "--net",
            "--pid",
            "--ipc",
            "--uts",
            "--userns",
            "--cgroupns",
        ] {
            for value in ["host", "HOST", "container:abc", "ns:/proc/1/ns/net"] {
                assert!(denied(&["create", flag, value]), "{flag} {value}");
                assert!(
                    denied(&["create", &format!("{flag}={value}")]),
                    "{flag}={value}"
                );
            }
        }
        assert!(denied(&["create", "--network", "bridge"]));
        assert!(denied(&["create", "--network=default"]));
        assert!(!denied(&["create", "--network", "none"]));
        assert!(!denied(&["create", "--network", "sf-job-1234"]));
        assert!(!denied(&["create", "--ipc", "none"]));
        assert!(!denied(&["create", "--cgroupns", "private"]));
    }

    #[test]
    fn a_limit_must_be_a_number_above_zero() {
        for bad in [
            &["create", "--pids-limit", "-1"][..],
            &["create", "--pids-limit=0"],
            &["create", "--pids-limit", "lots"],
            &["create", "--memory", "0"],
            &["create", "--memory", "-1"],
            &["create", "-m", "0"],
            &["create", "-m0m"],
            &["create", "--memory=0m"],
            &["create", "--memory-swap", "-1"],
            &["create", "--memory-swap=0"],
            &["create", "--memory", "unlimited"],
            &["create", "--cpus", "0"],
            &["create", "--cpus=-2"],
            &["create", "--cpus", "NaN"],
            &["create", "--pids-limit"],
        ] {
            assert!(denied(bad), "{bad:?}");
        }
        for good in [
            &["create", "--pids-limit", "256"][..],
            &["create", "--memory", "512m"],
            &["create", "-m", "2g"],
            &["create", "--memory-swap", "512m"],
            &["create", "--cpus", "1.500"],
        ] {
            assert!(!denied(good), "{good:?}");
        }
    }

    #[test]
    fn a_mount_is_read_with_its_aliases_and_checked_by_what_it_mounts() {
        for bad in [
            "type=bind,source=/,target=/h",
            "type=bind,src=/,dst=/h",
            "type=bind,source=/etc,target=/h",
            "type=bind,source=/etc/ssh,target=/h",
            "type=bind,source=/proc,target=/h",
            "type=bind,source=/dev,target=/h",
            "type=bind,source=/dev/sda,target=/h",
            "type=bind,source=/sys/fs,target=/h",
            "type=bind,source=//etc,target=/h",
            "type=bind,source=/tmp/../etc,target=/h",
            "type=bind,source=/./proc,target=/h",
            "type=bind,source=/var/run/docker.sock,target=/s",
            "type=bind,source=/run/user/1/docker.sock,destination=/s",
            "type=bind,target=/h",
            "type=bind,source=/Users/test/jobs/a/workspace",
            "type=volume,source=other-jobs-data,target=/h",
            "source=other-jobs-data,target=/h",
            "type=npipe,source=//./pipe/docker_engine,target=/p",
            // A tmpfs mount is not how the builder makes its scratch space.
            "type=tmpfs,destination=/scratch",
            "type=tmpfs,dst=/t,tmpfs-mode=1777,tmpfs-size=100g",
        ] {
            assert!(denied_with_mounts(&["create", "--mount", bad]), "{bad}");
            assert!(
                denied_with_mounts(&["create", &format!("--mount={bad}")]),
                "{bad}"
            );
        }
        for good in [
            "type=bind,src=/Users/test/jobs/a/workspace,dst=/workspace",
            "type=bind,source=/tmp/job/token,target=/run/factory/job-token,readonly",
            "type=bind,src=/var/folders/zz/job,dst=/out",
            "type=bind,src=/dev/null,dst=/workspace/.git,readonly",
            "type=bind,src=/Users/test/jobs/a/workspace/.github,destination=/workspace/.github,ro",
            // The keys are lower-cased, as Docker does, and the pair is the same pair.
            "TYPE=bind,SRC=/Users/test/jobs/a/workspace,DST=/workspace",
            "Type=Bind,Source=/var/folders/zz/job,Destination=/out,ReadOnly",
            // The last source wins, as in Docker, so an allowed source after a hostile one is the
            // mount that is made.
            "type=bind,src=/etc,SRC=/var/folders/zz/job,dst=/out",
        ] {
            assert!(!denied_with_mounts(&["create", "--mount", good]), "{good}");
        }
    }

    /// RR-10: the key in another case, and the last of two, are what Docker uses.
    #[test]
    fn a_mount_key_in_another_case_does_not_hide_the_source_and_the_last_one_wins() {
        for bad in [
            "type=bind,src=/Users/test/jobs/a/workspace,SRC=/etc,dst=/workspace",
            "type=bind,src=/Users/test/jobs/a/workspace,Source=/etc,dst=/workspace",
            "type=bind,src=/Users/test/jobs/a/workspace,SOURCE=/var/lib/docker,dst=/workspace",
            "type=bind,src=/Users/test/jobs/a/workspace,dst=/workspace,DST=/usr/local/bin",
            "TYPE=bind,src=/etc,dst=/x",
            "type=bind,src=/Users/test/jobs/a/workspace,dst=/workspace,TYPE=volume",
            // A key that only looks like a known one after Unicode lower-casing is read as Docker
            // reads it (U+0130 becomes i in Go), and a key that stays unknown is refused.
            "type=bind,src=/etc,dest\u{130}nation=/x",
            "type=bind,src=/etc,\u{212a}ind=x,dst=/x",
            "type=bind,\"src=/etc\",dst=/x",
            "type=bind,src=/Users/test/jobs/a/workspace,dst=/workspace,bind-propagation=rshared",
            "type=bind,src=/Users/test/jobs/a/workspace,dst=/workspace,consistency=cached",
        ] {
            assert!(denied_with_mounts(&["create", "--mount", bad]), "{bad}");
        }
        // The Go spelling of the capital I with a dot above is an ordinary i.
        assert_eq!(go_lower("DEST\u{130}NATION"), "destination");
        assert_eq!(go_lower("SRC"), "src");
        assert_eq!(go_lower("\u{212a}"), "k");
    }

    /// RR-11: the mounts of the factory are the only mounts, and what is not on the list is refused
    /// whatever its name.
    #[test]
    fn a_bind_mount_that_the_factory_does_not_provision_is_refused() {
        for source in [
            "/run/containerd/containerd.sock",
            "/run/podman/podman.sock",
            "/run",
            "/home",
            "/Users",
            "/private/etc",
            "/var/lib/containerd",
            "/var/lib/kubelet",
            "/lib/modules",
            "/usr/bin",
            "/tmp/anything-else",
            "/Users/test/jobs/b/workspace",
        ] {
            let mount = format!("type=bind,src={source},dst=/x");
            assert!(
                denied_with_mounts(&["create", "--mount", &mount]),
                "{source}"
            );
            assert!(denied(&["create", "--mount", &mount]), "{source}");
        }
        // The right source at another destination is another mount: over the token file, over a
        // tool of the image, over the mask of `.git`.
        for destination in [
            "/run/factory/job-token",
            "/usr/local/bin",
            "/workspace/.git",
            "/etc",
            "/",
        ] {
            let mount = format!("type=bind,src=/Users/test/jobs/a/workspace,dst={destination}");
            assert!(
                denied_with_mounts(&["create", "--mount", &mount]),
                "{destination}"
            );
        }
        // Nothing is on the list when no list is given, except the mask of `.git`.
        assert!(denied(&[
            "create",
            "--mount",
            "type=bind,src=/Users/test/jobs/a/workspace,dst=/workspace"
        ]));
        assert!(!denied(&[
            "create",
            "--mount",
            "type=bind,src=/dev/null,dst=/workspace/.git,readonly"
        ]));
        // A pair that is on the list is still refused when it names a sensitive tree, in case it was
        // put there by mistake.
        let wrong = BindAllowlist::none()
            .allow("/etc", "/workspace")
            .allow("/", "/out");
        for mount in [
            "type=bind,src=/etc,dst=/workspace",
            "type=bind,src=/,dst=/out",
        ] {
            assert!(first_denied(&words(&["create", "--mount", mount]), &wrong).is_some());
        }
        // And two mounts at one destination are refused: the second replaces the first.
        assert!(denied_with_mounts(&[
            "create",
            "--mount",
            "type=bind,src=/Users/test/jobs/a/workspace,dst=/workspace",
            "--mount",
            "type=bind,src=/x/ws,dst=/workspace",
        ]));
    }

    /// RR-12: the settings of the allowed flags that make the container weaker.
    #[test]
    fn the_weakening_values_of_the_flags_the_builder_uses_are_refused() {
        for bad in [
            &["create", "--tmpfs", "/tmp:rw,exec,suid,dev"][..],
            &["create", "--tmpfs=/tmp:rw,exec"],
            &["create", "--tmpfs", "/tmp:rw,noexec,suid,nodev"],
            &["create", "--tmpfs", "/tmp:rw,noexec,nosuid,dev"],
            &["create", "--tmpfs", "/tmp:rw,EXEC"],
            &["create", "--tmpfs", "/t:rw,noexec,nosuid,nodev"],
            &["create", "--tmpfs", "/usr/local/bin:rw,noexec,nosuid,nodev"],
            &["create", "--ulimit", "core=-1"],
            &["create", "--ulimit", "nproc=-1"],
            &["create", "--ulimit", "nofile=-1"],
            &["create", "--ulimit", "fsize=-1"],
            &["create", "--ulimit", "nofile=4096:-1"],
            &["create", "--ulimit", "nofile=unlimited"],
            &["create", "--ulimit", "nofile"],
            &["create", "--ulimit", "nofile="],
            &["create", "--ulimit"],
            &["create", "--init=false"],
            &["create", "--init=0"],
            &[
                "create",
                "--mount",
                "type=tmpfs,dst=/t,tmpfs-mode=1777,tmpfs-size=100g",
            ],
            &[
                "create",
                "--mount",
                "type=bind,src=/x/ws,dst=/workspace,bind-propagation=rshared",
            ],
        ] {
            assert!(denied_with_mounts(bad), "{bad:?}");
        }
        for good in [
            &[
                "create",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
            ][..],
            &["create", "--tmpfs", "/tmp"],
            &["create", "--ulimit", "core=0"],
            &["create", "--ulimit", "nofile=4096:4096"],
            &["create", "--ulimit", "fsize=67108864:67108864"],
            &["create", "--init"],
            &["create", "--init=true"],
            // A tightening stays allowed.
            &["create", "--cap-drop=NET_RAW"],
        ] {
            assert!(!denied_with_mounts(good), "{good:?}");
        }
    }

    #[test]
    fn the_user_is_a_number_that_is_not_zero() {
        for bad in [
            "0",
            "0:0",
            "00",
            "root",
            "root:root",
            "10001:0",
            "agent",
            ":10001",
            "",
            "-1",
            "10001:root",
        ] {
            assert!(denied(&["create", "--user", bad]), "{bad:?}");
            assert!(denied(&["create", &format!("--user={bad}")]), "{bad:?}");
            assert!(denied(&["create", &format!("-u{bad}")]), "{bad:?}");
        }
        assert!(denied(&["create", "--user"]));
        for good in ["10001", "10001:10001", "20000:30000"] {
            assert!(!denied(&["create", "--user", good]), "{good}");
        }
    }

    #[test]
    fn the_read_only_root_is_denied_only_when_switched_off() {
        assert!(denied(&["create", "--read-only=false"]));
        assert!(denied(&["create", "--read-only=0"]));
        assert!(denied(&["create", "--read-only=f"]));
        assert!(!denied(&["create", "--read-only"]));
        assert!(!denied(&["create", "--read-only=true"]));
    }

    #[test]
    fn the_environment_may_not_name_the_daemon_socket() {
        assert!(denied(&[
            "create",
            "--env",
            "DOCKER_HOST=unix:///var/run/docker.sock"
        ]));
        assert!(denied(&[
            "create",
            "-eDOCKER_HOST=unix:///var/run/docker.sock"
        ]));
        assert!(!denied(&["create", "--env", "HOME=/home/agent"]));
    }

    #[test]
    fn the_flags_the_builder_writes_are_clean() {
        assert!(!denied_with_mounts(&[
            "create",
            "--pull=never",
            "--name",
            "sf-1",
            "--label",
            "a=b",
            "--user",
            "10001:10001",
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
            "4096m",
            "--memory-swap",
            "4096m",
            "--cpus",
            "2.000",
            "--ulimit",
            "nofile=4096:4096",
            "--ulimit",
            "core=0",
            "--network",
            "none",
            "--log-driver",
            "none",
            "--stop-timeout",
            "10",
            "--restart",
            "no",
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/home/agent",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
            "--mount",
            "type=bind,src=/x/ws,dst=/workspace",
            "image@sha256:abc",
            "sleep",
            "infinity",
        ]));
    }
}
