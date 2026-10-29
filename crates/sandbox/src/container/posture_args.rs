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
//!   `--security-opt` key, a mount of a type that is neither `bind` nor `tmpfs`).
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

/// Roots on the host that no bind mount may start at.
const DENIED_SOURCES: &[&str] = &[
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",
    "/var/run",
    "/var/lib/docker",
];

/// The first rule the vector breaks, as short text. `None` means it is clean.
pub(super) fn first_denied(args: &[String]) -> Option<String> {
    for given in read(args) {
        if let Some(reason) = check(&given) {
            return Some(reason);
        }
    }
    None
}

fn check(given: &Given<'_>) -> Option<String> {
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
        "--read-only" => given
            .glued
            .then_some(value)
            .flatten()
            .filter(|v| !matches!(*v, "true" | "TRUE" | "True" | "1" | "t" | "T"))
            .map(|_| "writable root file system".to_owned()),
        "--mount" => mount(value),
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

/// A `--mount` value: comma separated `key=value` words, with the aliases Docker reads. A bind
/// mount may not start at the host root or at a system directory or name the daemon socket, and
/// a mount of any type but `bind` and `tmpfs` (a named volume is another job's data) is refused.
fn mount(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.contains("docker.sock") {
        return Some("--mount names the daemon socket".to_owned());
    }
    let mut kind = "volume";
    let mut source: Option<&str> = None;
    for word in value.split(',') {
        let (key, setting) = word.split_once('=').unwrap_or((word, ""));
        match key {
            "type" => kind = setting,
            "src" | "source" => source = Some(setting),
            _ => {}
        }
    }
    if !matches!(kind, "bind" | "tmpfs") {
        return Some(format!("--mount of type {kind}"));
    }
    if kind == "bind" {
        let Some(source) = source else {
            return Some("a bind mount with no source".to_owned());
        };
        let clean = lexical_path(source);
        let host_root = clean == "/";
        // `/dev/null` is the one device the builder binds: it masks the `.git` file.
        let system = clean != "/dev/null"
            && DENIED_SOURCES.iter().any(|dir| {
                clean == *dir || clean.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
            });
        if host_root || system {
            return Some(format!("--mount of the host path {clean}"));
        }
    }
    None
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
        first_denied(&words(items)).is_some()
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
            "type=volume,source=other-jobs-data,target=/h",
            "source=other-jobs-data,target=/h",
            "type=npipe,source=//./pipe/docker_engine,target=/p",
        ] {
            assert!(denied(&["create", "--mount", bad]), "{bad}");
            assert!(denied(&["create", &format!("--mount={bad}")]), "{bad}");
        }
        for good in [
            "type=bind,src=/Users/test/jobs/a/workspace,dst=/workspace",
            "type=bind,source=/tmp/job/token,target=/run/factory/job-token,readonly",
            "type=bind,src=/var/folders/zz/job,dst=/out",
            "type=bind,src=/dev/null,dst=/workspace/.git,readonly",
            "type=tmpfs,destination=/scratch",
        ] {
            assert!(!denied(&["create", "--mount", good]), "{good}");
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
        assert!(!denied(&[
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
