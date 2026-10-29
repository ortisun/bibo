//! Security re-review of the sandbox adapter's second-layer deny list and audit name filter
//! (SBX-1, SBX-2, SBX-3 of docs/reviews/isolation-core-security-review.md; the re-review is
//! docs/reviews/isolation-core-security-rereview.md).
//!
//! Tests marked `#[ignore = "confirmed defect RR-n: ..."]` fail today and show a defect; they pass
//! when the defect is fixed. Tests without `#[ignore]` pin an attack the re-review tried and the
//! code withstood. Run the defect tests with:
//!
//! ```text
//! CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
//!   cargo test -p factory-sandbox --test security_rereview -- --ignored
//! ```
//!
//! The Docker test only runs `docker create` with `--network none` (it never starts a container and
//! never makes a network), takes the machine-wide Docker lock, labels what it makes with
//! `factory.test=true` and the run label, and removes it. Without a daemon it panics with a message
//! that starts `BLOCKED:` and never passes. No hostile code runs on the host.

#![allow(dead_code, unused_imports)]

#[path = "../support/mod.rs"]
mod support;

use std::sync::atomic::AtomicBool;

use factory_sandbox::container::posture::denied_flag_in;
use factory_sandbox::workspace::{AuditLimits, audit_output};
use factory_testkit::fx::docker::{DockerGuard, blocked};

use support::docker_lock::DockerLock;

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|w| (*w).to_owned()).collect()
}

fn not_denied(vectors: &[&[&str]]) -> Vec<String> {
    vectors
        .iter()
        .filter(|vector| denied_flag_in(&words(vector)).is_none())
        .map(|vector| vector.join(" "))
        .collect()
}

// ---- what held --------------------------------------------------------------------------------

/// Every spelling that the real Docker CLI accepted for a setting that weakens the container (the
/// re-review asked the daemon's own CLI, see `held_docker_reads_flags_the_way_the_deny_list_does`)
/// is read and refused.
#[test]
fn held_the_spellings_docker_accepts_for_a_weaker_container_are_refused() {
    let escaped = not_denied(&[
        &["create", "--cap-add=ALL"],
        &["create", "--cap-add", "ALL"],
        &["create", "--privileged=true"],
        &["create", "--privileged"],
        &["create", "--pid=host"],
        &["create", "--pid", "host"],
        &["create", "--ipc=host"],
        &["create", "--ipc", "container:abc"],
        &["create", "--uts=host"],
        &["create", "--userns=host"],
        &["create", "--cgroupns=host"],
        &["create", "--network=host"],
        &["create", "--net=host"],
        &["create", "--network=container:abc"],
        &["create", "--network=bridge"],
        &["create", "--security-opt", "seccomp:unconfined"],
        &["create", "--security-opt=seccomp=unconfined"],
        &["create", "--security-opt", "label=disable"],
        &["create", "--security-opt", "no-new-privileges=false"],
        &["create", "--security-opt=no-new-privileges:0"],
        &["create", "--security-opt", "systempaths=unconfined"],
        &["create", "-v/tmp:/x:ro"],
        &["create", "-v=/tmp:/x"],
        &["create", "-v", "/tmp:/x"],
        &["create", "--volume=/tmp:/x"],
        &["create", "--user", "0"],
        &["create", "--user", "+0"],
        &["create", "--user", "00"],
        &["create", "--user", "10001:0"],
        &["create", "--user", "root"],
        &["create", "--user=0:0"],
        &["create", "--read-only=false"],
        &["create", "--read-only=0"],
        &["create", "--restart=on-failure:3"],
        &["create", "--restart", "always"],
        &["create", "--entrypoint=/bin/sh"],
        &["create", "--group-add=0"],
        &["create", "--sysctl", "net.ipv4.ip_forward=1"],
        &["create", "--device=/dev/null"],
        &["create", "--runtime=runc"],
        &["create", "--env-file=/dev/null"],
        &["create", "--volumes-from=other"],
        &["create", "--memory-swap=-1"],
        &["create", "--memory=0"],
        &["create", "--pids-limit=-1"],
        &["create", "--pids-limit=0"],
        &["create", "--cpus=0"],
        &["create", "--log-driver=json-file"],
        &["create", "--pull=always"],
        &["create", "--mount", "type=bind,src=/etc,dst=/x"],
        &["create", "--mount", "type=bind,source=/etc/,dst=/x"],
        &["create", "--mount", "type=bind,src=/tmp/../etc,dst=/x"],
        &["create", "--mount", "type=bind,src=//etc,dst=/x"],
        &["create", "--mount", "type=bind,src=/proc/1/root,dst=/x"],
        &[
            "create",
            "--mount",
            "type=bind,src=/var/run/docker.sock,dst=/x",
        ],
        &["create", "--mount", "type=bind,src=/var/lib/docker,dst=/x"],
        &["create", "--mount", "type=bind,dst=/x"],
        &["create", "--mount", "type=volume,src=other-job,dst=/x"],
        &["create", "--mount", "type=BIND,src=/etc,dst=/x"],
        &["create", "--mount", "type=bind,SRC=/etc,dst=/x"],
    ]);
    assert!(escaped.is_empty(), "not refused: {escaped:?}");
}

/// What held: an argument that follows the image or `--` is the command of the container, so a
/// flag-looking word there is not read as a flag, and the same word before the image is.
#[test]
fn held_the_image_ends_the_flags_and_a_flag_before_it_cannot_hide_behind_a_value() {
    assert!(
        denied_flag_in(&words(&[
            "create",
            "--init",
            "img",
            "sleep",
            "--privileged"
        ]))
        .is_none()
    );
    assert!(denied_flag_in(&words(&["create", "--privileged", "img", "sleep"])).is_some());
    assert!(denied_flag_in(&words(&["create", "--init", "--", "--privileged"])).is_none());
    // A value that looks like a flag is the value of the flag before it, as Docker reads it, and a
    // second flag after it is still read.
    assert!(denied_flag_in(&words(&["create", "--workdir", "--init", "--privileged"])).is_some());
    assert!(
        denied_flag_in(&words(&[
            "create",
            "--label",
            "a=b",
            "--cap-add",
            "ALL",
            "img"
        ]))
        .is_some()
    );
    // An image name that starts with a dash is read as a flag, not as an image.
    assert!(denied_flag_in(&words(&["create", "--privileged"])).is_some());
}

/// The part of the second layer the Docker CLI settles: no abbreviation, no other case, no
/// underscore, and the single-dash spelling is a cluster of short flags, not a long flag. Asked of
/// the daemon's own CLI with `docker create` (never started, no network).
#[test]
fn held_docker_reads_flags_the_way_the_deny_list_does() {
    let scope = DockerGuard::from_environment().require_or_block();
    let _lock = DockerLock::take();
    let cli = scope.cli();
    let image = support::catalog(support::IMAGES_JSON)
        .reference_for(factory_ports::sandbox::SandboxProfile::Agent)
        .expect("a listed profile")
        .reference()
        .to_owned();
    let found = cli.run(&["image", "inspect", "--format", "{{.Id}}", &image]);
    if !found.is_ok_and(|out| out.success()) {
        blocked(&format!("the image {image} is not on this host"));
    }
    let labels = scope.label_args();
    let mut made: Vec<String> = Vec::new();
    let mut create = |n: usize, extra: &[&str]| -> bool {
        let name = format!("rr-flag-{}-{n}", scope.label().value());
        let mut args = vec![
            "create",
            "--pull=never",
            "--name",
            name.as_str(),
            labels[0].as_str(),
            labels[1].as_str(),
            "--label",
            "factory.test=true",
            "--network",
            "none",
            "--log-driver",
            "none",
        ];
        args.extend_from_slice(extra);
        args.extend_from_slice(&[image.as_str(), "sleep", "1"]);
        let out = cli.run(&args).expect("docker runs");
        if out.success() {
            made.push(name);
        }
        out.success()
    };
    // Refused by the CLI itself, before the daemon is asked.
    let refused_spellings: [&[&str]; 8] = [
        &["--cap-ad", "ALL"],
        &["--cap_add=ALL"],
        &["--CAP-ADD=ALL"],
        &["--priv"],
        &["--PID=host"],
        &["--security-opts", "seccomp=unconfined"],
        &["--privileged=yes"],
        &["-privileged"],
    ];
    let mut accepted = Vec::new();
    for (n, spelling) in refused_spellings.iter().enumerate() {
        if create(n, spelling) {
            accepted.push(spelling.join(" "));
        }
    }
    for name in &made {
        let _ = cli.run(&["rm", "--force", name]);
    }
    assert!(
        accepted.is_empty(),
        "Docker accepted a spelling that the deny list does not read: {accepted:?}"
    );
}

// ---- defects ------------------------------------------------------------------------------------

/// RR-10. Docker lower-cases the keys of a `--mount` value and the last `src` or `source` wins:
/// `type=bind,src=/tmp,SRC=/etc,dst=/x` mounts `/etc` (shown with `docker inspect`, Docker Desktop
/// 29.9.2). The deny list reads only lower-case keys, takes `/tmp` as the source and accepts it.
#[test]
fn rr_10_a_mount_key_in_another_case_does_not_hide_the_host_source() {
    let escaped = not_denied(&[
        &["create", "--mount", "type=bind,src=/tmp/ok,SRC=/etc,dst=/x"],
        &[
            "create",
            "--mount",
            "type=bind,src=/tmp/ok,Source=/etc,dst=/x",
        ],
        &[
            "create",
            "--mount",
            "type=bind,src=/tmp/ok,SOURCE=/var/lib/docker,dst=/x",
        ],
        &["create", "--mount", "TYPE=bind,src=/etc,dst=/x"],
    ]);
    assert!(escaped.is_empty(), "not refused: {escaped:?}");
}

/// RR-11. The bind-mount check is a list of eight roots and the text `docker.sock`. The container
/// runtime's own socket (`/run/containerd/containerd.sock`, which gives the same power as the
/// Docker socket), `/run`, `/home`, the macOS home and system directories, and `/var/lib/containerd`
/// all pass. `docker create` accepted each (Docker Desktop 29.9.2). The builder's own mounts all lie
/// under paths it creates, so a list of the paths that may be mounted would be the right shape.
#[test]
fn rr_11_a_bind_mount_of_the_runtime_socket_or_a_home_directory_is_refused() {
    let escaped = not_denied(&[
        &[
            "create",
            "--mount",
            "type=bind,src=/run/containerd/containerd.sock,dst=/x",
        ],
        &[
            "create",
            "--mount",
            "type=bind,src=/run/podman/podman.sock,dst=/x",
        ],
        &["create", "--mount", "type=bind,src=/run,dst=/x"],
        &["create", "--mount", "type=bind,src=/home,dst=/x"],
        &["create", "--mount", "type=bind,src=/Users,dst=/x"],
        &["create", "--mount", "type=bind,src=/private/etc,dst=/x"],
        &[
            "create",
            "--mount",
            "type=bind,src=/var/lib/containerd,dst=/x",
        ],
        &["create", "--mount", "type=bind,src=/var/lib/kubelet,dst=/x"],
        &["create", "--mount", "type=bind,src=/lib/modules,dst=/x"],
        &["create", "--mount", "type=bind,src=/usr/bin,dst=/x"],
    ]);
    assert!(escaped.is_empty(), "not refused: {escaped:?}");
}

/// RR-12. Settings of allowed flags that make the container weaker and that the reader does not
/// look at: an executable, setuid, device-bearing tmpfs, an unlimited core or process limit, a
/// boolean given `false`, a run without the init process, and a mount destination over a file of
/// the image. Each is accepted by `docker create`.
#[test]
fn rr_12_weakening_values_of_the_flags_the_builder_uses_are_refused() {
    let escaped = not_denied(&[
        &["create", "--tmpfs", "/t:rw,exec,suid,dev"],
        &["create", "--tmpfs=/t:rw,exec"],
        &["create", "--ulimit", "core=-1"],
        &["create", "--ulimit", "nproc=-1"],
        &["create", "--ulimit", "nofile=-1"],
        &["create", "--ulimit", "fsize=-1"],
        &["create", "--init=false"],
        &["create", "--cap-drop=NET_RAW"],
        &[
            "create",
            "--mount",
            "type=tmpfs,dst=/t,tmpfs-mode=1777,tmpfs-size=100g",
        ],
        &[
            "create",
            "--mount",
            "type=bind,src=/tmp/ok,dst=/x,bind-propagation=rshared",
        ],
    ]);
    // `--cap-drop=NET_RAW` is a tightening and must stay allowed; it is in the list as the control.
    let expected_allowed = ["create --cap-drop=NET_RAW"];
    let unexpected: Vec<&String> = escaped
        .iter()
        .filter(|vector| !expected_allowed.contains(&vector.as_str()))
        .collect();
    assert!(unexpected.is_empty(), "not refused: {unexpected:?}");
}

/// RR-13. The audit refused the characters that hide or reorder text and passed the ones that only
/// look blank. It now also refuses a name that begins or ends with a space-like character, the
/// braille blank, a variation selector with no base, and a stack of more than two combining marks.
/// A space that is not an ASCII space in the middle of a name still passes, and is logged: the
/// ideographic space is how Japanese file names are written, and refusing it would refuse legitimate
/// names. A name that is not in normal form NFC also passes: the standard library cannot tell, and a
/// new dependency was not added for a hypothesis.
#[test]
fn rr_13_names_that_print_as_blank_or_as_another_name_are_refused() {
    let scratch = support::Scratch::new("rr13");
    let refused = [
        "report.md\u{00A0}",
        "report\u{2800}.md",
        "\u{2800}",
        "a\u{FE0E}b.rs",
        "a\u{180B}b.rs",
        "a\u{0300}\u{0301}\u{0302}b.rs",
    ];
    let mut accepted = Vec::new();
    for (i, name) in refused.iter().enumerate() {
        let dir = scratch.path().join(format!("case-{i}"));
        std::fs::create_dir_all(&dir).expect("a case directory");
        std::fs::write(dir.join(name), b"").expect("an empty file");
        let stop = AtomicBool::new(false);
        if audit_output(&dir, &AuditLimits::default(), &stop).is_ok_and(|files| !files.is_empty()) {
            accepted.push(*name);
        }
    }
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}

/// The part of RR-13 that stays a log line: a non-ASCII space inside a name.
#[test]
fn rr_13_a_space_inside_a_name_that_is_not_an_ascii_space_is_accepted() {
    let scratch = support::Scratch::new("rr13-inner");
    for (i, name) in ["a\u{3000}b.rs", "a\u{2009}b.rs"].iter().enumerate() {
        let dir = scratch.path().join(format!("case-{i}"));
        std::fs::create_dir_all(&dir).expect("a case directory");
        std::fs::write(dir.join(name), b"").expect("an empty file");
        let stop = AtomicBool::new(false);
        let files = audit_output(&dir, &AuditLimits::default(), &stop);
        assert!(files.is_ok_and(|files| files.len() == 1), "{name:?}");
    }
}
