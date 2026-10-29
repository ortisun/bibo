//! The checks that look at the machine before a real run (E1 and E2).
//!
//! [`crate::preflight::missing_needs`] only asks whether an environment variable is set. A set
//! variable can still name nothing, so this module looks at what the variables point to and at what
//! the repository and Docker hold: the private key file, the allowlist, the fixture's code owners,
//! the model routing policy, the agent image and whether it was rebuilt after its recipe changed.
//! Every answer comes from a check that ran. Where a check cannot run (no Docker, no git), that is
//! itself a reason to stop, and it is said so. Nothing here assumes.
//!
//! The checks that need GitHub itself (the ruleset on the fixture repository, the App
//! installation) cannot run without the network and a credential. They are the job of the composed
//! wiring, which reads the protection through the App, and they are named in the message of the
//! variable that points to them.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// What a read-only run of `docker` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerAnswer {
    /// The `docker` program is not installed.
    NotInstalled,
    /// It ran and failed (no daemon, no such image). The text is the first line of its error.
    Failed(String),
    /// It ran and printed this.
    Output(String),
}

/// What the checks look at. A test gives it a fixed machine.
pub struct Host<'a> {
    /// The root of the repository.
    pub root: &'a Path,
    /// Reads an environment variable.
    pub env: &'a dyn Fn(&str) -> Option<String>,
    /// Runs `docker` with these arguments. Only read-only subcommands are ever passed.
    pub docker: &'a dyn Fn(&[&str]) -> DockerAnswer,
    /// Runs `git -C ROOT` with these arguments and returns its output, or `None` on failure.
    pub git: &'a dyn Fn(&[&str]) -> Option<String>,
}

/// How long a read-only `docker` call may take before it counts as not answering. Docker Desktop
/// can accept a call and never reply, and a check that waits for it would hang the whole run.
pub const DOCKER_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a `git` call may take.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(20);

/// What a bounded run of a program came to.
enum Ran {
    Finished(std::process::Output),
    TimedOut,
    Failed(std::io::Error),
}

/// Runs a program and kills it when it takes longer than `limit`.
fn run_bounded(mut command: Command, limit: Duration) -> Ran {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Ran::Failed(error),
    };
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut err = Vec::new();
        if let Some(pipe) = stdout.as_mut() {
            let _ = pipe.read_to_end(&mut out);
        }
        if let Some(pipe) = stderr.as_mut() {
            let _ = pipe.read_to_end(&mut err);
        }
        let _ = sender.send((out, err));
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let (stdout, stderr) = receiver
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap_or_default();
                return Ran::Finished(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) if started.elapsed() > limit => {
                let _ = child.kill();
                let _ = child.wait();
                return Ran::TimedOut;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => return Ran::Failed(error),
        }
    }
}

/// Runs the real `docker`. Only `image inspect` is used.
#[must_use]
pub fn system_docker(args: &[&str]) -> DockerAnswer {
    let mut command = Command::new("docker");
    command.args(args);
    match run_bounded(command, DOCKER_TIMEOUT) {
        Ran::Failed(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DockerAnswer::NotInstalled
        }
        Ran::Failed(error) => DockerAnswer::Failed(error.to_string()),
        Ran::TimedOut => DockerAnswer::Failed(format!(
            "docker did not answer within {} seconds",
            DOCKER_TIMEOUT.as_secs()
        )),
        Ran::Finished(output) if output.status.success() => {
            DockerAnswer::Output(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        }
        Ran::Finished(output) => DockerAnswer::Failed(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("docker failed with no message")
                .to_owned(),
        ),
    }
}

/// Runs the real `git` in the repository.
#[must_use]
pub fn system_git(root: &Path, args: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(args);
    match run_bounded(command, GIT_TIMEOUT) {
        Ran::Finished(output) if output.status.success() => {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        }
        _ => None,
    }
}

/// The reasons a real run cannot start, found by looking. One sentence each, ready to print after
/// `BLOCKED:`. Empty when every check holds (which says nothing about GitHub: see the module note).
///
/// The environment variables themselves are reported by [`crate::preflight::missing_needs`]; this
/// function says nothing about a variable that is not set, so no item is named twice.
#[must_use]
pub fn problems(host: &Host<'_>) -> Vec<String> {
    let mut found = Vec::new();
    app_key_file(host, &mut found);
    spend_limit(host, &mut found);
    fixture_repository(host, &mut found);
    allowlist(host, &mut found);
    code_owners(host, &mut found);
    routing_policy(host, &mut found);
    agent_image(host, &mut found);
    found
}

fn set(host: &Host<'_>, name: &str) -> Option<String> {
    (host.env)(name).filter(|value| !value.trim().is_empty())
}

fn app_key_file(host: &Host<'_>, found: &mut Vec<String>) {
    if let Some(id) = set(host, "FACTORY_E2E_GITHUB_APP_ID")
        && id.trim().parse::<u64>().is_err()
    {
        found.push(
            "FACTORY_E2E_GITHUB_APP_ID is not a number; the App id is the number GitHub shows on the App's settings page"
                .to_owned(),
        );
    }
    let Some(path) = set(host, "FACTORY_E2E_GITHUB_APP_KEY_FILE") else {
        return;
    };
    let path = Path::new(path.trim());
    let Ok(metadata) = std::fs::metadata(path) else {
        found.push(format!(
            "FACTORY_E2E_GITHUB_APP_KEY_FILE names {}, which does not exist or cannot be read",
            path.display()
        ));
        return;
    };
    if !metadata.is_file() {
        found.push(format!(
            "FACTORY_E2E_GITHUB_APP_KEY_FILE names {}, which is not a file",
            path.display()
        ));
        return;
    }
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            found.push(format!(
                "the App key file {} is open to group or others (mode {:o}); run chmod 600 on it",
                path.display(),
                metadata.permissions().mode() & 0o777
            ));
        }
    }
    match std::fs::read_to_string(path) {
        Ok(text) if text.contains("PRIVATE KEY") => {}
        Ok(_) => found.push(format!(
            "the App key file {} does not look like a PEM private key",
            path.display()
        )),
        Err(_) => found.push(format!(
            "the App key file {} cannot be read as text",
            path.display()
        )),
    }
}

fn spend_limit(host: &Host<'_>, found: &mut Vec<String>) {
    // The key itself cannot say what limit the provider holds for it, so the person who owns the
    // key states the limit (the variable is one of the needs, and its absence is reported there).
    // Here the statement is read: it must be a positive number of US dollars.
    if let Some(value) = set(host, "FACTORY_E2E_MODEL_SPEND_LIMIT_USD") {
        match value.trim().parse::<f64>() {
            Ok(limit) if limit > 0.0 && limit.is_finite() => {}
            _ => found.push(format!(
                "FACTORY_E2E_MODEL_SPEND_LIMIT_USD is '{}', which is not a positive number of US dollars",
                value.trim()
            )),
        }
    }
}

fn fixture_repository(host: &Host<'_>, found: &mut Vec<String>) {
    let Some(repository) = set(host, "FACTORY_E2E_FIXTURE_REPO") else {
        return;
    };
    let shaped = repository.split_once('/').is_some_and(|(owner, name)| {
        !owner.is_empty() && !name.is_empty() && !name.contains('/') && !repository.contains(' ')
    });
    if !shaped {
        found.push(format!(
            "FACTORY_E2E_FIXTURE_REPO is '{}', and it must be owner/name",
            repository.trim()
        ));
    }
}

fn allowlist(host: &Host<'_>, found: &mut Vec<String>) {
    let Some(path) = set(host, "FACTORY_E2E_REQUESTER_ALLOWLIST") else {
        return;
    };
    let path = Path::new(path.trim());
    let Ok(text) = std::fs::read_to_string(path) else {
        found.push(format!(
            "FACTORY_E2E_REQUESTER_ALLOWLIST names {}, which does not exist or cannot be read",
            path.display()
        ));
        return;
    };
    for designation in ["requester", "approver"] {
        if !text.contains(designation) {
            found.push(format!(
                "the allowlist {} names nobody with the designation {designation}; the run needs a named requester and a different named approver",
                path.display()
            ));
        }
    }
}

fn code_owners(host: &Host<'_>, found: &mut Vec<String>) {
    let path = host.root.join("fixtures/repos/word-count/CODEOWNERS");
    let Ok(text) = std::fs::read_to_string(&path) else {
        found
            .push("the fixture has no CODEOWNERS file to copy to the GitHub repository".to_owned());
        return;
    };
    let mut handles: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(|line| line.split_whitespace().skip(1))
        .collect();
    handles.sort_unstable();
    handles.dedup();
    let placeholders = handles
        .iter()
        .filter(|handle| handle.starts_with("@example-org/"))
        .count();
    if placeholders > 0 {
        found.push(format!(
            "the fixture's CODEOWNERS still lists {placeholders} placeholder handle(s) (@example-org/...); the copy on GitHub needs real owners, and at least two of them, so a second owner who is not the requester can approve"
        ));
    } else if handles.len() < 2 {
        found.push(
            "the fixture's CODEOWNERS lists fewer than two owners; a second owner who is not the requester must be able to approve"
                .to_owned(),
        );
    }
}

fn routing_policy(host: &Host<'_>, found: &mut Vec<String>) {
    if !host.root.join("policies/model_routing.yaml").is_file() {
        found.push(
            "policies/model_routing.yaml does not exist, so the model router has no routes and no live stage can choose a model"
                .to_owned(),
        );
    }
}

/// The reference of the agent image for this machine's architecture, and the digest it pins.
fn agent_reference(root: &Path) -> Result<(String, String), String> {
    let path = root.join("infra/sandbox-images/images.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let document: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not JSON: {error}", path.display()))?;
    let platforms = document["platforms"]
        .as_object()
        .ok_or("images.json lists no platforms")?;
    let wanted = if std::env::consts::ARCH == "aarch64" {
        "linux/arm64"
    } else {
        "linux/amd64"
    };
    let entry = platforms
        .get(wanted)
        .and_then(|platform| platform.pointer("/images/agent"))
        .or_else(|| {
            platforms
                .values()
                .find_map(|platform| platform.pointer("/images/agent"))
        })
        .ok_or("images.json lists no agent image")?;
    let reference = entry["reference"]
        .as_str()
        .ok_or("the agent image has no reference")?
        .to_owned();
    let digest = entry["digest"]
        .as_str()
        .ok_or("the agent image has no digest")?
        .to_owned();
    Ok((reference, digest))
}

fn agent_image(host: &Host<'_>, found: &mut Vec<String>) {
    let (reference, digest) = match agent_reference(host.root) {
        Ok(pair) => pair,
        Err(why) => {
            found.push(format!("the agent image cannot be named: {why}"));
            return;
        }
    };
    // A locally built image has no repository digest, so it is looked up by its id, which
    // images.json records as the digest. Whether the image was rebuilt is a separate question,
    // answered from git below, so a Docker that does not answer does not hide it.
    match (host.docker)(&["image", "inspect", "--format", "{{.Id}}", &digest]) {
        DockerAnswer::NotInstalled => found.push(format!(
            "Docker is not installed, so the agent image {reference} cannot be checked and no sandbox can start"
        )),
        DockerAnswer::Failed(why) => found.push(format!(
            "the agent image {reference} is not in the local Docker store, or Docker did not answer ({why}); build it with infra/sandbox-images/build.sh"
        )),
        DockerAnswer::Output(id) if id.trim() != digest => found.push(format!(
            "the agent image in the local store has the id {}, and images.json pins {digest}",
            id.trim()
        )),
        DockerAnswer::Output(_) => {}
    }
    // Was the image rebuilt after the recipe last changed? The digest in
    // images.json changes in the commit that records a rebuild, so the pinned digest must have
    // been committed after the commit that last changed the recipe.
    let recipe = ["infra/sandbox-images/lib", "infra/sandbox-images/build.sh"];
    let mut args = vec!["log", "-1", "--format=%H", "--"];
    args.extend(recipe);
    let Some(recipe_commit) = (host.git)(&args).filter(|text| !text.is_empty()) else {
        found.push(
            "git could not say when the image recipe last changed, so it is not known whether the agent image was rebuilt"
                .to_owned(),
        );
        return;
    };
    let pickaxe = format!("-S{digest}");
    let Some(pinned_commit) = (host.git)(&[
        "log",
        "-1",
        "--format=%H",
        &pickaxe,
        "--",
        "infra/sandbox-images/images.json",
    ])
    .filter(|text| !text.is_empty()) else {
        found.push(format!(
            "git does not show when the digest {digest} was pinned, so it is not known whether the agent image was rebuilt"
        ));
        return;
    };
    // `merge-base --is-ancestor A B` succeeds (prints nothing) when A is an ancestor of B.
    let predates = (host.git)(&[
        "merge-base",
        "--is-ancestor",
        &pinned_commit,
        &recipe_commit,
    ]);
    if pinned_commit == recipe_commit || predates.is_some() {
        found.push(format!(
            "the agent image {reference} was pinned (commit {}) before the image recipe last changed (commit {}); it is not the image the recipe describes. Rebuild it with infra/sandbox-images/build.sh, run test.sh, and record the new digest in images.json",
            short(&pinned_commit),
            short(&recipe_commit)
        ));
    }
}

fn short(commit: &str) -> &str {
    commit.get(..8).unwrap_or(commit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn root() -> std::path::PathBuf {
        crate::repository_root()
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn docker_with(answer: DockerAnswer) -> impl Fn(&[&str]) -> DockerAnswer + use<> {
        move |_| answer.clone()
    }

    fn git_nothing(_: &[&str]) -> Option<String> {
        None
    }

    #[test]
    fn with_nothing_set_each_missing_thing_is_named_once_by_a_check_that_ran() {
        let env = env_of(&[]);
        let docker = docker_with(DockerAnswer::NotInstalled);
        let root = root();
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        let found = problems(&host);
        let joined = found.join("\n");
        // The routing policy exists in the repository now, so it is not named as missing.
        assert!(!joined.contains("policies/model_routing.yaml"), "{joined}");
        assert!(joined.contains("CODEOWNERS"), "{joined}");
        assert!(joined.contains("Docker is not installed"), "{joined}");
        // A variable that is not set is the business of `missing_needs`, not of this module.
        assert!(!joined.contains("KEY_FILE"), "{joined}");
        assert!(!joined.contains("SPEND_LIMIT"), "{joined}");
        assert!(!joined.contains("REQUESTER_ALLOWLIST"), "{joined}");
    }

    #[test]
    fn a_checkout_without_the_routing_policy_is_named_and_one_with_it_is_not() {
        let env = env_of(&[]);
        let docker = docker_with(DockerAnswer::NotInstalled);
        let empty = std::env::temp_dir().join(format!("e2e-no-routing-{}", std::process::id()));
        std::fs::create_dir_all(&empty).expect("dir");
        let missing = Host {
            root: &empty,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        let mut found = Vec::new();
        routing_policy(&missing, &mut found);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains("policies/model_routing.yaml"),
            "{found:?}"
        );
        let _ = std::fs::remove_dir_all(&empty);

        let real_root = root();
        let present = Host {
            root: &real_root,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        let mut found = Vec::new();
        routing_policy(&present, &mut found);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_key_file_that_does_not_exist_or_is_open_or_is_not_a_key_is_named() {
        let dir = std::env::temp_dir().join(format!("e2e-prereq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let root = root();
        let docker = docker_with(DockerAnswer::NotInstalled);
        let check = |path: &str| {
            let env = env_of(&[
                ("FACTORY_E2E_GITHUB_APP_ID", "12345"),
                ("FACTORY_E2E_GITHUB_APP_KEY_FILE", path),
            ]);
            let host = Host {
                root: &root,
                env: &env,
                docker: &docker,
                git: &git_nothing,
            };
            problems(&host).join("\n")
        };
        let missing = dir.join("absent.pem");
        assert!(check(&missing.to_string_lossy()).contains("does not exist"));

        let open = dir.join("open.pem");
        std::fs::write(&open, "not a key").expect("file");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).expect("mode");
        }
        let text = check(&open.to_string_lossy());
        assert!(text.contains("open to group or others"), "{text}");
        assert!(
            text.contains("does not look like a PEM private key"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_app_id_that_is_not_a_number_is_named() {
        let env = env_of(&[("FACTORY_E2E_GITHUB_APP_ID", "my-app")]);
        let root = root();
        let docker = docker_with(DockerAnswer::NotInstalled);
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        assert!(problems(&host).join("\n").contains("is not a number"));
    }

    #[test]
    fn a_spend_limit_must_be_a_positive_number() {
        let root = root();
        let docker = docker_with(DockerAnswer::NotInstalled);
        for (value, bad) in [("25", false), ("0", true), ("-3", true), ("lots", true)] {
            let env = env_of(&[("FACTORY_E2E_MODEL_SPEND_LIMIT_USD", value)]);
            let host = Host {
                root: &root,
                env: &env,
                docker: &docker,
                git: &git_nothing,
            };
            let said = problems(&host)
                .iter()
                .any(|line| line.contains("FACTORY_E2E_MODEL_SPEND_LIMIT_USD is"));
            assert_eq!(said, bad, "{value}");
        }
    }

    #[test]
    fn a_missing_image_and_a_daemon_that_does_not_answer_are_named_apart() {
        let env = env_of(&[]);
        let root = root();
        let docker = docker_with(DockerAnswer::Failed("No such image".to_owned()));
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        let text = problems(&host).join("\n");
        assert!(text.contains("is not in the local Docker store"), "{text}");
        assert!(text.contains("No such image"), "{text}");
    }

    #[test]
    fn an_image_pinned_before_the_recipe_changed_is_not_the_rebuilt_image() {
        let (_, digest) = agent_reference(&root()).expect("the catalog names the agent image");
        let env = env_of(&[]);
        let root = root();
        let docker = docker_with(DockerAnswer::Output(digest));
        // Git says: the recipe changed in commit BBBB, the digest was pinned in AAAA, and AAAA is
        // an ancestor of BBBB.
        let git = |args: &[&str]| -> Option<String> {
            match args {
                ["log", "-1", "--format=%H", "--", ..] => Some("b".repeat(40)),
                ["log", "-1", "--format=%H", _, "--", ..] => Some("a".repeat(40)),
                ["merge-base", "--is-ancestor", ..] => Some(String::new()),
                _ => None,
            }
        };
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git,
        };
        let text = problems(&host).join("\n");
        assert!(
            text.contains("before the image recipe last changed"),
            "{text}"
        );
        assert!(text.contains("Rebuild it"), "{text}");
    }

    #[test]
    fn an_image_pinned_after_the_recipe_changed_is_accepted() {
        let (_, digest) = agent_reference(&root()).expect("the catalog names the agent image");
        let env = env_of(&[]);
        let root = root();
        let docker = docker_with(DockerAnswer::Output(digest));
        let git = |args: &[&str]| -> Option<String> {
            match args {
                ["log", "-1", "--format=%H", "--", ..] => Some("b".repeat(40)),
                ["log", "-1", "--format=%H", _, "--", ..] => Some("c".repeat(40)),
                // Not an ancestor: the command fails.
                ["merge-base", "--is-ancestor", ..] => None,
                _ => None,
            }
        };
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git,
        };
        let text = problems(&host).join("\n");
        assert!(!text.contains("recipe"), "{text}");
        assert!(!text.contains("Docker"), "{text}");
    }

    #[test]
    fn a_digest_that_differs_from_the_image_in_the_store_is_named() {
        let env = env_of(&[]);
        let root = root();
        let docker = docker_with(DockerAnswer::Output("sha256:other".to_owned()));
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        assert!(
            problems(&host)
                .join("\n")
                .contains("images.json pins sha256:")
        );
    }

    #[test]
    fn a_program_that_never_answers_is_killed_and_counts_as_not_answering() {
        let mut sleeper = Command::new("sleep");
        sleeper.arg("30");
        let started = Instant::now();
        assert!(matches!(
            run_bounded(sleeper, Duration::from_millis(300)),
            Ran::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(10));
        let mut quick = Command::new("echo");
        quick.arg("hello");
        match run_bounded(quick, Duration::from_secs(10)) {
            Ran::Finished(output) => {
                assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
            }
            _ => panic!("echo did not finish"),
        }
    }

    #[test]
    fn placeholder_code_owners_are_named() {
        let env = env_of(&[]);
        let root = root();
        let docker = docker_with(DockerAnswer::NotInstalled);
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        assert!(problems(&host).join("\n").contains("placeholder handle"));
    }
}
