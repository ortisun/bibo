//! The checks that look at the machine before a real run (E1 and E2).
//!
//! [`crate::preflight::missing_needs`] only asks whether an environment variable is set. A set
//! variable can still name nothing, so this module looks at what the variables point to and at what
//! the repository and Docker hold: the private key file, the owner's Claude subscription token file,
//! the job budget, the allowlist, the code owners of the fixture copy, the model routing policy and
//! whether the owner confirmed it, the agent image and whether it was rebuilt after its recipe
//! changed.
//!
//! The run uses subscription mode, the factory's default (ADR 0020): the model credential is the
//! owner's subscription token, which the broker alone holds, and the most a job may use is the
//! factory's own job budget (`policies/model_routing.yaml`, `job.max_micro_usd`), which a run may
//! lower with `FACTORY_E2E_JOB_BUDGET_USD` and never raise. The token is never printed: a check
//! says what is wrong with the file, not what is in it.
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
    subscription_token(host, &mut found);
    job_budget(host, &mut found);
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

/// The variable that names the owner's Claude subscription token file, and the file used when it
/// is not set (ADR 0020, "How the owner turns it on").
pub const TOKEN_FILE_VARIABLE: &str = "FACTORY_E2E_SUBSCRIPTION_TOKEN_FILE";
/// The default token file, under the home directory.
pub const DEFAULT_TOKEN_FILE: &str = "claud-oauth-token.txt";
/// What a subscription token made with `claude setup-token` starts with.
pub const TOKEN_PREFIX: &str = "sk-ant-oat01-";
/// The variable that lowers the job budget for this run.
pub const BUDGET_VARIABLE: &str = "FACTORY_E2E_JOB_BUDGET_USD";

/// Where the token file is: the variable, or `~/claud-oauth-token.txt`.
#[must_use]
pub fn token_file(env: &dyn Fn(&str) -> Option<String>) -> Option<std::path::PathBuf> {
    if let Some(path) = env(TOKEN_FILE_VARIABLE).filter(|value| !value.trim().is_empty()) {
        let path = path.trim().to_owned();
        return Some(match path.strip_prefix("~/") {
            Some(rest) => Path::new(&env("HOME")?).join(rest),
            None => path.into(),
        });
    }
    env("HOME")
        .filter(|home| !home.trim().is_empty())
        .map(|home| Path::new(home.trim()).join(DEFAULT_TOKEN_FILE))
}

/// The checks the worker makes on the token file before its broker listens (ADR 0020), made here
/// so that the run does not start only to stop: the file exists, is closed to group and others,
/// and holds one token on one line that starts with `sk-ant-oat01-`. The text of the file is never
/// put in a message.
fn subscription_token(host: &Host<'_>, found: &mut Vec<String>) {
    let Some(path) = token_file(host.env) else {
        found.push(format!(
            "the owner's Claude subscription token file cannot be found: HOME is not set; set {TOKEN_FILE_VARIABLE} to the file that holds the token from `claude setup-token`"
        ));
        return;
    };
    let shown = path.display();
    let Ok(metadata) = std::fs::metadata(&path) else {
        found.push(format!(
            "the owner's Claude subscription token file {shown} does not exist or cannot be read; run `claude setup-token`, save the token as one line in that file and run chmod 600 on it, or set {TOKEN_FILE_VARIABLE} (ADR 0020)"
        ));
        return;
    };
    if !metadata.is_file() {
        found.push(format!("the subscription token file {shown} is not a file"));
        return;
    }
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            found.push(format!(
                "the subscription token file {shown} is open to group or others (mode {:o}); run chmod 600 on it",
                metadata.permissions().mode() & 0o777
            ));
        }
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        found.push(format!(
            "the subscription token file {shown} cannot be read as text"
        ));
        return;
    };
    let token = text.trim();
    if token.is_empty() {
        found.push(format!("the subscription token file {shown} is empty"));
    } else if token.contains(char::is_whitespace) {
        found.push(format!(
            "the subscription token in {shown} has a line break or a space inside; it was probably wrapped when copied. Save it again as one line"
        ));
    } else if !token.starts_with(TOKEN_PREFIX) {
        found.push(format!(
            "the file {shown} does not hold a Claude subscription token (one starts with {TOKEN_PREFIX}); make one with `claude setup-token`"
        ));
    }
}

/// The job budget the policy names (`job.max_micro_usd` of `policies/model_routing.yaml`), in
/// millionths of a US dollar, or `None` when the file does not say.
#[must_use]
pub fn policy_job_budget(root: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(root.join("policies/model_routing.yaml")).ok()?;
    let mut in_job = false;
    for line in text.lines() {
        if line.starts_with("job:") {
            in_job = true;
            continue;
        }
        if in_job {
            if !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
                return None;
            }
            if let Some(value) = line.trim().strip_prefix("max_micro_usd:") {
                return value.split('#').next()?.trim().parse().ok();
            }
        }
    }
    None
}

/// The budget of this run, in millionths of a US dollar: the policy's job budget, or the lower
/// amount the run names. An amount above the policy's, or one that is not a positive number, is an
/// error with the reason.
///
/// # Errors
/// A sentence that says what is wrong.
pub fn run_budget(root: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<u64, String> {
    let ceiling = policy_job_budget(root).ok_or(
        "policies/model_routing.yaml names no job budget (job.max_micro_usd), so the run has no ceiling",
    )?;
    let Some(value) = env(BUDGET_VARIABLE).filter(|value| !value.trim().is_empty()) else {
        return Ok(ceiling);
    };
    let asked = match value.trim().parse::<f64>() {
        Ok(dollars) if dollars > 0.0 && dollars.is_finite() => (dollars * 1_000_000.0).round(),
        _ => {
            return Err(format!(
                "{BUDGET_VARIABLE} is '{}', which is not a positive number of US dollars",
                value.trim()
            ));
        }
    };
    if asked > ceiling as f64 {
        return Err(format!(
            "{BUDGET_VARIABLE} asks for {:.2} US dollars, more than the job budget of the policy ({:.2}); a run may lower the budget, never raise it",
            asked / 1_000_000.0,
            ceiling as f64 / 1_000_000.0
        ));
    }
    Ok(asked as u64)
}

fn job_budget(host: &Host<'_>, found: &mut Vec<String>) {
    if let Err(why) = run_budget(host.root, host.env) {
        found.push(why);
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

/// One entry of an allowlist file, as far as these checks read it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListedPerson {
    /// The numeric GitHub id.
    pub github_user_id: Option<u64>,
    /// The login, for display.
    pub login: String,
    /// The designations.
    pub designations: Vec<String>,
}

/// The entries of an allowlist file in the factory's format (`crates/composition/README.md`,
/// "The allowlist"). A line-based reading: the factory's own reader judges the file for real.
#[must_use]
pub fn listed_people(text: &str) -> Vec<ListedPerson> {
    let mut people: Vec<ListedPerson> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("- tenant:") {
            people.push(ListedPerson::default());
            continue;
        }
        let Some(person) = people.last_mut() else {
            continue;
        };
        if let Some(value) = trimmed.strip_prefix("github_user_id:") {
            person.github_user_id = value.split('#').next().unwrap_or("").trim().parse().ok();
        } else if let Some(value) = trimmed.strip_prefix("login:") {
            value
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .clone_into(&mut person.login);
        } else if let Some(value) = trimmed.strip_prefix("designations:") {
            person.designations = value
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .map(|word| word.trim().to_owned())
                .filter(|word| !word.is_empty())
                .collect();
        }
    }
    people
}

/// Whether `policies/approval.yaml` switches the solo mode on (`solo_mode.enabled`, ADR 0022):
/// the one person who may approve approves their own request, and the engine checks the
/// conditions of the mode at each decision. A file that cannot be read says no.
#[must_use]
pub fn solo_mode_enabled(root: &Path) -> bool {
    std::fs::read_to_string(root.join("policies/approval.yaml"))
        .is_ok_and(|text| solo_mode_enabled_in(&text))
}

/// Reads `enabled` in the top-level `solo_mode` block of an approval policy text. A key of the same
/// name in another block, or a block with no `enabled` line, says no.
#[must_use]
pub fn solo_mode_enabled_in(text: &str) -> bool {
    let mut inside = false;
    for line in text.lines() {
        let content = line.split('#').next().unwrap_or("");
        if content.trim().is_empty() {
            continue;
        }
        let top_level = !content.starts_with(' ') && !content.starts_with('\t');
        if top_level {
            inside = content.trim_end() == "solo_mode:";
            continue;
        }
        if inside && let Some(value) = content.trim().strip_prefix("enabled:") {
            return value.trim() == "true";
        }
    }
    false
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
    let people = listed_people(&text);
    let holding = |designation: &str| -> Vec<&ListedPerson> {
        people
            .iter()
            .filter(|person| {
                person.github_user_id.is_some_and(|id| id > 0)
                    && person.designations.iter().any(|held| held == designation)
            })
            .collect()
    };
    let requesters = holding("requester");
    let approvers = holding("approver");
    for (designation, list) in [("requester", &requesters), ("approver", &approvers)] {
        if list.is_empty() {
            found.push(format!(
                "the allowlist {} names nobody, by numeric GitHub id, with the designation {designation}; the run needs a named requester and a named approver",
                path.display()
            ));
        }
    }
    // The owner works alone: one person may hold both when the solo mode is on (ADR 0022).
    // Otherwise an approver who is not a requester is needed.
    let only_self = !approvers.is_empty()
        && approvers.iter().all(|approver| {
            requesters
                .iter()
                .any(|r| r.github_user_id == approver.github_user_id)
        });
    if only_self && !solo_mode_enabled(host.root) {
        found.push(format!(
            "the allowlist {} names no approver who is not also a requester, and policies/approval.yaml does not switch the solo mode on (solo_mode.enabled)",
            path.display()
        ));
    }
}

/// Where the fixture setup script keeps the copy it pushed to `owner/name`, under the repository.
#[must_use]
pub fn fixture_copy(root: &Path, repository: &str) -> std::path::PathBuf {
    root.join("target/e2e-fixture").join(repository.trim())
}

/// The problems with a `CODEOWNERS` text for the run: a placeholder handle (`@example-org/...`)
/// left in, no owner at all, or only the requester as owner when the approval policy does not let
/// the requester approve. `requester_logins` are the logins of the requesters on the allowlist.
#[must_use]
pub fn code_owner_problems(
    text: &str,
    requester_logins: &[String],
    self_approval_allowed: bool,
) -> Vec<String> {
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
        return vec![format!(
            "the fixture's CODEOWNERS still lists {placeholders} placeholder handle(s) (@example-org/...); the copy on GitHub needs real owners"
        )];
    }
    if handles.is_empty() {
        return vec!["the fixture's CODEOWNERS lists no owner".to_owned()];
    }
    let only_requesters = handles.iter().all(|handle| {
        requester_logins
            .iter()
            .any(|login| handle.trim_start_matches('@').eq_ignore_ascii_case(login))
    });
    if only_requesters && !self_approval_allowed {
        return vec![
            "the fixture's CODEOWNERS lists only the requester, and policies/approval.yaml does not switch the solo mode on; add a second owner"
                .to_owned(),
        ];
    }
    Vec::new()
}

fn code_owners(host: &Host<'_>, found: &mut Vec<String>) {
    // The template in this repository keeps its placeholder handles on purpose. What counts is the
    // copy the setup script pushed, which it keeps under target/e2e-fixture/OWNER/NAME. Without a
    // fixture repository there is no copy to look at, and the missing variable says so.
    let Some(repository) = set(host, "FACTORY_E2E_FIXTURE_REPO") else {
        return;
    };
    let copy = fixture_copy(host.root, &repository);
    let Ok(text) = std::fs::read_to_string(copy.join("CODEOWNERS")) else {
        found.push(format!(
            "the fixture repository {} was not set up from this checkout: run scripts/setup-fixture-repository.sh {} (it keeps the copy it pushes under {})",
            repository.trim(),
            repository.trim(),
            copy.display()
        ));
        return;
    };
    let requesters: Vec<String> = set(host, "FACTORY_E2E_REQUESTER_ALLOWLIST")
        .and_then(|path| std::fs::read_to_string(path.trim()).ok())
        .map(|text| {
            listed_people(&text)
                .into_iter()
                .filter(|person| person.designations.iter().any(|d| d == "requester"))
                .map(|person| person.login)
                .collect()
        })
        .unwrap_or_default();
    found.extend(code_owner_problems(
        &text,
        &requesters,
        solo_mode_enabled(host.root),
    ));
}

fn routing_policy(host: &Host<'_>, found: &mut Vec<String>) {
    let Ok(text) = std::fs::read_to_string(host.root.join("policies/model_routing.yaml")) else {
        found.push(
            "policies/model_routing.yaml does not exist, so the model router has no routes and no live stage can choose a model"
                .to_owned(),
        );
        return;
    };
    // The production profile refuses a routing policy the owner has not confirmed
    // (`ModelRoutingPolicy::unconfirmed`): a real run is a production run.
    let waiting = routing_unconfirmed(&text);
    if !waiting.is_empty() {
        found.push(format!(
            "policies/model_routing.yaml waits for the owner's confirmation ({}), and the production profile of a real run refuses it; the owner reads each price on the provider's price page, sets price_checked_on to the date, and sets policy.status to enforced",
            waiting.join("; ")
        ));
    }
}

/// What in the routing policy still waits for the owner, in the words of
/// `ModelRoutingPolicy::unconfirmed`: the status `designed`, and each model whose prices are
/// `unchecked`.
#[must_use]
pub fn routing_unconfirmed(text: &str) -> Vec<String> {
    let mut waiting = Vec::new();
    let mut in_policy = false;
    let mut model = String::new();
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or("");
        if !line.starts_with(' ') && !code.trim().is_empty() {
            in_policy = code.starts_with("policy:");
        }
        let trimmed = code.trim();
        if in_policy && trimmed == "status: designed" {
            waiting.push("policy.status is designed".to_owned());
        }
        if let Some(id) = trimmed.strip_prefix("- id:") {
            id.trim().clone_into(&mut model);
        }
        if trimmed == "price_checked_on: unchecked" {
            waiting.push(format!("the prices of {model} are unchecked"));
        }
    }
    waiting
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
        assert!(
            !joined.contains("does not exist, so the model router"),
            "{joined}"
        );
        assert!(joined.contains("Docker is not installed"), "{joined}");
        // No HOME: the token file cannot be found, and that is said.
        assert!(joined.contains("subscription token file"), "{joined}");
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
        assert!(
            !found.iter().any(|line| line.contains("does not exist")),
            "{found:?}"
        );
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
    fn a_run_may_lower_the_job_budget_of_the_policy_and_never_raise_it() {
        let root = root();
        let ceiling = policy_job_budget(&root).expect("the policy names a job budget");
        let none = env_of(&[]);
        assert_eq!(run_budget(&root, &none), Ok(ceiling));
        let lower = env_of(&[(BUDGET_VARIABLE, "2.5")]);
        assert_eq!(run_budget(&root, &lower), Ok(2_500_000));
        for bad in ["0", "-3", "lots", "100000"] {
            let env = env_of(&[(BUDGET_VARIABLE, bad)]);
            assert!(run_budget(&root, &env).is_err(), "{bad}");
        }
    }

    fn token_problems(text: Option<&str>, mode: u32) -> String {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("e2e-token-{}-{}", std::process::id(), mode));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("token.txt");
        let _ = std::fs::remove_file(&file);
        if let Some(text) = text {
            std::fs::write(&file, text).expect("file");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).expect("mode");
        }
        let path = file.to_string_lossy().into_owned();
        let env = env_of(&[(TOKEN_FILE_VARIABLE, &path), ("HOME", "/nowhere")]);
        let root = root();
        let docker = docker_with(DockerAnswer::NotInstalled);
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        let mut found = Vec::new();
        subscription_token(&host, &mut found);
        let _ = std::fs::remove_dir_all(&dir);
        found.join("\n")
    }

    #[test]
    fn the_subscription_token_file_is_checked_and_its_text_is_never_shown() {
        // Built at run time, so that no token-shaped literal is in the source for the secret scan.
        let good = format!("{TOKEN_PREFIX}{}", "abcdefghijklmnop");
        let good = good.as_str();
        assert_eq!(token_problems(Some(&format!("{good}\n")), 0o600), "");
        assert!(token_problems(None, 0o600).contains("does not exist"));
        assert!(token_problems(Some(good), 0o644).contains("open to group or others"));
        let wrapped = token_problems(Some("sk-ant-oat01-abc\ndefghij"), 0o600);
        assert!(wrapped.contains("line break or a space"), "{wrapped}");
        let other = token_problems(Some("sk-ant-api03-secretvalue"), 0o600);
        assert!(
            other.contains("does not hold a Claude subscription token"),
            "{other}"
        );
        // No message ever carries the text of the file.
        for text in [
            good,
            "sk-ant-api03-secretvalue",
            "sk-ant-oat01-abc\ndefghij",
        ] {
            for mode in [0o600, 0o644] {
                let said = token_problems(Some(text), mode);
                assert!(!said.contains("abcdefghijklmnop"), "{said}");
                assert!(!said.contains("secretvalue"), "{said}");
                assert!(!said.contains("defghij"), "{said}");
            }
        }
    }

    #[test]
    fn the_default_token_file_is_in_the_home_directory() {
        let env = env_of(&[("HOME", "/Users/someone")]);
        assert_eq!(
            token_file(&env),
            Some(std::path::PathBuf::from(
                "/Users/someone/claud-oauth-token.txt"
            ))
        );
        let named = env_of(&[("HOME", "/Users/someone"), (TOKEN_FILE_VARIABLE, "~/t.txt")]);
        assert_eq!(
            token_file(&named),
            Some(std::path::PathBuf::from("/Users/someone/t.txt"))
        );
    }

    #[test]
    fn code_owners_need_real_owners_and_the_requester_alone_is_enough_when_the_policy_allows_it() {
        let me = vec!["owner-login".to_owned()];
        let template = std::fs::read_to_string(root().join("fixtures/repos/word-count/CODEOWNERS"))
            .expect("the template");
        assert!(code_owner_problems(&template, &me, true)[0].contains("placeholder handle"));
        assert!(code_owner_problems("* @owner-login\n/src/ @owner-login\n", &me, true).is_empty());
        assert!(code_owner_problems("* @Owner-Login\n", &me, false)[0].contains("second owner"));
        assert!(code_owner_problems("* @owner-login @friend\n", &me, false).is_empty());
        assert!(code_owner_problems("# nothing\n", &me, true)[0].contains("no owner"));
    }

    #[test]
    fn the_repository_policy_switches_the_solo_mode_on() {
        assert!(solo_mode_enabled(&root()));
    }

    #[test]
    fn only_the_enabled_line_of_the_solo_mode_block_counts() {
        let on = "separation_of_duties:\n  enabled: false\nsolo_mode:\n  enabled: true   # the owner works alone\n  minimum_wait_minutes:\n    dependency: 10\n";
        assert!(solo_mode_enabled_in(on));
        assert!(!solo_mode_enabled_in(
            &on.replace("enabled: true", "enabled: false")
        ));
        // `enabled` of another block, or after the block ends, is not the switch.
        assert!(!solo_mode_enabled_in(
            "other:\n  enabled: true\nsolo_mode:\n  minimum_wait_minutes: {}\n"
        ));
        assert!(!solo_mode_enabled_in(
            "solo_mode:\n  phrase: x\nother:\n  enabled: true\n"
        ));
        assert!(!solo_mode_enabled_in("# solo_mode:\n#   enabled: true\n"));
        assert!(!solo_mode_enabled_in(""));
    }

    #[test]
    fn an_allowlist_with_one_person_who_requests_and_approves_is_enough_under_the_policy() {
        let dir = std::env::temp_dir().join(format!("e2e-allow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let check = |text: &str| {
            let file = dir.join("allowlist.yaml");
            std::fs::write(&file, text).expect("file");
            let path = file.to_string_lossy().into_owned();
            let env = env_of(&[("FACTORY_E2E_REQUESTER_ALLOWLIST", &path)]);
            let root = root();
            let docker = docker_with(DockerAnswer::NotInstalled);
            let host = Host {
                root: &root,
                env: &env,
                docker: &docker,
                git: &git_nothing,
            };
            let mut found = Vec::new();
            allowlist(&host, &mut found);
            found.join("\n")
        };
        let alone = "version: 1\nentries:\n  - tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60\n    github_user_id: 1234567\n    login: owner-login\n    designations: [requester, operator, approver]\n";
        assert_eq!(check(alone), "");
        let nobody = "version: 1\nentries:\n  - tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60\n    github_user_id: 1234567\n    login: owner-login\n    designations: [operator]\n";
        let said = check(nobody);
        assert!(said.contains("designation requester"), "{said}");
        assert!(said.contains("designation approver"), "{said}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_routing_policy_of_the_repository_is_confirmed_and_a_waiting_copy_is_named() {
        // The owner confirmed the policy on 2026-11-13, so the repository's file passes. A copy
        // that puts back the waiting status and an unchecked price is named on both counts.
        let text = std::fs::read_to_string(root().join("policies/model_routing.yaml"))
            .expect("the routing policy");
        let confirmed = routing_unconfirmed(&text);
        assert!(confirmed.is_empty(), "{confirmed:?}");
        let waiting_text = text
            .replacen("  status: enforced", "  status: designed", 1)
            .replacen(
                "price_checked_on: \"2026-11-13\"",
                "price_checked_on: unchecked",
                1,
            );
        let waiting = routing_unconfirmed(&waiting_text);
        assert!(
            waiting
                .iter()
                .any(|item| item == "policy.status is designed"),
            "{waiting:?}"
        );
        assert!(
            waiting
                .iter()
                .any(|item| item == "the prices of claude-sonnet-5-5 are unchecked"),
            "{waiting:?}"
        );
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
    fn a_fixture_repository_that_was_not_set_up_from_this_checkout_is_named() {
        let env = env_of(&[("FACTORY_E2E_FIXTURE_REPO", "someone/never-set-up-here")]);
        let root = root();
        let docker = docker_with(DockerAnswer::NotInstalled);
        let host = Host {
            root: &root,
            env: &env,
            docker: &docker,
            git: &git_nothing,
        };
        let said = problems(&host).join("\n");
        assert!(
            said.contains("scripts/setup-fixture-repository.sh someone/never-set-up-here"),
            "{said}"
        );
    }
}
