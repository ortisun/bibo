//! Runs the fixture's own commands on a copy: on the host, or in the pinned verify image.
//!
//! The fixture is data that the factory works on. This is the one place where its code is run on
//! the host, and only to verify the fixture itself: the commands are fixed here, they run with no
//! shell, with the network switched off for cargo, on a copy in a temporary directory.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::{Finding, Outcome};

/// The commands that the project manifest declares as gates, with the flags the verify profile
/// adds (`--offline --locked`), in the order they run.
pub const COMMANDS: [(&str, &[&str]); 4] = [
    ("format", &["cargo", "fmt", "--check"]),
    (
        "lint",
        &[
            "cargo",
            "clippy",
            "--all-targets",
            "--offline",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    ),
    ("build", &["cargo", "build", "--offline", "--locked"]),
    ("unit-tests", &["cargo", "test", "--offline", "--locked"]),
];

/// The most output kept from one command.
const KEEP_BYTES: usize = 64 * 1024;

/// What one command did.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandResult {
    /// The gate this command stands for.
    pub label: String,
    /// The program and its arguments.
    pub argv: Vec<String>,
    /// The exit code, or `None` when the command did not start or was ended by a signal.
    pub exit_code: Option<i32>,
    /// What it wrote to standard output, cut to the first 64 KiB.
    pub stdout: String,
    /// What it wrote to standard error, cut to the first 64 KiB.
    pub stderr: String,
    /// How long it took, in seconds.
    pub seconds: f64,
}

impl CommandResult {
    /// True when the command exited with code 0.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
    }
}

fn keep(bytes: &[u8]) -> String {
    let cut = &bytes[..bytes.len().min(KEEP_BYTES)];
    String::from_utf8_lossy(cut).into_owned()
}

fn run(label: &str, mut command: Command) -> CommandResult {
    let argv: Vec<String> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|part| part.to_string_lossy().into_owned())
        .collect();
    let started = Instant::now();
    let output = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let seconds = started.elapsed().as_secs_f64();
    match output {
        Ok(output) => CommandResult {
            label: label.to_owned(),
            argv,
            exit_code: output.status.code(),
            stdout: keep(&output.stdout),
            stderr: keep(&output.stderr),
            seconds,
        },
        Err(error) => CommandResult {
            label: label.to_owned(),
            argv,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("the command did not start: {error}"),
            seconds,
        },
    }
}

/// True when `cargo --version` runs.
#[must_use]
pub fn cargo_available() -> bool {
    Command::new("cargo")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Runs the four gate commands in `copy`, writing build output to `target`. Cargo is told to stay
/// offline. The caller passes a copy, never the fixture directory.
#[must_use]
pub fn run_on_host(copy: &Path, target: &Path) -> Vec<CommandResult> {
    COMMANDS
        .iter()
        .map(|(label, argv)| {
            let mut command = Command::new(argv[0]);
            command
                .args(&argv[1..])
                .current_dir(copy)
                .env("CARGO_NET_OFFLINE", "true")
                .env("CARGO_TERM_COLOR", "never")
                .env("CARGO_TARGET_DIR", target);
            run(label, command)
        })
        .collect()
}

/// Turns the results of the four commands into an outcome: passed when every one exited with 0,
/// failed with the commands that did not, blocked when cargo is not on the host.
#[must_use]
pub fn outcome_of(results: &[CommandResult]) -> Outcome {
    if results.iter().all(|r| r.exit_code.is_none()) && !cargo_available() {
        return Outcome::Blocked("cargo is not installed on this host".to_owned());
    }
    let findings: Vec<Finding> = results
        .iter()
        .filter(|result| !result.succeeded())
        .map(|result| {
            Finding::new(
                "commands",
                format!(
                    "{} ({}) exited with {:?}: {}",
                    result.label,
                    result.argv.join(" "),
                    result.exit_code,
                    result.stderr.lines().last().unwrap_or_default()
                ),
            )
        })
        .collect();
    if findings.is_empty() {
        Outcome::Passed
    } else {
        Outcome::Failed(findings)
    }
}

/// What the built tool does, as the README and the deliberate gap need it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Behaviour {
    /// The output of `word-count --help`.
    pub help: String,
    /// The lines the tool printed for the inputs of the README's examples.
    pub example_outputs: Vec<String>,
    /// The exit code of `word-count --json <file>`.
    pub json_exit_code: Option<i32>,
    /// What `word-count --json <file>` wrote to standard error.
    pub json_stderr: String,
}

/// Runs the built tool. `copy` is the fixture copy that was built into `target`.
#[must_use]
pub fn probe_behaviour(copy: &Path, target: &Path) -> Behaviour {
    let binary = target.join("debug").join("word-count");
    let sample = copy.join("tests/golden/sample.txt");
    let mut behaviour = Behaviour::default();
    if let Ok(output) = Command::new(&binary)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
    {
        behaviour.help = String::from_utf8_lossy(&output.stdout).into_owned();
    }
    // The README's file example counts `notes.txt`. Give the tool a file of that name.
    if let Ok(dir) = crate::workdir::TempDir::new("probe")
        && std::fs::copy(&sample, dir.path().join("notes.txt")).is_ok()
        && let Ok(output) = Command::new(&binary)
            .arg("notes.txt")
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .output()
    {
        behaviour.example_outputs.push(
            String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_owned(),
        );
    }
    if let Ok(mut child) = Command::new(&binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(b"one two three\n");
        }
        if let Ok(output) = child.wait_with_output() {
            behaviour.example_outputs.push(
                String::from_utf8_lossy(&output.stdout)
                    .trim_end()
                    .to_owned(),
            );
        }
    }
    if let Ok(output) = Command::new(&binary)
        .arg("--json")
        .arg(&sample)
        .stdin(Stdio::null())
        .output()
    {
        behaviour.json_exit_code = output.status.code();
        behaviour.json_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    }
    behaviour
}

/// The deliberate gap is open: the tool refuses `--json` as an unknown option.
#[must_use]
pub fn gap_is_open(behaviour: &Behaviour) -> Vec<Finding> {
    let mut findings = Vec::new();
    if behaviour.json_exit_code != Some(2) {
        findings.push(Finding::new(
            "gap",
            format!(
                "`word-count --json FILE` exited with {:?}; the open gap needs exit code 2",
                behaviour.json_exit_code
            ),
        ));
    }
    if !behaviour.json_stderr.contains("unknown option '--json'") {
        findings.push(Finding::new(
            "gap",
            "`word-count --json FILE` does not say that --json is an unknown option",
        ));
    }
    findings
}

// ---------------------------------------------------------------------------------------------
// The pinned verify image

/// The label that every container started here carries, so a leftover can be found and removed.
pub const CONTAINER_LABEL: &str = "factory.e2e=word-count-fixture-check";

/// The image reference (by digest) of the verify image for this platform, read from the image
/// registry file of the factory.
///
/// # Errors
/// A sentence saying what is missing.
pub fn verify_image_reference(images_json: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(images_json)
        .map_err(|error| format!("cannot read {}: {error}", images_json.display()))?;
    let document: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("images.json is not JSON: {error}"))?;
    let platform = match std::env::consts::ARCH {
        "aarch64" => "linux/arm64",
        _ => "linux/amd64",
    };
    let image = &document["platforms"][platform]["images"]["verify"];
    match (image["reference"].as_str(), image["status"].as_str()) {
        (Some(reference), Some("ready")) => Ok(reference.to_owned()),
        (Some(_), other) => Err(format!(
            "the verify image for {platform} is not ready (status {other:?})"
        )),
        _ => Err(format!("images.json has no verify image for {platform}")),
    }
}

fn docker(args: &[&str]) -> Option<std::process::Output> {
    Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()
}

/// Why the image cannot be used here, or `None` when Docker answers and has the image.
#[must_use]
pub fn image_blocker(reference: &str) -> Option<String> {
    match docker(&["info", "--format", "{{.ServerVersion}}"]) {
        Some(output) if output.status.success() => {}
        Some(_) => return Some("the Docker daemon does not answer".to_owned()),
        None => return Some("docker is not installed".to_owned()),
    }
    match docker(&["image", "inspect", "--format", "{{.Id}}", reference]) {
        Some(output) if output.status.success() => None,
        _ => Some(format!(
            "the pinned verify image {reference} is not in the local Docker (build it with infra/sandbox-images/verify/build.sh)"
        )),
    }
}

/// Runs the four gate commands in the pinned verify image, one container each, with no network,
/// the source mounted read-only and a small writable memory file system for the build output. The
/// containers are labelled and removed when they end.
///
/// `copy` is a copy of the fixture. Containers run one after another.
#[must_use]
pub fn run_in_image(copy: &Path, reference: &str) -> Vec<CommandResult> {
    COMMANDS
        .iter()
        .map(|(label, argv)| {
            let mount = format!("{}:/workspace:ro", copy.display());
            let mut command = Command::new("docker");
            command.args([
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--user",
                "10001:10001",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "512",
                "--memory",
                "2g",
                "--label",
                CONTAINER_LABEL,
                "--tmpfs",
                "/out:rw,exec,nosuid,nodev,size=768m,uid=10001,gid=10001",
                "--tmpfs",
                "/home/agent:rw,nosuid,nodev,size=64m,uid=10001,gid=10001",
                "-v",
                &mount,
                "-w",
                "/workspace",
                "-e",
                "CARGO_TARGET_DIR=/out/target",
                "-e",
                "CARGO_HOME=/home/agent/.cargo",
                "-e",
                "CARGO_NET_OFFLINE=true",
                "-e",
                "CARGO_TERM_COLOR=never",
                "-e",
                "TMPDIR=/out",
                reference,
            ]);
            command.args(*argv);
            let mut result = run(label, command);
            // Show the command that ran in the container, not the long docker line around it.
            result.argv = argv.iter().map(|part| (*part).to_owned()).collect();
            result
        })
        .collect()
}

/// Removes any container that carries [`CONTAINER_LABEL`] and is still around, for example after a
/// run that was interrupted. Returns how many were removed.
pub fn remove_leftover_containers() -> usize {
    let listed = docker(&[
        "ps",
        "-a",
        "-q",
        "--filter",
        &format!("label={CONTAINER_LABEL}"),
    ]);
    let Some(listed) = listed else { return 0 };
    let ids: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    for id in &ids {
        let _ = docker(&["rm", "-f", id]);
    }
    ids.len()
}
