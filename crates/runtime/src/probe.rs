//! What both probes share: running a short command in the sandbox, reading the version, finding a
//! flag in help text, and remembering the answer per image.
//!
//! A probe reads the tool itself. A capability that no check observed counts as missing (ADR 0005:
//! "The adapter never guesses"). The accepted versions are policy: a tool at another version makes
//! the stage BLOCKED, whatever its help text says.

use std::time::Duration;

use factory_ports::agent::{
    Capability, CapabilityObservation, ProbeError, ProbeStep, RuntimeCapabilities,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{ExecArgv, ExecRequest, ImageDigest, SandboxError, SandboxSession};

use crate::future::BoxFuture;
use crate::io::RunIo;

/// How long one probe command may run. The probe as a whole has a fixed timeout of thirty seconds
/// in the port, and a probe has at most four commands.
pub const PROBE_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// How many bytes of a probe command's output are kept.
const PROBE_OUTPUT_BYTES: u64 = 512 * 1024;

/// The exit codes of a program that was not found or could not be executed.
const NOT_EXECUTABLE: [i32; 2] = [126, 127];

/// A cancel signal that never fires, for the probe commands. A probe is safe to drop, so nothing
/// needs to cancel it.
#[derive(Debug, Default)]
pub struct NeverCancelled;

impl CancelSignal for NeverCancelled {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Real
    }

    fn is_cancelled(&self) -> bool {
        false
    }

    fn cancelled<'life0, 'async_trait>(&'life0 self) -> BoxFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::pending())
    }
}

/// What a probe command printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutput {
    /// Standard output as text.
    pub stdout: String,
    /// Standard error as text.
    pub stderr: String,
    /// The exit code, when the command exited by itself.
    pub exit_code: Option<i32>,
}

/// Runs one short command in the sandbox and reads what it printed.
///
/// # Errors
/// [`ProbeError::BinaryMissing`] when the program cannot be executed, and
/// [`ProbeError::ProbeFailed`] with `step` for anything else that goes wrong.
pub async fn run_probe_command(
    session: &mut dyn SandboxSession,
    io: &RunIo,
    argv: Vec<String>,
    step: ProbeStep,
) -> Result<ProbeOutput, ProbeError> {
    let argv = ExecArgv::new(argv).map_err(|_| ProbeError::ProbeFailed(step))?;
    let request = ExecRequest {
        argv,
        cwd: None,
        stdin: None,
        timeout: PROBE_COMMAND_TIMEOUT,
        max_output_bytes: PROBE_OUTPUT_BYTES,
    };
    let result = session
        .exec(request, &NeverCancelled)
        .await
        .map_err(|error| {
            tracing::debug!(?error, ?step, "a probe command failed in the sandbox");
            match error {
                SandboxError::ImageUnavailable => ProbeError::BinaryMissing,
                _ => ProbeError::ProbeFailed(step),
            }
        })?;
    if result.timed_out {
        return Err(ProbeError::ProbeFailed(step));
    }
    let stdout = io
        .read(&result.stdout)
        .await
        .map_err(|_| ProbeError::ProbeFailed(step))?;
    let stderr = io
        .read(&result.stderr)
        .await
        .map_err(|_| ProbeError::ProbeFailed(step))?;
    if result
        .exit_code
        .is_some_and(|code| NOT_EXECUTABLE.contains(&code))
    {
        return Err(ProbeError::BinaryMissing);
    }
    Ok(ProbeOutput {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit_code: result.exit_code,
    })
}

/// The first dotted version number in `text` (`2.1.311`, `0.163.0`, `1.2.3-rc.1`).
#[must_use]
pub fn parse_version(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|word| {
        let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        let core = word.split(['-', '+']).next().unwrap_or(word);
        let parts: Vec<&str> = core.split('.').collect();
        let numeric = parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        numeric.then(|| word.to_owned())
    })
}

/// True when `help` names `flag` as a whole word: `--tools` is not found in `--tools-extra`.
#[must_use]
pub fn has_flag(help: &str, flag: &str) -> bool {
    let mut start = 0;
    while let Some(at) = help[start..].find(flag) {
        let begin = start + at;
        let end = begin + flag.len();
        let before_ok = help[..begin]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        let after_ok = help[end..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        if before_ok && after_ok {
            return true;
        }
        start = end;
    }
    false
}

/// One observation.
#[must_use]
pub fn observation(
    capability: Capability,
    supported: bool,
    source: impl Into<String>,
) -> CapabilityObservation {
    CapabilityObservation {
        capability,
        supported,
        source: source.into(),
    }
}

/// The accepted versions are exact strings. An unsupported version is `UnsupportedVersion`.
///
/// # Errors
/// [`ProbeError::UnsupportedVersion`] with the version found, or `"unreadable"` when the output
/// held none.
pub fn accept_version(found: Option<String>, accepted: &[String]) -> Result<String, ProbeError> {
    match found {
        Some(version) if accepted.contains(&version) => Ok(version),
        Some(version) => Err(ProbeError::UnsupportedVersion { found: version }),
        None => Err(ProbeError::UnsupportedVersion {
            found: "unreadable".to_owned(),
        }),
    }
}

/// Assembles the record the port returns.
#[must_use]
pub fn capabilities(
    version: String,
    observations: Vec<CapabilityObservation>,
) -> RuntimeCapabilities {
    RuntimeCapabilities {
        runtime_version: version,
        observations,
    }
}

/// The last probe of one image. A run reuses it; the engine re-probes when the image changes.
#[derive(Debug, Default)]
pub struct ProbeCache {
    slot: std::sync::Mutex<Option<(ImageDigest, RuntimeCapabilities)>>,
}

impl ProbeCache {
    /// Remembers a probe result for an image.
    pub fn remember(&self, image: &ImageDigest, found: &RuntimeCapabilities) {
        if let Ok(mut slot) = self.slot.lock() {
            *slot = Some((image.clone(), found.clone()));
        }
    }

    /// The remembered result, when it was made for this image.
    #[must_use]
    pub fn recall(&self, image: &ImageDigest) -> Option<RuntimeCapabilities> {
        let slot = self.slot.lock().ok()?;
        slot.as_ref()
            .filter(|(known, _)| known == image)
            .map(|(_, found)| found.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_read_from_the_forms_the_tools_print() {
        assert_eq!(
            parse_version("2.1.311 (Claude Code)\n").as_deref(),
            Some("2.1.311")
        );
        assert_eq!(
            parse_version("codex-cli 0.163.0\n").as_deref(),
            Some("0.163.0")
        );
        assert_eq!(parse_version("1.2.3-rc.1").as_deref(), Some("1.2.3-rc.1"));
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version("1.2"), None);
    }

    #[test]
    fn a_flag_must_match_as_a_whole_word() {
        let help =
            "  --tools <tools...>  the tools\n  --tools-extra  other\n  -p, --print  print\n";
        assert!(has_flag(help, "--tools"));
        assert!(has_flag(help, "--print"));
        assert!(!has_flag("only --tools-extra here", "--tools"));
        assert!(!has_flag(help, "--max-turns"));
        assert!(!has_flag("--print-more", "--print"));
    }

    #[test]
    fn only_the_accepted_versions_pass() {
        let accepted = vec!["2.1.311".to_owned()];
        assert_eq!(
            accept_version(Some("2.1.311".to_owned()), &accepted),
            Ok("2.1.311".to_owned())
        );
        assert_eq!(
            accept_version(Some("2.1.312".to_owned()), &accepted),
            Err(ProbeError::UnsupportedVersion {
                found: "2.1.312".to_owned()
            })
        );
        assert_eq!(
            accept_version(None, &accepted),
            Err(ProbeError::UnsupportedVersion {
                found: "unreadable".to_owned()
            })
        );
    }
}
