//! Running one command in a started container: the `docker exec` arguments, the exit status, and
//! the capture of output (cut, redacted, stored as artifacts).

use factory_domain::contracts::ArtifactRef;
use factory_domain::values::MediaType;
use factory_ports::sandbox::{ExecRequest, Resource, SandboxError, WORKSPACE_TARGET};

use super::Shared;

/// Bytes captured beyond the cap, so that a secret that straddles the cap is still whole in the
/// text the redactor reads. The kept output is cut to the cap after redaction.
pub(crate) const REDACTION_MARGIN: u64 = 4096;

/// `docker exec -i [--workdir D] <container> <argv...>`. The argument vector comes after the
/// container name and is passed on whole; Docker reads no flag after the container.
pub(crate) fn exec_args(container: &str, request: &ExecRequest) -> Vec<String> {
    let mut args = vec!["exec".to_owned(), "--interactive".to_owned()];
    if let Some(cwd) = &request.cwd {
        args.push("--workdir".to_owned());
        args.push(format!("{WORKSPACE_TARGET}/{}", cwd.as_str()));
    }
    args.push(container.to_owned());
    args.extend(request.argv.as_slice().iter().cloned());
    args
}

/// Splits the exit code the `docker exec` client returns into the process's own code and the
/// signal that ended it. The client reports a signal as 128 plus its number, so codes 129 to 159
/// are read as signals 1 to 31.
pub(crate) fn exit_parts(code: i32) -> (Option<i32>, Option<i32>) {
    if (129..=159).contains(&code) {
        (None, Some(code - 128))
    } else {
        (Some(code), None)
    }
}

/// What one stream became.
pub(crate) struct Kept {
    pub reference: ArtifactRef,
    pub truncated: bool,
}

/// Redacts `raw`, cuts the result to `cap` bytes and stores it. `capture_was_full` says the
/// capture itself stopped at its limit, so more output existed.
pub(crate) async fn keep(
    shared: &Shared,
    raw: Vec<u8>,
    cap: u64,
    capture_was_full: bool,
) -> Result<Kept, SandboxError> {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let mut bytes = match shared.redactor.redact(&raw) {
        Ok(clean) => clean.output.into_owned(),
        // The policy says to drop the content when the redactor fails.
        Err(_) => b"[output withheld: redaction failed]".to_vec(),
    };
    let truncated = capture_was_full || bytes.len() > cap;
    bytes.truncate(cap);
    let media = MediaType::parse("text/plain")
        .map_err(|_| SandboxError::ResourceExceeded(Resource::Disk))?;
    // The closed error set has no variant for a failed artifact store. The store refuses by size
    // or by I/O; both are reported as the disk resource.
    let reference = shared
        .artifacts
        .put(bytes, media)
        .await
        .map_err(|_| SandboxError::ResourceExceeded(Resource::Disk))?;
    Ok(Kept {
        reference,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_ports::sandbox::ExecArgv;
    use std::time::Duration;

    fn request(words: &[&str]) -> ExecRequest {
        ExecRequest {
            argv: ExecArgv::new(words.iter().map(|w| (*w).to_owned()).collect()).expect("argv"),
            cwd: None,
            stdin: None,
            timeout: Duration::from_secs(1),
            max_output_bytes: 10,
        }
    }

    #[test]
    fn the_command_follows_the_container_name_as_separate_arguments() {
        let args = exec_args("sf-x", &request(&["echo", "a b;", "$HOME", "--help", "-n"]));
        assert_eq!(
            args,
            vec![
                "exec",
                "--interactive",
                "sf-x",
                "echo",
                "a b;",
                "$HOME",
                "--help",
                "-n"
            ]
        );
    }

    #[test]
    fn exit_codes_that_are_signals_are_split_out() {
        assert_eq!(exit_parts(0), (Some(0), None));
        assert_eq!(exit_parts(1), (Some(1), None));
        assert_eq!(exit_parts(127), (Some(127), None));
        assert_eq!(exit_parts(137), (None, Some(9)));
        assert_eq!(exit_parts(143), (None, Some(15)));
        assert_eq!(exit_parts(200), (Some(200), None));
    }
}
