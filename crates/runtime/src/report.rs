//! Turns what a run produced into the report the port returns, whatever way the run ended.
//!
//! A failed attempt is the one that needs its evidence and may have cost money, so every part of the
//! report is built from whatever the run left, on every path (ADR 0014, decision 1). The steps here
//! are the same for both tools: the output is size-checked and redacted, the cost is compared with
//! the run's limit, the denials are redacted, and the transcript is stored.

use std::time::Duration;

use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, CostMicroUsd, Denial, ExitInfo, RawOutput,
    Usage,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{ExecArgv, ExecRequest, ExecResult, SandboxError, SandboxSession};

use crate::io::RunIo;

/// The words a transcript uses for how a run ended, so a reader can tell a cut run from a clean one.
pub const NOTE_FINISHED: &str = "the tool ended";

/// What one tool run left behind, before it is made into a report.
#[derive(Debug, Clone)]
pub struct RunEnd {
    /// The final output bytes, or why there are none.
    pub outcome: Result<Vec<u8>, AgentRunError>,
    /// What the run used, as far as the adapter could tell.
    pub usage: Usage,
    /// Tool calls the tool reported as denied.
    pub denials: Vec<Denial>,
    /// How the process ended.
    pub exit: Option<ExitInfo>,
    /// Standard output of the tool, as the sandbox stored it.
    pub stdout: Vec<u8>,
    /// Standard error of the tool.
    pub stderr: Vec<u8>,
    /// A note for the transcript.
    pub note: String,
}

impl RunEnd {
    /// A run that ended in `error` before the tool printed anything.
    #[must_use]
    pub fn failed(error: AgentRunError, note: &str) -> Self {
        Self {
            outcome: Err(error),
            usage: Usage::default(),
            denials: Vec::new(),
            exit: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            note: note.to_owned(),
        }
    }
}

/// A report for a run that failed before the tool started: no transcript exists.
#[must_use]
pub fn early(error: AgentRunError, version: Option<String>) -> AgentRunReport {
    AgentRunReport {
        outcome: Err(error),
        transcript: None,
        usage: Usage::default(),
        runtime_version: version,
        exit: None,
        permission_denials: Vec::new(),
    }
}

/// The least the capture of standard output may be for a final output of `max_output_bytes`: the
/// output appears twice in a Claude Code stream (the last message and the result), and the stream
/// has events around it. Below this the result event could be cut off for a run that is within its
/// limits.
#[must_use]
pub fn capture_floor(max_output_bytes: u64) -> u64 {
    max_output_bytes.saturating_mul(2).saturating_add(64 * 1024)
}

/// The cost limit of a request in millionths of a dollar, rounded up.
#[must_use]
pub fn cost_limit_micro(req: &AgentRunRequest) -> u64 {
    let micro = (req.limits.max_cost_usd.as_f64() * 1_000_000.0).ceil();
    if micro.is_finite() && micro >= 0.0 {
        // The value is finite and not negative; the cast saturates at the top, which is the
        // right edge for a limit.
        micro as u64
    } else {
        0
    }
}

/// Makes the report. Order matters: the output is checked for size, then for the cost limit, then
/// redacted; the transcript is stored last so that it holds the whole story.
pub async fn assemble(
    io: &RunIo,
    version: Option<String>,
    req: &AgentRunRequest,
    end: RunEnd,
) -> AgentRunReport {
    let RunEnd {
        outcome,
        usage,
        denials,
        exit,
        stdout,
        stderr,
        note,
    } = end;
    let outcome = match outcome {
        Ok(bytes) => judge_output(io, req, &usage, without_fence(bytes)),
        Err(error) => Err(error),
    };
    let permission_denials = denials
        .into_iter()
        .map(|d| Denial {
            tool: io.redact_text(&d.tool),
            reason: io.redact_text(&d.reason),
        })
        .collect();
    let transcript = io.store_transcript(&stdout, &stderr, &note).await;
    AgentRunReport {
        outcome,
        transcript,
        usage,
        runtime_version: version,
        exit,
        permission_denials,
    }
}

/// The final message without a Markdown code fence around it.
///
/// The prompts ask for a bare JSON document as the final message. A model often wraps such a
/// document in a fence all the same, and a run that did the work should not fail on that. So one
/// fence is taken off when the whole message is exactly one fenced block: the first line is
/// ` ``` ` or ` ```json `, the last line is ` ``` `, and no line between them starts a fence.
/// Anything else is returned as it is, prose before or after the block included, and the engine's
/// validator refuses it. Nothing here parses the document or decides whether it is valid.
#[must_use]
pub fn without_fence(bytes: Vec<u8>) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return bytes;
    };
    let trimmed = text.trim();
    let Some((first, rest)) = trimmed.split_once('\n') else {
        return bytes;
    };
    let opens = matches!(first.trim_end(), "```" | "```json" | "```JSON");
    let Some(inner) = rest.strip_suffix("```") else {
        return bytes;
    };
    let inner_is_one_block = inner.ends_with('\n')
        && !inner
            .lines()
            .any(|line| line.trim_start().starts_with("```"));
    if opens && inner_is_one_block {
        inner.trim_end_matches(['\n', '\r']).as_bytes().to_vec()
    } else {
        bytes
    }
}

/// Size, then cost, then redaction of a final output.
fn judge_output(
    io: &RunIo,
    req: &AgentRunRequest,
    usage: &Usage,
    bytes: Vec<u8>,
) -> Result<RawOutput, AgentRunError> {
    if bytes.len() as u64 > req.max_output_bytes {
        return Err(AgentRunError::OutputTooLarge);
    }
    if usage.cost.0 > cost_limit_micro(req) {
        return Err(AgentRunError::BudgetRefused);
    }
    match io.redact(&bytes) {
        Some(clean) => Ok(RawOutput::new(clean)),
        None => {
            tracing::warn!("the final output was dropped because the redactor could not finish");
            Err(AgentRunError::OutputMissing)
        }
    }
}

/// What `exec` of the tool gave.
pub enum ExecEnd {
    /// The command ran to an end the sandbox reports.
    Finished {
        /// The result.
        result: Box<ExecResult>,
        /// Standard output.
        stdout: Vec<u8>,
        /// Standard error.
        stderr: Vec<u8>,
    },
    /// The sandbox could not run the command; this is the closed error for it.
    Failed(AgentRunError),
}

/// Runs the tool command through the session and reads its output. Standard input is the prompt.
pub async fn exec_tool(
    session: &mut dyn SandboxSession,
    io: &RunIo,
    argv: Vec<String>,
    stdin: Vec<u8>,
    timeout: Duration,
    max_output_bytes: u64,
    cancel: &dyn CancelSignal,
) -> ExecEnd {
    let Ok(argv) = ExecArgv::new(argv) else {
        return ExecEnd::Failed(AgentRunError::ProcessFailed(ExitInfo {
            code: None,
            signal: None,
        }));
    };
    let request = ExecRequest {
        argv,
        cwd: None,
        stdin: Some(stdin),
        timeout,
        max_output_bytes,
    };
    match session.exec(request, cancel).await {
        Ok(result) => {
            let stdout = io.read(&result.stdout).await.unwrap_or_else(|error| {
                tracing::warn!(?error, "the tool's standard output could not be read");
                Vec::new()
            });
            let stderr = io.read(&result.stderr).await.unwrap_or_default();
            ExecEnd::Finished {
                result: Box::new(result),
                stdout,
                stderr,
            }
        }
        Err(error) => ExecEnd::Failed(sandbox_error(&error)),
    }
}

/// Runs one preparation command (make the home directory, write the pinned skills). It must exit
/// with 0.
///
/// # Errors
/// The closed error: `Cancelled` and `Timeout` as the sandbox reports them, and `ProcessFailed`
/// with the exit information for anything else.
pub async fn exec_prep(
    session: &mut dyn SandboxSession,
    argv: Vec<String>,
    stdin: Option<Vec<u8>>,
    cancel: &dyn CancelSignal,
) -> Result<(), AgentRunError> {
    let argv = ExecArgv::new(argv).map_err(|_| {
        AgentRunError::ProcessFailed(ExitInfo {
            code: None,
            signal: None,
        })
    })?;
    let request = ExecRequest {
        argv,
        cwd: None,
        stdin,
        timeout: Duration::from_secs(30),
        max_output_bytes: 64 * 1024,
    };
    match session.exec(request, cancel).await {
        Ok(result) if result.exit_code == Some(0) && !result.timed_out => Ok(()),
        Ok(result) => Err(AgentRunError::ProcessFailed(exit_info(&result))),
        Err(error) => Err(sandbox_error(&error)),
    }
}

/// The closed error for a sandbox failure while the tool ran.
#[must_use]
pub fn sandbox_error(error: &SandboxError) -> AgentRunError {
    match error {
        SandboxError::Cancelled => AgentRunError::Cancelled,
        SandboxError::Timeout => AgentRunError::Timeout,
        _ => AgentRunError::ProcessFailed(ExitInfo {
            code: None,
            signal: None,
        }),
    }
}

/// How the process ended, as the port reports it.
#[must_use]
pub fn exit_info(result: &ExecResult) -> ExitInfo {
    ExitInfo {
        code: result.exit_code,
        signal: result.signal,
    }
}

/// `timeout` exits with 124 when it had to interrupt the tool, and with 137 when the tool also
/// ignored the interrupt and was killed. Both mean the soft deadline passed.
#[must_use]
pub fn soft_deadline_passed(result: &ExecResult) -> bool {
    result.exit_code == Some(124) || (result.exit_code == Some(137) && !result.oom_killed)
}

/// The usage with the cost taken from millionths of a dollar.
#[must_use]
pub fn usage_of(input_tokens: u64, output_tokens: u64, cost_micro: u64, requests: u64) -> Usage {
    Usage {
        input_tokens,
        output_tokens,
        cost: CostMicroUsd(cost_micro),
        requests,
    }
}

#[cfg(test)]
mod tests {
    use super::without_fence;

    fn unwrapped(text: &str) -> String {
        String::from_utf8(without_fence(text.as_bytes().to_vec())).expect("UTF-8")
    }

    #[test]
    fn a_bare_document_is_returned_byte_for_byte() {
        for text in ["{\"a\": 1}", "  {\"a\": 1}\n", "", "not json at all"] {
            assert_eq!(unwrapped(text), text);
        }
    }

    #[test]
    fn one_fence_around_the_whole_message_is_taken_off() {
        assert_eq!(unwrapped("```json\n{\"a\": 1}\n```"), "{\"a\": 1}");
        assert_eq!(
            unwrapped("```\n{\n  \"a\": 1\n}\n```\n"),
            "{\n  \"a\": 1\n}"
        );
        assert_eq!(
            unwrapped("\n```json  \r\n{\"a\": 1}\r\n```  \n"),
            "{\"a\": 1}"
        );
    }

    #[test]
    fn prose_around_a_fence_is_not_stripped_so_the_validator_refuses_it() {
        for text in [
            "Here is the report:\n```json\n{\"a\": 1}\n```",
            "```json\n{\"a\": 1}\n```\nDone.",
            "```json\n{\"a\": 1}\n```\n```json\n{\"b\": 2}\n```",
            "```python\n{\"a\": 1}\n```",
            "```json {\"a\": 1} ```",
            "```json\n{\"a\": 1}```",
        ] {
            assert_eq!(unwrapped(text), text, "{text:?}");
        }
    }

    #[test]
    fn bytes_that_are_not_text_are_left_alone() {
        let bytes = vec![0x60, 0x60, 0x60, 0x0a, 0xff, 0x0a, 0x60, 0x60, 0x60];
        assert_eq!(without_fence(bytes.clone()), bytes);
    }
}
