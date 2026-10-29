//! The sandbox as a stage handler sees it: every sandbox it makes, every command it runs and every
//! sandbox it removes is a fact the audit log keeps.
//!
//! A handler never calls the provider itself. The engine hands it [`AuditedSandbox`], which does
//! what the provider does and writes down what the supervisor returned. The records are the two
//! types of `policies/security.yaml` (`audit.must_record`) that no stage can be trusted to write
//! for itself, because the stage is the thing the log is about:
//!
//! | Type | When | Decision |
//! |---|---|---|
//! | `sandbox_created_posture_result_destroyed` | the provider returned a session: the posture matched | `granted` |
//! | `sandbox_created_posture_result_destroyed` | the provider refused or failed: the posture did not match, or there was nothing to match | `denied` |
//! | `command_executed` | a command ran in the sandbox, or could not | `noted` |
//! | `sandbox_created_posture_result_destroyed` | the sandbox was removed | `ended` |
//!
//! # What a record holds
//!
//! The facts come from the results the supervisor returned and from nothing a tool printed. A
//! command is recorded by its program (the file name only, from a short list of characters) and
//! by how it ended: the exit code, the signal, whether it timed out, whether the kernel killed it
//! for memory, whether its output was cut, and how long it ran. Its arguments are not recorded:
//! the factory builds them, but they can carry a path or a value that came from a repository, and
//! the audit log is not the place for either. A posture that did not match lists the names of the
//! differing parts, which are fixed words of the port.
//!
//! # How many records
//!
//! One for each sandbox event and one for each command, up to [`MAX_COMMAND_RECORDS`] commands in
//! an attempt. A stage that runs more than that gets the first ones, one record that says how
//! many more ran, and no more rows: a handler in a loop cannot fill the log.
//!
//! The records are written with the result of the attempt (`Notes`), by the engine, with the
//! actor of the stage handler, the policy hash and the correlation id of the job.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{
    ExecRequest, ExecResult, PostureReport, SandboxError, SandboxId, SandboxProvider,
    SandboxSession, SandboxSpec, TeardownReason, TeardownReport,
};

use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::handlers::Notes;

/// The most commands of one attempt that get a record each.
pub(crate) const MAX_COMMAND_RECORDS: usize = 256;

/// A sandbox provider that writes down what it returned, and otherwise does what the provider it
/// wraps does.
pub(crate) struct AuditedSandbox<'a> {
    inner: &'a dyn SandboxProvider,
    notes: Notes,
    commands: Arc<AtomicUsize>,
}

impl<'a> AuditedSandbox<'a> {
    /// Wraps `inner` for the attempt whose notes these are.
    pub(crate) fn new(inner: &'a dyn SandboxProvider, notes: Notes) -> Self {
        Self {
            inner,
            notes,
            commands: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Writes the record that says how many commands ran past the limit, when some did. Called
    /// once, when the handler has stopped.
    pub(crate) fn finish(self) {
        let ran = self.commands.load(Ordering::Relaxed);
        if let Some(over) = ran
            .checked_sub(MAX_COMMAND_RECORDS)
            .filter(|over| *over > 0)
        {
            self.notes.note_fact(
                AuditAction::new(AuditKind::CommandExecuted, AuditDecision::Noted),
                format!(
                    "{over} more commands ran in this attempt; only the first {MAX_COMMAND_RECORDS} have a record each"
                ),
            );
        }
    }
}

#[async_trait]
impl SandboxProvider for AuditedSandbox<'_> {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn create_verified(
        &self,
        spec: SandboxSpec,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        let profile = spec.profile.as_str();
        match self.inner.create_verified(spec, cancel).await {
            Ok(session) => {
                self.notes.note_fact(
                    AuditAction::new(
                        AuditKind::SandboxCreatedPostureResultDestroyed,
                        AuditDecision::Granted,
                    ),
                    format!(
                        "sandbox created; its posture matched the spec and the policy; profile {profile}"
                    ),
                );
                Ok(Box::new(AuditedSession {
                    inner: session,
                    notes: self.notes.clone(),
                    commands: Arc::clone(&self.commands),
                }))
            }
            Err(error) => {
                self.notes.note_fact(
                    AuditAction::new(
                        AuditKind::SandboxCreatedPostureResultDestroyed,
                        AuditDecision::Denied,
                    ),
                    format!(
                        "sandbox not created; profile {profile}; {}",
                        refusal(&error)
                    ),
                );
                Err(error)
            }
        }
    }

    async fn sweep_orphans(
        &self,
        live: &[factory_domain::ids::AttemptId],
    ) -> Result<Vec<SandboxId>, SandboxError> {
        self.inner.sweep_orphans(live).await
    }
}

/// A session that writes down each command and its own removal.
struct AuditedSession {
    inner: Box<dyn SandboxSession>,
    notes: Notes,
    commands: Arc<AtomicUsize>,
}

#[async_trait]
impl SandboxSession for AuditedSession {
    fn id(&self) -> &SandboxId {
        self.inner.id()
    }

    fn posture(&self) -> &PostureReport {
        self.inner.posture()
    }

    async fn exec(
        &mut self,
        req: ExecRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<ExecResult, SandboxError> {
        let program = program_word(req.argv.program());
        let result = self.inner.exec(req, cancel).await;
        let seen = self.commands.fetch_add(1, Ordering::Relaxed);
        if seen < MAX_COMMAND_RECORDS {
            let reason = match &result {
                Ok(done) => format!("command ran; program {program}; {}", outcome(done)),
                Err(error) => format!(
                    "command did not complete; program {program}; {}",
                    refusal(error)
                ),
            };
            self.notes.note_fact(
                AuditAction::new(AuditKind::CommandExecuted, AuditDecision::Noted),
                reason,
            );
        }
        result
    }

    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        let this = *self;
        let result = this.inner.stop_and_remove(reason).await;
        let text = match &result {
            Ok(report) => format!(
                "sandbox destroyed; reason {}; killed for memory: {}",
                teardown_word(report.reason),
                yes_no(report.oom_killed)
            ),
            Err(error) => format!(
                "sandbox teardown reported a failure; reason {}; {}",
                teardown_word(reason),
                refusal(error)
            ),
        };
        this.notes.note_fact(
            AuditAction::new(
                AuditKind::SandboxCreatedPostureResultDestroyed,
                AuditDecision::Ended,
            ),
            text,
        );
        result
    }
}

/// How a command that ran ended, in words the log can hold.
fn outcome(done: &ExecResult) -> String {
    let code = done
        .exit_code
        .map_or_else(|| "exit none".to_owned(), |code| format!("exit {code}"));
    let signal = done.signal.map_or_else(
        || "no signal".to_owned(),
        |signal| format!("signal {signal}"),
    );
    let took = done
        .finished_at
        .duration_since(&done.started_at)
        .map_or_else(
            || "unknown time".to_owned(),
            |d| format!("{} ms", d.as_millis()),
        );
    format!(
        "{code}; {signal}; timed out: {}; killed for memory: {}; output cut: {}; {took}",
        yes_no(done.timed_out),
        yes_no(done.oom_killed),
        yes_no(done.stdout_truncated || done.stderr_truncated),
    )
}

/// Why a sandbox call failed, as a fixed phrase. The error of the port is a closed set; a
/// posture that differs lists the names of the parts, which are fixed words as well.
fn refusal(error: &SandboxError) -> String {
    match error {
        SandboxError::PolicyViolation(_) => "the spec is weaker than the policy".to_owned(),
        SandboxError::PostureMismatch(diff) => format!(
            "the posture check failed; {} parts differ: {}",
            diff.fields.len(),
            diff.fields.join(", ")
        ),
        SandboxError::ImageUnavailable => "the image is not on this host".to_owned(),
        SandboxError::DaemonUnavailable => "the container runtime is unavailable".to_owned(),
        SandboxError::ProvisionFailed(_) => "the sandbox could not be provisioned".to_owned(),
        SandboxError::Timeout => "the sandbox passed its wall-clock limit".to_owned(),
        SandboxError::ResourceExceeded(_) => "a resource limit was exceeded".to_owned(),
        SandboxError::Cancelled => "the call was cancelled".to_owned(),
        SandboxError::TeardownFailed { leaked } => {
            format!(
                "teardown failed; something may still run: {}",
                yes_no(*leaked)
            )
        }
    }
}

const fn teardown_word(reason: TeardownReason) -> &'static str {
    match reason {
        TeardownReason::Completed => "completed",
        TeardownReason::Failed => "failed",
        TeardownReason::Cancelled => "cancelled",
        TeardownReason::TimedOut => "timed out",
        TeardownReason::PostureMismatch => "posture mismatch",
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// The program as the log writes it: the file name, when it is made of the characters a program
/// name uses and is short; a fixed word otherwise. Nothing a repository chose is repeated.
fn program_word(program: &str) -> String {
    let name = program.rsplit('/').next().unwrap_or(program);
    let plain = !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'));
    if plain {
        name.to_owned()
    } else {
        "(other)".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_is_written_by_its_file_name_and_only_when_it_is_plain() {
        assert_eq!(program_word("git"), "git");
        assert_eq!(program_word("/usr/bin/cargo"), "cargo");
        assert_eq!(program_word("g++-14"), "g++-14");
        for odd in [
            "",
            "a b",
            "rm;id",
            "$(curl)",
            "naïve",
            "line\nbreak",
            &"x".repeat(49),
        ] {
            assert_eq!(program_word(odd), "(other)", "{odd:?}");
        }
    }

    #[test]
    fn every_refusal_is_a_fixed_phrase_and_a_posture_lists_its_parts() {
        let diff = factory_ports::sandbox::PostureDiff {
            fields: vec!["privileged", "network"],
        };
        let text = refusal(&SandboxError::PostureMismatch(diff));
        assert_eq!(
            text,
            "the posture check failed; 2 parts differ: privileged, network"
        );
        assert!(refusal(&SandboxError::DaemonUnavailable).contains("unavailable"));
    }
}
