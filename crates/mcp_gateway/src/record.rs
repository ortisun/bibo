//! The record of a run: every call, in order, as a typed value and as canonical JSON for the
//! ledger.

use std::fmt;
use std::time::Duration;

use factory_domain::policy::troubleshooting::GatewayLimits;
use factory_domain::values::Sha256Digest;
use serde::{Serialize, Serializer};

use crate::upstream::UpstreamId;

/// What one run may do. Built from the policy with [`RunLimits::from_policy`]; a run may be
/// opened with tighter limits, never looser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RunLimits {
    /// Agent calls forwarded to an upstream in the run.
    pub max_calls_per_run: u32,
    /// Agent calls forwarded in any 10 seconds.
    pub max_calls_per_10s: u32,
    /// Bytes of one result returned, the truncation marker included.
    pub max_result_bytes: u64,
    /// The deadline of one call.
    #[serde(serialize_with = "millis", rename = "call_deadline_ms")]
    pub call_deadline: Duration,
    /// How long the run's token and calls are valid after the run opened.
    #[serde(serialize_with = "millis", rename = "run_wall_clock_ms")]
    pub run_wall_clock: Duration,
}

/// The smallest result cap a run may have, so a truncation marker always fits.
pub const MIN_RESULT_BYTES: u64 = 128;

fn millis<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(u64::try_from(value.as_millis()).unwrap_or(u64::MAX))
}

impl RunLimits {
    /// The policy's limits (`gateway` section of `policies/troubleshooting.yaml`).
    #[must_use]
    pub fn from_policy(limits: &GatewayLimits) -> Self {
        Self {
            max_calls_per_run: limits.max_calls_per_run,
            max_calls_per_10s: limits.max_calls_per_10s,
            max_result_bytes: limits.max_result_bytes,
            call_deadline: Duration::from_secs(limits.call_deadline_s),
            run_wall_clock: Duration::from_secs(limits.run_wall_clock_s),
        }
    }

    /// The names of the limits where `self` is looser than `ceiling`, or zero.
    #[must_use]
    pub fn problems_against(&self, ceiling: &Self) -> Vec<&'static str> {
        let mut found = Vec::new();
        if self.max_calls_per_run == 0 || self.max_calls_per_run > ceiling.max_calls_per_run {
            found.push("max_calls_per_run");
        }
        if self.max_calls_per_10s == 0 || self.max_calls_per_10s > ceiling.max_calls_per_10s {
            found.push("max_calls_per_10s");
        }
        if self.max_result_bytes < MIN_RESULT_BYTES
            || self.max_result_bytes > ceiling.max_result_bytes
        {
            found.push("max_result_bytes");
        }
        if self.call_deadline.is_zero() || self.call_deadline > ceiling.call_deadline {
            found.push("call_deadline");
        }
        if self.run_wall_clock.is_zero() || self.run_wall_clock > ceiling.run_wall_clock {
            found.push("run_wall_clock");
        }
        found
    }
}

/// Who made a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallOrigin {
    /// The agent, over the gateway's MCP server with the run token. Counted against the run's
    /// call limits.
    Agent,
    /// The troubleshooter itself ([`crate::Gateway::call_for_run`]), for the deterministic
    /// probes. Recorded with the same call ids; not counted against the agent's call limits.
    ControlPlane,
}

/// Why a call was refused before it reached an upstream (or, for redaction, before its result
/// reached the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The tool is not on the policy's allowlist.
    ToolNotAllowed,
    /// The tool is on the allowlist but its upstream does not offer it now (or is down).
    ToolUnavailable,
    /// The run made its last allowed call.
    MaxCallsPerRun,
    /// The run made its allowed calls in the last 10 seconds.
    MaxCallsPer10s,
    /// The run's wall clock ended.
    RunWallClock,
    /// The result could not be checked for secrets and was dropped.
    RedactionFailed,
}

impl RefusalReason {
    /// The reason as it appears in an outcome: `refused:<this>`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToolNotAllowed => "tool_not_allowed",
            Self::ToolUnavailable => "tool_unavailable",
            Self::MaxCallsPerRun => "max_calls_per_run",
            Self::MaxCallsPer10s => "max_calls_per_10s",
            Self::RunWallClock => "run_wall_clock",
            Self::RedactionFailed => "redaction_failed",
        }
    }

    /// A short sentence for the caller.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::ToolNotAllowed => "this tool is not offered by the gateway",
            Self::ToolUnavailable => "this tool's source does not offer it right now",
            Self::MaxCallsPerRun => "this run has made all the tool calls it may make",
            Self::MaxCallsPer10s => {
                "too many tool calls in the last 10 seconds; wait a few seconds and try again"
            }
            Self::RunWallClock => "this run's time is over",
            Self::RedactionFailed => "the result could not be checked for secrets and was dropped",
        }
    }
}

/// How a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The upstream answered with a result.
    Ok,
    /// The upstream answered that the tool failed.
    ToolError,
    /// The gateway refused the call.
    Refused(RefusalReason),
    /// The call passed its deadline.
    Timeout,
    /// The upstream did not complete the call (transport, protocol, not connected).
    UpstreamError,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::ToolError => f.write_str("tool_error"),
            Self::Refused(reason) => write!(f, "refused:{}", reason.as_str()),
            Self::Timeout => f.write_str("timeout"),
            Self::UpstreamError => f.write_str("upstream_error"),
        }
    }
}

impl Serialize for Outcome {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// A call id: `call-1`, `call-2`, ... in the order the gateway received the calls of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallId(u64);

impl CallId {
    pub(crate) const fn new(sequence: u64) -> Self {
        Self(sequence)
    }

    /// The position in the run, from 1.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "call-{}", self.0)
    }
}

impl Serialize for CallId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// One call of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallRecord {
    /// `call-N`.
    pub call_id: CallId,
    /// Who made it.
    pub origin: CallOrigin,
    /// The gateway tool name the caller used, as given (capped at 128 bytes).
    pub gateway_tool: String,
    /// The upstream, when the tool is on the allowlist.
    pub upstream: Option<UpstreamId>,
    /// The upstream tool, when the tool is on the allowlist.
    pub upstream_tool: Option<String>,
    /// SHA-256 of the RFC 8785 canonical JSON of the arguments (`{}` when there were none).
    pub arguments_sha256: Sha256Digest,
    /// When the gateway received the call, in milliseconds since the Unix epoch.
    pub started_at_unix_ms: u64,
    /// How long the call took in the gateway, in milliseconds.
    pub duration_ms: u64,
    /// Bytes of the redacted result before truncation.
    pub result_bytes: u64,
    /// Bytes of the result returned, the truncation marker included.
    pub returned_bytes: u64,
    /// How it ended.
    pub outcome: Outcome,
    /// SHA-256 of the text the caller received for this call (the result, or the reason it has
    /// none), not counting the `call_id` line. A quote from the call can be matched to it (TR-5).
    pub result_sha256: Sha256Digest,
}

/// An agent call the gateway refused before it reached an upstream (or past the record's cap).
/// A refusal has no call id and cannot be cited (TR-5): only calls that reached an upstream, and
/// every call of the control plane, have one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusalRecord {
    /// The gateway tool name the agent used, as given (capped at 128 bytes).
    pub gateway_tool: String,
    /// SHA-256 of the RFC 8785 canonical JSON of the arguments.
    pub arguments_sha256: Sha256Digest,
    /// When the gateway received the call, in milliseconds since the Unix epoch.
    pub at_unix_ms: u64,
    /// Why it was refused.
    #[serde(serialize_with = "reason_name")]
    pub reason: RefusalReason,
}

fn reason_name<S: Serializer>(value: &RefusalReason, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.as_str())
}

/// What a citation of a call id can be checked against: the call's origin, tool, outcome and the
/// digest of the text its caller received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Citation<'a> {
    /// The id.
    pub call_id: CallId,
    /// Who made the call. The agent's evidence may cite its own calls and the probes' calls.
    pub origin: CallOrigin,
    /// The gateway tool of the call, which a citation's `tool` must equal.
    pub gateway_tool: &'a str,
    /// How the call ended; only `ok` showed something to cite.
    pub outcome: Outcome,
    /// SHA-256 of the text the caller received.
    pub result_sha256: &'a Sha256Digest,
}

/// The record of one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunRecord {
    /// The run, as the troubleshooter named it.
    pub run_id: String,
    /// When the run opened, in milliseconds since the Unix epoch.
    pub opened_at_unix_ms: u64,
    /// Whether the run was closed.
    pub closed: bool,
    /// The run's limits.
    pub limits: RunLimits,
    /// Every recorded call, in call id order: each agent call that reached an upstream and every
    /// call of the control plane, refused or not.
    pub calls: Vec<CallRecord>,
    /// Calls refused without a record because the record reached its size cap.
    pub unrecorded_calls: u64,
    /// The agent calls refused before they reached an upstream, in the order received, at most
    /// [`crate::MAX_RECORDED_REFUSALS`]. They have no call id.
    pub refusals: Vec<RefusalRecord>,
    /// Agent refusals past [`crate::MAX_RECORDED_REFUSALS`], counted only.
    pub unrecorded_refusals: u64,
}

/// The record could not be written as canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the run record cannot be written as canonical JSON")]
pub struct RecordEncodingFailed;

impl RunRecord {
    /// The RFC 8785 canonical JSON of the record, for the artifact store and the ledger.
    ///
    /// # Errors
    /// [`RecordEncodingFailed`] if the record cannot be serialized.
    pub fn canonical_json(&self) -> Result<Vec<u8>, RecordEncodingFailed> {
        serde_jcs::to_vec(self).map_err(|_| RecordEncodingFailed)
    }

    /// SHA-256 of [`RunRecord::canonical_json`], the digest the ledger entry of the run carries.
    ///
    /// # Errors
    /// [`RecordEncodingFailed`] if the record cannot be serialized.
    pub fn digest(&self) -> Result<Sha256Digest, RecordEncodingFailed> {
        Ok(Sha256Digest::of(&self.canonical_json()?))
    }

    /// The call with this id, if the gateway recorded it for this run. The engine refuses a
    /// finding whose observation cites a call that is not here (ADR 0021, decision 7). A refused
    /// agent call is never here: it has no id.
    #[must_use]
    pub fn call(&self, call_id: &str) -> Option<&CallRecord> {
        self.calls
            .iter()
            .find(|call| call.call_id.to_string() == call_id)
    }

    /// What a citation of `call_id` can be checked against, if the gateway recorded the call for
    /// this run (TR-5): its origin, gateway tool, outcome and result digest. The caller checks
    /// that the tool is the one cited and that the outcome is `ok`, or uses
    /// [`RunRecord::evidence`], which does both.
    #[must_use]
    pub fn citable(&self, call_id: &str) -> Option<Citation<'_>> {
        self.call(call_id).map(|call| Citation {
            call_id: call.call_id,
            origin: call.origin,
            gateway_tool: &call.gateway_tool,
            outcome: call.outcome,
            result_sha256: &call.result_sha256,
        })
    }

    /// The call `call_id` when it may back an observation of `tool`: recorded for this run, a
    /// call of that gateway tool, and ended `ok`.
    #[must_use]
    pub fn evidence(&self, call_id: &str, tool: &str) -> Option<Citation<'_>> {
        self.citable(call_id)
            .filter(|citation| citation.outcome == Outcome::Ok && citation.gateway_tool == tool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_and_call_ids_have_their_wire_names() {
        assert_eq!(Outcome::Ok.to_string(), "ok");
        assert_eq!(Outcome::ToolError.to_string(), "tool_error");
        assert_eq!(
            Outcome::Refused(RefusalReason::MaxCallsPer10s).to_string(),
            "refused:max_calls_per_10s"
        );
        assert_eq!(Outcome::Timeout.to_string(), "timeout");
        assert_eq!(Outcome::UpstreamError.to_string(), "upstream_error");
        assert_eq!(CallId::new(7).to_string(), "call-7");
    }

    #[test]
    fn looser_or_zero_limits_are_named() {
        let ceiling = RunLimits {
            max_calls_per_run: 60,
            max_calls_per_10s: 40,
            max_result_bytes: 65_536,
            call_deadline: Duration::from_secs(20),
            run_wall_clock: Duration::from_secs(900),
        };
        assert!(ceiling.problems_against(&ceiling).is_empty());
        let looser = RunLimits {
            max_calls_per_run: 61,
            max_calls_per_10s: 0,
            max_result_bytes: 64,
            call_deadline: Duration::from_secs(21),
            run_wall_clock: Duration::ZERO,
        };
        assert_eq!(
            looser.problems_against(&ceiling),
            [
                "max_calls_per_run",
                "max_calls_per_10s",
                "max_result_bytes",
                "call_deadline",
                "run_wall_clock"
            ]
        );
    }
}
