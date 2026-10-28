//! The limits the broker enforces before it forwards a request, and the closed set of reasons it
//! gives when it refuses one.
//!
//! A cap is checked at admission, so a breach refuses the next request and nothing is sent to the
//! provider for it. The cost of a request is known only when its answer has been read, so the
//! request that crosses the ceiling is let through and the token is revoked in the same step
//! (NT-BUD-01: recorded cost is at most the ceiling plus the cost of the requests that were in
//! flight, and `max_in_flight` bounds those).

use std::fmt;

/// Why a token was revoked. The reason is kept with the token and written to the audit stream, so
/// "why did this job stop" has an answer that is not a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevokeReason {
    /// A caller revoked the token (`ModelBroker::revoke`).
    Requested,
    /// The job ended and every token of it was revoked (`ModelBroker::revoke_for_job`).
    JobEnded,
    /// The recorded cost reached the ceiling of the token.
    CostCeiling,
    /// The number of model requests reached the request (turn) cap.
    RequestCap,
    /// The input tokens reached the input token cap.
    InputTokenCap,
    /// The output tokens reached the output token cap.
    OutputTokenCap,
}

impl RevokeReason {
    /// The name used in audit lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::JobEnded => "job_ended",
            Self::CostCeiling => "cost_ceiling",
            Self::RequestCap => "request_cap",
            Self::InputTokenCap => "input_token_cap",
            Self::OutputTokenCap => "output_token_cap",
        }
    }

    /// True when a budget or a cap stopped the job, as opposed to a person or the end of the job.
    /// A budget stop is answered with 402 so Claude Code gives up at once; the supervisor then
    /// kills the container (docs/spikes/agent-runtime.md section 4.7).
    #[must_use]
    pub const fn is_budget_stop(self) -> bool {
        !matches!(self, Self::Requested | Self::JobEnded)
    }
}

/// Why the broker refused a request. The set is closed and carries no free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No token with that secret exists, or the credential was missing or malformed.
    UnknownToken,
    /// The token was revoked, for the reason inside.
    Revoked(RevokeReason),
    /// The token passed its expiry time.
    Expired,
    /// The token is valid, but not for this provider or not for this job.
    WrongAudience,
    /// The model is not in the token's list of allowed models.
    ModelNotAllowed,
    /// The price list has no price for the model, so its cost cannot be metered.
    PriceUnknown,
    /// Too many requests in the last minute. The caller may retry after the delay.
    RateLimited {
        /// How long to wait, in whole seconds, at least one.
        retry_after_secs: u64,
    },
    /// The token already has the largest number of requests in flight.
    TooManyInFlight,
}

impl Refusal {
    /// The name used in audit lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownToken => "unknown_token",
            Self::Revoked(_) => "revoked",
            Self::Expired => "expired",
            Self::WrongAudience => "wrong_audience",
            Self::ModelNotAllowed => "model_not_allowed",
            Self::PriceUnknown => "price_unknown",
            Self::RateLimited { .. } => "rate_limited",
            Self::TooManyInFlight => "too_many_in_flight",
        }
    }

    /// The HTTP status the listener answers with.
    ///
    /// 401 for a credential that does not work (Claude Code retries it ten times and Codex five),
    /// 402 for a budget stop (Claude Code stops at once), 403 for a valid credential used where
    /// it must not be, 429 for a rate limit.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::UnknownToken | Self::Expired => 401,
            Self::Revoked(reason) => {
                if reason.is_budget_stop() {
                    402
                } else {
                    401
                }
            }
            Self::WrongAudience | Self::ModelNotAllowed | Self::PriceUnknown => 403,
            Self::RateLimited { .. } | Self::TooManyInFlight => 429,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Limits on the size of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerRequestCaps {
    /// The largest request body the listener reads, in bytes.
    pub max_body_bytes: usize,
    /// The most input tokens one request is assumed to use when its answer cannot be read. The
    /// body limit is what actually bounds a request; this number prices the worst case.
    pub max_input_tokens: u64,
    /// The most output tokens one request may ask for. A request that asks for more is clamped to
    /// this number, and a request that asks for none is given this number.
    pub max_output_tokens: u64,
}

impl Default for PerRequestCaps {
    /// The values of `budgets.per_request_caps` in `policies/security.yaml`, and an 8 MiB body.
    fn default() -> Self {
        Self {
            max_body_bytes: 8 * 1024 * 1024,
            max_input_tokens: 200_000,
            max_output_tokens: 32_000,
        }
    }
}

/// The caps that apply to every token of a broker. The cost ceiling is not here: it belongs to
/// each token (`JobTokenRequest::cost_ceiling`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapPolicy {
    /// The most model requests one token may make (a turn cap by another name: Codex has none, so
    /// the broker counts). `None` means no cap.
    pub max_requests: Option<u64>,
    /// The most model requests in any 60 seconds. `None` means no cap.
    pub max_requests_per_minute: Option<u32>,
    /// The most input tokens one token may use. `None` means no cap.
    pub max_input_tokens: Option<u64>,
    /// The most output tokens one token may use. `None` means no cap.
    pub max_output_tokens: Option<u64>,
    /// The most requests of one token the broker forwards at the same time. It bounds how far the
    /// cost can pass the ceiling: by at most this many requests.
    pub max_in_flight: u32,
    /// The percentage of the ceiling at which the first audit event is written (the second is at
    /// 100). `budgets.thresholds.warn_at_fraction` is 0.8.
    pub warn_percent: u8,
    /// The limits on one request.
    pub per_request: PerRequestCaps,
}

impl Default for CapPolicy {
    fn default() -> Self {
        Self {
            max_requests: None,
            max_requests_per_minute: None,
            max_input_tokens: None,
            max_output_tokens: None,
            max_in_flight: 2,
            warn_percent: 80,
            per_request: PerRequestCaps::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_stop_answers_402_and_a_revoke_by_a_person_answers_401() {
        assert_eq!(
            Refusal::Revoked(RevokeReason::CostCeiling).http_status(),
            402
        );
        assert_eq!(
            Refusal::Revoked(RevokeReason::RequestCap).http_status(),
            402
        );
        assert_eq!(Refusal::Revoked(RevokeReason::Requested).http_status(), 401);
        assert_eq!(Refusal::Revoked(RevokeReason::JobEnded).http_status(), 401);
        assert_eq!(Refusal::UnknownToken.http_status(), 401);
        assert_eq!(Refusal::Expired.http_status(), 401);
        assert_eq!(Refusal::WrongAudience.http_status(), 403);
        assert_eq!(
            Refusal::RateLimited {
                retry_after_secs: 3
            }
            .http_status(),
            429
        );
    }

    #[test]
    fn the_default_per_request_caps_are_the_policy_numbers() {
        let caps = PerRequestCaps::default();
        assert_eq!(caps.max_input_tokens, 200_000);
        assert_eq!(caps.max_output_tokens, 32_000);
    }
}
