//! Sending a request with back-off, and turning a failed answer into the closed error set of the
//! ports.
//!
//! * A rate-limit answer (403 or 429 with `Retry-After`, or `x-ratelimit-remaining: 0` with
//!   `x-ratelimit-reset`, or a body that names a rate limit or abuse detection) is retried after
//!   the wait the headers give, when that wait is short. A longer wait is not slept: the call
//!   returns `RateLimited` with the wait, and the engine schedules a later try.
//! * A 5xx answer to a read is retried a few times with a doubling pause. A write that got no
//!   answer is not retried here; the idempotency of each write is handled by its own method.
//!
//! UNVERIFIED against the real GitHub: the exact wording of the secondary rate limit message and
//! whether it ever comes without `Retry-After`. The code treats a rate limit it cannot time as a
//! 60 second wait, which is what GitHub's guidance says.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_ports::clock::Clock;
use factory_ports::githost::{GitHostError, Rejection};
use serde_json::Value;

use crate::wire::{Method, Transport, WireRequest, WireResponse};

/// Waits. A seam so that the tests record the wait and do not sleep.
#[async_trait]
pub trait Sleeper: Send + Sync {
    /// Waits for `duration`.
    async fn sleep(&self, duration: Duration);
}

/// Sleeps on the tokio timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSleeper;

#[async_trait]
impl Sleeper for TokioSleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// How the adapter backs off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// How many times one call is retried.
    pub max_retries: u32,
    /// The longest wait the adapter sleeps through. A longer wait is returned to the caller.
    pub max_wait: Duration,
    /// The pause before the first retry of a failed read. It doubles on each retry.
    pub first_pause: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            max_wait: Duration::from_secs(10),
            first_pause: Duration::from_millis(250),
        }
    }
}

/// The wait applied when GitHub names a rate limit and gives no time.
const UNTIMED_WAIT: Duration = Duration::from_secs(60);

/// The longest wait ever reported, whatever the header says.
const WAIT_CEILING: Duration = Duration::from_secs(3600);

/// Sends requests to the transport with the back-off above.
pub(crate) struct HttpCore {
    transport: Arc<dyn Transport>,
    sleeper: Arc<dyn Sleeper>,
    clock: Arc<dyn Clock>,
    backoff: BackoffPolicy,
}

impl HttpCore {
    pub(crate) fn new(
        transport: Arc<dyn Transport>,
        sleeper: Arc<dyn Sleeper>,
        clock: Arc<dyn Clock>,
        backoff: BackoffPolicy,
    ) -> Self {
        Self {
            transport,
            sleeper,
            clock,
            backoff,
        }
    }

    /// Sends the request and returns the final answer, whatever its status. An answer that is a
    /// rate limit after the retries becomes `RateLimited`; a transport failure becomes
    /// `Unavailable`.
    pub(crate) async fn send(&self, request: WireRequest) -> Result<WireResponse, GitHostError> {
        let mut attempt = 0_u32;
        loop {
            let response = self
                .transport
                .execute(request.clone())
                .await
                .map_err(|_| GitHostError::Unavailable)?;
            if let Some(wait) = rate_limit_wait(&response, &self.clock.now()) {
                if attempt < self.backoff.max_retries && wait <= self.backoff.max_wait {
                    self.sleeper.sleep(wait).await;
                    attempt += 1;
                    continue;
                }
                return Err(GitHostError::RateLimited {
                    retry_after: Some(wait),
                });
            }
            if response.status >= 500
                && request.method == Method::Get
                && attempt < self.backoff.max_retries
            {
                let pause = self
                    .backoff
                    .first_pause
                    .saturating_mul(2_u32.saturating_pow(attempt));
                self.sleeper.sleep(pause).await;
                attempt += 1;
                continue;
            }
            return Ok(response);
        }
    }
}

/// How long to wait when the answer is a rate limit, and `None` when it is not one.
pub(crate) fn rate_limit_wait(response: &WireResponse, now: &Timestamp) -> Option<Duration> {
    if response.status != 403 && response.status != 429 {
        return None;
    }
    let seconds = |name: &str| {
        response
            .header(name)
            .and_then(|v| v.trim().parse::<u64>().ok())
    };
    let mentions_a_limit = {
        let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        text.contains("rate limit") || text.contains("abuse detection")
    };
    let wait = if let Some(retry_after) = seconds("retry-after") {
        Duration::from_secs(retry_after.max(1))
    } else if seconds("x-ratelimit-remaining") == Some(0) {
        match seconds("x-ratelimit-reset").and_then(|reset| {
            u64::try_from(now.unix_seconds())
                .ok()
                .map(|n| reset.saturating_sub(n))
        }) {
            Some(until) => Duration::from_secs(until.saturating_add(1)),
            None => UNTIMED_WAIT,
        }
    } else if mentions_a_limit || response.status == 429 {
        UNTIMED_WAIT
    } else {
        return None;
    };
    Some(wait.min(WAIT_CEILING))
}

/// The error of the ports for an answer that is not a success.
pub(crate) fn error_for(response: &WireResponse) -> GitHostError {
    match response.status {
        401 => GitHostError::Unauthorized,
        403 => GitHostError::Forbidden,
        404 | 410 | 301 | 302 | 307 | 308 => GitHostError::NotFound,
        409 => GitHostError::Conflict,
        422 => GitHostError::Rejected(classify_rejection(&response.body)),
        429 => GitHostError::RateLimited { retry_after: None },
        500..=599 => GitHostError::Unavailable,
        _ => GitHostError::Rejected(Rejection::Other),
    }
}

/// Why a 422 answer rejected the request, from the validation errors GitHub lists.
fn classify_rejection(body: &[u8]) -> Rejection {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Rejection::Other;
    };
    let mut text = value["message"].as_str().unwrap_or_default().to_owned();
    let mut head_invalid = false;
    let mut text_field = false;
    for error in value["errors"].as_array().into_iter().flatten() {
        if let Some(message) = error["message"].as_str() {
            text.push(' ');
            text.push_str(message);
        }
        match error["field"].as_str() {
            Some("head") => head_invalid = true,
            Some("title" | "body") => text_field = true,
            _ => {}
        }
    }
    if text.contains("No commits between") {
        Rejection::NoDifference
    } else if head_invalid {
        Rejection::HeadNotPushed
    } else if text_field {
        Rejection::TextBounds
    } else {
        Rejection::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> WireResponse {
        WireResponse {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn now() -> Timestamp {
        Timestamp::parse("2026-10-28T10:00:00Z").unwrap()
    }

    #[test]
    fn retry_after_sets_the_wait() {
        let r = response(429, &[("retry-after", "7")], "");
        assert_eq!(rate_limit_wait(&r, &now()), Some(Duration::from_secs(7)));
        let r = response(403, &[("retry-after", "0")], "secondary rate limit");
        assert_eq!(rate_limit_wait(&r, &now()), Some(Duration::from_secs(1)));
    }

    #[test]
    fn an_exhausted_primary_limit_waits_until_the_reset_time() {
        // now is 1793181600
        let r = response(
            403,
            &[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset", "1793181650"),
            ],
            "API rate limit exceeded",
        );
        assert_eq!(rate_limit_wait(&r, &now()), Some(Duration::from_secs(51)));
        let past = response(
            403,
            &[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset", "1793181000"),
            ],
            "",
        );
        assert_eq!(rate_limit_wait(&past, &now()), Some(Duration::from_secs(1)));
    }

    #[test]
    fn a_limit_with_no_timing_waits_one_minute_and_the_wait_has_a_ceiling() {
        let r = response(403, &[], "You have exceeded a secondary rate limit.");
        assert_eq!(rate_limit_wait(&r, &now()), Some(UNTIMED_WAIT));
        let huge = response(429, &[("retry-after", "999999")], "");
        assert_eq!(rate_limit_wait(&huge, &now()), Some(WAIT_CEILING));
    }

    #[test]
    fn a_plain_403_and_other_statuses_are_not_rate_limits() {
        assert_eq!(
            rate_limit_wait(
                &response(403, &[], "Resource not accessible by integration"),
                &now()
            ),
            None
        );
        assert_eq!(
            rate_limit_wait(&response(404, &[("retry-after", "5")], ""), &now()),
            None
        );
        assert_eq!(rate_limit_wait(&response(200, &[], ""), &now()), None);
        let with_remaining = response(403, &[("x-ratelimit-remaining", "4999")], "Forbidden");
        assert_eq!(rate_limit_wait(&with_remaining, &now()), None);
    }

    #[test]
    fn statuses_map_to_the_closed_error_set() {
        let cases = [
            (401, GitHostError::Unauthorized),
            (403, GitHostError::Forbidden),
            (404, GitHostError::NotFound),
            (409, GitHostError::Conflict),
            (301, GitHostError::NotFound),
            (502, GitHostError::Unavailable),
            (418, GitHostError::Rejected(Rejection::Other)),
        ];
        for (status, expected) in cases {
            assert_eq!(error_for(&response(status, &[], "")), expected, "{status}");
        }
    }

    #[test]
    fn a_422_is_classified_from_its_validation_errors() {
        let head = r#"{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"head","code":"invalid"}]}"#;
        assert_eq!(
            error_for(&response(422, &[], head)),
            GitHostError::Rejected(Rejection::HeadNotPushed)
        );
        let none = r#"{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"No commits between main and x"}]}"#;
        assert_eq!(
            error_for(&response(422, &[], none)),
            GitHostError::Rejected(Rejection::NoDifference)
        );
        let title = r#"{"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"title","code":"missing_field"}]}"#;
        assert_eq!(
            error_for(&response(422, &[], title)),
            GitHostError::Rejected(Rejection::TextBounds)
        );
        assert_eq!(
            error_for(&response(422, &[], "not json")),
            GitHostError::Rejected(Rejection::Other)
        );
    }
}
