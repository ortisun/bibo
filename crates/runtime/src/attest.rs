//! The broker's word that a run ended, so that the stream is not the only authority for success
//! (finding RR-14 of `docs/reviews/isolation-core-security-rereview.md`, the part that does not
//! depend on a file mode).
//!
//! A process inside the sandbox can write to files and, however well the image closes the usual
//! ways, may sometimes write to a pipe it inherited. What it cannot do is change what the model
//! broker saw: the broker runs outside the sandbox, holds the provider keys, and forwards every
//! request of the job and reads every answer. So before the tool starts the adapter takes a
//! [`TurnSummary`] from the broker (the baseline), and after the tool ended it takes another. A run
//! that the stream calls "completed" is a success only when, between the two summaries:
//!
//! 1. no request was left in flight, at least one request was admitted and at least one answer was
//!    read to its end (the stream cannot have finished a run the broker never served);
//! 2. the most recent answer ended the turn (`EndTurn`). A tool result can reach the model only in
//!    a request, so the answer to the latest request is after every tool result: a run cut in the
//!    middle of a tool call, or whose last answer ran into the output limit or failed, is not a
//!    completed run whatever the stream says;
//! 3. the stream does not claim more than the broker metered: its message count is at most the
//!    answers the broker read (plus [`REQUEST_SLACK`]), and its input and output tokens are at most
//!    the broker's, plus [`TOKEN_TOLERANCE_PERCENT`] percent and [`TOKEN_TOLERANCE_ABSOLUTE`] tokens.
//!    The broker may meter more than the stream says (side requests of the tool), never less.
//!
//! A run that fails the first two is `unattested_completion`; one that fails the third is
//! `claim_exceeds_ledger`. Both end the run as `OutputMissing`, with the code in the transcript note
//! and the log.
//!
//! What this does not cover: the **content** of the final text. A process that can alter the stream
//! of a run that really ended can still replace the final text with its own. The broker could bind
//! the text (a digest of the last answer), but the tools reformat it (the result of Claude Code is a
//! concatenation, Codex trims) and a mismatch would fail runs that are fine; that binding is left
//! for the architect to weigh. What the attestation does remove is the cheaper attack, a forged
//! "completed" in a run that did not complete, and a run that never reached the model.

use std::sync::Arc;
use std::time::Duration;

use factory_ports::agent::{AnswerEnd, JobTokenId, TurnAttestation, TurnSummary};

use crate::report::{NOTE_FINISHED, RunEnd};
use crate::trust::Distrust;

/// How many more messages than the broker read answers the stream may name, for a request the tool
/// counted that never reached the broker (a connection that failed before it was sent).
pub const REQUEST_SLACK: u64 = 2;

/// The part of the broker's token count, in percent, that the stream's count may exceed.
pub const TOKEN_TOLERANCE_PERCENT: u64 = 10;

/// Tokens the stream's count may exceed the broker's by on top of the percentage, so that a small
/// run is not judged on a rounding.
pub const TOKEN_TOLERANCE_ABSOLUTE: u64 = 256;

/// How long a call to the broker may take. A broker that does not answer is a run that is not
/// attested.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// What the stream says the run used, as the adapter read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claim {
    /// The model answers the stream names: for Claude Code, the distinct provider messages; for
    /// Codex, the least the stream implies (one answer, and a second when a tool ran).
    pub turns: u64,
    /// Tokens sent, with cache reads and writes.
    pub input_tokens: u64,
    /// Tokens written.
    pub output_tokens: u64,
}

fn tolerance(base: u64) -> u64 {
    let percent = u128::from(base) * u128::from(TOKEN_TOLERANCE_PERCENT) / 100;
    u64::try_from(percent)
        .unwrap_or(u64::MAX)
        .saturating_add(TOKEN_TOLERANCE_ABSOLUTE)
}

/// The decision, as a pure function of the two summaries and the claim.
///
/// # Errors
/// The [`Distrust`] reason.
pub fn judge(before: &TurnSummary, after: &TurnSummary, claim: &Claim) -> Result<(), Distrust> {
    let answers = after.answers.saturating_sub(before.answers);
    let requests = after.usage.requests.saturating_sub(before.usage.requests);
    if after.in_flight != 0
        || requests == 0
        || answers == 0
        || after.last_answer != Some(AnswerEnd::EndTurn)
    {
        return Err(Distrust::UnattestedCompletion);
    }
    let input = after
        .usage
        .input_tokens
        .saturating_sub(before.usage.input_tokens);
    let output = after
        .usage
        .output_tokens
        .saturating_sub(before.usage.output_tokens);
    if claim.turns > answers.saturating_add(REQUEST_SLACK)
        || claim.input_tokens > input.saturating_add(tolerance(input))
        || claim.output_tokens > output.saturating_add(tolerance(output))
    {
        return Err(Distrust::ClaimExceedsLedger);
    }
    Ok(())
}

/// Asks the broker for the summaries and applies [`judge`].
#[derive(Clone)]
pub struct Attestor {
    source: Arc<dyn TurnAttestation>,
}

impl std::fmt::Debug for Attestor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attestor").finish_non_exhaustive()
    }
}

impl Attestor {
    /// An attestor that asks `source`: the real broker in production, a stand-in in tests.
    #[must_use]
    pub fn new(source: Arc<dyn TurnAttestation>) -> Self {
        Self { source }
    }

    /// The broker's summary of the token, or `None` when the broker cannot say.
    pub async fn summary(&self, token: &JobTokenId) -> Option<TurnSummary> {
        match tokio::time::timeout(CALL_TIMEOUT, self.source.turn_summary(token)).await {
            Ok(Ok(summary)) => Some(summary),
            Ok(Err(error)) => {
                tracing::warn!(?error, "the broker could not give the summary of the turns");
                None
            }
            Err(_) => {
                tracing::warn!("the broker did not answer for the summary of the turns in time");
                None
            }
        }
    }

    /// Judges a run that ended: the summary after it against the baseline from before it.
    ///
    /// # Errors
    /// The [`Distrust`] reason; a broker that cannot answer is `UnattestedCompletion`.
    pub async fn verdict(
        &self,
        token: &JobTokenId,
        before: &TurnSummary,
        claim: &Claim,
    ) -> Result<(), Distrust> {
        let Some(after) = self.summary(token).await else {
            return Err(Distrust::UnattestedCompletion);
        };
        judge(before, &after, claim)
    }

    /// Applies the broker's word to the end of a run. A run that already failed is returned as it
    /// is: there is nothing to attest and its error is the more useful one. A run that the stream
    /// calls a success becomes `OutputMissing`, with the fixed reason in the note, unless the
    /// broker confirms it.
    pub async fn require(
        &self,
        token: &JobTokenId,
        before: &TurnSummary,
        claim: &Claim,
        mut end: RunEnd,
    ) -> RunEnd {
        if end.outcome.is_err() {
            return end;
        }
        if let Err(why) = self.verdict(token, before, claim).await {
            tracing::warn!(
                reason = why.code(),
                "the stream says the run completed and the broker's record does not bear that out"
            );
            end.outcome = Err(why.error());
            end.note = rejected_note(why);
        }
        end
    }
}

/// The transcript note of a run that looked like a success and was not accepted.
#[must_use]
pub fn rejected_note(why: Distrust) -> String {
    format!("{}; not accepted: {}", NOTE_FINISHED, why.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_ports::agent::{CostMicroUsd, Usage};

    fn summary(requests: u64, answers: u64, input: u64, output: u64) -> TurnSummary {
        TurnSummary {
            usage: Usage {
                input_tokens: input,
                output_tokens: output,
                cost: CostMicroUsd(0),
                requests,
            },
            answers,
            last_answer: Some(AnswerEnd::EndTurn),
            in_flight: 0,
        }
    }

    fn claim(turns: u64, input: u64, output: u64) -> Claim {
        Claim {
            turns,
            input_tokens: input,
            output_tokens: output,
        }
    }

    #[test]
    fn a_run_the_broker_saw_end_is_attested() {
        let before = summary(0, 0, 0, 0);
        let after = summary(2, 2, 2660, 112);
        assert_eq!(judge(&before, &after, &claim(2, 2660, 112)), Ok(()));
    }

    #[test]
    fn the_broker_may_have_metered_more_than_the_stream_says() {
        let before = summary(0, 0, 0, 0);
        let after = summary(5, 5, 9000, 500);
        assert_eq!(judge(&before, &after, &claim(2, 2660, 112)), Ok(()));
    }

    #[test]
    fn a_stream_that_names_a_run_the_broker_never_served_is_unattested() {
        let before = summary(0, 0, 0, 0);
        assert_eq!(
            judge(&before, &before, &claim(1, 10, 1)),
            Err(Distrust::UnattestedCompletion)
        );
    }

    #[test]
    fn only_the_change_since_the_baseline_counts() {
        // The token served an earlier run; this run reached the broker not at all.
        let before = summary(4, 4, 5000, 400);
        assert_eq!(
            judge(&before, &before, &claim(1, 10, 1)),
            Err(Distrust::UnattestedCompletion)
        );
        // A request that was admitted and failed is not an answer.
        let failed = TurnSummary {
            usage: Usage {
                requests: 5,
                ..before.usage
            },
            last_answer: Some(AnswerEnd::Failed),
            ..before
        };
        assert_eq!(
            judge(&before, &failed, &claim(1, 10, 1)),
            Err(Distrust::UnattestedCompletion)
        );
    }

    #[test]
    fn a_last_answer_that_is_not_the_end_of_a_turn_is_unattested() {
        let before = summary(0, 0, 0, 0);
        for end in [AnswerEnd::ToolUse, AnswerEnd::Cut, AnswerEnd::Failed] {
            let after = TurnSummary {
                last_answer: Some(end),
                ..summary(2, 2, 2660, 112)
            };
            assert_eq!(
                judge(&before, &after, &claim(2, 2660, 112)),
                Err(Distrust::UnattestedCompletion),
                "{end:?}"
            );
        }
        let none = TurnSummary {
            last_answer: None,
            ..summary(2, 2, 2660, 112)
        };
        assert_eq!(
            judge(&before, &none, &claim(2, 2660, 112)),
            Err(Distrust::UnattestedCompletion)
        );
    }

    #[test]
    fn a_request_still_in_flight_is_unattested() {
        let before = summary(0, 0, 0, 0);
        let after = TurnSummary {
            in_flight: 1,
            ..summary(2, 2, 2660, 112)
        };
        assert_eq!(
            judge(&before, &after, &claim(2, 2660, 112)),
            Err(Distrust::UnattestedCompletion)
        );
    }

    #[test]
    fn a_stream_that_claims_more_than_the_ledger_is_refused() {
        let before = summary(0, 0, 0, 0);
        let after = summary(2, 2, 2660, 112);
        // More messages than the broker read answers, beyond the slack.
        assert_eq!(
            judge(&before, &after, &claim(2 + REQUEST_SLACK + 1, 2660, 112)),
            Err(Distrust::ClaimExceedsLedger)
        );
        // Within the slack.
        assert_eq!(
            judge(&before, &after, &claim(2 + REQUEST_SLACK, 2660, 112)),
            Ok(())
        );
        // Tokens: just inside and just outside the tolerance.
        let limit_in = 2660 + tolerance(2660);
        assert_eq!(judge(&before, &after, &claim(2, limit_in, 112)), Ok(()));
        assert_eq!(
            judge(&before, &after, &claim(2, limit_in + 1, 112)),
            Err(Distrust::ClaimExceedsLedger)
        );
        let limit_out = 112 + tolerance(112);
        assert_eq!(judge(&before, &after, &claim(2, 2660, limit_out)), Ok(()));
        assert_eq!(
            judge(&before, &after, &claim(2, 2660, limit_out + 1)),
            Err(Distrust::ClaimExceedsLedger)
        );
    }

    #[test]
    fn the_tolerance_is_ten_percent_and_256_tokens() {
        assert_eq!(tolerance(0), 256);
        assert_eq!(tolerance(1000), 356);
        assert_eq!(tolerance(u64::MAX), u64::MAX / 10 + 256);
    }

    #[test]
    fn a_counter_that_went_backwards_is_unattested_and_cannot_overflow() {
        let before = summary(9, 9, 9000, 900);
        let after = summary(1, 1, 10, 1);
        assert_eq!(
            judge(&before, &after, &claim(1, 10, 1)),
            Err(Distrust::UnattestedCompletion)
        );
        let huge = summary(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(
            judge(
                &summary(0, 0, 0, 0),
                &huge,
                &claim(u64::MAX, u64::MAX, u64::MAX)
            ),
            Ok(())
        );
    }
}
