//! When a stream that looks like a success is not accepted as one.
//!
//! The event stream of a tool is the standard output of a process chain inside the sandbox. Another
//! process of the sandbox may be able to write into it (findings SBX-4 and RR-14 of the security
//! reviews): the image closes the usual ways, and nothing here assumes it worked. The adapters
//! therefore accept a stream as a success only when all of this holds, and a stream that fails any
//! part of it is a failure with one fixed reason code:
//!
//! * the process ended cleanly (exit code 0, no signal);
//! * the capture was not cut at the output limit (`stream_truncated`): the end of the stream was
//!   never seen, so the one terminal event that was seen may be the only thing someone wrote;
//! * no line before the terminal event was unreadable (`malformed_line`): the tools write whole JSON
//!   objects, and a line torn in two by a write that was interleaved is how a forged line gets a
//!   clear way through (finding RR-7);
//! * exactly one terminal event (`second_terminal_event`);
//! * nothing after it (`output_after_terminal_event`);
//! * the model broker, outside the sandbox, saw the run end (`unattested_completion`,
//!   `claim_exceeds_ledger`; see [`crate::attest`]).
//!
//! A legitimate stream passes all of it. 97 recorded runs of the two tools hold one terminal event,
//! last, and no line that is not a JSON object.

use factory_ports::agent::AgentRunError;

/// Why a run that looks like a success was not accepted. The codes are fixed words: they are written
/// to the transcript note and to the log, and no text from the stream is part of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distrust {
    /// The capture of standard output stopped at the output limit.
    StreamTruncated,
    /// A line before the terminal event was not a JSON object.
    MalformedLine,
    /// More than one terminal event.
    SecondTerminalEvent,
    /// A line, of any kind, after the terminal event.
    OutputAfterTerminalEvent,
    /// The broker did not see this run end with a final end-of-turn answer.
    UnattestedCompletion,
    /// The stream claims more turns or tokens than the broker metered.
    ClaimExceedsLedger,
}

impl Distrust {
    /// The fixed reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StreamTruncated => "stream_truncated",
            Self::MalformedLine => "malformed_line",
            Self::SecondTerminalEvent => "second_terminal_event",
            Self::OutputAfterTerminalEvent => "output_after_terminal_event",
            Self::UnattestedCompletion => "unattested_completion",
            Self::ClaimExceedsLedger => "claim_exceeds_ledger",
        }
    }

    /// The closed error the report carries. A cut capture is `OutputTooLarge`, as it is on every
    /// other path; every other reason is "the tool produced no output the factory can accept".
    #[must_use]
    pub const fn error(self) -> AgentRunError {
        match self {
            Self::StreamTruncated => AgentRunError::OutputTooLarge,
            _ => AgentRunError::OutputMissing,
        }
    }
}

/// A failed run: the closed error and, when the run looked like a success, why it was not accepted.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejection {
    /// What the report carries.
    pub error: AgentRunError,
    /// The fixed reason, when the stream said "completed" and the rule refused it.
    pub distrust: Option<Distrust>,
}

impl From<AgentRunError> for Rejection {
    fn from(error: AgentRunError) -> Self {
        Self {
            error,
            distrust: None,
        }
    }
}

impl From<Distrust> for Rejection {
    fn from(distrust: Distrust) -> Self {
        Self {
            error: distrust.error(),
            distrust: Some(distrust),
        }
    }
}

/// What the shape of a stream says, read from the stream and from the sandbox's report of the
/// capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// How many terminal events the stream held.
    pub terminal_events: usize,
    /// Lines before the first terminal event that were not JSON objects.
    pub malformed_before: usize,
    /// Non-blank lines after the first terminal event, of any kind.
    pub lines_after: usize,
    /// The sandbox cut the capture at the output limit.
    pub truncated: bool,
}

/// The strict part of the success rule that reads the stream. In this order, so that a stream with
/// several faults always gets the same code: a cut capture, a torn or unreadable line, a second
/// terminal event, output after it.
///
/// # Errors
/// The [`Distrust`] reason.
pub fn check_shape(shape: &Shape) -> Result<(), Distrust> {
    if shape.truncated {
        Err(Distrust::StreamTruncated)
    } else if shape.malformed_before > 0 {
        Err(Distrust::MalformedLine)
    } else if shape.terminal_events > 1 {
        Err(Distrust::SecondTerminalEvent)
    } else if shape.lines_after > 0 {
        Err(Distrust::OutputAfterTerminalEvent)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean() -> Shape {
        Shape {
            terminal_events: 1,
            malformed_before: 0,
            lines_after: 0,
            truncated: false,
        }
    }

    #[test]
    fn a_clean_stream_passes() {
        assert_eq!(check_shape(&clean()), Ok(()));
    }

    #[test]
    fn each_fault_has_its_own_fixed_code() {
        let cases = [
            (
                Shape {
                    truncated: true,
                    ..clean()
                },
                Distrust::StreamTruncated,
                "stream_truncated",
            ),
            (
                Shape {
                    malformed_before: 1,
                    ..clean()
                },
                Distrust::MalformedLine,
                "malformed_line",
            ),
            (
                Shape {
                    terminal_events: 2,
                    ..clean()
                },
                Distrust::SecondTerminalEvent,
                "second_terminal_event",
            ),
            (
                Shape {
                    lines_after: 1,
                    ..clean()
                },
                Distrust::OutputAfterTerminalEvent,
                "output_after_terminal_event",
            ),
        ];
        for (shape, why, code) in cases {
            assert_eq!(check_shape(&shape), Err(why));
            assert_eq!(why.code(), code);
        }
    }

    #[test]
    fn several_faults_give_the_first_code_of_the_order() {
        let all = Shape {
            terminal_events: 3,
            malformed_before: 2,
            lines_after: 4,
            truncated: true,
        };
        assert_eq!(check_shape(&all), Err(Distrust::StreamTruncated));
        let torn_and_doubled = Shape {
            truncated: false,
            ..all
        };
        assert_eq!(check_shape(&torn_and_doubled), Err(Distrust::MalformedLine));
    }

    #[test]
    fn a_cut_capture_is_too_large_and_every_other_reason_is_no_output() {
        assert_eq!(
            Distrust::StreamTruncated.error(),
            AgentRunError::OutputTooLarge
        );
        for why in [
            Distrust::MalformedLine,
            Distrust::SecondTerminalEvent,
            Distrust::OutputAfterTerminalEvent,
            Distrust::UnattestedCompletion,
            Distrust::ClaimExceedsLedger,
        ] {
            assert_eq!(why.error(), AgentRunError::OutputMissing);
        }
    }

    #[test]
    fn the_codes_are_distinct_plain_words() {
        let codes: Vec<&str> = [
            Distrust::StreamTruncated,
            Distrust::MalformedLine,
            Distrust::SecondTerminalEvent,
            Distrust::OutputAfterTerminalEvent,
            Distrust::UnattestedCompletion,
            Distrust::ClaimExceedsLedger,
        ]
        .iter()
        .map(|d| d.code())
        .collect();
        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len());
        assert!(
            codes
                .iter()
                .all(|c| c.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'))
        );
    }
}
