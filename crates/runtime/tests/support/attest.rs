//! A stand-in for the model broker's record of the turns of a job, **labelled fake**.
//!
//! The adapters ask it twice per run: for the baseline before the tool starts and for the summary
//! after it ended. The script says what each answer is. The default, [`ScriptedAttestation::generous`],
//! is a broker that saw a long run end well: it attests whatever the stream says, so the tests that
//! are about something else (arguments, probes, failures) keep their meaning. A test of the
//! attestation itself scripts the answers it needs.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AnswerEnd, BrokerError, CostMicroUsd, JobTokenId, TurnAttestation, TurnSummary, Usage,
};

/// What a call answers.
#[derive(Debug, Clone, Copy)]
pub enum Answer {
    /// This summary.
    Summary(TurnSummary),
    /// The broker cannot be reached.
    Unavailable,
    /// The broker never issued the token.
    Unknown,
}

/// A summary of nothing: no request, no answer.
pub fn nothing() -> TurnSummary {
    TurnSummary {
        usage: Usage::default(),
        answers: 0,
        last_answer: None,
        in_flight: 0,
    }
}

/// A summary of a run that ended its turn: `answers` answers, the given tokens.
pub fn ended(answers: u64, input_tokens: u64, output_tokens: u64) -> TurnSummary {
    TurnSummary {
        usage: Usage {
            input_tokens,
            output_tokens,
            cost: CostMicroUsd(0),
            requests: answers,
        },
        answers,
        last_answer: Some(AnswerEnd::EndTurn),
        in_flight: 0,
    }
}

/// The attestation: the first call answers `first` (the baseline), every later call `later`.
pub struct ScriptedAttestation {
    /// A broker that serves a long run of requests: every call finds more answers and more tokens
    /// than the one before, so that any two calls bracket a run that ended well.
    growing: bool,
    first: Answer,
    /// The answers after the first, in order; the last one repeats.
    later: Mutex<Vec<Answer>>,
    calls: AtomicUsize,
    tokens: Mutex<Vec<JobTokenId>>,
}

impl ScriptedAttestation {
    /// A broker that attests any run, however many runs share it: every call finds a thousand more
    /// answers and a million million more tokens than the call before, ending its turn.
    pub fn generous() -> Self {
        Self {
            growing: true,
            ..Self::new(Answer::Summary(nothing()), Answer::Summary(nothing()))
        }
    }

    /// A baseline and an answer after the run.
    pub fn new(first: Answer, later: Answer) -> Self {
        Self::sequence(first, vec![later])
    }

    /// A baseline, then these answers in order (the last one repeats).
    pub fn sequence(first: Answer, later: Vec<Answer>) -> Self {
        assert!(!later.is_empty());
        Self {
            growing: false,
            first,
            later: Mutex::new(later),
            calls: AtomicUsize::new(0),
            tokens: Mutex::new(Vec::new()),
        }
    }

    /// Nothing before, `after` after.
    pub fn after(after: TurnSummary) -> Self {
        Self::new(Answer::Summary(nothing()), Answer::Summary(after))
    }

    /// How many times the adapter asked.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The tokens the adapter asked about.
    pub fn tokens(&self) -> Vec<JobTokenId> {
        self.tokens.lock().expect("lock").clone()
    }
}

#[async_trait]
impl TurnAttestation for ScriptedAttestation {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn turn_summary(&self, token: &JobTokenId) -> Result<TurnSummary, BrokerError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.tokens.lock().expect("lock").push(*token);
        if self.growing {
            let n = call as u64;
            return Ok(ended(
                n * 1_000,
                n * 1_000_000_000_000,
                n * 1_000_000_000_000,
            ));
        }
        let answer = if call == 0 {
            self.first
        } else {
            let later = self.later.lock().expect("lock");
            later[(call - 1).min(later.len() - 1)]
        };
        match answer {
            Answer::Summary(summary) => Ok(summary),
            Answer::Unavailable => Err(BrokerError::Unavailable),
            Answer::Unknown => Err(BrokerError::UnknownToken),
        }
    }
}
