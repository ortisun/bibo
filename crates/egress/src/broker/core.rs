//! The broker core: tokens, caps, metering and the per-job ledger, with no I/O.
//!
//! Everything here is a function of its inputs and of the injected clock, id generator, random
//! source, price list and audit sink. The HTTP listener (`crate::http`) and the contract suite
//! both drive the same type, so the rules a test proves are the rules the listener enforces.
//!
//! # What a request goes through
//!
//! 1. [`BrokerCore::authorize`] looks the presented credential up by hash and checks, in this
//!    order: the token exists, is not revoked, has not expired, is valid for this provider (and
//!    this job, when the listener is bound to one), allows this model, has a price, is under the
//!    ceiling and the request, token and in-flight caps, and is under the rate limit. A refusal
//!    is a [`Refusal`] and sends nothing to a provider. An admission counts the request at once,
//!    so a request that fails at the provider, or whose answer cannot be read, still counts
//!    (NT-BUD-07, NT-BUD-08).
//! 2. The caller forwards the request and reads the answer, then settles the [`Permit`] with
//!    what it used. A permit that is dropped without settling is charged the worst case for one
//!    request, so abandoning a request is never cheaper than finishing it.
//! 3. Settling adds the usage, writes the 80 and 100 percent audit events once each, and revokes
//!    the token in the same step when the cost reaches the ceiling or a token cap.
//!
//! # Settling after a revoke
//!
//! [`MeteringOps::record_usage`] refuses spend under a revoked or expired token, as the port
//! says. A permit that was admitted before the revoke is different: the provider has already
//! been called, the money is spent, and the ledger must show it. [`Permit::settle`] therefore
//! records the usage whatever the token's state now is, and never makes a revoked token active.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::{
    AnswerEnd, BrokerError, CostMicroUsd, InvalidTokenRequest, IssuedJobToken, JobTokenId,
    JobTokenRequest, JobTokenSecret, MeteringOps, ModelBroker, ModelSelection, TokenState,
    TokenUsage, TurnAttestation, TurnSummary, Usage,
};
use factory_ports::clock::{Clock, IdGenerator, duration_between, timestamp_after};

use super::audit::{AuditEvent, AuditKind, AuditSink};
use super::caps::{CapPolicy, Refusal, RevokeReason};
use super::pricing::{PriceList, TokenCounts};
use super::provider::Provider;
use super::shape::Violation;
use super::token::{TokenEntropy, TokenHash, has_token_shape, mint_secret};

/// The most ledger entries kept for one job. Older entries are dropped; the totals stay exact.
const LEDGER_LIMIT: usize = 4096;

/// The length of the window of the per-minute rate limit.
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// A boxed, sendable future, as `#[async_trait]` returns. The `async-trait` crate is not on the
/// `egress` entry of the dependency rules, so the port traits are implemented with the signatures
/// the macro would write, as the runtime and sandbox crates do.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the broker is built from.
pub struct BrokerParts {
    /// The clock. A production run refuses a clock that reports `fake`.
    pub clock: Arc<dyn Clock>,
    /// Makes the token identifiers.
    pub ids: Arc<dyn IdGenerator>,
    /// The random source of the token secrets.
    pub entropy: Arc<dyn TokenEntropy>,
    /// The prices.
    pub prices: Arc<dyn PriceList>,
    /// The caps that apply to every token.
    pub caps: CapPolicy,
    /// Where audit events go.
    pub audit: Arc<dyn AuditSink>,
}

/// What a request asks for, as far as the core needs to know.
#[derive(Debug, Clone, Copy)]
pub struct RequestFacts<'a> {
    /// The provider the route belongs to.
    pub provider: Provider,
    /// The model named in the request body.
    pub model: &'a str,
    /// The job this listener serves, when it serves one. A token of another job is refused.
    pub expected_job: Option<JobId>,
}

/// Who a valid credential belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenView {
    /// The token.
    pub id: JobTokenId,
    /// Its job.
    pub job: JobId,
    /// Its tenant.
    pub tenant: TenantId,
    /// Its stage.
    pub stage: StageKind,
}

/// What an admitted request turned out to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The answer reported these token counts.
    Counted(TokenCounts),
    /// The provider answered with an error, or could not be reached, and nothing was billed as
    /// far as the broker can tell. The request still counts as a request.
    NoCharge,
    /// The request was forwarded, but the usage could not be read: the stream ended early, the
    /// client went away, or the answer had no usage in it. The broker charges the worst case for
    /// one request.
    Unreadable,
}

/// One entry of a job's ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// When it happened.
    pub at: Timestamp,
    /// The token it happened to.
    pub token: JobTokenId,
    /// What happened.
    pub kind: LedgerKind,
}

/// What a ledger entry records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerKind {
    /// A token was issued.
    Issued,
    /// A request was admitted.
    Admitted {
        /// Its provider.
        provider: Provider,
    },
    /// A request was settled.
    Settled {
        /// What it added.
        added: Usage,
        /// False when the worst case was charged because the usage could not be read.
        usage_read: bool,
    },
    /// A request was refused, and why. This is the record that says why a job stopped.
    Refused(Refusal),
    /// The token was revoked, and why.
    Revoked(RevokeReason),
    /// The cost crossed this percentage of the ceiling.
    Threshold(u8),
}

/// What a job has used across all of its tokens, and what happened to them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JobLedger {
    /// The sum of the usage of every token of the job, including tokens that were revoked.
    pub total: Usage,
    /// The most recent entries, oldest first.
    pub entries: Vec<LedgerEntry>,
}

#[derive(Debug)]
struct Record {
    tenant: TenantId,
    job: JobId,
    stage: StageKind,
    ceiling: CostMicroUsd,
    models: Vec<ModelSelection>,
    providers: Vec<Provider>,
    expires_at: Timestamp,
    usage: Usage,
    revoked: Option<RevokeReason>,
    warned: bool,
    hundred: bool,
    in_flight: u32,
    admissions: VecDeque<Timestamp>,
    /// Model answers read to their end, and how the most recently settled one ended. They are the
    /// broker's own record of the turns of the token (`TurnAttestation`).
    answers: u64,
    last_answer: Option<AnswerEnd>,
}

impl Record {
    fn state(&self, now: &Timestamp) -> TokenState {
        if self.revoked.is_some() {
            TokenState::Revoked
        } else if *now >= self.expires_at {
            TokenState::Expired
        } else {
            TokenState::Active
        }
    }

    fn allows(&self, provider: Provider, model: &str) -> bool {
        self.models.iter().any(|m| {
            Provider::for_runtime(&m.runtime) == Some(provider) && m.model.as_str() == model
        })
    }
}

#[derive(Debug, Default)]
struct Ledger {
    total: Usage,
    entries: VecDeque<LedgerEntry>,
}

impl Ledger {
    fn push(&mut self, entry: LedgerEntry) {
        if self.entries.len() >= LEDGER_LIMIT {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }
}

#[derive(Debug, Default)]
struct State {
    tokens: HashMap<JobTokenId, Record>,
    by_hash: HashMap<TokenHash, JobTokenId>,
    by_job: HashMap<JobId, Vec<JobTokenId>>,
    ledgers: HashMap<JobId, Ledger>,
}

/// The pure broker. Build one with [`BrokerCore::new`] and share it behind the `Arc`.
pub struct BrokerCore {
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    entropy: Arc<dyn TokenEntropy>,
    prices: Arc<dyn PriceList>,
    caps: CapPolicy,
    audit: Arc<dyn AuditSink>,
    state: Mutex<State>,
}

impl BrokerCore {
    /// Builds a broker.
    #[must_use]
    pub fn new(parts: BrokerParts) -> Arc<Self> {
        Arc::new(Self {
            clock: parts.clock,
            ids: parts.ids,
            entropy: parts.entropy,
            prices: parts.prices,
            caps: parts.caps,
            audit: parts.audit,
            state: Mutex::new(State::default()),
        })
    }

    /// The caps in force.
    #[must_use]
    pub fn caps(&self) -> &CapPolicy {
        &self.caps
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while the lock was held cannot leave the state half-written in a way that makes
        // a refusal into an admission: every update below is a field set after its checks.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn emit(&self, now: Timestamp, kinds: Vec<AuditKind>) {
        for kind in kinds {
            self.audit.record(AuditEvent { at: now, kind });
        }
    }

    // ---- issuing, revoking and reading -------------------------------------------------------

    /// Issues a token. See `ModelBroker::issue`.
    ///
    /// # Errors
    /// [`BrokerError::InvalidRequest`] for a zero ceiling, no models or a zero lifetime, and
    /// [`BrokerError::Unavailable`] when the random source fails.
    pub fn issue_token(&self, req: JobTokenRequest) -> Result<IssuedJobToken, BrokerError> {
        if req.cost_ceiling == CostMicroUsd(0) {
            return Err(BrokerError::InvalidRequest(
                InvalidTokenRequest::ZeroCeiling,
            ));
        }
        if req.allowed_models.is_empty() {
            return Err(BrokerError::InvalidRequest(InvalidTokenRequest::NoModels));
        }
        if req.ttl == Duration::ZERO {
            return Err(BrokerError::InvalidRequest(InvalidTokenRequest::ZeroTtl));
        }
        let secret = mint_secret(self.entropy.as_ref()).map_err(|_| BrokerError::Unavailable)?;
        let id = JobTokenId::from_uuid(self.ids.new_uuid());
        let now = self.clock.now();
        let expires_at = timestamp_after(&now, req.ttl);
        let mut providers: Vec<Provider> = req
            .allowed_models
            .iter()
            .filter_map(|m| Provider::for_runtime(&m.runtime))
            .collect();
        providers.sort();
        providers.dedup();
        {
            let mut state = self.lock();
            // Only the hash of the secret is stored. The secret itself leaves in the return value.
            state.by_hash.insert(TokenHash::of(&secret), id);
            state.by_job.entry(req.job).or_default().push(id);
            state.tokens.insert(
                id,
                Record {
                    tenant: req.tenant,
                    job: req.job,
                    stage: req.stage,
                    ceiling: req.cost_ceiling,
                    models: req.allowed_models.clone(),
                    providers,
                    expires_at,
                    usage: Usage::default(),
                    revoked: None,
                    warned: false,
                    hundred: false,
                    in_flight: 0,
                    admissions: VecDeque::new(),
                    answers: 0,
                    last_answer: None,
                },
            );
            state.ledgers.entry(req.job).or_default().push(LedgerEntry {
                at: now,
                token: id,
                kind: LedgerKind::Issued,
            });
        }
        self.emit(
            now,
            vec![AuditKind::TokenIssued {
                token: id,
                tenant: req.tenant,
                job: req.job,
                stage: req.stage,
                ceiling: req.cost_ceiling,
            }],
        );
        Ok(IssuedJobToken {
            id,
            secret: JobTokenSecret::new(secret),
            expires_at,
        })
    }

    /// Revokes a token. Idempotent; a token that was never issued is not an error.
    pub fn revoke_token(&self, token: &JobTokenId) {
        let now = self.clock.now();
        let mut events = Vec::new();
        {
            let mut state = self.lock();
            revoke_in(&mut state, token, RevokeReason::Requested, now, &mut events);
        }
        self.emit(now, events);
    }

    /// Revokes every token of a job. Idempotent.
    pub fn revoke_job(&self, job: JobId) {
        let now = self.clock.now();
        let mut events = Vec::new();
        {
            let mut state = self.lock();
            let ids = state.by_job.get(&job).cloned().unwrap_or_default();
            for id in ids {
                revoke_in(&mut state, &id, RevokeReason::JobEnded, now, &mut events);
            }
        }
        self.emit(now, events);
    }

    /// What a token has used and where it stands.
    ///
    /// # Errors
    /// [`BrokerError::UnknownToken`] when the broker never issued it.
    pub fn token_usage(&self, token: &JobTokenId) -> Result<TokenUsage, BrokerError> {
        let now = self.clock.now();
        let state = self.lock();
        let record = state.tokens.get(token).ok_or(BrokerError::UnknownToken)?;
        Ok(TokenUsage {
            usage: record.usage,
            ceiling: record.ceiling,
            state: record.state(&now),
        })
    }

    /// What the broker saw of the turns of a token: the usage it metered, how many answers it read to
    /// their end, how the latest one ended, and how many requests are still open. See
    /// [`TurnAttestation`].
    ///
    /// # Errors
    /// [`BrokerError::UnknownToken`] when the broker never issued it.
    pub fn turn_summary_of(&self, token: &JobTokenId) -> Result<TurnSummary, BrokerError> {
        let state = self.lock();
        let record = state.tokens.get(token).ok_or(BrokerError::UnknownToken)?;
        Ok(TurnSummary {
            usage: record.usage,
            answers: record.answers,
            last_answer: record.last_answer,
            in_flight: record.in_flight,
        })
    }

    /// Why a token was revoked, when it was.
    #[must_use]
    pub fn revoke_reason(&self, token: &JobTokenId) -> Option<RevokeReason> {
        self.lock().tokens.get(token).and_then(|r| r.revoked)
    }

    /// The ledger of a job: what it used across its tokens and what happened to them.
    #[must_use]
    pub fn ledger(&self, job: JobId) -> JobLedger {
        let state = self.lock();
        match state.ledgers.get(&job) {
            Some(ledger) => JobLedger {
                total: ledger.total,
                entries: ledger.entries.iter().cloned().collect(),
            },
            None => JobLedger::default(),
        }
    }

    // ---- metering ----------------------------------------------------------------------------

    /// Adds spend reported through [`MeteringOps`]. Refused with [`BrokerError::UnknownToken`]
    /// when the token is unknown, revoked or expired.
    ///
    /// # Errors
    /// [`BrokerError::UnknownToken`].
    pub fn add_usage(&self, token: &JobTokenId, delta: Usage) -> Result<TokenUsage, BrokerError> {
        let now = self.clock.now();
        let mut events = Vec::new();
        let result = {
            let mut state = self.lock();
            let Some(record) = state.tokens.get(token) else {
                return Err(BrokerError::UnknownToken);
            };
            if record.state(&now) != TokenState::Active {
                return Err(BrokerError::UnknownToken);
            }
            apply_usage(&mut state, token, delta, &self.caps, now, &mut events);
            state.tokens.get(token).map(|r| TokenUsage {
                usage: r.usage,
                ceiling: r.ceiling,
                state: r.state(&now),
            })
        };
        self.emit(now, events);
        result.ok_or(BrokerError::UnknownToken)
    }

    // ---- admission ---------------------------------------------------------------------------

    /// Says who a credential belongs to without admitting a request. Used for routes that cost
    /// nothing (the model list).
    ///
    /// # Errors
    /// The [`Refusal`] that applies to the credential.
    pub fn authenticate(
        &self,
        presented: &str,
        expected_job: Option<JobId>,
    ) -> Result<TokenView, Refusal> {
        let now = self.clock.now();
        let result = {
            let mut state = self.lock();
            check_credential(&mut state, presented, expected_job, now)
        };
        match result {
            Ok((_, view)) => Ok(view),
            Err((token, reason)) => {
                self.emit(now, vec![AuditKind::RequestRefused { token, reason }]);
                Err(reason)
            }
        }
    }

    /// Records that a request was refused for what its body or headers hold (see
    /// [`crate::broker::shape`]) and returns the refusal to answer with. The request is not
    /// admitted and does not count against the token's caps, because nothing is sent to a
    /// provider for it. The audit line and the ledger entry name the class and nothing else.
    ///
    /// A credential that is not valid gets the refusal it deserves instead, so that this method
    /// cannot be used to learn anything about a token.
    pub fn refuse_request_shape(
        &self,
        presented: &str,
        expected_job: Option<JobId>,
        violation: Violation,
    ) -> Refusal {
        let now = self.clock.now();
        let (token, reason) = {
            let mut state = self.lock();
            match check_credential(&mut state, presented, expected_job, now) {
                Ok((id, view)) => {
                    let reason = Refusal::RequestShape(violation);
                    record_refusal(&mut state, &view, id, reason, now);
                    (Some(id), reason)
                }
                Err((token, reason)) => (token, reason),
            }
        };
        self.emit(now, vec![AuditKind::RequestRefused { token, reason }]);
        reason
    }

    /// Checks a request and, when every check passes, admits it and counts it.
    ///
    /// # Errors
    /// The [`Refusal`] that applies. A cap breach also revokes the token, so that the supervisor
    /// sees the stop in `ModelBroker::usage`.
    pub fn authorize(
        self: &Arc<Self>,
        presented: &str,
        facts: &RequestFacts<'_>,
    ) -> Result<Permit, Refusal> {
        let now = self.clock.now();
        let mut events = Vec::new();
        let result = {
            let mut state = self.lock();
            self.admit_locked(&mut state, presented, facts, now, &mut events)
        };
        let outcome = match result {
            Ok((id, job)) => {
                events.push(AuditKind::RequestAdmitted {
                    token: id,
                    job,
                    provider: facts.provider,
                });
                Ok(Permit {
                    core: Arc::clone(self),
                    token: id,
                    job,
                    provider: facts.provider,
                    model: facts.model.to_owned(),
                    settled: false,
                    turn: false,
                })
            }
            Err((token, reason)) => {
                events.push(AuditKind::RequestRefused { token, reason });
                Err(reason)
            }
        };
        self.emit(now, events);
        outcome
    }

    fn admit_locked(
        &self,
        state: &mut State,
        presented: &str,
        facts: &RequestFacts<'_>,
        now: Timestamp,
        events: &mut Vec<AuditKind>,
    ) -> Result<(JobTokenId, JobId), (Option<JobTokenId>, Refusal)> {
        let (id, view) = check_credential(state, presented, facts.expected_job, now)?;
        let (audience_ok, model_ok, usage, ceiling, in_flight) = {
            let record = state.tokens.get(&id).ok_or((None, Refusal::UnknownToken))?;
            (
                record.providers.contains(&facts.provider),
                record.allows(facts.provider, facts.model),
                record.usage,
                record.ceiling,
                record.in_flight,
            )
        };
        let refuse = |state: &mut State, reason: Refusal| {
            record_refusal(state, &view, id, reason, now);
            (Some(id), reason)
        };
        if !audience_ok {
            return Err(refuse(state, Refusal::WrongAudience));
        }
        if !model_ok {
            return Err(refuse(state, Refusal::ModelNotAllowed));
        }
        if self
            .prices
            .cost(facts.provider, facts.model, &TokenCounts::default())
            .is_none()
        {
            return Err(refuse(state, Refusal::PriceUnknown));
        }
        // Caps. A breach revokes the token and refuses this request: the NEXT request after the
        // one that reached the cap, and every request after it.
        let breach = if usage.cost >= ceiling {
            Some(RevokeReason::CostCeiling)
        } else if self
            .caps
            .max_requests
            .is_some_and(|max| usage.requests >= max)
        {
            Some(RevokeReason::RequestCap)
        } else if self
            .caps
            .max_input_tokens
            .is_some_and(|max| usage.input_tokens >= max)
        {
            Some(RevokeReason::InputTokenCap)
        } else if self
            .caps
            .max_output_tokens
            .is_some_and(|max| usage.output_tokens >= max)
        {
            Some(RevokeReason::OutputTokenCap)
        } else {
            None
        };
        if let Some(reason) = breach {
            revoke_in(state, &id, reason, now, events);
            return Err(refuse(state, Refusal::Revoked(reason)));
        }
        if in_flight >= self.caps.max_in_flight {
            return Err(refuse(state, Refusal::TooManyInFlight));
        }
        if let Some(limit) = self.caps.max_requests_per_minute {
            let limited = {
                let record = state
                    .tokens
                    .get_mut(&id)
                    .ok_or((None, Refusal::UnknownToken))?;
                while record.admissions.front().is_some_and(|oldest| {
                    duration_between(oldest, &now).is_some_and(|age| age >= RATE_WINDOW)
                }) {
                    record.admissions.pop_front();
                }
                if record.admissions.len() >= usize::try_from(limit).unwrap_or(usize::MAX) {
                    let wait = record
                        .admissions
                        .front()
                        .and_then(|oldest| duration_between(oldest, &now))
                        .map_or(RATE_WINDOW, |age| RATE_WINDOW.saturating_sub(age));
                    Some(wait.as_secs().saturating_add(1))
                } else {
                    None
                }
            };
            if let Some(retry_after_secs) = limited {
                return Err(refuse(state, Refusal::RateLimited { retry_after_secs }));
            }
        }
        let record = state
            .tokens
            .get_mut(&id)
            .ok_or((None, Refusal::UnknownToken))?;
        record.usage.requests = record.usage.requests.saturating_add(1);
        record.in_flight = record.in_flight.saturating_add(1);
        record.admissions.push_back(now);
        let job = record.job;
        if let Some(ledger) = state.ledgers.get_mut(&job) {
            ledger.total.requests = ledger.total.requests.saturating_add(1);
            ledger.push(LedgerEntry {
                at: now,
                token: id,
                kind: LedgerKind::Admitted {
                    provider: facts.provider,
                },
            });
        }
        Ok((id, job))
    }

    /// The usage to charge when a forwarded request's answer could not be read: the worst case
    /// for one request, so that abandoning or truncating a request is never cheaper than
    /// finishing it.
    fn worst_case(&self, provider: Provider, model: &str, ceiling: CostMicroUsd) -> Usage {
        let per_request = self.caps.per_request;
        let counts = TokenCounts {
            // The cache-write price is the highest input price, so it bounds the input cost.
            cache_write: per_request.max_input_tokens,
            output: per_request.max_output_tokens,
            ..TokenCounts::default()
        };
        let cost = self
            .prices
            .cost(provider, model, &counts)
            .unwrap_or(ceiling);
        Usage {
            input_tokens: per_request.max_input_tokens,
            output_tokens: per_request.max_output_tokens,
            cost,
            requests: 0,
        }
    }

    fn settle(
        &self,
        token: JobTokenId,
        provider: Provider,
        model: &str,
        outcome: Outcome,
        end: Option<AnswerEnd>,
    ) -> Usage {
        let now = self.clock.now();
        let mut events = Vec::new();
        let added = {
            let mut state = self.lock();
            let Some(record) = state.tokens.get_mut(&token) else {
                return Usage::default();
            };
            record.in_flight = record.in_flight.saturating_sub(1);
            let ceiling = record.ceiling;
            let job = record.job;
            let (added, usage_read) = match outcome {
                Outcome::NoCharge => (Usage::default(), true),
                Outcome::Counted(counts) => match self.prices.cost(provider, model, &counts) {
                    Some(cost) => (
                        Usage {
                            input_tokens: counts.total_input(),
                            output_tokens: counts.output,
                            cost,
                            requests: 0,
                        },
                        true,
                    ),
                    None => (self.worst_case(provider, model, ceiling), false),
                },
                Outcome::Unreadable => (self.worst_case(provider, model, ceiling), false),
            };
            apply_usage(&mut state, &token, added, &self.caps, now, &mut events);
            if let (Some(end), Some(record)) = (end, state.tokens.get_mut(&token)) {
                // Only a model request that was forwarded settles with an end; a count-tokens
                // call or a refused request leaves the record of the turns alone.
                record.last_answer = Some(end);
                if end != AnswerEnd::Failed {
                    record.answers = record.answers.saturating_add(1);
                }
            }
            if let Some(ledger) = state.ledgers.get_mut(&job) {
                ledger.push(LedgerEntry {
                    at: now,
                    token,
                    kind: LedgerKind::Settled { added, usage_read },
                });
            }
            events.push(AuditKind::RequestSettled {
                token,
                job,
                added,
                usage_read,
            });
            added
        };
        self.emit(now, events);
        added
    }
}

/// Looks a credential up and checks the parts of it that do not depend on the request. On a
/// refusal the first part of the error is the token, when the credential matched one.
fn check_credential(
    state: &mut State,
    presented: &str,
    expected_job: Option<JobId>,
    now: Timestamp,
) -> Result<(JobTokenId, TokenView), (Option<JobTokenId>, Refusal)> {
    if !has_token_shape(presented) {
        return Err((None, Refusal::UnknownToken));
    }
    let id = *state
        .by_hash
        .get(&TokenHash::of(presented))
        .ok_or((None, Refusal::UnknownToken))?;
    let record = state.tokens.get(&id).ok_or((None, Refusal::UnknownToken))?;
    let view = TokenView {
        id,
        job: record.job,
        tenant: record.tenant,
        stage: record.stage,
    };
    let refusal = if let Some(reason) = record.revoked {
        Some(Refusal::Revoked(reason))
    } else if record.state(&now) == TokenState::Expired {
        Some(Refusal::Expired)
    } else if expected_job.is_some_and(|job| job != record.job) {
        Some(Refusal::WrongAudience)
    } else {
        None
    };
    match refusal {
        Some(reason) => {
            record_refusal(state, &view, id, reason, now);
            Err((Some(id), reason))
        }
        None => Ok((id, view)),
    }
}

fn record_refusal(
    state: &mut State,
    view: &TokenView,
    token: JobTokenId,
    reason: Refusal,
    now: Timestamp,
) {
    if let Some(ledger) = state.ledgers.get_mut(&view.job) {
        ledger.push(LedgerEntry {
            at: now,
            token,
            kind: LedgerKind::Refused(reason),
        });
    }
}

fn revoke_in(
    state: &mut State,
    token: &JobTokenId,
    reason: RevokeReason,
    now: Timestamp,
    events: &mut Vec<AuditKind>,
) {
    let Some(record) = state.tokens.get_mut(token) else {
        return;
    };
    if record.revoked.is_some() {
        return;
    }
    record.revoked = Some(reason);
    let job = record.job;
    if let Some(ledger) = state.ledgers.get_mut(&job) {
        ledger.push(LedgerEntry {
            at: now,
            token: *token,
            kind: LedgerKind::Revoked(reason),
        });
    }
    events.push(AuditKind::TokenRevoked {
        token: *token,
        job,
        reason,
    });
}

/// Adds usage to a token and its job, writes the threshold events and revokes at the ceiling or
/// a token cap. It does not look at the token's state: callers decide whether spend is allowed.
fn apply_usage(
    state: &mut State,
    token: &JobTokenId,
    delta: Usage,
    caps: &CapPolicy,
    now: Timestamp,
    events: &mut Vec<AuditKind>,
) {
    let Some(record) = state.tokens.get_mut(token) else {
        return;
    };
    record.usage = record.usage.saturating_add(delta);
    let job = record.job;
    let cost = record.usage.cost;
    let ceiling = record.ceiling;
    let percent_reached =
        u128::from(cost.0) * 100 >= u128::from(ceiling.0) * u128::from(caps.warn_percent);
    let mut thresholds = Vec::new();
    if percent_reached && !record.warned {
        record.warned = true;
        thresholds.push(caps.warn_percent);
    }
    let at_ceiling = cost >= ceiling;
    if at_ceiling && !record.hundred {
        record.hundred = true;
        thresholds.push(100);
    }
    let input_cap = caps
        .max_input_tokens
        .is_some_and(|max| record.usage.input_tokens >= max);
    let output_cap = caps
        .max_output_tokens
        .is_some_and(|max| record.usage.output_tokens >= max);
    if let Some(ledger) = state.ledgers.get_mut(&job) {
        ledger.total = ledger.total.saturating_add(delta);
        for percent in &thresholds {
            ledger.push(LedgerEntry {
                at: now,
                token: *token,
                kind: LedgerKind::Threshold(*percent),
            });
        }
    }
    for percent in thresholds {
        events.push(AuditKind::BudgetThreshold {
            token: *token,
            job,
            percent,
            cost,
            ceiling,
        });
    }
    if at_ceiling {
        revoke_in(state, token, RevokeReason::CostCeiling, now, events);
    } else if input_cap {
        revoke_in(state, token, RevokeReason::InputTokenCap, now, events);
    } else if output_cap {
        revoke_in(state, token, RevokeReason::OutputTokenCap, now, events);
    }
}

/// Permission to forward one request. Settle it with what the request used. A permit that is
/// dropped without being settled is charged the worst case for one request.
pub struct Permit {
    core: Arc<BrokerCore>,
    token: JobTokenId,
    job: JobId,
    provider: Provider,
    model: String,
    settled: bool,
    /// True for a model request (a turn of the conversation). Its settlement records how the
    /// answer ended; a permit for another route (count tokens) records nothing about the turns.
    turn: bool,
}

impl Permit {
    /// The token the request was admitted under.
    #[must_use]
    pub fn token(&self) -> JobTokenId {
        self.token
    }

    /// The job of the token.
    #[must_use]
    pub fn job(&self) -> JobId {
        self.job
    }

    /// The provider the request goes to.
    #[must_use]
    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// The model the request names.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The most output tokens a request may ask for.
    #[must_use]
    pub fn max_output_tokens(&self) -> u64 {
        self.core.caps.per_request.max_output_tokens
    }

    /// Marks the request as a turn of the model conversation, so that its settlement is recorded
    /// as an answer of the token ([`TurnAttestation`]). The listener does this for the model
    /// routes. A turn settled without an end counts as `Failed`.
    #[must_use]
    pub fn for_turn(mut self) -> Self {
        self.turn = true;
        self
    }

    /// Records what the request used and releases the in-flight slot. Returns what was added.
    pub fn settle(self, outcome: Outcome) -> Usage {
        self.settle_with_end(outcome, AnswerEnd::Failed)
    }

    /// Like [`settle`](Self::settle), and for a turn records how the answer ended.
    pub fn settle_with_end(mut self, outcome: Outcome, end: AnswerEnd) -> Usage {
        self.settled = true;
        let end = self.turn.then_some(end);
        self.core
            .settle(self.token, self.provider, &self.model, outcome, end)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if !self.settled {
            let end = self.turn.then_some(AnswerEnd::Failed);
            self.core.settle(
                self.token,
                self.provider,
                &self.model,
                Outcome::Unreadable,
                end,
            );
        }
    }
}

impl std::fmt::Debug for Permit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permit")
            .field("token", &self.token)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl ModelBroker for BrokerCore {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn issue<'life0, 'async_trait>(
        &'life0 self,
        req: JobTokenRequest,
    ) -> BoxFuture<'async_trait, Result<IssuedJobToken, BrokerError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.issue_token(req) })
    }

    fn revoke<'life0, 'life1, 'async_trait>(
        &'life0 self,
        token: &'life1 JobTokenId,
    ) -> BoxFuture<'async_trait, Result<(), BrokerError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.revoke_token(token);
            Ok(())
        })
    }

    fn revoke_for_job<'life0, 'async_trait>(
        &'life0 self,
        job: JobId,
    ) -> BoxFuture<'async_trait, Result<(), BrokerError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.revoke_job(job);
            Ok(())
        })
    }

    fn usage<'life0, 'life1, 'async_trait>(
        &'life0 self,
        token: &'life1 JobTokenId,
    ) -> BoxFuture<'async_trait, Result<TokenUsage, BrokerError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.token_usage(token) })
    }
}

impl TurnAttestation for BrokerCore {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn turn_summary<'life0, 'life1, 'async_trait>(
        &'life0 self,
        token: &'life1 JobTokenId,
    ) -> BoxFuture<'async_trait, Result<TurnSummary, BrokerError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.turn_summary_of(token) })
    }
}

impl MeteringOps for BrokerCore {
    fn record_usage<'life0, 'life1, 'async_trait>(
        &'life0 self,
        token: &'life1 JobTokenId,
        delta: Usage,
    ) -> BoxFuture<'async_trait, Result<TokenUsage, BrokerError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.add_usage(token, delta) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::audit::NullAudit;
    use crate::broker::pricing::PriceTable;
    use crate::broker::token::SystemEntropy;
    use factory_ports::agent::RuntimeId;
    use factory_ports::clock::Uuid;
    use factory_testkit::clock::{FakeClock, SequentialIdGenerator};

    #[test]
    fn the_stored_state_holds_a_hash_and_never_the_secret() {
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new());
        let core = BrokerCore::new(BrokerParts {
            clock,
            ids: Arc::new(SequentialIdGenerator::new()),
            entropy: Arc::new(SystemEntropy),
            prices: Arc::new(PriceTable::new()),
            caps: CapPolicy::default(),
            audit: Arc::new(NullAudit),
        });
        let issued = core
            .issue_token(JobTokenRequest {
                tenant: TenantId::from_uuid(Uuid::from_u128(1)),
                job: JobId::from_uuid(Uuid::from_u128(2)),
                stage: StageKind::Implementation,
                cost_ceiling: CostMicroUsd(1_000),
                allowed_models: vec![ModelSelection {
                    runtime: RuntimeId::new("claude-code-cli").expect("a slug"),
                    model: factory_domain::values::NonEmptyString::parse("m").expect("a name"),
                }],
                ttl: Duration::from_secs(60),
            })
            .expect("a token");
        let everything = format!("{:?}", *core.lock());
        let secret = issued.secret.expose();
        assert!(
            !everything.contains(secret),
            "the secret is stored in clear"
        );
        assert!(
            !everything.contains(&secret[super::super::token::TOKEN_PREFIX.len()..]),
            "the secret's random part is stored in clear"
        );
    }
}
