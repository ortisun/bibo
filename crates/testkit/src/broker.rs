//! An in-memory model broker.
//!
//! It issues tokens bound to a tenant, job and stage with a cost ceiling and a lifetime, meters
//! the requests that [`FakeModelBroker::meter`] receives (the stand-in for the sidecar's traffic),
//! revokes a token when it reaches its ceiling or when asked, and lets a token expire. It holds no
//! provider key and forwards nothing: it is a ledger of what a real broker would have allowed.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    BrokerError, CostMicroUsd, IssuedJobToken, JobTokenId, JobTokenRequest, JobTokenSecret,
    ModelBroker, TokenState, TokenUsage, Usage,
};
use factory_ports::clock::{Clock, IdGenerator, timestamp_after};

use crate::clock::{FakeClock, SequentialIdGenerator};
use crate::contracts::broker::{BrokerSubject, Spend};
use crate::fixtures::Ids;

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerDefect {
    /// `issue` accepts any request.
    IssuesWithoutValidation,
    /// A token that reaches its ceiling stays active.
    NeverRevokesAtCeiling,
    /// A revoked token still accepts requests.
    RevokeKeepsSpending,
    /// Revoking a token that is already revoked is an error.
    RevokeFailsTwice,
    /// A token never expires.
    ForgetsExpiry,
    /// Every token shares one usage counter.
    SharedMeter,
    /// Revoking one token revokes them all.
    RevokesEveryone,
}

struct Record {
    request: JobTokenRequest,
    usage: Usage,
    revoked: bool,
    expires_at: Timestamp,
}

/// An in-memory broker. Reports fidelity `fake`.
pub struct FakeModelBroker {
    clock: Arc<FakeClock>,
    ids: Arc<dyn IdGenerator>,
    tokens: Mutex<BTreeMap<JobTokenId, Record>>,
    shared_usage: Mutex<Usage>,
    defect: Option<BrokerDefect>,
}

impl FakeModelBroker {
    /// A broker that reads time from `clock` and makes token ids with `ids`.
    #[must_use]
    pub fn new(clock: Arc<FakeClock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self {
            clock,
            ids,
            tokens: Mutex::new(BTreeMap::new()),
            shared_usage: Mutex::new(Usage::default()),
            defect: None,
        }
    }

    /// A broker that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(
        clock: Arc<FakeClock>,
        ids: Arc<dyn IdGenerator>,
        defect: BrokerDefect,
    ) -> Self {
        Self {
            defect: Some(defect),
            ..Self::new(clock, ids)
        }
    }

    fn has(&self, defect: BrokerDefect) -> bool {
        self.defect == Some(defect)
    }

    fn state_of(&self, record: &Record) -> TokenState {
        if record.revoked {
            TokenState::Revoked
        } else if !self.has(BrokerDefect::ForgetsExpiry) && self.clock.now() >= record.expires_at {
            TokenState::Expired
        } else {
            TokenState::Active
        }
    }

    /// Passes one metered request through the broker, as the per-job sidecar would. A request is
    /// forwarded while the token is active. A request that takes the total to the ceiling is
    /// forwarded too (its cost was unknown in advance) and then revokes the token.
    pub fn meter(&self, token: &JobTokenId, usage: Usage) -> Spend {
        let mut tokens = self.tokens.lock().expect("the lock is never poisoned");
        let Some(record) = tokens.get_mut(token) else {
            return Spend::Refused;
        };
        let active = match self.state_of(record) {
            TokenState::Active => true,
            TokenState::Revoked => self.has(BrokerDefect::RevokeKeepsSpending),
            TokenState::Expired => false,
        };
        if !active {
            return Spend::Refused;
        }
        if self.has(BrokerDefect::SharedMeter) {
            let mut shared = self
                .shared_usage
                .lock()
                .expect("the lock is never poisoned");
            *shared = shared.saturating_add(usage);
        }
        record.usage = record.usage.saturating_add(usage);
        if record.usage.cost >= record.request.cost_ceiling
            && !self.has(BrokerDefect::NeverRevokesAtCeiling)
        {
            record.revoked = true;
        }
        Spend::Allowed
    }
}

#[async_trait]
impl ModelBroker for FakeModelBroker {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn issue(&self, req: JobTokenRequest) -> Result<IssuedJobToken, BrokerError> {
        if !self.has(BrokerDefect::IssuesWithoutValidation) {
            if req.cost_ceiling == CostMicroUsd(0) {
                return Err(BrokerError::InvalidRequest(
                    "the cost ceiling must be above zero".to_owned(),
                ));
            }
            if req.allowed_models.is_empty() {
                return Err(BrokerError::InvalidRequest(
                    "at least one model must be allowed".to_owned(),
                ));
            }
            if req.ttl == Duration::ZERO {
                return Err(BrokerError::InvalidRequest(
                    "the lifetime must be above zero".to_owned(),
                ));
            }
        }
        let id = JobTokenId::from_uuid(self.ids.new_uuid());
        let expires_at = timestamp_after(&self.clock.now(), req.ttl);
        self.tokens
            .lock()
            .expect("the lock is never poisoned")
            .insert(
                id,
                Record {
                    request: req,
                    usage: Usage::default(),
                    revoked: false,
                    expires_at,
                },
            );
        Ok(IssuedJobToken {
            id,
            secret: JobTokenSecret::new(format!("sfjt_{id}")),
            expires_at,
        })
    }

    async fn revoke(&self, token: &JobTokenId) -> Result<(), BrokerError> {
        let mut tokens = self.tokens.lock().expect("the lock is never poisoned");
        if self.has(BrokerDefect::RevokesEveryone) {
            for record in tokens.values_mut() {
                record.revoked = true;
            }
            return Ok(());
        }
        if let Some(record) = tokens.get_mut(token) {
            if record.revoked && self.has(BrokerDefect::RevokeFailsTwice) {
                return Err(BrokerError::UnknownToken);
            }
            record.revoked = true;
        }
        Ok(())
    }

    async fn usage(&self, token: &JobTokenId) -> Result<TokenUsage, BrokerError> {
        let tokens = self.tokens.lock().expect("the lock is never poisoned");
        let record = tokens.get(token).ok_or(BrokerError::UnknownToken)?;
        let usage = if self.has(BrokerDefect::SharedMeter) {
            *self
                .shared_usage
                .lock()
                .expect("the lock is never poisoned")
        } else {
            record.usage
        };
        Ok(TokenUsage {
            usage,
            ceiling: record.request.cost_ceiling,
            state: self.state_of(record),
        })
    }
}

/// The in-memory broker packaged as a subject of the broker contract suite.
pub struct FakeBrokerSubject {
    clock: Arc<FakeClock>,
    broker: FakeModelBroker,
    ids: Ids,
}

impl FakeBrokerSubject {
    /// The cost ceiling of the requests this subject makes: one US dollar.
    pub const CEILING: CostMicroUsd = CostMicroUsd(1_000_000);

    /// A faithful fake.
    #[must_use]
    pub fn new() -> Self {
        Self::build(None)
    }

    /// A fake that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: BrokerDefect) -> Self {
        Self::build(Some(defect))
    }

    fn build(defect: Option<BrokerDefect>) -> Self {
        let clock = Arc::new(FakeClock::new());
        let ids: Arc<dyn IdGenerator> = Arc::new(SequentialIdGenerator::new());
        let broker = match defect {
            Some(defect) => FakeModelBroker::with_defect(Arc::clone(&clock), ids, defect),
            None => FakeModelBroker::new(Arc::clone(&clock), ids),
        };
        Self {
            clock,
            broker,
            ids: Ids::new(),
        }
    }
}

impl Default for FakeBrokerSubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BrokerSubject for FakeBrokerSubject {
    fn broker(&self) -> &dyn ModelBroker {
        &self.broker
    }

    fn request(&self) -> JobTokenRequest {
        use factory_ports::agent::{ModelSelection, RuntimeId};
        JobTokenRequest {
            tenant: self.ids.tenant(),
            job: self.ids.job(),
            stage: factory_domain::vocabulary::StageKind::Implementation,
            cost_ceiling: Self::CEILING,
            allowed_models: vec![ModelSelection {
                runtime: RuntimeId::new("fake").expect("a valid runtime id"),
                model: factory_domain::values::NonEmptyString::parse("fake-model")
                    .expect("a valid model name"),
            }],
            ttl: Duration::from_secs(3600),
        }
    }

    async fn spend(&self, token: &JobTokenId, usage: Usage) -> Spend {
        self.broker.meter(token, usage)
    }

    async fn advance_time(&self, by: Duration) {
        self.clock.advance(by);
    }
}
