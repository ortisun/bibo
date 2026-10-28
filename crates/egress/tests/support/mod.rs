//! Shared test support: a broker built on fakes, labelled as such, and the prices of two made-up
//! models. Nothing here is a real key, a real model name or a real price.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::NonEmptyString;
use factory_domain::vocabulary::StageKind;
use factory_egress::broker::{
    BrokerCore, BrokerParts, CapPolicy, EntropyError, MemoryAudit, ModelPrice, PriceTable,
    Provider, TokenEntropy,
};
use factory_ports::agent::{
    CostMicroUsd, JobTokenId, JobTokenRequest, MeteringOps, ModelBroker, ModelSelection, RuntimeId,
    Usage,
};
use factory_ports::clock::Clock;
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::contracts::broker::{BrokerSubject, Spend};
use factory_testkit::fixtures::Ids;

/// The made-up Anthropic model of the tests.
pub const CLAUDE_MODEL: &str = "claude-test-model";
/// The made-up OpenAI model of the tests.
pub const GPT_MODEL: &str = "gpt-test-model";
/// The ceiling of the tokens the subjects issue: one dollar.
pub const CEILING: CostMicroUsd = CostMicroUsd(1_000_000);

/// A random source that is not random: a counter spread over 32 bytes. Two calls never give the
/// same bytes, which is all a test needs from it.
#[derive(Default)]
pub struct CountingEntropy(AtomicU64);

impl TokenEntropy for CountingEntropy {
    fn fill(&self, out: &mut [u8]) -> Result<(), EntropyError> {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = n.to_le_bytes()[i % 8] ^ (i as u8).wrapping_mul(31);
        }
        Ok(())
    }
}

/// One dollar per million input tokens and five per million output tokens, for both models; a
/// cache read costs a tenth of an input token and a cache write 1.25.
pub fn prices() -> PriceTable {
    let price = ModelPrice {
        input: 1_000_000,
        cache_write: 1_250_000,
        cache_read: 100_000,
        output: 5_000_000,
    };
    PriceTable::new()
        .with_model(Provider::Anthropic, CLAUDE_MODEL, price)
        .with_model(Provider::OpenAi, GPT_MODEL, price)
}

/// A broker, its clock and its audit log.
pub struct Rig {
    pub clock: Arc<FakeClock>,
    pub core: Arc<BrokerCore>,
    pub audit: Arc<MemoryAudit>,
    pub ids: Ids,
}

impl Rig {
    pub fn new() -> Self {
        Self::with_caps(CapPolicy::default())
    }

    pub fn with_caps(caps: CapPolicy) -> Self {
        let clock = Arc::new(FakeClock::new());
        let audit = Arc::new(MemoryAudit::new());
        let as_clock: Arc<dyn Clock> = clock.clone();
        let core = BrokerCore::new(BrokerParts {
            clock: as_clock,
            ids: Arc::new(SequentialIdGenerator::new()),
            entropy: Arc::new(CountingEntropy::default()),
            prices: Arc::new(prices()),
            caps,
            audit: audit.clone(),
        });
        Self {
            clock,
            core,
            audit,
            ids: Ids::new(),
        }
    }

    /// A token request for the Anthropic model, with the given ceiling, for a new job.
    pub fn request(&self, ceiling: CostMicroUsd) -> JobTokenRequest {
        self.request_for(self.ids.job(), ceiling)
    }

    /// A token request for the Anthropic model, for the given job.
    pub fn request_for(&self, job: JobId, ceiling: CostMicroUsd) -> JobTokenRequest {
        JobTokenRequest {
            tenant: self.ids.tenant(),
            job,
            stage: StageKind::Implementation,
            cost_ceiling: ceiling,
            allowed_models: vec![ModelSelection {
                runtime: RuntimeId::new("claude-code-cli").expect("a slug"),
                model: NonEmptyString::parse(CLAUDE_MODEL).expect("a model name"),
            }],
            ttl: Duration::from_secs(3600),
        }
    }

    pub fn tenant(&self) -> TenantId {
        self.ids.tenant()
    }
}

/// The real broker core as a subject of the shared contract suite. Spend goes through
/// `MeteringOps`, the seam the port describes.
pub struct CoreSubject {
    pub rig: Rig,
}

impl CoreSubject {
    pub fn new() -> Self {
        Self { rig: Rig::new() }
    }
}

#[async_trait]
impl BrokerSubject for CoreSubject {
    fn broker(&self) -> &dyn ModelBroker {
        self.rig.core.as_ref()
    }

    fn request(&self) -> JobTokenRequest {
        // One job for every request of one subject, so the `revoke_for_job` check can find them.
        let mut request = self.rig.request(CEILING);
        request.job = JobId::from_uuid(factory_ports::clock::Uuid::from_u128(
            (0xfeed_u128 << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
        ));
        request
    }

    async fn spend(&self, token: &JobTokenId, usage: Usage) -> Spend {
        match MeteringOps::record_usage(self.rig.core.as_ref(), token, usage).await {
            Ok(_) => Spend::Allowed,
            Err(_) => Spend::Refused,
        }
    }

    async fn advance_time(&self, by: Duration) {
        self.rig.clock.advance(by);
    }
}
