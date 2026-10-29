//! Shared test support: a broker built on fakes, labelled as such, and the prices of two made-up
//! models. Nothing here is a real key, a real model name or a real price.

#![allow(dead_code)]

mod fake_provider;

#[allow(unused_imports)]
pub use fake_provider::{Ending, FakeProvider, Recorded, Script};

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::NonEmptyString;
use factory_domain::vocabulary::StageKind;
use factory_egress::broker::{
    BrokerCore, BrokerParts, CapPolicy, EntropyError, MemoryAudit, ModelPrice, PriceList,
    PriceTable, Provider, SystemEntropy, TokenEntropy,
};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, ServerLimits, UpstreamConfig,
};
use factory_ports::agent::{
    CostMicroUsd, IssuedJobToken, JobTokenId, JobTokenRequest, MeteringOps, ModelBroker,
    ModelSelection, RuntimeId, Usage,
};
use factory_ports::clock::Clock;
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::contracts::broker::{BrokerSubject, Spend};
use factory_testkit::fixtures::Ids;
use factory_testkit::fx::http::{ClientResponse, send_request};

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
        Self::with_prices(caps, Arc::new(prices()))
    }

    pub fn with_prices(caps: CapPolicy, prices: Arc<dyn PriceList>) -> Self {
        let clock = Arc::new(FakeClock::new());
        let audit = Arc::new(MemoryAudit::new());
        let as_clock: Arc<dyn Clock> = clock.clone();
        let core = BrokerCore::new(BrokerParts {
            clock: as_clock,
            ids: Arc::new(SequentialIdGenerator::new()),
            entropy: Arc::new(CountingEntropy::default()),
            prices,
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
            per_request: None,
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

/// A job id that is the same for every request of one subject.
pub fn fixed_job() -> JobId {
    JobId::from_uuid(factory_ports::clock::Uuid::from_u128(
        (0xfeed_u128 << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ))
}

#[async_trait]
impl BrokerSubject for CoreSubject {
    fn broker(&self) -> &dyn ModelBroker {
        self.rig.core.as_ref()
    }

    fn request(&self) -> JobTokenRequest {
        // One job for every request of one subject, so the `revoke_for_job` check can find them.
        self.rig.request_for(fixed_job(), CEILING)
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

/// A made-up provider key, built at run time from the operating system's random source so no key
/// is in the source or in the history. The prefix only gives it the look of a key.
pub fn made_up_key(prefix: &str) -> String {
    let mut bytes = [0_u8; 24];
    SystemEntropy.fill(&mut bytes).expect("random bytes");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}{hex}")
}

/// The real broker listener, in front of the fake provider, on the loopback address.
pub struct HttpRig {
    pub rig: Rig,
    pub server: BrokerServer,
    pub provider: FakeProvider,
    pub anthropic_key: String,
    pub openai_key: String,
}

impl HttpRig {
    pub fn new() -> Self {
        Self::build(CapPolicy::default(), None)
    }

    pub fn with_caps(caps: CapPolicy) -> Self {
        Self::build(caps, None)
    }

    pub fn for_job(job: JobId) -> Self {
        Self::build(CapPolicy::default(), Some(job))
    }

    pub fn with_prices(caps: CapPolicy, prices: Arc<dyn PriceList>) -> Self {
        Self::build_with(Rig::with_prices(caps, prices), None)
    }

    fn build(caps: CapPolicy, expected_job: Option<JobId>) -> Self {
        Self::build_with(Rig::with_caps(caps), expected_job)
    }

    fn build_with(rig: Rig, expected_job: Option<JobId>) -> Self {
        let provider = FakeProvider::start();
        let anthropic_key = made_up_key("anthropic-test-key-");
        let openai_key = made_up_key("openai-test-key-");
        let upstreams = vec![
            UpstreamConfig::new(
                Provider::Anthropic,
                &provider.base_url(),
                ProviderKey::new(anthropic_key.clone()).expect("a key"),
            )
            .expect("an upstream"),
            UpstreamConfig::new(
                Provider::OpenAi,
                &provider.base_url(),
                ProviderKey::new(openai_key.clone()).expect("a key"),
            )
            .expect("an upstream"),
        ];
        let server = BrokerServer::start(
            BrokerServerConfig {
                listen: "127.0.0.1:0".parse().expect("an address"),
                upstreams,
                expected_job,
                limits: ServerLimits::default(),
            },
            rig.core.clone(),
        )
        .expect("the listener starts");
        Self {
            rig,
            server,
            provider,
            anthropic_key,
            openai_key,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    /// A token for the Anthropic model with this ceiling.
    pub fn claude_token(&self, ceiling: CostMicroUsd) -> IssuedJobToken {
        self.rig
            .core
            .issue_token(self.rig.request(ceiling))
            .expect("a token")
    }

    /// A token for the OpenAI model with this ceiling.
    pub fn codex_token(&self, ceiling: CostMicroUsd) -> IssuedJobToken {
        let mut request = self.rig.request(ceiling);
        request.allowed_models = vec![ModelSelection {
            runtime: RuntimeId::new("codex-cli").expect("a slug"),
            model: NonEmptyString::parse(GPT_MODEL).expect("a model name"),
        }];
        self.rig.core.issue_token(request).expect("a token")
    }

    /// POSTs JSON to the broker as the sidecar would forward it.
    pub fn post(
        &self,
        path: &str,
        credential: (&str, &str),
        body: &serde_json::Value,
    ) -> ClientResponse {
        send_request(
            self.addr(),
            "POST",
            path,
            &[
                ("Content-Type", "application/json"),
                credential,
                ("anthropic-version", "2023-06-01"),
                (
                    "anthropic-beta",
                    "claude-code-20250219,test-beta-1,test-beta-2",
                ),
                ("x-claude-code-session-id", "session-should-not-cross"),
                ("Cookie", "cookie-should-not-cross=1"),
            ],
            body.to_string().as_bytes(),
        )
        .expect("the broker answers")
    }

    /// A Messages request from Claude Code with the job token in `x-api-key`.
    pub fn claude(&self, token: &IssuedJobToken, stream: bool) -> ClientResponse {
        self.post(
            "/v1/messages?beta=true",
            ("x-api-key", token.secret.expose()),
            &serde_json::json!({
                "model": CLAUDE_MODEL, "stream": stream, "max_tokens": 128_000,
                "messages": [{"role": "user", "content": "hi"}],
            }),
        )
    }

    /// A Responses request from Codex with the job token as a bearer credential.
    pub fn codex(&self, token: &IssuedJobToken, stream: bool) -> ClientResponse {
        self.post(
            "/v1/responses",
            (
                "Authorization",
                &format!("Bearer {}", token.secret.expose()),
            ),
            &serde_json::json!({
                "model": GPT_MODEL, "stream": stream, "store": false,
                "input": [{"role": "user", "content": "hi"}],
            }),
        )
    }
}
