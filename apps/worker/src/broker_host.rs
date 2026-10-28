//! The model broker, hosted in the worker's process.
//!
//! The broker holds the provider keys and the job tokens; the sandbox holds neither the key nor a
//! route to the provider (`crates/egress`). In Slice 1 the worker hosts it (`apps` entry `worker`
//! of the rules file): [`start`] builds the `BrokerCore` (tokens hashed at rest, caps, the price
//! list, the audit stream through the redactor) and binds the listener that the per-job sidecar
//! forwards to. The same `Arc<BrokerCore>` is the engine's `ModelBroker` (wrapped by
//! `RegisteringBroker`), so a token the engine issues is the token the listener accepts.
//!
//! The provider keys come from files named in the configuration, are read through
//! [`SecretFile`](crate::config::SecretFile) (private, regular, not a link) and are registered
//! with the redactor before the listener starts.

use std::sync::Arc;

use factory_domain::redaction::Redactor;
use factory_egress::broker::{
    BrokerCore, BrokerParts, CapPolicy, JsonLinesAudit, ModelPrice, PriceTable, Provider,
    SystemEntropy,
};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, ServerLimits, UpstreamConfig,
};
use factory_ports::clock::{Clock, IdGenerator};

use crate::config::BrokerConfig;
use crate::redaction::{FactorySecrets, SecretKind};
use crate::startup::StartupFailure;

fn provider(name: &str) -> Result<Provider, StartupFailure> {
    match name {
        "anthropic" => Ok(Provider::Anthropic),
        "openai" => Ok(Provider::OpenAi),
        other => Err(StartupFailure::Other(format!(
            "the broker names the unknown provider {other:?}"
        ))),
    }
}

/// A running broker.
pub struct HostedBroker {
    /// The core, which is also the engine's `ModelBroker`.
    pub core: Arc<BrokerCore>,
    server: BrokerServer,
}

impl HostedBroker {
    /// The address the listener bound.
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }

    /// Stops the listener and waits for it.
    pub fn shutdown(&self) {
        self.server.shutdown();
    }
}

/// Builds the broker core and starts the listener.
///
/// # Errors
/// [`StartupFailure`] when a key file is unsafe, a provider is unknown, a base URL is refused, or
/// the listener cannot bind.
pub fn start(
    config: &BrokerConfig,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    secrets: &mut FactorySecrets,
) -> Result<HostedBroker, StartupFailure> {
    let mut upstreams = Vec::new();
    for upstream in &config.upstreams {
        let text = secrets
            .register_file(SecretKind::BrokerKeys, &upstream.key_file)
            .map_err(|error| StartupFailure::Other(error.to_string()))?;
        let key = ProviderKey::new(text.expose().to_owned()).map_err(|error| {
            StartupFailure::Other(format!("a provider key is unusable: {error}"))
        })?;
        upstreams.push(
            UpstreamConfig::new(provider(&upstream.provider)?, &upstream.base_url, key)
                .map_err(|error| StartupFailure::Other(error.to_string()))?,
        );
    }
    let mut prices = PriceTable::new();
    for price in &config.prices {
        prices = prices.with_model(
            provider(&price.provider)?,
            &price.model,
            ModelPrice {
                input: price.input,
                cache_write: price.cache_write,
                cache_read: price.cache_read,
                output: price.output,
            },
        );
    }
    let core = BrokerCore::new(BrokerParts {
        clock,
        ids,
        entropy: Arc::new(SystemEntropy),
        prices: Arc::new(prices),
        caps: CapPolicy::default(),
        audit: Arc::new(JsonLinesAudit::new(std::io::stderr(), redactor)),
    });
    let server = BrokerServer::start(
        BrokerServerConfig {
            listen: config.listen,
            upstreams,
            expected_job: None,
            limits: ServerLimits::default(),
        },
        Arc::clone(&core),
    )
    .map_err(|error| StartupFailure::Other(format!("the broker listener cannot start: {error}")))?;
    Ok(HostedBroker { core, server })
}
