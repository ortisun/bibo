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
//! [`SecretFile`](factory_composition::config::SecretFile) (private, regular, not a link) and are registered
//! with the redactor before the listener starts.

use std::sync::Arc;

use factory_domain::policy::routing::ModelRoutingPolicy;
use factory_domain::redaction::Redactor;
use factory_egress::broker::{BrokerCore, BrokerParts, JsonLinesAudit, Provider, SystemEntropy};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, ServerLimits, UpstreamConfig,
};
use factory_ports::clock::{Clock, IdGenerator};

use factory_composition::config::BrokerConfig;
use factory_composition::redaction::{FactorySecrets, SecretKind};
use factory_composition::routing::{broker_caps, price_table_with};
use factory_composition::startup::StartupFailure;

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

/// Builds the broker core from the routing policy and starts the listener.
///
/// # Errors
/// [`StartupFailure`] when a key file is unsafe, a provider is unknown, a base URL is refused, or
/// the listener cannot bind.
pub fn start(
    config: &BrokerConfig,
    routing: &ModelRoutingPolicy,
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
    // The routing policy is the price list and the source of the per-request caps. A price in the
    // configuration can only raise one of the policy's, and a model the policy does not list has no
    // price at all, so the broker refuses it.
    let prices = price_table_with(routing, &config.prices)
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
    let caps = broker_caps(routing).map_err(|error| StartupFailure::Other(error.to_string()))?;
    let core = BrokerCore::new(BrokerParts {
        clock,
        ids,
        entropy: Arc::new(SystemEntropy),
        prices: Arc::new(prices),
        caps,
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
