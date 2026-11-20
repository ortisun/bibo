//! The model broker, hosted in the process that runs agents: the worker, and the troubleshooter
//! (ADR 0021), which runs its agent outside any job and so cannot use the tokens of the worker's
//! broker, whose vault is in the worker's memory. It moved here from `apps/worker` so that both
//! binaries start the same broker the same way (ADR 0015: shared wiring belongs to this library).
//!
//! The broker holds the provider keys and the job tokens; the sandbox holds neither the key nor a
//! route to the provider (`crates/egress`). [`start`] builds the `BrokerCore` (tokens hashed at
//! rest, caps, the price list, the audit stream through the redactor) and binds the listener that
//! the per-job sidecar forwards to. The same `Arc<BrokerCore>` is the caller's `ModelBroker`
//! (wrapped by `RegisteringBroker`), so a token the caller issues is the token the listener
//! accepts.
//!
//! The real credential comes from a file named in the configuration (`broker.upstreams[].key_file`),
//! is read through [`SecretFile`](crate::config::SecretFile) (private, regular, not a
//! link) and is registered with the redactor before the listener starts. What the file holds follows
//! the mode of the security policy (`credentials.model_providers.mode`, ADR 0020):
//!
//! * `subscription` (the default): the Anthropic entry's file holds the owner's Claude subscription
//!   token, made with `claude setup-token`. The file must be mode 0600 or stricter, the token must
//!   start with `sk-ant-oat01-` and have no whitespace inside (a token wrapped when it was copied is
//!   refused by name). It is registered as `subscription_token` and sent upstream as a bearer token.
//!   An `openai` entry is not started: Codex is unavailable in this mode, and the worker says so by
//!   name when it assembles the runtimes. Start-up refuses with
//!   [`StartupFailure::SubscriptionTokenMissing`] when the token cannot be used.
//! * `api_key`: each entry's file holds that provider's API key, registered as `broker_keys`. A
//!   subscription token in its place is refused.

use std::sync::Arc;

use factory_domain::policy::routing::ModelRoutingPolicy;
use factory_domain::policy::security::ProviderCredentialMode;
use factory_domain::redaction::Redactor;
use factory_egress::broker::{BrokerCore, BrokerParts, JsonLinesAudit, Provider, SystemEntropy};
use factory_egress::http::{
    BrokerServer, BrokerServerConfig, ProviderKey, SUBSCRIPTION_TOKEN_PREFIX, ServerLimits,
    UpstreamConfig,
};
use factory_ports::clock::{Clock, IdGenerator};

use crate::config::{BrokerConfig, SecretFile};
use crate::profile::Profile;
use crate::redaction::{FactorySecrets, SecretKind};
use crate::routing::{broker_caps, price_table_with};
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

/// What the broker is started in: the credential mode of the security policy and the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialSetting {
    /// `credentials.model_providers.mode`.
    pub mode: ProviderCredentialMode,
    /// The deployment profile. In production subscription mode needs the token.
    pub profile: Profile,
}

/// Reads the owner's subscription token: a private file of mode 0600 or stricter that holds one
/// token, `sk-ant-oat01-...`, with no whitespace inside.
///
/// # Errors
/// [`StartupFailure::SubscriptionTokenMissing`], naming the file and what is wrong, never the value.
pub fn read_subscription_token(file: &SecretFile) -> Result<(ProviderKey, String), StartupFailure> {
    use std::os::unix::fs::PermissionsExt;
    let shown = file.path().display().to_string();
    let missing =
        |problem: String| StartupFailure::SubscriptionTokenMissing(format!("{shown}: {problem}"));
    let meta = std::fs::symlink_metadata(file.path())
        .map_err(|_| missing("the file does not exist or cannot be read".to_owned()))?;
    if meta.is_file() && meta.permissions().mode() & 0o177 != 0 {
        return Err(missing(format!(
            "the file has mode {:o}; it must be 0600 or stricter (chmod 600)",
            meta.permissions().mode() & 0o777
        )));
    }
    let text = file.read().map_err(|error| missing(error.to_string()))?;
    let token = ProviderKey::subscription_token(text.expose())
        .map_err(|error| missing(error.to_string()))?;
    let cleaned = text.expose().trim().to_owned();
    Ok((token, cleaned))
}

/// Builds the broker core from the routing policy and starts the listener.
///
/// # Errors
/// [`StartupFailure`] when a credential file is unsafe or holds the wrong kind of credential, a
/// provider is unknown, a base URL is refused, or the listener cannot bind;
/// [`StartupFailure::SubscriptionTokenMissing`] in subscription mode when the token cannot be used.
pub fn start(
    config: &BrokerConfig,
    setting: CredentialSetting,
    routing: &ModelRoutingPolicy,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    secrets: &mut FactorySecrets,
) -> Result<HostedBroker, StartupFailure> {
    let upstreams = match setting.mode {
        ProviderCredentialMode::Subscription => subscription_upstreams(config, setting, secrets)?,
        ProviderCredentialMode::ApiKey => api_key_upstreams(config, secrets)?,
    };
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
    if upstreams.is_empty() && !config.upstreams.is_empty() {
        return Err(StartupFailure::SubscriptionTokenMissing(
            "broker.upstreams lists no anthropic entry, and the subscription relays only Claude"
                .to_owned(),
        ));
    }
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

/// Subscription mode: the Anthropic entry, signed with the owner's token. An `openai` entry is not
/// started (Codex is unavailable in this mode; the worker names it as BLOCKED). API-key files are
/// not this mode's kind, so `broker_keys` is not required.
fn subscription_upstreams(
    config: &BrokerConfig,
    setting: CredentialSetting,
    secrets: &mut FactorySecrets,
) -> Result<Vec<UpstreamConfig>, StartupFailure> {
    secrets.mark_not_applicable(SecretKind::BrokerKeys);
    let mut upstreams = Vec::new();
    for upstream in &config.upstreams {
        if provider(&upstream.provider)? != Provider::Anthropic {
            continue;
        }
        let (token, cleaned) = read_subscription_token(&upstream.key_file)?;
        secrets
            .register(SecretKind::SubscriptionToken, &cleaned)
            .map_err(|error| StartupFailure::Other(error.to_string()))?;
        upstreams.push(
            UpstreamConfig::subscription(Provider::Anthropic, &upstream.base_url, token)
                .map_err(|error| StartupFailure::Other(error.to_string()))?,
        );
    }
    if upstreams.is_empty() && setting.profile == Profile::Production {
        return Err(StartupFailure::SubscriptionTokenMissing(
            "broker.upstreams lists no anthropic entry with a key_file".to_owned(),
        ));
    }
    Ok(upstreams)
}

/// API-key mode: every entry, each signed with its provider's API key.
fn api_key_upstreams(
    config: &BrokerConfig,
    secrets: &mut FactorySecrets,
) -> Result<Vec<UpstreamConfig>, StartupFailure> {
    secrets.mark_not_applicable(SecretKind::SubscriptionToken);
    let mut upstreams = Vec::new();
    for upstream in &config.upstreams {
        let text = secrets
            .register_file(SecretKind::BrokerKeys, &upstream.key_file)
            .map_err(|error| StartupFailure::Other(error.to_string()))?;
        if text.expose().trim().starts_with(SUBSCRIPTION_TOKEN_PREFIX) {
            return Err(StartupFailure::Other(format!(
                "{}: holds a Claude subscription token, and credentials.model_providers.mode is api_key; give the provider's API key, or set the mode to subscription",
                upstream.key_file.path().display()
            )));
        }
        let key = ProviderKey::new(text.expose().to_owned()).map_err(|error| {
            StartupFailure::Other(format!("a provider key is unusable: {error}"))
        })?;
        upstreams.push(
            UpstreamConfig::new(provider(&upstream.provider)?, &upstream.base_url, key)
                .map_err(|error| StartupFailure::Other(error.to_string()))?,
        );
    }
    Ok(upstreams)
}
