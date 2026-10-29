//! Start-up of the API, in the order an operator meets the failures:
//!
//! 1. the policy from the protected checkout, hashed;
//! 2. the redactor built from it, and the registry of the secret values this process holds (the
//!    database URL and its password, every webhook secret);
//! 3. the telemetry set-up with that redactor in front of every log line and span;
//! 4. the webhook verifier from the secret files;
//! 5. the one database pool, as the API login: role and schema checked by the store;
//! 6. the ports, and the profile's rule over each of them (`ApiPorts::check`): the production
//!    profile refuses a fake;
//! 7. the kinds of secret the policy requires: in production, one with no value is a refusal.
//!
//! The pieces are the composition library's (`factory_composition`); only the order and the set of
//! ports are the API's own.

use std::sync::Arc;

use factory_composition::assemble::Identity;
use factory_composition::authority::StoreAuthority;
use factory_composition::database::connect_api;
use factory_composition::decision_signing::DecisionKeys;
use factory_composition::profile::Profile;
use factory_composition::redaction::{FactorySecrets, SecretKind, redactor_from_policy};
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::{LoadedPolicies, StartupFailure, load_policy};
use factory_composition::system::{RandomIds, SystemClock};
use factory_composition::{telemetry, webhook};
use factory_domain::redaction::Redactor;
use factory_observability::telemetry::TelemetryGuard;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::store::{Audience, Store};
use factory_workflow::commands::Authority;
use tokio::task::JoinHandle;

use crate::config::{ApiConfig, GithubSettings, Limits};
use crate::limits::{PlatformAudit, RateLimiter, RefusalBudget, write_platform_audit};
use crate::state::{ApiPorts, ApiState, expected_schema};

/// The identity the API reports to telemetry.
pub const IDENTITY: Identity = Identity {
    service: "factory-api",
    version: env!("CARGO_PKG_VERSION"),
};

/// The platform audit queue holds this many events.
const AUDIT_QUEUE: usize = 256;

/// The platform audit task writes at most this many events a minute.
const AUDIT_PER_MINUTE: u32 = 60;

/// What [`boot`] built.
pub struct Booted {
    /// What the handlers read.
    pub state: Arc<ApiState>,
    /// The telemetry pipeline, kept alive for the process.
    pub telemetry: Option<TelemetryGuard>,
    /// The task that writes the platform audit events.
    pub audit_writer: JoinHandle<()>,
}

/// Everything [`assemble_state`] needs that start-up has already built.
pub struct StateInputs {
    /// The profile.
    pub profile: Profile,
    /// The ports.
    pub ports: ApiPorts,
    /// The allowlist file.
    pub allowlist_file: Arc<FileAllowlist>,
    /// The policy.
    pub policies: LoadedPolicies,
    /// The redactor.
    pub redactor: Arc<Redactor>,
    /// The keys that sign the requests for decisions.
    pub decision_keys: Arc<DecisionKeys>,
    /// The audience of the tokens.
    pub audience: String,
    /// GitHub-facing settings.
    pub github: GithubSettings,
    /// The limits.
    pub limits: Limits,
}

/// Checks the ports against the profile and builds the shared state and the audit writer. Start-up
/// and the tests both go through here, so a test of the production rule runs the code that runs in
/// production.
///
/// # Errors
/// [`StartupFailure::Ports`] when the profile refuses a port, [`StartupFailure::Other`] for an
/// audience that is not a slug.
pub fn assemble_state(
    inputs: StateInputs,
) -> Result<(Arc<ApiState>, JoinHandle<()>), StartupFailure> {
    inputs.ports.check(inputs.profile)?;
    let audience = factory_domain::values::Slug::parse(&inputs.audience)
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
    let (platform_audit, events) = PlatformAudit::channel(AUDIT_QUEUE);
    let writer = tokio::spawn(write_platform_audit(
        events,
        Arc::clone(&inputs.ports.store),
        Arc::clone(&inputs.ports.ids),
        inputs.policies.hash.clone(),
        AUDIT_PER_MINUTE,
    ));
    let state = ApiState {
        profile: inputs.profile,
        ports: inputs.ports,
        allowlist_file: inputs.allowlist_file,
        policies: inputs.policies,
        redactor: inputs.redactor,
        decision_keys: inputs.decision_keys,
        audience: Audience(audience),
        github: inputs.github,
        limits: inputs.limits,
        limiter: RateLimiter::new(),
        refusals: RefusalBudget::new(),
        platform_audit,
        expected_schema: expected_schema(),
    };
    Ok((Arc::new(state), writer))
}

/// Runs the start-up checks and builds the state.
///
/// # Errors
/// The first [`StartupFailure`].
pub async fn boot(config: &ApiConfig) -> Result<Booted, StartupFailure> {
    let policies = load_policy(&config.protected_checkout, &[])?;
    let redactor = Arc::new(
        redactor_from_policy(&policies.security)
            .map_err(|error| StartupFailure::Other(error.to_string()))?,
    );
    let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
    // The API holds no key of these kinds; the policy still lists them for the factory as a whole.
    for kind in [
        SecretKind::ObjectStoreKeys,
        SecretKind::AppPrivateKey,
        SecretKind::BrokerKeys,
    ] {
        secrets.mark_not_applicable(kind);
    }
    let webhooks = if config.github.webhook_secret_files.is_empty() {
        secrets.mark_not_applicable(SecretKind::WebhookSecret);
        None
    } else {
        Some(webhook::verifier_from_files(
            &config.github.webhook_secret_files,
            &mut secrets,
        )?)
    };

    let guard = {
        let settings = telemetry::config_for(
            IDENTITY.service,
            IDENTITY.version,
            config.profile,
            &config.telemetry,
            &redactor,
        )
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
        Some(telemetry::init(&settings).map_err(|error| StartupFailure::Other(error.to_string()))?)
    };

    // The key is read before the pool opens: a process that cannot sign a request must not take
    // traffic. The production profile refuses to start without it (AUT-12).
    let decision_keys = Arc::new(DecisionKeys::load(
        config.profile,
        config.decisions.as_ref(),
        &redactor,
    )?);

    let store: Arc<dyn Store> = Arc::new(connect_api(&config.database.api, &mut secrets).await?);
    if let Some(kind) = secrets.unregistered_kinds().first() {
        if config.profile == Profile::Production {
            return Err(StartupFailure::SecretKindMissing(kind.label()));
        }
        tracing::warn!(
            kind = kind.label(),
            "no secret of a kind the policy lists is registered"
        );
    }

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let ids: Arc<dyn IdGenerator> =
        Arc::new(RandomIds::new().map_err(|error| StartupFailure::Other(error.to_string()))?);
    let allowlist_file = Arc::new(FileAllowlist::in_checkout(&config.protected_checkout));
    let authority: Arc<dyn Authority> = Arc::new(StoreAuthority::new(
        Arc::clone(&store),
        Arc::clone(&allowlist_file),
        Arc::clone(&policies.engine),
        Arc::clone(&clock),
    ));
    let artifacts = config
        .artifacts
        .as_ref()
        .map(|settings| {
            factory_composition::database::open_artifacts(
                &settings.root,
                settings.max_bytes,
                Arc::clone(&store),
            )
        })
        .transpose()?;
    let ports = ApiPorts {
        store,
        clock,
        ids,
        webhooks,
        authority,
        allowlist: allowlist_file.clone(),
        artifacts,
    };
    let (state, audit_writer) = assemble_state(StateInputs {
        profile: config.profile,
        ports,
        allowlist_file,
        policies,
        redactor,
        decision_keys,
        audience: config.tokens.audience.clone(),
        github: config.github.clone(),
        limits: config.limits.clone(),
    })?;
    Ok(Booted {
        state,
        telemetry: guard,
        audit_writer,
    })
}
