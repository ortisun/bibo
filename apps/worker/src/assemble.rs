//! Assembly of a process: everything that does not need a credential, and the list of what does.
//!
//! [`prepare`] runs the start-up checks in the order that makes a failure easiest to read, and
//! returns the parts that are ready: the loaded and hashed policy, the redactor and the registry
//! of secret values, the telemetry guard, the connected store with its two pools (roles and schema
//! checked), the hosted broker. [`blocked_adapters`] says which adapters of the port registry this
//! part of the work package does not assemble, and why. The worker binary prints that list as
//! `BLOCKED:` lines and exits with code 3 until the list is empty: it never starts a loop on a
//! half-built registry, and it never fills a hole with a fake outside a test.
//!
//! The order of the checks is the order of the failures an operator meets:
//!
//! 1. the policy, from the protected checkout, hashed;
//! 2. the sandbox image catalog: pinned, ready, no skeleton;
//! 3. the redactor from the policy, and every secret value the process holds registered;
//! 4. the telemetry set-up with that redactor;
//! 5. both database pools: roles, schema version;
//! 6. the broker listener.

use std::path::Path;
use std::sync::Arc;

use factory_domain::redaction::Redactor;
use factory_observability::telemetry::TelemetryGuard;
use factory_storage::pg::PgStore;

use crate::broker_host::{HostedBroker, start as start_broker};
use crate::config::FactoryConfig;
use crate::database;
use crate::profile::{PortName, Profile};
use crate::redaction::{FactorySecrets, SecretKind, redactor_from_policy};
use crate::startup::{LoadedPolicies, StartupFailure, check_image_catalog, load_policy};
use crate::system::{RandomIds, SystemClock};
use crate::telemetry;

/// What [`prepare`] built.
pub struct Prepared {
    /// The policies and their hash.
    pub policies: LoadedPolicies,
    /// The one redactor of the process.
    pub redactor: Arc<Redactor>,
    /// The secret values registered with it.
    pub secrets: FactorySecrets,
    /// The connected store.
    pub store: PgStore,
    /// The hosted broker.
    pub broker: HostedBroker,
    /// The telemetry pipeline, kept alive for the process.
    pub telemetry: Option<TelemetryGuard>,
}

/// One adapter this part of the work package does not assemble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    /// The port.
    pub port: PortName,
    /// Why it is missing, in a sentence an operator can act on.
    pub reason: &'static str,
}

/// The adapters that are not assembled, with the reason for each.
#[must_use]
pub fn blocked_adapters(profile: Profile) -> Vec<Blocked> {
    let mut blocked = vec![
        Blocked {
            port: PortName::Runtime,
            reason: "the agent runtime adapters bind one tenant at construction (RunIo takes a TenantScope), the worker serves many, and a live run needs a model credential and the tool in the agent image",
        },
        Blocked {
            port: PortName::Router,
            reason: "policies/model_routing.yaml does not exist, so there is no real ModelRouter to read it",
        },
        Blocked {
            port: PortName::Issues,
            reason: "the GitHub issue source needs a registered GitHub App and its private key",
        },
        Blocked {
            port: PortName::Changes,
            reason: "the GitHub change host needs a registered GitHub App and its private key",
        },
        Blocked {
            port: PortName::Workspaces,
            reason: "the workspace provider clones from the GitHub remote with an installation token",
        },
        Blocked {
            port: PortName::Sandbox,
            reason: "the Docker sandbox provider is not assembled in this part of the work package (the spec builder and the indexing wrapper are)",
        },
        Blocked {
            port: PortName::Specification,
            reason: "the Spec Kit provider is not assembled in this part of the work package",
        },
    ];
    if profile == Profile::Local {
        // The local profile may use stand-ins for the credentialed ports, but the stand-ins live
        // in the testkit, which no binary may link (DEP-03). A test wiring provides them.
        blocked.push(Blocked {
            port: PortName::Authority,
            reason: "the local profile needs the testkit's stand-ins, which only tests may link",
        });
    }
    blocked
}

/// Runs the start-up checks and builds the parts that need no credential.
///
/// # Errors
/// The first [`StartupFailure`].
pub async fn prepare(config: &FactoryConfig) -> Result<Prepared, StartupFailure> {
    let untrusted = [config.sandbox.workspace_root.as_path()];
    let untrusted: Vec<&Path> = untrusted.to_vec();
    let policies = load_policy(&config.protected_checkout, &untrusted)?;

    let catalog = std::fs::read_to_string(&config.sandbox.images_catalog).map_err(|_| {
        StartupFailure::Images(format!(
            "{} cannot be read",
            config.sandbox.images_catalog.display()
        ))
    })?;
    check_image_catalog(&catalog, config.sandbox.platform.as_deref())?;

    let redactor = Arc::new(
        redactor_from_policy(&policies.security)
            .map_err(|error| StartupFailure::Other(error.to_string()))?,
    );
    let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
    // Slice 1 keeps artifacts on the local disk, so there is no object store key.
    secrets.mark_not_applicable(SecretKind::ObjectStoreKeys);
    if let Some(github) = &config.github {
        secrets
            .register_file(SecretKind::AppPrivateKey, &github.key_file)
            .map_err(|error| StartupFailure::Other(error.to_string()))?;
        if let Some(webhook) = &github.webhook_secret_file {
            secrets
                .register_file(SecretKind::WebhookSecret, webhook)
                .map_err(|error| StartupFailure::Other(error.to_string()))?;
        }
    } else {
        // The worker does not verify webhooks; the API holds that secret.
        secrets.mark_not_applicable(SecretKind::WebhookSecret);
    }
    for extra in &config.extra_secrets {
        let text = extra
            .file
            .read()
            .map_err(|error| StartupFailure::Other(error.to_string()))?;
        secrets
            .register(SecretKind::BrokerKeys, text.expose())
            .map_err(|error| StartupFailure::Other(error.to_string()))?;
    }

    let guard = {
        let telemetry_config = telemetry::config_for(
            "factory-worker",
            env!("CARGO_PKG_VERSION"),
            config.profile,
            &config.telemetry,
            &redactor,
        )
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
        Some(
            telemetry::init(&telemetry_config)
                .map_err(|error| StartupFailure::Other(error.to_string()))?,
        )
    };

    let store = database::connect(&config.database, &mut secrets).await?;
    let broker = start_broker(
        &config.broker,
        Arc::clone(&redactor),
        Arc::new(SystemClock),
        Arc::new(RandomIds::new().map_err(|error| StartupFailure::Other(error.to_string()))?),
        &mut secrets,
    )?;

    // A kind of secret the policy requires and that nothing registered means the redactor does
    // not know a value it should. Production refuses to start; the other profiles say so.
    if let Some(kind) = secrets.unregistered_kinds().first() {
        if config.profile == Profile::Production {
            return Err(StartupFailure::SecretKindMissing(kind.label()));
        }
        tracing::warn!(
            kind = kind.label(),
            "no secret of a kind the policy lists is registered"
        );
    }
    Ok(Prepared {
        policies,
        redactor,
        secrets,
        store,
        broker,
        telemetry: guard,
    })
}
