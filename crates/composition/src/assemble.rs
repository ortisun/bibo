//! Assembly of a process: everything that does not need a credential, and the list of what does.
//!
//! [`prepare`] runs the start-up checks in the order that makes a failure easiest to read, and
//! returns the parts that are ready: the loaded and hashed policy, the redactor and the registry
//! of secret values, the telemetry guard, the connected store with its two pools (roles and schema
//! checked). [`blocked_adapters`] says which adapters of the port registry this part of the work
//! package does not assemble, and why. The worker binary prints that list as `BLOCKED:` lines and
//! exits with code 3 until the list is empty: it never starts a loop on a half-built registry,
//! and it never fills a hole with a fake outside a test.
//!
//! The order of the checks is the order of the failures an operator meets:
//!
//! 1. the policy, from the protected checkout, hashed;
//! 2. the sandbox image catalog: pinned, ready, no skeleton;
//! 3. the redactor from the policy, and every secret value the process holds registered;
//! 4. the telemetry set-up with that redactor;
//! 5. both database pools: roles, schema version.
//!
//! The model broker listener is the worker's: the worker starts it after [`prepare`] and then
//! calls [`Prepared::check_secret_kinds`], because the broker's provider keys are one of the
//! secret kinds the policy requires.

use std::path::Path;
use std::sync::Arc;

use factory_domain::redaction::Redactor;
use factory_observability::telemetry::TelemetryGuard;
use factory_ports::artifact::ArtifactStore;
use factory_storage::artifact_fs::LocalFsArtifactStore;
use factory_storage::pg::PgStore;

use crate::config::FactoryConfig;
use crate::database;
use crate::profile::{PortName, Profile};
use crate::redaction::{FactorySecrets, SecretKind, redactor_from_policy};
use crate::startup::{
    LoadedPolicies, LoadedRouting, StartupFailure, check_image_catalog, confirm_routing,
    load_policy, load_routing,
};
use crate::telemetry;

/// Who is starting: the service name and version telemetry reports.
#[derive(Debug, Clone, Copy)]
pub struct Identity {
    /// The service name, such as `factory-worker`.
    pub service: &'static str,
    /// The version.
    pub version: &'static str,
}

/// What [`prepare`] built.
pub struct Prepared {
    /// The policies and their hash.
    pub policies: LoadedPolicies,
    /// The routing policy: which models each stage may use, what they cost, what a stage and a
    /// job may spend.
    pub routing: LoadedRouting,
    /// The one redactor of the process.
    pub redactor: Arc<Redactor>,
    /// The secret values registered with it.
    pub secrets: FactorySecrets,
    /// The connected store.
    pub store: Arc<PgStore>,
    /// The content-addressed artifact store on the local disk, indexing through `store`.
    pub artifacts: Arc<dyn ArtifactStore>,
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

/// The adapters that depend on the configuration, with what each needs.
///
/// The sandbox, the workspaces and the specification provider are assembled
/// ([`crate::providers::assemble`]). The four below are assembled by
/// [`crate::external::assemble_external`] from the configuration, and each is `BLOCKED` while the
/// configuration lacks what it needs. The worker prints one line for each item that is missing,
/// starting with the key to write; this list is the set of ports a line can be about. The operator
/// CLI, which assembles none of them, prints these as the ones it cannot check.
#[must_use]
pub fn blocked_adapters(_profile: Profile) -> Vec<Blocked> {
    vec![
        Blocked {
            port: PortName::Runtime,
            reason: "built from broker.upstreams (a provider and its key_file) and runtimes; blocked while broker.upstreams lists no provider",
        },
        Blocked {
            port: PortName::Router,
            reason: "built from policies/model_routing.yaml and the models broker.upstreams enables; blocked while broker.upstreams lists no provider or enables a model the policy does not list",
        },
        Blocked {
            port: PortName::Issues,
            reason: "built from github (app_id, key_file, installations, api_base_url); blocked while github is not set, github.installations is empty or the key file is unusable",
        },
        Blocked {
            port: PortName::Changes,
            reason: "built from github (app_id, key_file, installations, api_base_url); blocked while github is not set, github.installations is empty or the key file is unusable",
        },
    ]
}

/// A seam that is only partly implemented, with what is missing and who owns the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedSeam {
    /// The seam and method.
    pub seam: &'static str,
    /// Why it cannot be answered, in a sentence an owner can act on.
    pub reason: &'static str,
}

/// The seam methods that fail closed because the thing they need does not exist yet.
#[must_use]
pub fn blocked_seams() -> Vec<BlockedSeam> {
    vec![
        BlockedSeam {
            seam: "DeliverySources::tree_of",
            reason: "implemented over JobRepo::tree_of (pending architect confirmation) and wired by pipeline::assemble_pipeline through StoreDeliverySources::with_repository; a binary that does not assemble the pipeline, such as the operator CLI, gets a closed answer",
        },
        BlockedSeam {
            seam: "DeliverySources::current_values",
            reason: "implemented over validation::current_values and wired by pipeline::assemble_pipeline through StoreDeliverySources::with_repository; a binary that does not assemble the pipeline, such as the operator CLI, gets a closed answer",
        },
    ]
}

/// What `pipeline::assemble_pipeline` needs beyond the four adapters above, and what decides each.
/// A worker stops with these listed while the configuration lacks what they need.
///
/// The recorded decisions of people are not on this list: `assemble_pipeline` reads them from the
/// ledger itself (`LedgerApprovals`). The registry source ([`crate::crates_io`]) and the advisory
/// date ([`crate::advisory`]) are adapters now, and each is blocked only while its key is not set;
/// a source that cannot be read at run time answers unknown, and the dependency gates fail closed
/// on unknown (a new direct dependency waits for a security approver, the advisories gate is
/// BLOCKED). [`crate::supply_chain::SupplyChainSources::blocked`] remains for a process that does
/// not assemble the outside world, such as the operator CLI.
#[must_use]
pub fn blocked_pipeline_inputs() -> Vec<BlockedSeam> {
    vec![
        BlockedSeam {
            seam: "RegistryMetadata",
            reason: "built from registry (base_url, user_agent); blocked while registry.base_url is not set, and in production while the host is not one the egress policy lists for the cargo ecosystem",
        },
        BlockedSeam {
            seam: "AdvisoryDatabase",
            reason: "built from advisory_database.date_file, which the image build writes; blocked while the key is not set",
        },
        BlockedSeam {
            seam: "CapabilityProbes",
            reason: "each runtime is probed in an agent sandbox at start-up; blocked while the Docker daemon does not answer or the agent image is not on the host, or while runtimes.declare_capabilities is unset in a profile that may declare",
        },
    ]
}

/// Runs the start-up checks and builds the parts that need no credential.
///
/// # Errors
/// The first [`StartupFailure`].
pub async fn prepare(
    config: &FactoryConfig,
    identity: Identity,
) -> Result<Prepared, StartupFailure> {
    let untrusted = [config.sandbox.workspace_root.as_path()];
    let untrusted: Vec<&Path> = untrusted.to_vec();
    let policies = load_policy(&config.protected_checkout, &untrusted)?;
    // The hosts the production profile may reach are the ones the policy lists, and the routing
    // policy must load and be confirmed before anything is built from it.
    config
        .check_endpoints(&policies.security)
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
    let routing = load_routing(&config.protected_checkout, &untrusted, &policies.security)?;
    confirm_routing(config.profile, &routing)?;
    crate::routing::enabled_models(&routing.policy, &config.broker.upstreams)
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
    crate::routing::price_table_with(&routing.policy, &config.broker.prices)
        .map_err(|error| StartupFailure::Other(error.to_string()))?;

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
            identity.service,
            identity.version,
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

    let store = Arc::new(database::connect(&config.database, &mut secrets).await?);
    let artifacts: Arc<dyn ArtifactStore> = Arc::new(
        LocalFsArtifactStore::open(
            &config.artifacts.root,
            config.artifacts.max_bytes,
            store.clone(),
        )
        .map_err(|error| {
            StartupFailure::Other(format!("the artifact store cannot open: {error}"))
        })?,
    );
    Ok(Prepared {
        policies,
        routing,
        redactor,
        secrets,
        store,
        artifacts,
        telemetry: guard,
    })
}

impl Prepared {
    /// Refuses to go on when a kind of secret the policy requires has no value registered.
    ///
    /// Call it once everything that registers a value has run (the broker listener registers the
    /// provider keys). A kind that nothing registered means the redactor does not know a value it
    /// should. Production refuses to start; the other profiles say so in the log.
    ///
    /// # Errors
    /// [`StartupFailure::SecretKindMissing`], in the production profile only.
    pub fn check_secret_kinds(&self, profile: Profile) -> Result<(), StartupFailure> {
        if let Some(kind) = self.secrets.unregistered_kinds().first() {
            if profile == Profile::Production {
                return Err(StartupFailure::SecretKindMissing(kind.label()));
            }
            tracing::warn!(
                kind = kind.label(),
                "no secret of a kind the policy lists is registered"
            );
        }
        Ok(())
    }
}
