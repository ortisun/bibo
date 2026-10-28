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
use crate::startup::{LoadedPolicies, StartupFailure, check_image_catalog, load_policy};
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

/// The adapters that are not assembled, with the reason for each.
///
/// The sandbox, the workspaces and the specification provider are assembled
/// ([`crate::providers::assemble`]). What is left needs a credential or a file that does not
/// exist, in the production profile and in the others alike: the local and test profiles may
/// stand in for these four, but only a test wiring can supply the stand-ins, because the
/// testkit that holds them may not be linked by a library or a binary (DEP-03).
#[must_use]
pub fn blocked_adapters(_profile: Profile) -> Vec<Blocked> {
    vec![
        Blocked {
            port: PortName::Runtime,
            reason: "a live run needs a model credential and the tool in the agent image (the adapters bind one tenant, which crate::runtimes::TenantRuntimes handles)",
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
            reason: "no port exposes the tree id of a commit and only the sandbox crate may start git (DEP-10): needs JobRepo::tree_of in the ports and the sandbox adapter",
        },
        BlockedSeam {
            seam: "DeliverySources::current_values",
            reason: "the gate definition hash is computed by private code of the validation stage: needs a public function there, so that the delivery stage and the validation stage cannot disagree",
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
