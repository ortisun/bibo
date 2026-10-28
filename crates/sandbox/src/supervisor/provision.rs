//! Making a sandbox: the steps from a validated spec to a started, verified container.
//!
//! Every step either succeeds or fails closed. A failure removes everything made so far (the
//! caller runs [`Guard::cleanup`]), reports the stage in [`ProvisionStage`], and never retries
//! with a weaker setting.

use std::path::Path;
use std::sync::Arc;

use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{
    JOB_TOKEN_TARGET, NetworkAttachment, PostureDiff, ProvisionStage, SandboxError, SandboxId,
    SandboxSpec,
};
use tokio::time::Instant;

use super::cleanup::Guard;
use super::session::DockerSession;
use super::watchdog::{self, Limits};
use super::{Shared, daemon_error};
use crate::container::args::{CreatePlan, SidecarPlan, create_args, sidecar_args};
use crate::container::docker::{DockerClient, DockerError};
use crate::container::images::CatalogImage;
use crate::container::names::{Kind, SandboxNames, labels};
use crate::container::posture::{
    ObserveInput, evaluate_self_check, normalize_file_share_sources, observe, sidecar_alias,
    sidecar_deviations,
};

/// How long the self-check and the token read may take.
const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Maps a failed docker call at `stage` onto the closed error set.
fn failed(error: DockerError, stage: ProvisionStage) -> SandboxError {
    match error {
        DockerError::Unavailable => SandboxError::DaemonUnavailable,
        DockerError::Cancelled => SandboxError::Cancelled,
        DockerError::Timeout | DockerError::Os | DockerError::Failed { .. } => {
            SandboxError::ProvisionFailed(stage)
        }
    }
}

/// Checks that an image is on this host, by the digest the catalog lists. Images are never
/// pulled.
async fn ensure_image_present(
    shared: &Shared,
    image: &CatalogImage,
    cancel: &dyn CancelSignal,
) -> Result<(), SandboxError> {
    match shared
        .docker
        .image_id(image.reference.reference(), cancel)
        .await
    {
        Ok(id) if id == image.digest => Ok(()),
        Ok(_) => Err(SandboxError::ImageUnavailable),
        Err(error) if error.is_missing_object() => Err(SandboxError::ImageUnavailable),
        Err(error) => Err(daemon_error(error)),
    }
}

pub(crate) async fn create_verified(
    shared: &Arc<Shared>,
    spec: SandboxSpec,
    cancel: &dyn CancelSignal,
) -> Result<DockerSession, SandboxError> {
    spec.validate(&shared.config.policy)
        .map_err(SandboxError::PolicyViolation)?;
    if cancel.is_cancelled() {
        return Err(SandboxError::Cancelled);
    }
    let catalog = shared.catalog(cancel).await?;
    let image = catalog
        .check_spec_image(spec.profile, &spec.image)
        .map_err(|_| SandboxError::ImageUnavailable)?
        .clone();
    ensure_image_present(shared, &image, cancel).await?;
    let sidecar_image = match spec.network {
        NetworkAttachment::None => None,
        NetworkAttachment::JobInternal { .. } => {
            // A skeleton sidecar blocks the job before anything is created.
            let sidecar = catalog
                .sidecar()
                .map_err(|_| SandboxError::ProvisionFailed(ProvisionStage::Network))?
                .clone();
            ensure_image_present(shared, &sidecar, cancel)
                .await
                .map_err(|error| match error {
                    SandboxError::ImageUnavailable => {
                        SandboxError::ProvisionFailed(ProvisionStage::Network)
                    }
                    other => other,
                })?;
            Some(sidecar)
        }
    };
    if cancel.is_cancelled() {
        return Err(SandboxError::Cancelled);
    }

    let names = SandboxNames::new(&spec.job, &spec.attempt, &shared.ids.new_uuid().to_string());
    let mut guard = Guard::new(Arc::clone(shared), names);
    match build(
        shared,
        &spec,
        &image,
        sidecar_image.as_ref(),
        &mut guard,
        cancel,
    )
    .await
    {
        Ok(session) => Ok(session),
        Err(error) => {
            let interrupted = matches!(error, SandboxError::Cancelled);
            guard.cleanup(interrupted).await;
            Err(error)
        }
    }
}

fn check_cancel(cancel: &dyn CancelSignal) -> Result<(), SandboxError> {
    if cancel.is_cancelled() {
        Err(SandboxError::Cancelled)
    } else {
        Ok(())
    }
}

/// The per-job network and its sidecar. Returns the alias observed on the sidecar.
async fn prepare_network(
    shared: &Shared,
    spec: &SandboxSpec,
    sidecar_image: &CatalogImage,
    guard: &mut Guard,
    cancel: &dyn CancelSignal,
) -> Result<String, SandboxError> {
    let NetworkAttachment::JobInternal { sidecar: alias } = &spec.network else {
        return Err(SandboxError::ProvisionFailed(ProvisionStage::Network));
    };
    let stage = ProvisionStage::Network;
    let docker = &shared.docker;
    let names = guard.names().clone();
    let owner = &shared.config.owner_labels;

    guard.created.network = true;
    let mut create = vec![
        "network".to_owned(),
        "create".to_owned(),
        "--internal".to_owned(),
        "--driver".to_owned(),
        "bridge".to_owned(),
    ];
    for (key, value) in labels(Kind::Network, spec, None, owner) {
        create.push("--label".to_owned());
        create.push(format!("{key}={value}"));
    }
    create.push(names.network.clone());
    docker
        .run(create, cancel)
        .await
        .map_err(|e| failed(e, stage))?;
    let network = docker
        .inspect("network", &names.network, cancel)
        .await
        .map_err(|e| failed(e, stage))?;
    let internal = network.get("Internal").and_then(serde_json::Value::as_bool) == Some(true);
    if !internal {
        return Err(SandboxError::ProvisionFailed(stage));
    }
    check_cancel(cancel)?;

    guard.created.sidecar = true;
    let sidecar_labels = labels(Kind::Sidecar, spec, Some(alias), owner);
    let plan = SidecarPlan {
        container: &names.sidecar,
        image: sidecar_image.reference.reference(),
        network: &names.network,
        alias,
        ids: (sidecar_image.uid, sidecar_image.gid),
        labels: &sidecar_labels,
        command: &shared.config.sidecar_command,
    };
    let args = sidecar_args(&plan).map_err(|_| SandboxError::ProvisionFailed(stage))?;
    docker
        .run(args, cancel)
        .await
        .map_err(|e| failed(e, stage))?;
    // The sidecar is the one container with a way out: the default bridge, next to the job's
    // internal network. The sandbox itself never joins it.
    docker
        .run(
            vec![
                "network".to_owned(),
                "connect".to_owned(),
                "bridge".to_owned(),
                names.sidecar.clone(),
            ],
            cancel,
        )
        .await
        .map_err(|e| failed(e, stage))?;
    let document = docker
        .inspect("container", &names.sidecar, cancel)
        .await
        .map_err(|e| failed(e, stage))?;
    let deviations = sidecar_deviations(
        &document,
        (sidecar_image.uid, sidecar_image.gid),
        &names.network,
        sidecar_image.reference.reference(),
        shared.config.policy.apparmor_may_be_unavailable,
    );
    if !deviations.is_empty() {
        // The sidecar is part of the sandbox's posture: a sidecar that differs from its plan
        // fails closed like a container that differs from its spec.
        tracing::warn!(deviations = ?deviations, "the egress sidecar differs from its plan");
        return Err(SandboxError::PostureMismatch(PostureDiff {
            fields: deviations,
        }));
    }
    let observed = sidecar_alias(&document, &names.network, alias)
        .ok_or(SandboxError::ProvisionFailed(stage))?;
    docker
        .run(vec!["start".to_owned(), names.sidecar.clone()], cancel)
        .await
        .map_err(|e| failed(e, stage))?;
    Ok(observed)
}

async fn run_in_container(
    docker: &DockerClient,
    container: &str,
    words: &[&str],
    cancel: &dyn CancelSignal,
) -> Result<Vec<u8>, DockerError> {
    let mut args = vec!["exec".to_owned(), container.to_owned()];
    args.extend(words.iter().map(|w| (*w).to_owned()));
    let output = docker
        .run_raw(args, None, CHECK_TIMEOUT, 64 * 1024, cancel)
        .await?;
    if output.success() {
        Ok(output.stdout)
    } else {
        Err(DockerError::Failed {
            code: output.code,
            message: docker.safe_text(&output.stderr),
        })
    }
}

async fn build(
    shared: &Arc<Shared>,
    spec: &SandboxSpec,
    image: &CatalogImage,
    sidecar_image: Option<&CatalogImage>,
    guard: &mut Guard,
    cancel: &dyn CancelSignal,
) -> Result<DockerSession, SandboxError> {
    let docker = &shared.docker;
    let names = guard.names().clone();
    let owner = &shared.config.owner_labels;

    let observed_sidecar = match sidecar_image {
        Some(sidecar) => Some(prepare_network(shared, spec, sidecar, guard, cancel).await?),
        None => None,
    };
    check_cancel(cancel)?;

    // The token file, for an agent. The secret is registered with the redactor first, so nothing
    // that follows can print it.
    let mut registration = Registration {
        redactor: Arc::clone(&shared.redactor),
        handle: None,
    };
    let token_file = match &spec.job_token {
        Some(token) => {
            if let Ok(factory_domain::redaction::Registered::Added(handle)) =
                shared.redactor.register("job_token", token.secret.expose())
            {
                registration.handle = Some(handle);
            }
            guard.created.token = true;
            let file = shared
                .tokens
                .write(
                    &names.suffix,
                    &token.secret,
                    spec.hardening.uid,
                    spec.hardening.gid,
                )
                .map_err(|_| SandboxError::ProvisionFailed(ProvisionStage::TokenFile))?;
            Some(file)
        }
        None => None,
    };
    check_cancel(cancel)?;

    let cache_dirs: Vec<(String, &Path)> = shared
        .config
        .caches
        .iter()
        .map(|(name, path)| (name.clone(), path.as_path()))
        .collect();
    let container_labels = labels(
        Kind::Sandbox,
        spec,
        match &spec.network {
            NetworkAttachment::JobInternal { sidecar } => Some(sidecar.as_str()),
            NetworkAttachment::None => None,
        },
        owner,
    );
    let plan = CreatePlan {
        container: &names.container,
        image: image.reference.reference(),
        network: sidecar_image.map(|_| names.network.as_str()),
        labels: &container_labels,
        token_file: token_file.as_ref().map(|file| file.path()),
        cache_dirs: &cache_dirs,
    };
    let args = create_args(spec, &plan)
        .map_err(|_| SandboxError::ProvisionFailed(ProvisionStage::Create))?;
    guard.created.container = true;
    docker.run(args, cancel).await.map_err(|error| {
        if error.is_missing_object() {
            SandboxError::ImageUnavailable
        } else {
            failed(error, ProvisionStage::Create)
        }
    })?;
    check_cancel(cancel)?;

    // Inspect, read, compare. The container has not started.
    let document = docker
        .inspect("container", &names.container, cancel)
        .await
        .map_err(|e| failed(e, ProvisionStage::Inspect))?;
    let inspected = observe(&ObserveInput {
        document: &document,
        expected_image_id: &image.digest,
        job_network: sidecar_image.map(|_| names.network.as_str()),
        observed_sidecar: observed_sidecar.as_deref(),
        verified_at: shared.clock.now(),
    })
    .map_err(SandboxError::PostureMismatch)?;
    let mut report = inspected.report;
    // The self-check cannot have run yet. It is counted as passed for this comparison only and is
    // decided for real after the start.
    report.self_check_passed = true;
    normalize_file_share_sources(&mut report.mounts, &spec.expected_mounts());
    let mut fields = report.differences(spec, &shared.config.policy).fields;
    for extra in inspected.extra {
        if !fields.contains(&extra) {
            fields.push(extra);
        }
    }
    if !fields.is_empty() {
        return Err(SandboxError::PostureMismatch(PostureDiff { fields }));
    }
    check_cancel(cancel)?;

    docker
        .run(vec!["start".to_owned(), names.container.clone()], cancel)
        .await
        .map_err(|e| failed(e, ProvisionStage::Start))?;
    let started = Instant::now();

    // The runtime self-check: what the kernel says about a process inside the container.
    let status = run_in_container(
        docker,
        &names.container,
        &["cat", "/proc/self/status"],
        cancel,
    )
    .await
    .map_err(|e| failed(e, ProvisionStage::SelfCheck))?;
    if evaluate_self_check(&String::from_utf8_lossy(&status), spec.hardening.uid).is_err() {
        return Err(SandboxError::PostureMismatch(PostureDiff {
            fields: vec!["self_check"],
        }));
    }
    // The token must be readable by the sandbox user before the workload is released.
    if let Some(token) = &spec.job_token {
        let seen = run_in_container(docker, &names.container, &["cat", JOB_TOKEN_TARGET], cancel)
            .await
            .map_err(|e| failed(e, ProvisionStage::TokenFile))?;
        if seen != token.secret.expose().as_bytes() {
            return Err(SandboxError::ProvisionFailed(ProvisionStage::TokenFile));
        }
    }
    report.self_check_passed = true;
    report.verified_at = shared.clock.now();

    let moved = guard.take();
    let watch = watchdog::spawn(
        Arc::clone(shared),
        names.container.clone(),
        Limits {
            deadline: started + spec.limits.wall_clock,
            disk_cap_kib: u64::from(spec.limits.workspace_disk_mb.get()) * 1024,
            poll_interval: shared.config.watchdog.disk_poll_interval,
        },
    );
    Ok(DockerSession::new(
        Arc::clone(shared),
        SandboxId::new(names.container.clone()),
        report,
        names,
        moved,
        started + spec.limits.wall_clock,
        watch,
        registration.handle.take(),
    ))
}

/// A job token registered with the redactor. If provisioning fails before the session takes
/// the handle, the secret is forgotten again, so a failed job leaves nothing in the registry.
struct Registration {
    redactor: Arc<factory_domain::redaction::Redactor>,
    handle: Option<factory_domain::redaction::SecretHandle>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.redactor.forget(handle);
        }
    }
}
