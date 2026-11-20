//! The contract suite for `SandboxProvider` and `SandboxSession`: policy refusal, posture
//! verification, commands, timeouts, output caps, cancellation, the wall clock, teardown and the
//! orphan sweep.
//!
//! The commands the checks run are `echo`, `true`, `false`, `cat`, `sleep` and `head`. The image
//! the subject uses must provide them (any coreutils or busybox image does).

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::AttemptId;
use factory_ports::sandbox::{
    CacheMount, CacheName, ExecRequest, SandboxError, SandboxId, SandboxProfile, SandboxProvider,
    SandboxRule, SandboxSession, SandboxSpec, TeardownReason,
};

use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks, skip,
};
use crate::clock::FakeCancel;
use crate::fixtures::argv;

/// What the suite needs beyond the two sandbox ports.
#[async_trait]
pub trait SandboxSubject: Send + Sync {
    /// The provider under test. It starts with no sandboxes and is used by one check only.
    fn provider(&self) -> &dyn SandboxProvider;

    /// Reads stored command output. A fake indexes the artifact for a test tenant first, as the
    /// engine does; a real adapter reads through its store.
    async fn read_output(
        &self,
        reference: &factory_domain::contracts::ArtifactRef,
    ) -> Result<Vec<u8>, String>;

    /// A spec the provider's policy accepts, for the profile and attempt.
    fn spec(&self, profile: SandboxProfile, attempt: AttemptId) -> SandboxSpec;

    /// Lets `by` of wall-clock time pass. A fake moves its clock. A real adapter sleeps.
    async fn advance_time(&self, by: Duration);

    /// Makes the next container the provider builds differ from its spec, as if the daemon had
    /// ignored a setting. Returns `false` when the subject cannot do that, and the check is then
    /// reported as skipped.
    async fn inject_posture_drift(&self, part: DriftPart) -> bool;

    /// True when a job token file for any sandbox of this provider exists on the host. `None`
    /// when the subject cannot look.
    async fn token_file_present(&self) -> Option<bool>;

    /// Sets whether the provider's policy accepts a daemon without AppArmor. Returns `false`
    /// when the subject cannot change its policy.
    async fn allow_apparmor_unavailable(&self, allowed: bool) -> bool;
}

/// A part of the posture that a daemon can be made to get wrong, for the drift checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftPart {
    /// A security setting.
    Hardening,
    /// The image.
    Image,
    /// A resource limit.
    Limits,
    /// The network.
    Network,
    /// A mount nobody asked for.
    ExtraMount,
    /// A read-only mount that is writable.
    WritableMount,
    /// The environment.
    Env,
    /// AppArmor reported as not available.
    AppArmorNotAvailable,
}

/// A check of the sandbox contract.
pub type SandboxCheck = Check<dyn SandboxSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: SandboxSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn SandboxSubject>
    })
    .await
}

/// Every check of the sandbox contract.
#[must_use]
pub fn checks() -> Vec<SandboxCheck> {
    check_list![dyn SandboxSubject;
        every_profile_can_be_created_and_its_posture_matches_the_spec,
        a_spec_weaker_than_the_policy_is_refused_and_builds_nothing,
        a_network_that_does_not_suit_the_profile_is_refused,
        a_container_that_differs_from_its_spec_is_removed_and_never_returned,
        a_command_runs_as_an_argument_vector_and_its_output_is_stored,
        exit_codes_are_reported_as_they_are,
        standard_input_reaches_the_command,
        a_missing_program_is_a_failed_command,
        a_command_past_its_timeout_is_killed_and_flagged,
        output_beyond_the_cap_is_cut_and_flagged,
        a_cancel_that_is_already_set_stops_the_command_before_it_starts,
        a_cancel_during_a_long_command_ends_it_promptly,
        a_sandbox_past_its_wall_clock_refuses_commands,
        teardown_removes_the_sandbox,
        sweeping_removes_only_sandboxes_whose_attempt_is_not_live,
        a_different_image_is_a_mismatch,
        a_drifted_limit_is_a_mismatch,
        a_drifted_network_is_a_mismatch,
        an_extra_mount_is_a_mismatch,
        a_writable_mount_that_should_be_read_only_is_a_mismatch,
        a_drifted_environment_is_a_mismatch,
        a_zero_wall_clock_is_refused,
        a_writable_cache_is_refused_outside_fetch_deps,
        the_job_token_file_is_absent_after_stop_and_remove,
        the_job_token_never_shows_in_debug_output,
        apparmor_not_available_is_accepted_only_by_policy,
        a_cancelled_create_removes_what_it_made,
    ]
}

/// The one check a fake cannot fail: the types decide what `Debug` shows.
pub const WAIVERS: &[Waiver] = &[Waiver {
    check: "the_job_token_never_shows_in_debug_output",
    reason: "JobTokenSecret implements Debug in the ports crate, so no sandbox fake can make a spec or a posture report show the secret.",
    trigger: "None: the unit test of JobTokenSecret in factory-ports is the proof. The check guards the real adapter's own types and logs.",
}];

fn attempt(n: u128) -> AttemptId {
    AttemptId::from_uuid(factory_ports::clock::Uuid::from_u128(
        (n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ))
}

fn request(words: &[&str]) -> ExecRequest {
    ExecRequest {
        argv: argv(words),
        cwd: None,
        stdin: None,
        timeout: Duration::from_secs(30),
        max_output_bytes: 1024 * 1024,
    }
}

async fn create(
    subject: &dyn SandboxSubject,
    profile: SandboxProfile,
    n: u128,
) -> Result<Box<dyn SandboxSession>, String> {
    subject
        .provider()
        .create_verified(subject.spec(profile, attempt(n)), &FakeCancel::new())
        .await
        .ctx("create a sandbox")
}

async fn read(
    subject: &dyn SandboxSubject,
    reference: &factory_domain::contracts::ArtifactRef,
) -> Result<Vec<u8>, String> {
    subject.read_output(reference).await
}

async fn every_profile_can_be_created_and_its_posture_matches_the_spec(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    for (n, profile) in [
        SandboxProfile::FetchDeps,
        SandboxProfile::Agent,
        SandboxProfile::Verify,
    ]
    .into_iter()
    .enumerate()
    {
        let spec = subject.spec(profile, attempt(n as u128 + 1));
        let session = subject
            .provider()
            .create_verified(spec.clone(), &FakeCancel::new())
            .await
            .ctx(&format!("create a {} sandbox", profile.as_str()))?;
        ensure_eq!(
            session.posture().observed,
            spec.hardening.clone(),
            "the posture of the {} sandbox",
            profile.as_str()
        );
        ensure_eq!(
            session.posture().image.clone(),
            spec.image.clone(),
            "the image"
        );
        ensure!(
            session.posture().self_check_passed,
            "the runtime self-check must have passed"
        );
        ensure!(!session.id().as_str().is_empty(), "a sandbox needs a name");
    }
    Ok(())
}

async fn a_spec_weaker_than_the_policy_is_refused_and_builds_nothing(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut spec = subject.spec(SandboxProfile::Agent, attempt(1));
    spec.hardening.privileged = true;
    spec.hardening.cap_add = vec!["SYS_ADMIN".to_owned()];
    match subject
        .provider()
        .create_verified(spec, &FakeCancel::new())
        .await
    {
        Err(SandboxError::PolicyViolation(violation)) => {
            ensure!(
                violation.rules.contains(&SandboxRule::Privileged),
                "the refusal must name the privileged setting, but listed {:?}",
                violation.rules
            );
        }
        Err(other) => {
            return Err(format!(
                "a privileged spec: expected PolicyViolation but found {other:?}"
            ));
        }
        Ok(_) => return Err("a privileged spec: the provider returned a sandbox".to_owned()),
    }
    let swept = subject.provider().sweep_orphans(&[]).await.ctx("sweep")?;
    ensure_eq!(swept.len(), 0, "sandboxes that exist after a refused spec");
    Ok(())
}

async fn a_network_that_does_not_suit_the_profile_is_refused(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut spec = subject.spec(SandboxProfile::Verify, attempt(1));
    spec.network = factory_ports::sandbox::NetworkAttachment::JobInternal {
        sidecar: "sidecar-x".to_owned(),
    };
    ensure_err!(
        subject
            .provider()
            .create_verified(spec, &FakeCancel::new())
            .await,
        SandboxError::PolicyViolation(_),
        "a verify sandbox with a network"
    );
    Ok(())
}

async fn a_container_that_differs_from_its_spec_is_removed_and_never_returned(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    if !subject.inject_posture_drift(DriftPart::Hardening).await {
        skip!("this subject cannot make a container differ from its spec");
    }
    let spec = subject.spec(SandboxProfile::Agent, attempt(1));
    ensure_err!(
        subject
            .provider()
            .create_verified(spec, &FakeCancel::new())
            .await,
        SandboxError::PostureMismatch(_),
        "a container that does not match its spec"
    );
    let left = subject.provider().sweep_orphans(&[]).await.ctx("sweep")?;
    ensure_eq!(left.len(), 0, "containers left behind by the failed check");
    Ok(())
}

async fn a_command_runs_as_an_argument_vector_and_its_output_is_stored(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut session = create(subject, SandboxProfile::Verify, 1).await?;
    let cancel = FakeCancel::new();
    // `;` and `$HOME` are plain text to a command with no shell.
    let result = session
        .exec(request(&["echo", "hello;", "$HOME"]), &cancel)
        .await
        .ctx("exec")?;
    ensure_eq!(result.exit_code, Some(0), "the exit code");
    ensure_eq!(result.signal, None, "the signal");
    ensure!(!result.timed_out, "a quick command must not time out");
    ensure!(
        !result.oom_killed,
        "a quick command must not run out of memory"
    );
    ensure_eq!(
        read(subject, &result.stdout).await?,
        b"hello; $HOME\n".to_vec(),
        "standard output (no shell may expand the argument)"
    );
    ensure_eq!(
        read(subject, &result.stderr).await?,
        Vec::<u8>::new(),
        "standard error"
    );
    ensure!(
        result.started_at <= result.finished_at,
        "a command cannot end before it starts"
    );
    Ok(())
}

async fn exit_codes_are_reported_as_they_are(subject: &dyn SandboxSubject) -> Result<(), String> {
    let mut session = create(subject, SandboxProfile::Verify, 1).await?;
    let cancel = FakeCancel::new();
    let ok = session
        .exec(request(&["true"]), &cancel)
        .await
        .ctx("true")?;
    ensure_eq!(ok.exit_code, Some(0), "the exit code of `true`");
    let failed = session
        .exec(request(&["false"]), &cancel)
        .await
        .ctx("false")?;
    ensure_eq!(failed.exit_code, Some(1), "the exit code of `false`");
    Ok(())
}

async fn standard_input_reaches_the_command(subject: &dyn SandboxSubject) -> Result<(), String> {
    let mut session = create(subject, SandboxProfile::Verify, 1).await?;
    let cancel = FakeCancel::new();
    let mut req = request(&["cat"]);
    req.stdin = Some(b"typed in".to_vec());
    let result = session.exec(req, &cancel).await.ctx("cat")?;
    ensure_eq!(
        read(subject, &result.stdout).await?,
        b"typed in".to_vec(),
        "what `cat` printed"
    );
    Ok(())
}

async fn a_missing_program_is_a_failed_command(subject: &dyn SandboxSubject) -> Result<(), String> {
    let mut session = create(subject, SandboxProfile::Verify, 1).await?;
    let cancel = FakeCancel::new();
    let result = session
        .exec(request(&["no-such-program-in-the-image"]), &cancel)
        .await
        .ctx("exec")?;
    ensure!(
        result.exit_code.is_some_and(|code| code != 0) || result.signal.is_some(),
        "a program that does not exist must not look like a success: exit {:?}, signal {:?}",
        result.exit_code,
        result.signal
    );
    Ok(())
}

async fn a_command_past_its_timeout_is_killed_and_flagged(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut session = create(subject, SandboxProfile::Verify, 1).await?;
    let cancel = FakeCancel::new();
    let mut req = request(&["sleep", "3600"]);
    req.timeout = Duration::from_secs(1);
    let result = tokio::time::timeout(Duration::from_secs(30), session.exec(req, &cancel))
        .await
        .map_err(|_| {
            "a command with a 1 second timeout was still running after 30 seconds".to_owned()
        })?
        .ctx("exec")?;
    ensure!(
        result.timed_out,
        "a command past its timeout must be flagged timed_out"
    );
    ensure_eq!(result.exit_code, None, "a killed command has no exit code");
    ensure!(
        result.signal.is_some(),
        "a killed command reports the signal that ended it"
    );
    Ok(())
}

async fn output_beyond_the_cap_is_cut_and_flagged(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut session = create(subject, SandboxProfile::Verify, 1).await?;
    let cancel = FakeCancel::new();
    let mut capped = request(&["head", "-c", "5000", "/dev/zero"]);
    capped.max_output_bytes = 100;
    let cut = session.exec(capped, &cancel).await.ctx("capped exec")?;
    ensure_eq!(
        read(subject, &cut.stdout).await?.len(),
        100,
        "bytes kept under a cap of 100"
    );
    ensure!(cut.stdout_truncated, "cut output must be flagged");
    let mut roomy = request(&["head", "-c", "5000", "/dev/zero"]);
    roomy.max_output_bytes = 10_000;
    let whole = session.exec(roomy, &cancel).await.ctx("roomy exec")?;
    ensure_eq!(
        read(subject, &whole.stdout).await?.len(),
        5000,
        "bytes kept under a cap of 10000"
    );
    ensure!(
        !whole.stdout_truncated,
        "output under the cap must not be flagged"
    );
    Ok(())
}

async fn a_cancel_that_is_already_set_stops_the_command_before_it_starts(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut session = create(subject, SandboxProfile::Verify, 1).await?;
    let cancel = FakeCancel::new();
    cancel.cancel();
    ensure_err!(
        session
            .exec(request(&["echo", "must-not-run"]), &cancel)
            .await,
        SandboxError::Cancelled,
        "a command started after the cancel was set"
    );
    Ok(())
}

async fn a_cancel_during_a_long_command_ends_it_promptly(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut session = create(subject, SandboxProfile::Verify, 1).await?;
    let cancel = FakeCancel::new();
    let mut req = request(&["sleep", "3600"]);
    req.timeout = Duration::from_secs(7200);
    let run = tokio::time::timeout(Duration::from_secs(10), session.exec(req, &cancel));
    let trigger = async {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(run, trigger);
    match outcome {
        Err(_) => Err("the command was still running 10 seconds after the cancel".to_owned()),
        Ok(Err(SandboxError::Cancelled)) => Ok(()),
        Ok(Err(other)) => Err(format!(
            "a cancelled command: expected Cancelled but found {other:?}"
        )),
        Ok(Ok(result)) => Err(format!(
            "a cancelled command returned a result (exit {:?}, signal {:?}, timed_out {})",
            result.exit_code, result.signal, result.timed_out
        )),
    }
}

async fn a_sandbox_past_its_wall_clock_refuses_commands(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut spec = subject.spec(SandboxProfile::Verify, attempt(1));
    spec.limits.wall_clock = Duration::from_secs(5);
    let mut session = subject
        .provider()
        .create_verified(spec, &FakeCancel::new())
        .await
        .ctx("create")?;
    let cancel = FakeCancel::new();
    session
        .exec(request(&["true"]), &cancel)
        .await
        .ctx("a command inside the wall clock")?;
    subject.advance_time(Duration::from_secs(6)).await;
    ensure_err!(
        session.exec(request(&["true"]), &cancel).await,
        SandboxError::Timeout,
        "a command after the wall-clock limit"
    );
    Ok(())
}

async fn teardown_removes_the_sandbox(subject: &dyn SandboxSubject) -> Result<(), String> {
    let session = create(subject, SandboxProfile::Verify, 1).await?;
    let id: SandboxId = session.id().clone();
    let report = session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .ctx("stop and remove")?;
    ensure_eq!(report.sandbox, id, "the sandbox the report names");
    ensure_eq!(
        report.reason,
        TeardownReason::Completed,
        "the reason in the report"
    );
    let left = subject.provider().sweep_orphans(&[]).await.ctx("sweep")?;
    ensure_eq!(left.len(), 0, "sandboxes left after teardown");
    Ok(())
}

async fn sweeping_removes_only_sandboxes_whose_attempt_is_not_live(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let mut one = create(subject, SandboxProfile::Verify, 1).await?;
    let mut two = create(subject, SandboxProfile::Verify, 2).await?;
    let orphan = create(subject, SandboxProfile::Verify, 3).await?;
    let orphan_id = orphan.id().clone();

    let swept = subject
        .provider()
        .sweep_orphans(&[attempt(1), attempt(2)])
        .await
        .ctx("sweep")?;
    ensure_eq!(swept, vec![orphan_id], "the sandboxes the sweep removed");
    let again = subject
        .provider()
        .sweep_orphans(&[attempt(1), attempt(2)])
        .await
        .ctx("second sweep")?;
    ensure_eq!(again.len(), 0, "a second sweep with the same live list");

    let cancel = FakeCancel::new();
    one.exec(request(&["true"]), &cancel)
        .await
        .ctx("a live sandbox after the sweep")?;
    two.exec(request(&["true"]), &cancel)
        .await
        .ctx("the other live sandbox after the sweep")?;
    Ok(())
}

// ---- ports-v1.1: the posture is compared in every part ----------------------------------------------

async fn drift_is_a_mismatch(
    subject: &dyn SandboxSubject,
    part: DriftPart,
    field: &str,
) -> Result<(), String> {
    if !subject.inject_posture_drift(part).await {
        skip!("this subject cannot make a container differ from its spec in {part:?}");
    }
    let spec = subject.spec(SandboxProfile::Agent, attempt(1));
    match subject
        .provider()
        .create_verified(spec, &FakeCancel::new())
        .await
    {
        Err(SandboxError::PostureMismatch(diff)) => {
            ensure!(
                diff.fields.contains(&leak(field)),
                "the mismatch should name {field}, but named {:?}",
                diff.fields
            );
        }
        Err(other) => {
            return Err(format!(
                "a drifted {field}: expected PostureMismatch but found {other:?}"
            ));
        }
        Ok(_) => {
            return Err(format!(
                "a drifted {field}: the provider returned a sandbox"
            ));
        }
    }
    let left = subject.provider().sweep_orphans(&[]).await.ctx("sweep")?;
    ensure_eq!(left.len(), 0, "containers left behind by the failed check");
    Ok(())
}

/// The names in a mismatch are `&'static str`; the check compares by text.
fn leak(field: &str) -> &'static str {
    match field {
        "image" => "image",
        "limits" => "limits",
        "network" => "network",
        "mounts" => "mounts",
        "env" => "env",
        _ => "hardening",
    }
}

async fn a_different_image_is_a_mismatch(subject: &dyn SandboxSubject) -> Result<(), String> {
    drift_is_a_mismatch(subject, DriftPart::Image, "image").await
}

async fn a_drifted_limit_is_a_mismatch(subject: &dyn SandboxSubject) -> Result<(), String> {
    drift_is_a_mismatch(subject, DriftPart::Limits, "limits").await
}

async fn a_drifted_network_is_a_mismatch(subject: &dyn SandboxSubject) -> Result<(), String> {
    drift_is_a_mismatch(subject, DriftPart::Network, "network").await
}

async fn an_extra_mount_is_a_mismatch(subject: &dyn SandboxSubject) -> Result<(), String> {
    drift_is_a_mismatch(subject, DriftPart::ExtraMount, "mounts").await
}

async fn a_writable_mount_that_should_be_read_only_is_a_mismatch(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    drift_is_a_mismatch(subject, DriftPart::WritableMount, "mounts").await
}

async fn a_drifted_environment_is_a_mismatch(subject: &dyn SandboxSubject) -> Result<(), String> {
    drift_is_a_mismatch(subject, DriftPart::Env, "env").await
}

async fn a_zero_wall_clock_is_refused(subject: &dyn SandboxSubject) -> Result<(), String> {
    let mut spec = subject.spec(SandboxProfile::Agent, attempt(1));
    spec.limits.wall_clock = Duration::ZERO;
    match subject
        .provider()
        .create_verified(spec, &FakeCancel::new())
        .await
    {
        Err(SandboxError::PolicyViolation(violation)) => {
            ensure!(
                violation
                    .rules
                    .contains(&SandboxRule::LimitIsZero("wall_clock")),
                "the refusal must name the zero wall clock, but listed {:?}",
                violation.rules
            );
            Ok(())
        }
        Err(other) => Err(format!(
            "a zero wall clock: expected PolicyViolation but found {other:?}"
        )),
        Ok(_) => Err("a zero wall clock: the provider returned a sandbox".to_owned()),
    }
}

async fn a_writable_cache_is_refused_outside_fetch_deps(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let cache = |writable| CacheMount {
        name: CacheName(factory_domain::values::Slug::parse("cargo-registry").expect("a slug")),
        writable,
    };
    let mut agent = subject.spec(SandboxProfile::Agent, attempt(1));
    agent.mounts.caches = vec![cache(true)];
    ensure_err!(
        subject
            .provider()
            .create_verified(agent, &FakeCancel::new())
            .await,
        SandboxError::PolicyViolation(_),
        "an agent sandbox with a writable cache"
    );
    let mut fetch = subject.spec(SandboxProfile::FetchDeps, attempt(2));
    fetch.mounts.caches = vec![cache(true)];
    subject
        .provider()
        .create_verified(fetch, &FakeCancel::new())
        .await
        .ctx("a fetch_deps sandbox may write its cache")?;
    Ok(())
}

async fn the_job_token_file_is_absent_after_stop_and_remove(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let Some(before) = subject.token_file_present().await else {
        skip!("this subject cannot look for the token file");
    };
    ensure!(!before, "no token file exists before a sandbox is made");
    let session = create(subject, SandboxProfile::Agent, 1).await?;
    ensure_eq!(
        subject.token_file_present().await,
        Some(true),
        "the file exists while the sandbox lives"
    );
    session
        .stop_and_remove(TeardownReason::Completed)
        .await
        .ctx("stop and remove")?;
    ensure_eq!(
        subject.token_file_present().await,
        Some(false),
        "the file is gone after teardown"
    );
    Ok(())
}

async fn the_job_token_never_shows_in_debug_output(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let spec = subject.spec(SandboxProfile::Agent, attempt(1));
    let secret = spec
        .job_token
        .as_ref()
        .map(|mount| mount.secret.expose().to_owned())
        .ok_or("an agent spec must carry a job token")?;
    ensure!(
        !format!("{spec:?}").contains(&secret),
        "the spec's Debug output shows the secret"
    );
    let session = subject
        .provider()
        .create_verified(spec, &FakeCancel::new())
        .await
        .ctx("create")?;
    ensure!(
        !format!("{:?}", session.posture()).contains(&secret),
        "the posture report's Debug output shows the secret"
    );
    Ok(())
}

async fn apparmor_not_available_is_accepted_only_by_policy(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    if !subject.allow_apparmor_unavailable(false).await {
        skip!("this subject cannot change its policy");
    }
    if !subject
        .inject_posture_drift(DriftPart::AppArmorNotAvailable)
        .await
    {
        skip!("this subject cannot make the daemon lack AppArmor");
    }
    let spec = subject.spec(SandboxProfile::Agent, attempt(1));
    ensure_err!(
        subject
            .provider()
            .create_verified(spec.clone(), &FakeCancel::new())
            .await,
        SandboxError::PostureMismatch(_),
        "a daemon without AppArmor on a production policy"
    );
    subject.allow_apparmor_unavailable(true).await;
    subject
        .inject_posture_drift(DriftPart::AppArmorNotAvailable)
        .await;
    subject
        .provider()
        .create_verified(spec, &FakeCancel::new())
        .await
        .ctx("a daemon without AppArmor on a development policy")?;
    Ok(())
}

async fn a_cancelled_create_removes_what_it_made(
    subject: &dyn SandboxSubject,
) -> Result<(), String> {
    let cancel = FakeCancel::new();
    cancel.cancel();
    let spec = subject.spec(SandboxProfile::Agent, attempt(1));
    ensure_err!(
        subject.provider().create_verified(spec, &cancel).await,
        SandboxError::Cancelled,
        "a create whose cancel signal is set"
    );
    let left = subject.provider().sweep_orphans(&[]).await.ctx("sweep")?;
    ensure_eq!(left.len(), 0, "sandboxes left behind by a cancelled create");
    if let Some(present) = subject.token_file_present().await {
        ensure!(
            !present,
            "a token file is left behind by a cancelled create"
        );
    }
    Ok(())
}
