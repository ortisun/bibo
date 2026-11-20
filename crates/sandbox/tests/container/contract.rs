//! The shared sandbox contract suite, run against the Docker adapter with real containers.
//!
//! The suite is the one the in-memory fake passes. The adapter-specific parts are the subject:
//! how a spec is built for the images in `images.json`, how the daemon is made to "ignore" a
//! setting (a runner that rewrites the next `docker create`), how time passes (it sleeps), and
//! where the token file lives.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::AttemptId;
use factory_ports::sandbox::{Confinement, SandboxProfile, SandboxProvider, SandboxSpec};
use factory_sandbox::SystemProcessRunner;
use factory_testkit::contracts::sandbox::{DriftPart, SandboxSubject};

use crate::harness::{DriftRunner, Lab, Switch, daemon_lacks_apparmor};
use crate::support::{self, Scratch};

/// The subject: one lab, one switchable provider.
pub struct DockerSubject {
    lab: Lab,
    switch: Switch,
    drift: Arc<DriftRunner>,
    apparmor_policy: Mutex<bool>,
    lacks_apparmor: bool,
    /// A host directory the "extra mount" drift points at.
    _spare: Scratch,
}

fn build_provider(
    lab: &Lab,
    drift: &Arc<DriftRunner>,
    apparmor: bool,
) -> factory_sandbox::DockerSandboxProvider {
    let world = Lab::build(
        &lab.scope,
        &lab.images_json,
        &lab.token_root,
        apparmor,
        Some(Arc::clone(drift) as Arc<dyn factory_ports::process::ProcessRunner>),
        Arc::clone(&lab.world.artifacts),
    );
    world.provider
}

impl DockerSubject {
    pub fn new() -> Self {
        let lab = Lab::new(true);
        let spare = Scratch::new("spare");
        let drift = Arc::new(DriftRunner::new(
            SystemProcessRunner::new(),
            spare.path().to_path_buf(),
        ));
        let switch = Switch::new(build_provider(&lab, &drift, true));
        let lacks = daemon_lacks_apparmor(&lab.scope);
        Self {
            lab,
            switch,
            drift,
            apparmor_policy: Mutex::new(true),
            lacks_apparmor: lacks,
            _spare: spare,
        }
    }
}

impl Drop for DockerSubject {
    fn drop(&mut self) {
        // Sessions that a check left open start their own removal when they are dropped. Let
        // those finish before the lab removes what is labelled, so the two never collide.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.switch.drain());
        });
    }
}

#[async_trait]
impl SandboxSubject for DockerSubject {
    fn provider(&self) -> &dyn SandboxProvider {
        &self.switch
    }

    async fn read_output(&self, reference: &ArtifactRef) -> Result<Vec<u8>, String> {
        Ok(self.lab.read(reference).await)
    }

    fn spec(&self, profile: SandboxProfile, attempt: AttemptId) -> SandboxSpec {
        let mounts = self
            .lab
            .workspace(profile == SandboxProfile::Verify, &[".github"]);
        let mut spec = support::spec(
            profile,
            &self.lab.catalog(),
            &mounts,
            attempt,
            Duration::from_secs(120),
        );
        if *self.apparmor_policy.lock().expect("lock") && self.lacks_apparmor {
            // A host without AppArmor records that, and the policy of a development host allows it.
            spec.hardening.apparmor = Confinement::NotAvailable;
        }
        if profile == SandboxProfile::FetchDeps {
            spec.mounts.caches.clear();
        }
        spec
    }

    async fn advance_time(&self, by: Duration) {
        tokio::time::sleep(by).await;
    }

    async fn inject_posture_drift(&self, part: DriftPart) -> bool {
        if part == DriftPart::AppArmorNotAvailable {
            // The daemon either lacks AppArmor or it does not. Nothing is rewritten.
            return self.lacks_apparmor;
        }
        self.drift.arm(part);
        true
    }

    async fn token_file_present(&self) -> Option<bool> {
        Some(self.lab.token_files() > 0)
    }

    async fn allow_apparmor_unavailable(&self, allowed: bool) -> bool {
        *self.apparmor_policy.lock().expect("lock") = allowed;
        self.switch
            .replace(build_provider(&self.lab, &self.drift, allowed));
        true
    }
}
