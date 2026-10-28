//! Removing what a sandbox made: the container, the sidecar, the network and the token file.
//!
//! [`remove_all`] is the one routine for every path: a failed provisioning, a cancelled one, a
//! posture mismatch, the end of a session and the drop guard. It never stops at the first
//! failure, treats "no such object" as success (so it is idempotent), and reports whether
//! something may still exist.

use std::sync::Arc;
use std::time::Duration;

use super::Shared;
use crate::container::docker::{DockerClient, DockerError, NeverCancel};
use crate::container::names::SandboxNames;

/// Which objects exist, or may exist. A flag is set before the command that creates the object,
/// so a command that was cancelled half way is still cleaned up.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Created {
    pub network: bool,
    pub sidecar: bool,
    pub container: bool,
    pub token: bool,
}

/// How long to wait before looking again for a container whose `create` was interrupted: the
/// daemon finishes a request even when its client has gone.
const LATE_CREATE_WAIT: Duration = Duration::from_millis(400);

async fn remove_container(docker: &DockerClient, name: &str) -> bool {
    match docker
        .run(
            vec![
                "rm".to_owned(),
                "--force".to_owned(),
                "--volumes".to_owned(),
                name.to_owned(),
            ],
            &NeverCancel,
        )
        .await
    {
        Ok(_) => true,
        Err(error) => error.is_missing_object() && !matches!(error, DockerError::Unavailable),
    }
}

async fn remove_network(docker: &DockerClient, name: &str) -> bool {
    match docker
        .run(
            vec!["network".to_owned(), "rm".to_owned(), name.to_owned()],
            &NeverCancel,
        )
        .await
    {
        Ok(_) => true,
        Err(error) => error.is_missing_object(),
    }
}

/// Removes everything flagged in `what` for the sandbox `names`. Returns true when something may
/// still exist.
pub(crate) async fn remove_all(
    shared: &Shared,
    names: &SandboxNames,
    what: Created,
    interrupted: bool,
) -> bool {
    let mut leaked = false;
    for (flag, name) in [
        (what.container, &names.container),
        (what.sidecar, &names.sidecar),
    ] {
        if !flag {
            continue;
        }
        let mut gone = remove_container(&shared.docker, name).await;
        if gone && interrupted {
            tokio::time::sleep(LATE_CREATE_WAIT).await;
            gone = remove_container(&shared.docker, name).await;
        }
        if !gone {
            tracing::warn!(container = %name, "a sandbox container could not be removed");
        }
        leaked |= !gone;
    }
    if what.network && !remove_network(&shared.docker, &names.network).await {
        tracing::warn!(network = %names.network, "a sandbox network could not be removed");
        leaked = true;
    }
    if what.token && shared.tokens.remove(&names.suffix).is_err() {
        tracing::warn!(sandbox = %names.suffix, "a job token file could not be removed");
        leaked = true;
    }
    leaked
}

/// Removes what a sandbox made when it is dropped without having been torn down: a provisioning
/// future that was dropped, or a session that was dropped. The janitor is the backstop where no
/// runtime is left to run this.
pub(crate) struct Guard {
    shared: Arc<Shared>,
    names: SandboxNames,
    pub created: Created,
    armed: bool,
}

impl Guard {
    pub fn new(shared: Arc<Shared>, names: SandboxNames) -> Self {
        Self {
            shared,
            names,
            created: Created::default(),
            armed: true,
        }
    }

    pub fn names(&self) -> &SandboxNames {
        &self.names
    }

    /// Removes everything now and disarms the guard. True when something may still exist.
    pub async fn cleanup(&mut self, interrupted: bool) -> bool {
        self.armed = false;
        remove_all(&self.shared, &self.names, self.created, interrupted).await
    }

    /// Moves the responsibility to a new guard with the same names and flags, and disarms this
    /// one. The session holds the new guard.
    pub fn take(&mut self) -> Guard {
        self.armed = false;
        Guard {
            shared: Arc::clone(&self.shared),
            names: self.names.clone(),
            created: self.created,
            armed: true,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let names = self.names.clone();
        let created = self.created;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                remove_all(&shared, &names, created, true).await;
            });
        }
    }
}
