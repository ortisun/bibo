//! Learning what became of the pull requests the factory opened (ports v1.5, ADR 0029).
//!
//! The factory opens a draft pull request and never merges it. A person merges it or closes it,
//! often days after the job has ended. Two process metrics need that fate (the rejection rate
//! and the cost of an accepted pull request), so this step asks the code host.
//!
//! # What one pass does
//!
//! Before each claim ([`BeforeClaim`]), for each tenant the worker serves, and at most once every
//! [`PASS_EVERY`] for a tenant:
//!
//! 1. It lists up to [`PER_PASS`] pull requests that are still open in the store and were never
//!    looked at, or were last looked at more than [`RECHECK_AFTER`] ago, the longest wait first
//!    (`PullRequestOps::list_pull_requests_to_check`).
//! 2. For each, it reads the repository's name from its row, asks the code host
//!    ([`PullRequestFateSource::observe`]) and records what it found
//!    (`PullRequestOps::record_pull_request_sighting`). A look that fails is recorded as a look
//!    that could not read, so a repository that was deleted is asked once an hour and not at
//!    every pass.
//! 3. It ends the credential of the pass.
//!
//! # What it never does
//!
//! It never fails a claim or a job: a failure is logged and the next pass tries again. It writes
//! nothing on the code host: the port has one read. It writes no audit record: it records a fact
//! and decides nothing. It never changes a fate that is recorded: the store keeps the first
//! decision.
//!
//! # The clocks
//!
//! "An hour ago" is judged against the time of the last look, which the database stamps, so the
//! pass reads the database's time and not the worker's. The five minutes between two passes are
//! the worker's own clock: they only spare the store a query.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{JobId, RepositoryId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::Timestamp;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{ChangeHost, PullRequestLifecycle, PullRequestRef};
use factory_ports::paths::RepoRef;
use factory_ports::pull_request_fate::{FateScope, PullRequestFateSource};
use factory_ports::store::{PullRequestRecord, PullRequestSighting, Store};

use crate::hooks::BeforeClaim;
use crate::indexing::ActiveJobs;
use crate::issue_status::Round;

/// How long the step waits before it looks at the same open pull request again: one hour.
pub const RECHECK_AFTER: Duration = Duration::from_secs(60 * 60);

/// How long one process waits between two passes for a tenant: five minutes.
pub const PASS_EVERY: Duration = Duration::from_secs(5 * 60);

/// The most pull requests one pass looks at for one tenant.
pub const PER_PASS: u32 = 20;

/// What the step is built from.
pub struct PullRequestFateSyncDeps {
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// The code host, through the port that reads a fate.
    pub source: Arc<dyn PullRequestFateSource>,
    /// The change host, to end the credential of each pass (`revoke_job_tokens`).
    pub changes: Arc<dyn ChangeHost>,
    /// The jobs the process is working on: a pass's session is noted there while it runs, so the
    /// sweep of ended jobs does not revoke its credential mid-way.
    pub jobs: Arc<ActiveJobs>,
    /// The worker's time, for the minutes between two passes.
    pub clock: Arc<dyn Clock>,
    /// Fresh identifiers: one session for each pass.
    pub ids: Arc<dyn IdGenerator>,
    /// The tenants this worker serves.
    pub tenants: Vec<TenantId>,
}

/// What one pass over a tenant did, for a test and the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pass {
    /// Pull requests found merged.
    pub merged: u32,
    /// Pull requests found closed without a merge.
    pub closed: u32,
    /// Pull requests found still open.
    pub still_open: u32,
    /// Looks that failed: the repository is unknown, the code host could not be read, or the
    /// sighting could not be stored.
    pub unread: u32,
}

impl Pass {
    /// How many pull requests the pass looked at.
    #[must_use]
    pub const fn looked_at(&self) -> u32 {
        self.merged + self.closed + self.still_open + self.unread
    }
}

/// How a call to [`PullRequestFateSync::pass`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassOutcome {
    /// The tenant had a pass less than [`PASS_EVERY`] ago.
    Recently,
    /// The store could not be read. The next pass tries again.
    StoreUnavailable,
    /// The pass ran.
    Ran(Pass),
}

/// The step that follows the pull requests of the factory.
pub struct PullRequestFateSync {
    deps: PullRequestFateSyncDeps,
    last: Mutex<BTreeMap<TenantId, Timestamp>>,
}

impl PullRequestFateSync {
    /// The step, over its collaborators.
    #[must_use]
    pub fn new(deps: PullRequestFateSyncDeps) -> Self {
        Self {
            deps,
            last: Mutex::new(BTreeMap::new()),
        }
    }

    /// Runs a pass for `tenant` unless one ran less than [`PASS_EVERY`] ago.
    pub async fn pass(&self, tenant: TenantId) -> PassOutcome {
        let now = self.deps.clock.now();
        {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            let recent = last
                .get(&tenant)
                .is_some_and(|at| now.duration_since(at).is_some_and(|gap| gap < PASS_EVERY));
            if recent {
                return PassOutcome::Recently;
            }
            last.insert(tenant, now);
        }
        self.pass_now(tenant).await
    }

    /// Runs a pass for `tenant` now.
    pub async fn pass_now(&self, tenant: TenantId) -> PassOutcome {
        let Some(due) = self.due(tenant).await else {
            tracing::warn!("the pull requests to look at cannot be listed; tried again later");
            return PassOutcome::StoreUnavailable;
        };
        if due.is_empty() {
            return PassOutcome::Ran(Pass::default());
        }
        let session = JobId::from_uuid(self.deps.ids.new_uuid());
        let round = Round::start(
            Arc::clone(&self.deps.jobs),
            Arc::clone(&self.deps.changes),
            session,
            tenant,
        );
        let mut pass = Pass::default();
        let mut names: BTreeMap<RepositoryId, Option<RepoRef>> = BTreeMap::new();
        for pull in due {
            let repo = match names.get(&pull.repository) {
                Some(known) => known.clone(),
                None => {
                    let found = self.repository(tenant, pull.repository).await;
                    names.insert(pull.repository, found.clone());
                    found
                }
            };
            let sighting = match repo {
                Some(repo) => self.look(tenant, session, repo, pull.number).await,
                None => PullRequestSighting::Unread,
            };
            let stored = self.record(tenant, &pull, sighting).await;
            match (stored, sighting) {
                (true, PullRequestSighting::Merged(_)) => pass.merged += 1,
                (true, PullRequestSighting::Closed(_)) => pass.closed += 1,
                (true, PullRequestSighting::Open) => pass.still_open += 1,
                (_, PullRequestSighting::Unread) | (false, _) => pass.unread += 1,
            }
        }
        round.finish().await;
        tracing::info!(
            merged = pass.merged,
            closed = pass.closed,
            still_open = pass.still_open,
            unread = pass.unread,
            "looked at the open pull requests of the factory"
        );
        PassOutcome::Ran(pass)
    }

    /// The open pull requests whose last look is more than [`RECHECK_AFTER`] before the
    /// database's time, or `None` when the store cannot be read.
    async fn due(&self, tenant: TenantId) -> Option<Vec<PullRequestRecord>> {
        let mut tx = self.deps.store.begin(TenantScope::new(tenant)).await.ok()?;
        let listed = async {
            let now = tx.database_time().await.ok()?;
            // A database whose clock is less than an hour after the first instant it can name
            // has nothing that old.
            let before = now.checked_sub(RECHECK_AFTER)?;
            tx.list_pull_requests_to_check(before, PER_PASS).await.ok()
        }
        .await;
        let _ = tx.rollback().await;
        listed
    }

    async fn repository(&self, tenant: TenantId, repository: RepositoryId) -> Option<RepoRef> {
        let mut tx = self.deps.store.begin(TenantScope::new(tenant)).await.ok()?;
        let found = tx.get_repository(repository).await;
        let _ = tx.rollback().await;
        RepoRef::parse(&found.ok()?.value.full_name).ok()
    }

    /// Asks the code host. An answer that cannot be had is a look that could not read.
    async fn look(
        &self,
        tenant: TenantId,
        session: JobId,
        repo: RepoRef,
        number: u64,
    ) -> PullRequestSighting {
        let scope = FateScope {
            tenant,
            session,
            repo: repo.clone(),
        };
        let pr = PullRequestRef { repo, number };
        match self.deps.source.observe(&scope, &pr).await {
            Ok(seen) => match (seen.lifecycle(), seen.decided_at()) {
                (PullRequestLifecycle::Open, _) => PullRequestSighting::Open,
                (PullRequestLifecycle::Merged, Some(at)) => PullRequestSighting::Merged(at),
                (PullRequestLifecycle::Closed, Some(at)) => PullRequestSighting::Closed(at),
                // The port gives a decided pull request its time; one without is not believed.
                (_, None) => PullRequestSighting::Unread,
            },
            // The error is one of a closed set and carries no text; the count is in the log line
            // of the pass.
            Err(_) => PullRequestSighting::Unread,
        }
    }

    /// Stores a sighting. True when it was stored.
    async fn record(
        &self,
        tenant: TenantId,
        pull: &PullRequestRecord,
        sighting: PullRequestSighting,
    ) -> bool {
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            return false;
        };
        let written = tx
            .record_pull_request_sighting(pull.repository, pull.number, sighting)
            .await;
        match written {
            Ok(_) => tx.commit().await.is_ok(),
            Err(_) => {
                let _ = tx.rollback().await;
                false
            }
        }
    }
}

#[async_trait(?Send)]
impl BeforeClaim for PullRequestFateSync {
    async fn before_claim(&self) {
        for tenant in &self.deps.tenants {
            let _ = self.pass(*tenant).await;
        }
    }
}
