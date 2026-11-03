//! Revokes the GitHub installation tokens of a job that is over.
//!
//! The adapter mints a token for a job, narrowed to one repository and to the permissions of the
//! stage, and keeps it in memory until the job ends (`ChangeHost::revoke_job_tokens`: "called at
//! job end, failure and cancel, and by the cleanup sweep"). Nothing in the engine holds the change
//! host, so before this step nothing called it, and a token lived until its hour ran out. This step
//! runs before each claim and revokes the live tokens of every job that is no longer open.
//!
//! # What "open" means
//!
//! A job is open when its status is not terminal (`COMPLETED`, `FAILED`, `CANCELLED`, `REJECTED`)
//! or when this process is working on it now. A job that waits for a person is open: revoking its
//! tokens would end it for the adapter, which refuses every later call for an ended job.
//!
//! # A job that stays blocked (LB-04)
//!
//! A job in `BLOCKED` is open, so the sweep above keeps its tokens, and until now they lived until
//! GitHub expired them. A job that waits for an operator to repair the environment, unblock it or
//! override it is not working, and its read token is of no use to anybody. With
//! [`RevokeEndedJobs::revoking_blocked_after`] the step also revokes the tokens of a job that has
//! been `BLOCKED` for longer than the bound of `credentials.github_app.installation_token`
//! (`revoke_when_blocked_after_s` of `policies/security.yaml`, 15 minutes). The job is **not** ended:
//! `ChangeHost::revoke_job_tokens` refuses every later call for the job, and an unblocked job has
//! to go on, so the release only revokes (`GithubAdapter::release_idle_after`) and the next call of
//! the job mints a new token. Only `BLOCKED` counts. A job that waits for a person to answer or
//! approve (`WAITING_FOR_HUMAN`), a paused job and an active one keep their tokens: the person is
//! expected, and the rule that a job which waits for a person keeps its token stays.
//!
//! The database does not say when a job became blocked, so the step notes the first pass that saw
//! the job blocked and counts from there. A job that leaves `BLOCKED` is forgotten, so a second
//! block counts anew. After a restart of the worker the count starts over, and so does the token:
//! the tokens live in the memory of the process that minted them. The bound is therefore never
//! reached early, and it can be reached up to one pass of the loop late.
//!
//! # It fails safe
//!
//! If the store cannot list the open jobs of a tenant, or the list is cut short, the step revokes
//! nothing in that pass. Revoking a token of a job that is still open would stop the job, and a
//! token that stays another poll interval expires within the hour anyway.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, Status as _};
use factory_domain::values::Timestamp;
use factory_github::GithubAdapter;
use factory_ports::clock::Clock;
use factory_ports::store::{JobFilter, Store};

use crate::hooks::BeforeClaim;
use crate::indexing::ActiveJobs;

/// The most jobs read in one page.
const PAGE: u32 = 200;

/// The most pages read for one tenant. A tenant with more open jobs than this is not swept.
const PAGES: u32 = 50;

/// Notes when each blocked job was first seen blocked, and says which have been blocked for the
/// bound. It reads no clock: the caller gives the time of the pass.
#[derive(Debug)]
pub struct BlockedFor {
    after: Duration,
    first_seen: HashMap<JobId, Timestamp>,
}

impl BlockedFor {
    /// A tracker for the bound `after`.
    #[must_use]
    pub fn new(after: Duration) -> Self {
        Self {
            after,
            first_seen: HashMap::new(),
        }
    }

    /// Notes the jobs that are blocked at `now`, forgets every job that is not, and returns the
    /// jobs that have been seen blocked for at least the bound. A job that is not in `blocked` is
    /// never returned, so a job in any other status keeps its tokens.
    pub fn observe(&mut self, blocked: &HashSet<JobId>, now: Timestamp) -> HashSet<JobId> {
        self.first_seen.retain(|job, _| blocked.contains(job));
        for job in blocked {
            self.first_seen.entry(*job).or_insert(now);
        }
        self.first_seen
            .iter()
            .filter(|(_, since)| since.checked_add(self.after).is_some_and(|due| due <= now))
            .map(|(job, _)| *job)
            .collect()
    }
}

/// What the step needs to release the tokens of a job that stays blocked.
struct ReleaseBlocked {
    clock: Arc<dyn Clock>,
    seen: Mutex<BlockedFor>,
}

/// Revokes the tokens of jobs that are over, before each claim, and (when it is given a bound) the
/// tokens of jobs that have been blocked for longer than the bound.
pub struct RevokeEndedJobs {
    adapter: GithubAdapter,
    store: Arc<dyn Store>,
    tenants: Vec<TenantId>,
    jobs: Arc<ActiveJobs>,
    blocked: Option<ReleaseBlocked>,
}

impl RevokeEndedJobs {
    /// A step for the tenants this worker serves.
    #[must_use]
    pub fn new(
        adapter: GithubAdapter,
        store: Arc<dyn Store>,
        tenants: Vec<TenantId>,
        jobs: Arc<ActiveJobs>,
    ) -> Self {
        Self {
            adapter,
            store,
            tenants,
            jobs,
            blocked: None,
        }
    }

    /// Also revokes (without ending the job) the tokens of a job that has been `BLOCKED` for
    /// `after` or longer, counted by `clock` (LB-04). A job in any other status keeps its tokens.
    #[must_use]
    pub fn revoking_blocked_after(mut self, after: Duration, clock: Arc<dyn Clock>) -> Self {
        self.blocked = Some(ReleaseBlocked {
            clock,
            seen: Mutex::new(BlockedFor::new(after)),
        });
        self
    }

    /// The jobs the database says are open, and among them the jobs that are `BLOCKED`, or `None`
    /// when that cannot be known. The jobs this process is working on are not in it; the sweep asks
    /// for them last.
    async fn open_jobs(&self) -> Option<(HashSet<JobId>, HashSet<JobId>)> {
        let open: Vec<JobStatus> = JobStatus::ALL
            .iter()
            .copied()
            .filter(|status| !status.is_terminal())
            .collect();
        let mut found = HashSet::new();
        let mut blocked = HashSet::new();
        for tenant in &self.tenants {
            let mut tx = self.store.begin(TenantScope::new(*tenant)).await.ok()?;
            let mut cursor = None;
            let mut pages = 0;
            loop {
                let page = tx
                    .list_jobs(
                        JobFilter {
                            statuses: open.clone(),
                            repository: None,
                        },
                        cursor.clone(),
                        PAGE,
                    )
                    .await;
                let Ok(page) = page else {
                    let _ = tx.rollback().await;
                    return None;
                };
                found.extend(page.rows.iter().map(|job| job.value.id));
                blocked.extend(
                    page.rows
                        .iter()
                        .filter(|job| job.value.status == JobStatus::Blocked)
                        .map(|job| job.value.id),
                );
                pages += 1;
                match page.next {
                    Some(next) if pages < PAGES => cursor = Some(next),
                    Some(_) => {
                        let _ = tx.rollback().await;
                        return None;
                    }
                    None => break,
                }
            }
            let _ = tx.rollback().await;
        }
        Some((found, blocked))
    }
}

#[async_trait(?Send)]
impl BeforeClaim for RevokeEndedJobs {
    async fn before_claim(&self) {
        let Some((open, blocked)) = self.open_jobs().await else {
            tracing::warn!(
                "the open jobs cannot be listed, so no installation token is revoked in this pass"
            );
            return;
        };
        // The jobs this process is working on are read when the tokens have been listed, not
        // before the database was asked: a round of the status step that began meanwhile is spared.
        let jobs = Arc::clone(&self.jobs);
        let revoked = self
            .adapter
            .sweep_orphans_after(&open, &move || jobs.running())
            .await;
        if revoked > 0 {
            tracing::info!(revoked, "installation tokens of ended jobs were revoked");
        }
        // A job that has stayed blocked for the bound gives up its tokens but is not ended.
        if let Some(release) = &self.blocked {
            let long_blocked = release
                .seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .observe(&blocked, release.clock.now());
            if !long_blocked.is_empty() {
                let jobs = Arc::clone(&self.jobs);
                let released = self
                    .adapter
                    .release_idle_after(&long_blocked, &move || jobs.running())
                    .await;
                if released > 0 {
                    tracing::info!(
                        released,
                        "installation tokens of jobs that stayed blocked were revoked"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a timestamp")
    }

    fn job(n: u128) -> JobId {
        JobId::from_uuid(uuid::Uuid::from_u128(n))
    }

    fn set(jobs: &[JobId]) -> HashSet<JobId> {
        jobs.iter().copied().collect()
    }

    #[test]
    fn a_job_is_long_blocked_only_after_the_bound_has_run_from_the_first_pass_that_saw_it() {
        let mut seen = BlockedFor::new(Duration::from_secs(3600));
        let blocked = set(&[job(1)]);
        assert!(
            seen.observe(&blocked, at("2026-11-03T10:00:00Z"))
                .is_empty()
        );
        assert!(
            seen.observe(&blocked, at("2026-11-03T10:59:59Z"))
                .is_empty()
        );
        assert_eq!(
            seen.observe(&blocked, at("2026-11-03T11:00:00Z")),
            set(&[job(1)])
        );
        // And it stays on the list while it stays blocked.
        assert_eq!(
            seen.observe(&blocked, at("2026-11-03T15:00:00Z")),
            set(&[job(1)])
        );
    }

    #[test]
    fn a_job_that_left_blocked_is_forgotten_and_a_second_block_counts_anew() {
        let mut seen = BlockedFor::new(Duration::from_secs(3600));
        let blocked = set(&[job(1)]);
        assert!(
            seen.observe(&blocked, at("2026-11-03T10:00:00Z"))
                .is_empty()
        );
        // The job went on (it is not blocked in this pass).
        assert!(
            seen.observe(&HashSet::new(), at("2026-11-03T10:50:00Z"))
                .is_empty()
        );
        // It is blocked again: the hour starts here, not at ten o'clock.
        assert!(
            seen.observe(&blocked, at("2026-11-03T11:10:00Z"))
                .is_empty()
        );
        assert!(
            seen.observe(&blocked, at("2026-11-03T12:09:00Z"))
                .is_empty()
        );
        assert_eq!(
            seen.observe(&blocked, at("2026-11-03T12:10:00Z")),
            set(&[job(1)])
        );
    }

    #[test]
    fn only_the_jobs_that_are_blocked_are_ever_returned() {
        let mut seen = BlockedFor::new(Duration::from_secs(60));
        let _ = seen.observe(&set(&[job(1), job(2)]), at("2026-11-03T10:00:00Z"));
        // Job 2 is no longer blocked (it waits for a person, say): it is not on the list however
        // long ago it was seen.
        assert_eq!(
            seen.observe(&set(&[job(1)]), at("2026-11-03T20:00:00Z")),
            set(&[job(1)])
        );
    }
}
