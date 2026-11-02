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
//! # It fails safe
//!
//! If the store cannot list the open jobs of a tenant, or the list is cut short, the step revokes
//! nothing in that pass. Revoking a token of a job that is still open would stop the job, and a
//! token that stays another poll interval expires within the hour anyway.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, Status as _};
use factory_github::GithubAdapter;
use factory_ports::store::{JobFilter, Store};

use crate::hooks::BeforeClaim;
use crate::indexing::ActiveJobs;

/// The most jobs read in one page.
const PAGE: u32 = 200;

/// The most pages read for one tenant. A tenant with more open jobs than this is not swept.
const PAGES: u32 = 50;

/// Revokes the tokens of jobs that are over, before each claim.
pub struct RevokeEndedJobs {
    adapter: GithubAdapter,
    store: Arc<dyn Store>,
    tenants: Vec<TenantId>,
    jobs: Arc<ActiveJobs>,
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
        }
    }

    /// The jobs the database says are open, or `None` when that cannot be known. The jobs this
    /// process is working on are not in it; the sweep asks for them last.
    async fn open_jobs(&self) -> Option<HashSet<JobId>> {
        let open: Vec<JobStatus> = JobStatus::ALL
            .iter()
            .copied()
            .filter(|status| !status.is_terminal())
            .collect();
        let mut found = HashSet::new();
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
        Some(found)
    }
}

#[async_trait(?Send)]
impl BeforeClaim for RevokeEndedJobs {
    async fn before_claim(&self) {
        let Some(open) = self.open_jobs().await else {
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
    }
}
