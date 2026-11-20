//! The engine's `Authority` seam over the allowlist file and the principal rows.
//!
//! Authority comes from the named allowlist of the protected configuration and never from a
//! GitHub role (ADR 0009 item 5). Every call reads the file as it is now, so removing a person
//! takes effect on the next decision. A file that cannot be read is `AuthorityError::Unavailable`,
//! which the engine treats as a denial.
//!
//! # Admission
//!
//! `Authority::admission(tenant, requester, repository)` is asked with the repository, so the three
//! facts that depend on it are read from its row and its jobs:
//!
//! * `repository_registered_and_enabled` is true when the row exists and is switched on.
//! * `protection_preflight_passed` is the result recorded for the repository. A repository with no
//!   passed preflight is admitted and limited to level L0 (ADR 0009).
//! * `tenant_within_job_quota` counts the repository's jobs that have not ended against the sum of
//!   the policy's running and queued caps per repository.
//!
//! # The ceilings of a day
//!
//! Admission also reads what was used since the start of the day and asks the budget policy
//! (`BudgetPolicy::check`) whether a ceiling of `budgets.hard_ceilings` is reached:
//!
//! * `repository_day_budget_has_room`: what the repository's jobs spent, and how many of its jobs
//!   were started (`per_repo_day`).
//! * `organization_day_budget_has_room`: what all the jobs of the tenant spent (`per_org_day`). A
//!   tenant is an organization.
//!
//! The day is the UTC calendar day of the database clock (ADR 0011: the canonical time is UTC and
//! the database is the clock of a decision). The spend is the cost the runtime adapters reported
//! for each ended attempt, which the engine wrote on the event that ended it. No price is applied
//! here. An attempt that is still running has reported nothing yet, so the ceiling can be passed
//! by what the running attempts spend; each of those is bounded by its own token ceiling.
//!
//! A reading that cannot be made (the events of a job cannot be read, or a cost is not a number)
//! is handed to the policy as not-a-number, which the policy counts as the ceiling reached. The
//! job is then refused, and the audit record of the refusal names the ceiling.
//!
//! # The running cap
//!
//! `concurrency_allows` is asked before an attempt starts. It finds the repository of the job and
//! counts the other jobs of that repository that have a stage run in `RUNNING`. At the cap
//! (`budgets.concurrency.max_running_jobs_per_repo`) the attempt does not start, and the engine
//! looks at the stage run again later. The count and the start are two transactions, so two
//! workers that claim at the same instant can each see room; one worker, which is how Slice 1
//! runs, cannot.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::machines::guards::AdmissionFacts;
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::authority::RepositoryIdentity;
use factory_domain::policy::budget::{BudgetVerdict, Metric, Reading, Scope};
use factory_domain::policy::decision::Designation;
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus, Status};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{Fidelity, HumanRole};
use factory_ports::clock::Clock;
use factory_ports::store::{
    Job, JobFilter, OutboxSeq, PrincipalKind, Store, StoreError, Tx, Versioned,
};
use factory_workflow::commands::{Authority, AuthorityError};
use factory_workflow::engine::attempt_cost_micro_usd;

use crate::seams::FileAllowlist;

/// How many rows one read of a listing asks for.
const PAGE: u32 = 500;

/// Every job the filter selects, read page by page to the end.
async fn all_jobs(tx: &mut dyn Tx, filter: JobFilter) -> Result<Vec<Versioned<Job>>, StoreError> {
    let mut jobs = Vec::new();
    let mut after = None;
    loop {
        let page = tx.list_jobs(filter.clone(), after, PAGE).await?;
        jobs.extend(page.rows);
        match page.next {
            Some(next) => after = Some(next),
            None => return Ok(jobs),
        }
    }
}

/// What the ended attempts of `job` reported as spent from `since` on, in millionths of a dollar.
/// `None` when it cannot be said: the events cannot be read, or one states a cost that is not a
/// number.
async fn spent_since(tx: &mut dyn Tx, job: &Job, since: Timestamp) -> Option<u64> {
    let mut total = 0_u64;
    let mut from = OutboxSeq::START;
    loop {
        let rows = tx.read_events(job.id, from, PAGE).await.ok()?;
        for row in &rows {
            if row.event.occurred_at >= since {
                total = total.saturating_add(attempt_cost_micro_usd(&row.event).ok()?);
            }
        }
        match rows.last() {
            Some(last) if rows.len() == PAGE as usize => {
                from = OutboxSeq::new(last.seq.get().saturating_add(1));
            }
            _ => return Some(total),
        }
    }
}

/// A sum of money in millionths of a dollar as the dollars the policy counts in. A sum that could
/// not be read is not-a-number, which `BudgetPolicy::check` counts as the ceiling reached.
#[allow(clippy::cast_precision_loss)]
fn dollars(micro_usd: Option<u64>) -> f64 {
    micro_usd.map_or(f64::NAN, |value| value as f64 / 1_000_000.0)
}

/// What a repository and its organization used since the start of the day.
struct DayUsage {
    repository_micro_usd: Option<u64>,
    organization_micro_usd: Option<u64>,
    repository_jobs_started: u64,
}

impl DayUsage {
    /// Reads the usage from `jobs`, which are all the jobs of the tenant, and their events.
    async fn read(
        tx: &mut dyn Tx,
        jobs: &[Versioned<Job>],
        repository: RepositoryId,
        since: Timestamp,
    ) -> Self {
        let mut usage = Self {
            repository_micro_usd: Some(0),
            organization_micro_usd: Some(0),
            repository_jobs_started: 0,
        };
        let add = |sum: Option<u64>, more: Option<u64>| Some(sum?.saturating_add(more?));
        for job in jobs.iter().map(|job| &job.value) {
            let own = job.repository == repository;
            // A job is started when admission let it in. One that waits for admission or was
            // refused started nothing.
            let started = !matches!(job.status, JobStatus::Received | JobStatus::Rejected);
            if own && started && job.created_at >= since {
                usage.repository_jobs_started += 1;
            }
            // A job that ended before the day began spent nothing in it.
            if job.terminal_at.is_some_and(|ended| ended < since) {
                continue;
            }
            let spent = spent_since(tx, job, since).await;
            usage.organization_micro_usd = add(usage.organization_micro_usd, spent);
            if own {
                usage.repository_micro_usd = add(usage.repository_micro_usd, spent);
            }
        }
        usage
    }
}

/// The authority of the worker and, later, of the API.
pub struct StoreAuthority {
    store: Arc<dyn Store>,
    allowlist: Arc<FileAllowlist>,
    policy: Arc<PolicyEngine>,
    clock: Arc<dyn Clock>,
}

impl StoreAuthority {
    /// An authority over the store, the allowlist file, the policy and the clock.
    #[must_use]
    pub fn new(
        store: Arc<dyn Store>,
        allowlist: Arc<FileAllowlist>,
        policy: Arc<PolicyEngine>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            allowlist,
            policy,
            clock,
        }
    }

    async fn github_user(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
    ) -> Result<Option<u64>, AuthorityError> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
        let found = tx.get_principal(principal).await;
        let _ = tx.rollback().await;
        match found {
            Ok(principal) => Ok(match (principal.kind, principal.disabled_at) {
                (PrincipalKind::Human { github_user_id }, None) => Some(github_user_id),
                _ => None,
            }),
            Err(StoreError::NotFound) => Ok(None),
            Err(_) => Err(AuthorityError::Unavailable),
        }
    }

    /// The designations a person holds for a tenant now: listed, for that tenant, not expired, and,
    /// when `repository` is given, naming it if the entry is narrowed to some repositories. With
    /// `None` the question is "anywhere in the tenant".
    fn designations(
        &self,
        tenant: TenantId,
        github_user: u64,
        repository: Option<&RepositoryIdentity<'_>>,
    ) -> Result<BTreeSet<Designation>, AuthorityError> {
        self.allowlist
            .designations_on(tenant, github_user, repository, self.clock.now())
            .map_err(|_| AuthorityError::Unavailable)
    }

    /// Whether the readings leave room under the ceilings of `scope`. A ceiling that is reached,
    /// or a reading that could not be made, is logged with the scope and the numbers, because the
    /// audit record of the refusal names the ceiling and not the numbers.
    fn day_has_room(&self, scope: Scope, readings: &[Reading], repository: RepositoryId) -> bool {
        match self.policy.budget.check(scope, readings) {
            BudgetVerdict::Exhausted { metrics, rule } => {
                tracing::warn!(
                    %repository,
                    rule = ?rule,
                    metrics = ?metrics,
                    readings = ?readings,
                    "a day ceiling is reached or its reading could not be made; admission is refused"
                );
                false
            }
            BudgetVerdict::Warn { .. } | BudgetVerdict::Within => true,
        }
    }

    /// Whether another job of the repository of `job` may have a running attempt: fewer than the
    /// cap of the other jobs of that repository have a stage run that is running.
    async fn running_cap_allows(&self, tx: &mut dyn Tx, job: JobId) -> Result<bool, StoreError> {
        let repository = tx.get_job(job).await?.value.repository;
        let others = all_jobs(
            tx,
            JobFilter {
                statuses: Vec::new(),
                repository: Some(repository),
            },
        )
        .await?;
        let mut running = 0_u64;
        for other in others
            .iter()
            .map(|other| &other.value)
            .filter(|other| other.id != job && !other.status.is_terminal())
        {
            let runs = tx.list_stage_runs(other.id).await?;
            if runs
                .iter()
                .any(|run| run.value.status == StageRunStatus::Running)
            {
                running += 1;
            }
        }
        Ok(running < self.policy.budget.max_running_jobs_per_repo())
    }
}

#[async_trait]
impl Authority for StoreAuthority {
    fn fidelity(&self) -> Fidelity {
        self.store.fidelity()
    }

    async fn admission(
        &self,
        tenant: TenantId,
        requester: PrincipalId,
        repository: RepositoryId,
    ) -> Result<AdmissionFacts, AuthorityError> {
        let (active, usage, enabled, preflight_passed, registered) = {
            let mut tx = self
                .store
                .begin(TenantScope::new(tenant))
                .await
                .map_err(|_| AuthorityError::Unavailable)?;
            // All the jobs of the tenant: the organization's ceiling counts every repository.
            let jobs = all_jobs(&mut *tx, JobFilter::default()).await;
            let row = tx.get_repository(repository).await;
            let now = tx.database_time().await;
            let usage = match (&jobs, &now) {
                (Ok(jobs), Ok(now)) => {
                    Some(DayUsage::read(&mut *tx, jobs, repository, now.start_of_utc_day()).await)
                }
                _ => None,
            };
            let _ = tx.rollback().await;
            // A store that cannot list the jobs or tell the time cannot answer at all.
            let (Ok(jobs), Some(usage)) = (jobs, usage) else {
                return Err(AuthorityError::Unavailable);
            };
            let active = jobs
                .iter()
                .filter(|job| job.value.repository == repository && !job.value.status.is_terminal())
                .count() as u64;
            // A repository the tenant does not have is not registered. Only a store that cannot
            // answer is an error.
            match row {
                // A repository whose attestor or enabler is no longer an active human of the
                // tenant is not enabled for new work (finding REG-6).
                Ok(found) => (
                    active,
                    usage,
                    found.value.open_for_new_jobs(),
                    found.value.protection_preflight_passed,
                    Some((found.value.full_name, found.value.github_repository_id.0)),
                ),
                Err(StoreError::NotFound) => (active, usage, false, false, None),
                Err(_) => return Err(AuthorityError::Unavailable),
            }
        };
        // The requester designation is asked for this repository: an entry narrowed to other
        // repositories does not make its person a requester here (API-1). A repository that does not
        // exist fails the registered fact below, so what the narrowing says about it does not matter.
        let requester_on_allowlist = match self.github_user(tenant, requester).await? {
            Some(user) => {
                // The repository is asked about with GitHub's numeric id, so an entry that lists
                // the id follows it through a rename and a new repository under the old name is
                // another repository (RR-28).
                let identity = registered
                    .as_ref()
                    .map(|(name, id)| RepositoryIdentity::registered(name, *id));
                self.designations(tenant, user, identity.as_ref())?
                    .contains(&Designation::Requester)
            }
            None => false,
        };
        let cap = self.policy.budget.max_running_jobs_per_repo()
            + self.policy.budget.max_queued_jobs_per_repo();
        #[allow(clippy::cast_precision_loss)]
        let jobs_started = usage.repository_jobs_started as f64;
        let repository_day_budget_has_room = self.day_has_room(
            Scope::RepoDay,
            &[
                Reading {
                    metric: Metric::Usd,
                    used: dollars(usage.repository_micro_usd),
                },
                Reading {
                    metric: Metric::JobsStarted,
                    used: jobs_started,
                },
            ],
            repository,
        );
        let organization_day_budget_has_room = self.day_has_room(
            Scope::OrgDay,
            &[Reading {
                metric: Metric::Usd,
                used: dollars(usage.organization_micro_usd),
            }],
            repository,
        );
        Ok(AdmissionFacts {
            requester_on_allowlist,
            tenant_within_job_quota: active < cap,
            repository_registered_and_enabled: enabled,
            // Slice 1 has one class of request, a labelled issue or its equal through the API,
            // and the policy has no rule that forbids it.
            policy_allows_request_class: true,
            repository_day_budget_has_room,
            organization_day_budget_has_room,
            protection_preflight_passed: preflight_passed,
        })
    }

    async fn roles(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
    ) -> Result<Vec<HumanRole>, AuthorityError> {
        let Some(user) = self.github_user(tenant, principal).await? else {
            return Ok(Vec::new());
        };
        Ok(self
            .designations(tenant, user, None)?
            .into_iter()
            .filter_map(|designation| match designation {
                Designation::Requester => Some(HumanRole::Requester),
                Designation::Operator => Some(HumanRole::Operator),
                Designation::Approver => Some(HumanRole::Approver),
                Designation::SecurityApprover => Some(HumanRole::SecurityApprover),
                Designation::OrgAdmin => Some(HumanRole::OrgAdmin),
                // The engine has no repository-admin role; the designation matters to the policy.
                Designation::RepoAdmin => None,
            })
            .collect())
    }

    async fn approver_count(
        &self,
        tenant: TenantId,
        repository: RepositoryId,
    ) -> Result<u32, AuthorityError> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
        let now = self.clock.now();
        let inputs =
            crate::solo::solo_inputs(&mut *tx, &self.allowlist, tenant, repository, now).await;
        let _ = tx.rollback().await;
        inputs
            .map(|inputs| inputs.approver_count)
            .map_err(|_| AuthorityError::Unavailable)
    }

    async fn concurrency_allows(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Result<bool, AuthorityError> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
        let allows = self.running_cap_allows(&mut *tx, job).await;
        let _ = tx.rollback().await;
        allows.map_err(|_| AuthorityError::Unavailable)
    }
}
