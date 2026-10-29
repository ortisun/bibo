//! The sources the dependency gates read that no adapter of this workspace can supply: what the
//! package registry says about a package, and how old the advisory database of the audit image is.
//!
//! # What is real and what is not
//!
//! The decisions people recorded about new dependencies are real: `assemble_pipeline` builds a
//! [`LedgerApprovals`](factory_workflow::gates::supply_chain::ledger::LedgerApprovals) over the
//! store and the artifact store, so the caller cannot hand the gate a list of decisions of its own.
//!
//! The registry client and the reader of the advisory database date have no real adapter yet. A
//! registry client talks to the internet through the control plane's egress path, which the policy
//! does not allow today, and the date of the database is written by the image build, which does
//! not install the audit tool yet (review H-5). Until they exist, a process is given one of two
//! kinds of source:
//!
//! * **Blocked by design** ([`SupplyChainSources::blocked`]): the production kind. Both answer
//!   "I do not know". The gate reads that as the worst case: a package the registry source cannot
//!   describe is unknown, so a new direct dependency waits for a security approver, and an audit
//!   against a database of unknown age is BLOCKED (`dependency_unavailable`). Nothing is approved
//!   by these sources; they only fail closed, and the worker lists both as `BLOCKED:` lines.
//! * **Stand-ins** ([`SupplyChainSources::stand_in`]): for the `local` and `test` profiles. They
//!   are labelled ([`Standing::StandIn`]), the pipeline reports them, and the production profile
//!   refuses them ([`PipelineError::StandIn`](crate::pipeline::PipelineError::StandIn)).
//!
//! A real adapter, when it exists, comes in through [`SupplyChainSources::real`].

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::Clock;
use factory_ports::store::Store;
use factory_workflow::gates::scope::own_build_code::ProjectBuildCodeApproval;
use factory_workflow::gates::supply_chain::approval::{DependencyApproval, RecordedApprovals};
use factory_workflow::gates::supply_chain::facts::{
    AdvisoryDatabase, RegistryMetadata, RegistryRecord,
};
use factory_workflow::stages::approval::warnings::WarningDecision;

use crate::seams::FileAllowlist;

/// What kind of source it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// A real adapter: it reads the registry or the image.
    Real,
    /// Blocked by design: it knows nothing and says so, so the gate fails closed.
    Blocked,
    /// A stand-in for a test or a local run. Labelled, and refused in production.
    StandIn,
}

impl Standing {
    /// The word a report prints.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::Blocked => "blocked by design (fails closed)",
            Self::StandIn => "stand-in (test or local only)",
        }
    }
}

/// The registry source that knows nothing. Every record is all unknown, which the policy reads as
/// the worst answer, so a new direct dependency goes to a security approver.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockedRegistry;

#[async_trait]
impl RegistryMetadata for BlockedRegistry {
    fn fidelity(&self) -> Fidelity {
        // It knows nothing and says so: it cannot make a false pass, which is all the profile
        // asks of a source that has no real adapter yet.
        Fidelity::Real
    }

    async fn lookup(&self, _name: &str, _version: &str) -> RegistryRecord {
        RegistryRecord::default()
    }
}

/// The advisory database source that does not know the date. An audit against a database of
/// unknown age is not a clean audit, so the advisories gate is BLOCKED.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockedAdvisoryDatabase;

#[async_trait]
impl AdvisoryDatabase for BlockedAdvisoryDatabase {
    fn fidelity(&self) -> Fidelity {
        // It does not know the date and says so: it cannot make a false pass.
        Fidelity::Real
    }

    async fn updated_at(&self) -> Option<Timestamp> {
        None
    }
}

/// How old the stand-in says the advisory database is.
const STAND_IN_DATABASE_AGE: std::time::Duration = std::time::Duration::from_secs(86_400);

/// A stand-in registry: it describes no package. It is the same answer as [`BlockedRegistry`],
/// kept as its own type so that a report can tell a stand-in from the blocked adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandInRegistry;

#[async_trait]
impl RegistryMetadata for StandInRegistry {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn lookup(&self, _name: &str, _version: &str) -> RegistryRecord {
        RegistryRecord::default()
    }
}

/// A stand-in for the date of the advisory database: it says the database was updated one day
/// ago. That is a claim nobody checked, which is why it is a stand-in and why production refuses
/// it. It is a day and not "now": the gate reads the clock before it asks for the date, and a date
/// a few microseconds in the future is read as unknown (a date in the future cannot be true).
#[derive(Clone)]
pub struct StandInAdvisoryDatabase {
    clock: Arc<dyn Clock>,
}

impl StandInAdvisoryDatabase {
    /// A database that is always as old as `clock` says now.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

#[async_trait]
impl AdvisoryDatabase for StandInAdvisoryDatabase {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn updated_at(&self) -> Option<Timestamp> {
        self.clock.now().checked_sub(STAND_IN_DATABASE_AGE)
    }
}

/// The recorded decisions that still count: those whose person still holds, now, the designation
/// they decided under.
///
/// The ledger holds a decision for good. The gate drops a decision of another tenant, another job
/// or another policy bundle, but it cannot read the allowlist, and review requirement 6 of the
/// supply chain review says a decision of a person who has left the allowlist is dropped. This
/// wrapper does that, reading the allowlist file at every call (NT-AUTHZ-04), by the numeric id of
/// the approver, for the repository of the job. A decision it cannot check, because the allowlist
/// or the store cannot be read, does not count: the gate asks the person again, which is the safe
/// side.
#[derive(Clone)]
pub struct CurrentApprovals {
    inner: Arc<dyn RecordedApprovals>,
    allowlist: Arc<FileAllowlist>,
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
}

impl CurrentApprovals {
    /// The decisions of `inner` that the allowlist still stands behind.
    #[must_use]
    pub fn new(
        inner: Arc<dyn RecordedApprovals>,
        allowlist: Arc<FileAllowlist>,
        store: Arc<dyn Store>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner,
            allowlist,
            store,
            clock,
        }
    }

    /// Keeps the decisions whose person still holds, now, the designation they decided under.
    async fn still_standing<T>(
        &self,
        (tenant, job): (TenantId, JobId),
        recorded: Vec<T>,
        who: impl Fn(&T) -> (u64, factory_domain::policy::decision::Designation),
    ) -> Vec<T> {
        if recorded.is_empty() {
            return recorded;
        }
        let Some(repository) = self.repository_of(tenant, job).await else {
            return Vec::new();
        };
        let now = self.clock.now();
        recorded
            .into_iter()
            .filter(|approval| {
                let (approver, designation) = who(approval);
                self.allowlist
                    .designations_on(tenant, approver, Some(&repository), now)
                    .is_ok_and(|held| held.contains(&designation))
            })
            .collect()
    }

    async fn repository_of(&self, tenant: TenantId, job: JobId) -> Option<String> {
        let mut tx = self.store.begin(TenantScope::new(tenant)).await.ok()?;
        let found = async {
            let stored = tx.get_job(job).await.ok()?;
            let repository = tx.get_repository(stored.value.repository).await.ok()?;
            Some(repository.value.full_name)
        }
        .await;
        let _ = tx.rollback().await;
        found
    }
}

#[async_trait]
impl RecordedApprovals for CurrentApprovals {
    fn fidelity(&self) -> Fidelity {
        // As real as the decisions it filters. The allowlist file is read at every call.
        self.inner.fidelity()
    }

    async fn for_job(&self, tenant: TenantId, job: JobId) -> Vec<DependencyApproval> {
        let recorded = self.inner.for_job(tenant, job).await;
        self.still_standing((tenant, job), recorded, |approval| {
            (approval.approver.get(), approval.designation)
        })
        .await
    }

    async fn warning_decisions_for_job(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Vec<WarningDecision> {
        let recorded = self.inner.warning_decisions_for_job(tenant, job).await;
        self.still_standing((tenant, job), recorded, |decision| {
            (decision.approver.get(), decision.designation)
        })
        .await
    }

    async fn build_code_for_job(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Vec<ProjectBuildCodeApproval> {
        let recorded = self.inner.build_code_for_job(tenant, job).await;
        self.still_standing((tenant, job), recorded, |approval| {
            (approval.approver.get(), approval.designation)
        })
        .await
    }
}

/// The two sources, with what kind each is.
#[derive(Clone)]
pub struct SupplyChainSources {
    registry: Arc<dyn RegistryMetadata>,
    registry_standing: Standing,
    advisory_db: Arc<dyn AdvisoryDatabase>,
    advisory_standing: Standing,
}

impl SupplyChainSources {
    /// The production default: both sources are blocked by design.
    #[must_use]
    pub fn blocked() -> Self {
        Self {
            registry: Arc::new(BlockedRegistry),
            registry_standing: Standing::Blocked,
            advisory_db: Arc::new(BlockedAdvisoryDatabase),
            advisory_standing: Standing::Blocked,
        }
    }

    /// The sources of a `local` or `test` run: labelled stand-ins, refused in production.
    #[must_use]
    pub fn stand_in(clock: Arc<dyn Clock>) -> Self {
        Self {
            registry: Arc::new(StandInRegistry),
            registry_standing: Standing::StandIn,
            advisory_db: Arc::new(StandInAdvisoryDatabase::new(clock)),
            advisory_standing: Standing::StandIn,
        }
    }

    /// What a process of this profile is given when no real adapter exists: the blocked adapters
    /// in production, and labelled stand-ins elsewhere.
    #[must_use]
    pub fn for_profile(profile: crate::profile::Profile, clock: Arc<dyn Clock>) -> Self {
        match profile {
            crate::profile::Profile::Production => Self::blocked(),
            crate::profile::Profile::Local | crate::profile::Profile::Test => Self::stand_in(clock),
        }
    }

    /// Stand-ins the caller built: a test that wants the registry to describe a package, or the
    /// database to have a date.
    #[must_use]
    pub fn stand_in_of(
        registry: Arc<dyn RegistryMetadata>,
        advisory_db: Arc<dyn AdvisoryDatabase>,
    ) -> Self {
        Self {
            registry,
            registry_standing: Standing::StandIn,
            advisory_db,
            advisory_standing: Standing::StandIn,
        }
    }

    /// Real adapters, for the day they exist.
    #[must_use]
    pub fn real(
        registry: Arc<dyn RegistryMetadata>,
        advisory_db: Arc<dyn AdvisoryDatabase>,
    ) -> Self {
        Self {
            registry,
            registry_standing: Standing::Real,
            advisory_db,
            advisory_standing: Standing::Real,
        }
    }

    /// The registry source.
    #[must_use]
    pub fn registry(&self) -> Arc<dyn RegistryMetadata> {
        Arc::clone(&self.registry)
    }

    /// The source of the date of the advisory database.
    #[must_use]
    pub fn advisory_db(&self) -> Arc<dyn AdvisoryDatabase> {
        Arc::clone(&self.advisory_db)
    }

    /// The kind of each source, named, for a report and for the production check.
    #[must_use]
    pub fn standings(&self) -> Vec<(&'static str, Standing)> {
        vec![
            ("RegistryMetadata", self.registry_standing),
            ("AdvisoryDatabase", self.advisory_standing),
        ]
    }

    /// The names of the sources that are stand-ins.
    #[must_use]
    pub fn stand_ins(&self) -> Vec<&'static str> {
        self.standings()
            .into_iter()
            .filter(|(_, standing)| *standing == Standing::StandIn)
            .map(|(name, _)| name)
            .collect()
    }
}

impl std::fmt::Debug for SupplyChainSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupplyChainSources")
            .field("registry", &self.registry_standing)
            .field("advisory_db", &self.advisory_standing)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_blocked_sources_are_the_production_default_and_know_nothing() {
        let sources = SupplyChainSources::blocked();
        assert!(sources.stand_ins().is_empty());
        assert!(
            sources
                .standings()
                .iter()
                .all(|(_, standing)| *standing == Standing::Blocked)
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        runtime.block_on(async {
            assert_eq!(
                sources.registry().lookup("any-crate", "1.0.0").await,
                RegistryRecord::default()
            );
            assert_eq!(sources.advisory_db().updated_at().await, None);
        });
    }

    #[test]
    fn a_stand_in_is_named_so_that_production_can_refuse_it() {
        struct Now;
        impl Clock for Now {
            fn now(&self) -> Timestamp {
                Timestamp::parse("2026-10-28T12:00:00Z").expect("a time")
            }
            fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
                factory_domain::vocabulary::Fidelity::Fake
            }
        }
        let sources = SupplyChainSources::stand_in(Arc::new(Now));
        assert_eq!(
            sources.stand_ins(),
            ["RegistryMetadata", "AdvisoryDatabase"]
        );
    }
}
