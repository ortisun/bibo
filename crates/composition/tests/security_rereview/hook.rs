//! The worker's hook (`ClaimWork`) against records that a login of the API's database group can write.
//! Real PostgreSQL, the real engine, the real allowlist file, the real policy files and the real hook.
//! Needs the database of `docs/database/running.md`; a test that cannot get one panics with
//! `BLOCKED:` (the storage crate's helper does that).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::authority::StoreAuthority;
use factory_composition::decision_signing::{DecisionKeys, Signing};
use factory_composition::decisions::{
    AllowlistAuthority, ApprovalSubmitter, AuditMarkers, ClaimWork, ClaimWorkDeps,
    DECISIONS_PER_PASS, DecisionFields, REJECTED, REQUESTED,
};
use factory_composition::delivery::StoreApprovalSources;
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::{LoadedPolicies, load_policy};
use factory_domain::ids::{AuditEventId, JobId, PrincipalId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::JobStatus;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, NewAuditEvent, NewPrincipal,
    PrincipalKind, Store,
};
use factory_workflow::engine::Engine;
use factory_workflow::stages::approval::{ApprovalCommand, Outcome, ServiceError, Verb};

use crate::repository_root;
use crate::support::engine::PgWorld;
use crate::support::pg_world;

const REQUESTER: u64 = 1001;
const OPERATOR: u64 = 3001;
const STRANGER: u64 = 3003;

/// A pull request approval is not part of these tests; a call to the service is an error.
struct NeverSubmits;

#[async_trait(?Send)]
impl ApprovalSubmitter for NeverSubmits {
    async fn submit(&self, _command: ApprovalCommand) -> Result<Outcome, ServiceError> {
        Err(ServiceError::Unavailable)
    }
}

struct Rig {
    _db: crate::support::TestDb,
    world: PgWorld,
    tenant: TenantId,
    checkout: PathBuf,
    policies: LoadedPolicies,
    allowlist: Arc<FileAllowlist>,
    engine: Arc<Engine>,
    operator: PrincipalId,
    stranger: PrincipalId,
    keys: Arc<DecisionKeys>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.checkout);
    }
}

impl Rig {
    async fn new() -> Self {
        let (db, world, tenant) = pg_world().await;
        let policies = load_policy(&repository_root(), &[]).expect("the real policies load");
        let checkout = repository_root()
            .join("target/security-rereview-hook")
            .join(world.ids.new_uuid().simple().to_string());
        std::fs::create_dir_all(checkout.join("allowlist")).expect("a directory");
        let allowlist = Arc::new(FileAllowlist::in_checkout(&checkout));
        let mut text = String::from("version: 1\nentries:\n");
        for (id, login, designation) in [
            (REQUESTER, "requester-one", "requester"),
            (OPERATOR, "operator-one", "operator"),
            (STRANGER, "stranger-one", "requester"),
        ] {
            text.push_str(&format!(
                "  - tenant: {}\n    github_user_id: {id}\n    login: {login}\n    designations: [{designation}]\n",
                tenant.as_uuid()
            ));
        }
        std::fs::write(checkout.join("allowlist/allowlist.yaml"), text).expect("the allowlist");
        let operator = person(&world, tenant, OPERATOR, "operator-one").await;
        let stranger = person(&world, tenant, STRANGER, "stranger-one").await;
        let mut deps = world.deps.clone();
        deps.authority = Arc::new(StoreAuthority::new(
            world.store.clone(),
            allowlist.clone(),
            Arc::clone(&policies.engine),
            world.deps.clock.clone(),
        ));
        let engine = Arc::new(
            Engine::new(deps, world.config.clone(), world.handlers.clone())
                .expect("the engine starts"),
        );
        Self {
            _db: db,
            world,
            tenant,
            checkout,
            policies,
            allowlist,
            engine,
            operator,
            stranger,
            keys: Arc::new(DecisionKeys::generated().expect("a key")),
        }
    }

    fn hook(&self) -> ClaimWork {
        let clock: Arc<dyn Clock> = self.world.deps.clock.clone();
        ClaimWork::new(ClaimWorkDeps {
            engine: Arc::clone(&self.engine),
            store: self.world.store.clone(),
            tenants: vec![self.tenant],
            submitter: Arc::new(NeverSubmits),
            approvals: Arc::new(StoreApprovalSources::new(
                self.world.store.clone(),
                self.world.deps.artifacts.clone(),
                self.allowlist.clone(),
            )),
            authority: Arc::new(AllowlistAuthority::new(
                self.allowlist.clone(),
                Arc::clone(&self.policies.approval),
                self.world.deps.clock.clone(),
            )),
            markers: Arc::new(AuditMarkers::new(
                self.world.store.clone(),
                self.policies.hash.clone(),
            )),
            clock,
            max_age: Duration::from_secs(72 * 3600),
            per_pass: DECISIONS_PER_PASS,
            keys: self.keys.clone(),
        })
    }

    async fn active(&self) -> JobId {
        let job = self
            .engine
            .receive_job(self.tenant, self.world.requester, self.world.repository)
            .await
            .expect("received");
        self.hook().pass(self.tenant).await;
        assert_eq!(self.status(job).await, JobStatus::Active);
        job
    }

    async fn status(&self, job: JobId) -> JobStatus {
        self.engine
            .job_status(self.tenant, job)
            .await
            .expect("a status")
    }

    /// The record `POST /v1/jobs/{id}/decisions` writes for a pause by the operator.
    async fn signed_pause(&self, job: JobId) -> AuditEventId {
        let id = AuditEventId::from_uuid(self.world.ids.new_uuid());
        let fields = DecisionFields {
            verb: Verb::Pause,
            job,
            stage_run: None,
            head: None,
            evidence: None,
            target: None,
        };
        let subject = self.keys.signed_subject(&Signing {
            tenant: self.tenant,
            actor: self.operator,
            event: id,
            requested_at: "2026-10-29T12:00:00Z",
            fields: &fields,
        });
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let correlation = tx.get_job(job).await.expect("a job").value.correlation_id;
        tx.record_audit(NewAuditEvent {
            id,
            actor: AuditActor::Human(self.operator),
            action: AuditAction::new(REQUESTED).expect("an action"),
            subject,
            decision: AuditDecision::Record,
            reason: "requested: stop the job".to_owned(),
            policy_hash: self.policies.hash.clone(),
            job: Some(job),
            stage_run: None,
            correlation_id: correlation,
        })
        .await
        .expect("the request is recorded");
        tx.commit().await.expect("commit");
        id
    }

    /// Any audit record, as a login of the API's group can write one: the action, the actor and the
    /// subject are the writer's to choose.
    async fn forged_record(&self, action: &str, actor: AuditActor, subject: String) {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        tx.record_audit(NewAuditEvent {
            id: AuditEventId::from_uuid(self.world.ids.new_uuid()),
            actor,
            action: AuditAction::new(action).expect("an action"),
            subject,
            decision: AuditDecision::Deny,
            reason: "recorded".to_owned(),
            policy_hash: self.policies.hash.clone(),
            job: None,
            stage_run: None,
            correlation_id: factory_domain::ids::CorrelationId::from_uuid(
                self.world.ids.new_uuid(),
            ),
        })
        .await
        .expect("the record is written");
        tx.commit().await.expect("commit");
    }

    async fn actions(&self) -> Vec<String> {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let records = tx
            .read_audit(AuditFilter::Tenant, 0, 1000)
            .await
            .expect("audit");
        let _ = tx.rollback().await;
        records
            .into_iter()
            .map(|record| record.event.action.as_str().to_owned())
            .filter(|action| action.starts_with("decision."))
            .collect()
    }
}

async fn person(world: &PgWorld, tenant: TenantId, github: u64, login: &str) -> PrincipalId {
    let id = PrincipalId::from_uuid(world.ids.new_uuid());
    let mut tx = world
        .store
        .begin(TenantScope::new(tenant))
        .await
        .expect("a tx");
    tx.insert_principal(NewPrincipal {
        id,
        kind: PrincipalKind::Human {
            github_user_id: github,
        },
        login: Some(login.to_owned()),
    })
    .await
    .expect("a principal");
    tx.commit().await.expect("commit");
    id
}

/// Control: the signed request alone is applied, and the hook writes its own marker.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL (docs/database/running.md)"]
async fn held_a_signed_pause_is_applied_and_marked_by_the_worker() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    rig.signed_pause(job).await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Paused);
    assert_eq!(rig.actions().await, [REQUESTED, "decision.applied"]);
}

/// RR-8. A `decision.applied` or `decision.rejected` record ends a request. The hook accepts such a
/// record from anyone: no actor check, no word. The API's database login may insert any audit row, so
/// whoever holds that login (and not the API process, the key, or any role) can end a signed request
/// before the worker looks at it. The request is never applied, the job keeps running, and the
/// timeline shows a rejection that the worker did not write. The cheapest victim is the operator's
/// pause or cancel, the kill switch. A forged `decision.applied` for the request of an approval does
/// the same and also tells the person that their approval took effect.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "confirmed defect RR-8 (needs PostgreSQL): a forged decision marker silently drops a signed request; cargo test -p factory-composition --test security_rereview --locked -- --ignored rr_8 --exact"]
async fn rr_8_a_forged_marker_does_not_drop_a_signed_request() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let request = rig.signed_pause(job).await;
    // What anyone with an INSERT grant on audit_events can write, naming the request.
    rig.forged_record(
        REJECTED,
        AuditActor::Human(rig.stranger),
        format!(
            "decision={} verb=pause job={} code=not_authorized actor=none allowlist=none",
            request.as_uuid().hyphenated(),
            job.as_text()
        ),
    )
    .await;
    rig.hook().pass(rig.tenant).await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(
        rig.status(job).await,
        JobStatus::Paused,
        "the signed request was dropped by a record the worker never wrote; the trail is {:?}",
        rig.actions().await
    );
}

/// RR-21. A pass deals with malformed and unsigned records first and with signed requests in the room
/// that is left (`apply_decisions`: `room = per_pass - malformed.len()`). A holder of the API's
/// database login writes unsigned `decision.requested` rows at will, so a queue of them as long as the
/// pass leaves no room at all: a signed request that arrived before the junk waits behind it, pass
/// after pass, for as long as the writer keeps the queue full. The first victim is again a cancel or a
/// pause. Here sixty junk rows (a pass deals with fifty) sit between the job and its pause.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "confirmed defect RR-21 (needs PostgreSQL): unsigned records ahead of a signed request starve it; cargo test -p factory-composition --test security_rereview --locked -- --ignored rr_21 --exact"]
async fn rr_21_junk_records_do_not_starve_a_signed_request() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    rig.signed_pause(job).await;
    let plain = DecisionFields {
        verb: Verb::Cancel,
        job,
        stage_run: None,
        head: None,
        evidence: None,
        target: None,
    }
    .subject();
    for _ in 0..(DECISIONS_PER_PASS + 10) {
        rig.forged_record(REQUESTED, AuditActor::Human(rig.stranger), plain.clone())
            .await;
    }
    rig.hook().pass(rig.tenant).await;
    assert_eq!(
        rig.status(job).await,
        JobStatus::Paused,
        "one pass dealt only with junk; the signed pause is still waiting"
    );
}
