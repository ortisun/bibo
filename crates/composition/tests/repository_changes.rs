//! Register, attest and enable as signed requests that the worker applies (finding REG-2).
//!
//! Real: PostgreSQL (the worker's login), the signing and the step. Fake and labelled so: the allowlist,
//! which the tests set person by person and which records what it was asked, so that a test shows the
//! designation was asked again, by numeric id, with the repository's GitHub id. The real allowlist file is
//! tried in `apps/api/tests/repositories.rs`.

mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::decision_signing::{DecisionKeys, RepositoryChangeSigning};
use factory_composition::decisions::Unreadable;
use factory_composition::repository_changes::{
    ATTEST_ACTION, Change, ChangeAuthority, DISABLED, ENABLE_ACTION, REFUSED, REGISTER_ACTION,
    REQUEST_MAX_AGE, REQUESTED, RepositoryChangeFields, RepositoryChanges, RepositoryChangesDeps,
    payload_digest, registration_detail,
};
use factory_domain::ids::{AuditEventId, CorrelationId, PrincipalId, RepositoryId, TenantId};
use factory_domain::policy::authority::RepositoryIdentity;
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_domain::values::Slug;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, NewAuditEvent, Store,
};
use factory_testkit::clock::FakeClock;
use support::pg_world;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const AT: &str = "2026-11-03T10:00:00.123456789Z";

/// What the allowlist was asked: the GitHub id of the person, the action, and the name and GitHub id of the repository.
type Asked = (u64, String, String, Option<u64>);

/// A point at which the allowlist stops until the test lets it go, so that a test can change the world between
/// two requests of one pass.
struct Gate {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

/// The allowlist of the test: who holds which action, and what it was asked.
struct Allowed {
    permitted: Mutex<BTreeSet<(u64, String)>>,
    asked: Mutex<Vec<Asked>>,
    /// Whether each question was about a registration that a person typed (finding RH-2).
    typed: Mutex<Vec<bool>>,
    gate: Mutex<Option<(u64, String, Arc<Gate>)>>,
}

impl Allowed {
    fn nobody() -> Arc<Self> {
        Arc::new(Self {
            permitted: Mutex::new(BTreeSet::new()),
            asked: Mutex::new(Vec::new()),
            typed: Mutex::new(Vec::new()),
            gate: Mutex::new(None),
        })
    }

    /// Stops the next question of this person about this action until the returned gate is released.
    fn hold(&self, github_user: u64, action: &str) -> Arc<Gate> {
        let gate = Arc::new(Gate {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        *self.gate.lock().expect("lock") =
            Some((github_user, action.to_owned(), Arc::clone(&gate)));
        gate
    }

    fn permit(&self, github_user: u64, action: &str) {
        self.permitted
            .lock()
            .expect("lock")
            .insert((github_user, action.to_owned()));
    }

    fn forbid(&self, github_user: u64, action: &str) {
        self.permitted
            .lock()
            .expect("lock")
            .remove(&(github_user, action.to_owned()));
    }
}

#[async_trait(?Send)]
impl ChangeAuthority for Allowed {
    async fn permits(
        &self,
        _tenant: TenantId,
        github_user_id: u64,
        action: &str,
        repository: &RepositoryIdentity<'_>,
    ) -> Result<bool, Unreadable> {
        self.asked.lock().expect("lock").push((
            github_user_id,
            action.to_owned(),
            repository.name.to_owned(),
            repository.github_repository_id,
        ));
        self.typed.lock().expect("lock").push(repository.typed);
        let held = self.gate.lock().expect("lock").clone();
        if let Some((user, held_action, gate)) = held
            && user == github_user_id
            && held_action == action
        {
            *self.gate.lock().expect("lock") = None;
            gate.reached.notify_one();
            gate.release.notified().await;
        }
        Ok(self
            .permitted
            .lock()
            .expect("lock")
            .contains(&(github_user_id, action.to_owned())))
    }

    async fn constrained_holders(
        &self,
        _tenant: TenantId,
        _repository: &RepositoryIdentity<'_>,
    ) -> Result<BTreeSet<u64>, Unreadable> {
        Ok(self
            .permitted
            .lock()
            .expect("lock")
            .iter()
            .filter(|(_, action)| action == ATTEST_ACTION || action == ENABLE_ACTION)
            .map(|(user, _)| *user)
            .collect())
    }
}

struct Rig {
    db: support::TestDb,
    tenant: TenantId,
    store: Arc<dyn Store>,
    keys: Arc<DecisionKeys>,
    allowed: Arc<Allowed>,
    clock: Arc<FakeClock>,
    step: RepositoryChanges,
    ids: factory_composition::system::RandomIds,
}

#[derive(Clone, Copy)]
struct Person {
    id: PrincipalId,
    github: u64,
}

impl Rig {
    async fn new() -> Self {
        let (db, world, tenant) = pg_world().await;
        let keys = Arc::new(DecisionKeys::generated().expect("a key"));
        let allowed = Allowed::nobody();
        let store: Arc<dyn Store> = world.store.clone();
        // Thirty seconds after the time the requests of the tests are dated (`AT`).
        let clock = Arc::new(FakeClock::starting_at("2026-11-03T10:00:30Z"));
        let step = Self::step_with(&store, &allowed, &keys, &clock);
        Self {
            db,
            tenant,
            store,
            keys,
            allowed,
            clock,
            step,
            ids: factory_composition::system::RandomIds::new().expect("random"),
        }
    }

    fn step_with(
        store: &Arc<dyn Store>,
        allowed: &Arc<Allowed>,
        keys: &Arc<DecisionKeys>,
        clock: &Arc<FakeClock>,
    ) -> RepositoryChanges {
        RepositoryChanges::new(RepositoryChangesDeps {
            store: Arc::clone(store),
            authority: allowed.clone(),
            policy_hash: Sha256Digest::of(b"a policy"),
            keys: Arc::clone(keys),
            clock: clock.clone(),
            max_age: REQUEST_MAX_AGE,
        })
    }

    /// A person disables a repository the way the API does: the table and the record, in one transaction.
    async fn disable(&self, who: Person, repository: RepositoryId) {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("tx");
        let row = tx.get_repository(repository).await.expect("the row");
        tx.disable_repository(repository, row.version)
            .await
            .expect("disabled");
        tx.record_audit(self.disabled_row(AuditActor::Human(who.id), repository))
            .await
            .expect("the record");
        tx.commit().await.expect("commit");
    }

    fn disabled_row(&self, actor: AuditActor, repository: RepositoryId) -> NewAuditEvent {
        NewAuditEvent {
            id: AuditEventId::from_uuid(self.ids.new_uuid()),
            actor,
            action: AuditAction::new(DISABLED).expect("an action"),
            subject: format!("repository {} disabled", repository.as_text()),
            decision: AuditDecision::Record,
            reason: "A person disabled the repository.".to_owned(),
            policy_hash: Sha256Digest::of(b"a policy"),
            job: None,
            stage_run: None,
            correlation_id: CorrelationId::from_uuid(self.ids.new_uuid()),
        }
    }

    /// A record in the log that nobody should believe: the system claims a disable.
    async fn forge_disabled_by_the_system(&self, repository: RepositoryId) {
        let actor = AuditActor::System(Slug::parse("worker.repository").expect("a slug"));
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("tx");
        tx.record_audit(self.disabled_row(actor, repository))
            .await
            .expect("the record");
        tx.commit().await.expect("commit");
    }

    /// A human principal of the tenant with this GitHub id.
    async fn person(&self, github: u64) -> Person {
        let id = PrincipalId::from_uuid(self.ids.new_uuid());
        self.db
            .run(&format!(
                "INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES ('{}', '{}', 'human', {github}, 'person-{github}')",
                self.tenant.as_uuid(),
                id.as_uuid()
            ))
            .await;
        Person { id, github }
    }

    fn repository_id(&self) -> RepositoryId {
        RepositoryId::from_uuid(self.ids.new_uuid())
    }

    /// Writes a request the way the API does, with the word chosen by `how`, dated `AT`.
    async fn ask(&self, who: Person, change: Change, detail: &str, how: Sign) -> AuditEventId {
        self.ask_at(who, change, detail, how, AT).await
    }

    /// The same, dated `at`.
    async fn ask_at(
        &self,
        who: Person,
        change: Change,
        detail: &str,
        how: Sign,
        at: &str,
    ) -> AuditEventId {
        let id = AuditEventId::from_uuid(self.ids.new_uuid());
        let fields = RepositoryChangeFields {
            payload: payload_digest(detail),
            change,
        };
        let signed_for = if let Sign::ForAnother(other) = how {
            other.id
        } else {
            who.id
        };
        let mut subject = self
            .keys
            .signed_repository_change_subject(&RepositoryChangeSigning {
                tenant: self.tenant,
                actor: signed_for,
                event: id,
                requested_at: at,
                fields: &fields,
            });
        let mut reason = detail.to_owned();
        match how {
            Sign::Good | Sign::ForAnother(_) => {}
            Sign::WrongKey => {
                let other = DecisionKeys::generated().expect("a key");
                subject = other.signed_repository_change_subject(&RepositoryChangeSigning {
                    tenant: self.tenant,
                    actor: who.id,
                    event: id,
                    requested_at: at,
                    fields: &fields,
                });
            }
            Sign::NoWord => {
                subject = fields.subject();
            }
            Sign::DetailChangedAfterSigning => reason = format!("{detail} but not that"),
        }
        let event = NewAuditEvent {
            id,
            actor: AuditActor::Human(who.id),
            action: AuditAction::new(REQUESTED).expect("an action"),
            subject,
            decision: AuditDecision::Record,
            reason,
            policy_hash: Sha256Digest::of(b"a policy"),
            job: None,
            stage_run: None,
            correlation_id: CorrelationId::from_uuid(self.ids.new_uuid()),
        };
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("tx");
        tx.record_audit(event)
            .await
            .expect("the request is recorded");
        tx.commit().await.expect("commit");
        id
    }

    async fn settle(&self) {
        // One pass applies at most ten requests; a test never asks for more.
        self.step.pass(self.tenant).await;
    }

    /// The records of the tenant, as (action, actor, subject, reason) with the actor as a word.
    async fn records(&self) -> Vec<(String, String, String, String)> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("tx");
        let page = tx
            .read_audit(AuditFilter::Tenant, 0, 1000)
            .await
            .expect("the log reads");
        let _ = tx.rollback().await;
        page.into_iter()
            .map(|record| {
                let actor = match record.event.actor {
                    AuditActor::Human(_) => "human",
                    AuditActor::System(_) => "system",
                    AuditActor::Service(_) => "service",
                    AuditActor::Anonymous(_) => "anonymous",
                };
                (
                    record.event.action.as_str().to_owned(),
                    actor.to_owned(),
                    record.event.subject,
                    record.event.reason,
                )
            })
            .collect()
    }

    async fn count(&self, action: &str) -> usize {
        self.records()
            .await
            .iter()
            .filter(|(found, ..)| found == action)
            .count()
    }

    async fn repository(&self, id: RepositoryId) -> Option<factory_ports::store::Repository> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("tx");
        let found = tx.get_repository(id).await.ok();
        let _ = tx.rollback().await;
        found.map(|row| row.value)
    }

    /// Where the request stands, as the API reads it: the keyed result record.
    async fn result_of(&self, request: AuditEventId) -> Option<(String, String)> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("tx");
        let found = tx
            .find_audit(self.keys.repository_change_result_id(request))
            .await
            .expect("the log reads");
        let _ = tx.rollback().await;
        found.map(|record| (record.event.action.as_str().to_owned(), record.event.reason))
    }
}

#[derive(Clone, Copy)]
enum Sign {
    Good,
    WrongKey,
    NoWord,
    DetailChangedAfterSigning,
    ForAnother(Person),
}

fn register(id: RepositoryId, github_repository: u64, single_maintainer: bool) -> Change {
    Change::Register {
        repository: id,
        installation: 7001,
        github_repository,
        single_maintainer,
    }
}

fn detail(name: &str) -> String {
    registration_detail(name, "main")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_registration_is_applied_by_the_worker_and_the_result_is_the_systems() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    let id = rig.repository_id();
    let request = rig
        .ask(
            operator,
            register(id, 8_001, false),
            &detail("org/new"),
            Sign::Good,
        )
        .await;

    // Nothing happens until the worker's step runs: the request alone changes no repository.
    assert!(rig.repository(id).await.is_none());
    assert!(rig.result_of(request).await.is_none());

    rig.settle().await;
    let row = rig.repository(id).await.expect("the repository exists now");
    assert_eq!(row.full_name, "org/new");
    assert_eq!(row.github_repository_id.0, 8_001);
    assert!(
        !row.enabled && !row.single_maintainer,
        "disabled and strict"
    );
    // The designation was asked again, by the numeric GitHub id, for the action row, with the typed id.
    assert_eq!(
        rig.allowed.asked.lock().expect("lock").clone(),
        vec![(
            5_001,
            REGISTER_ACTION.to_owned(),
            "org/new".to_owned(),
            Some(8_001)
        )]
    );
    // The result is the system's, names the request and the person, and is found by its keyed id.
    let (action, _) = rig.result_of(request).await.expect("a result");
    assert_eq!(action, "repository.registered");
    let result = rig
        .records()
        .await
        .into_iter()
        .find(|(action, ..)| action == "repository.registered")
        .expect("the record");
    assert_eq!(result.1, "system");
    assert!(
        result
            .2
            .starts_with(&format!("request={}", request.as_uuid().hyphenated()))
            && result
                .2
                .contains(&format!("requested_by={}", operator.id.as_text())),
        "{}",
        result.2
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_is_applied_once_whatever_the_number_of_passes_and_workers() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    // The tenant has one person who holds the designations of the strict rule, so the exception is possible (RH-6).
    let sole = rig.person(5_002).await;
    rig.allowed.permit(sole.github, ATTEST_ACTION);
    rig.allowed.permit(sole.github, ENABLE_ACTION);
    let id = rig.repository_id();
    rig.ask(
        operator,
        register(id, 8_001, true),
        &detail("org/new"),
        Sign::Good,
    )
    .await;
    rig.settle().await;
    rig.settle().await;
    // A second worker that starts later reads the log from the beginning.
    let later = Rig::step_with(&rig.store, &rig.allowed, &rig.keys, &rig.clock);
    later.pass(rig.tenant).await;
    assert_eq!(rig.count("repository.registered").await, 1);
    assert_eq!(rig.count("repository.change_refused").await, 0);
    assert!(
        rig.repository(id)
            .await
            .expect("registered")
            .single_maintainer
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_designation_is_asked_again_when_the_request_is_applied() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    let id = rig.repository_id();
    let request = rig
        .ask(
            operator,
            register(id, 8_001, false),
            &detail("org/new"),
            Sign::Good,
        )
        .await;
    // The person was taken off the allowlist between the request and the worker's turn.
    rig.allowed.forbid(operator.github, REGISTER_ACTION);
    rig.settle().await;
    assert!(rig.repository(id).await.is_none(), "nothing was registered");
    let (action, reason) = rig.result_of(request).await.expect("a refusal is recorded");
    assert_eq!(action, REFUSED);
    assert!(reason.starts_with("not_permitted:"), "{reason}");

    // The sibling: the same person with the designation, asking again, is applied.
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    let again = rig.repository_id();
    rig.ask(
        operator,
        register(again, 8_002, false),
        &detail("org/again"),
        Sign::Good,
    )
    .await;
    rig.settle().await;
    assert!(rig.repository(again).await.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_person_who_is_no_longer_an_active_human_of_the_tenant_is_refused() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    let id = rig.repository_id();
    let request = rig
        .ask(
            operator,
            register(id, 8_001, false),
            &detail("org/new"),
            Sign::Good,
        )
        .await;
    rig.db
        .run(&format!(
            "UPDATE principals SET disabled_at = now() WHERE id = '{}'",
            operator.id.as_uuid()
        ))
        .await;
    rig.settle().await;
    assert!(rig.repository(id).await.is_none());
    let (_, reason) = rig.result_of(request).await.expect("a refusal");
    assert!(reason.starts_with("not_an_active_person:"), "{reason}");
    assert!(
        rig.allowed.asked.lock().expect("lock").is_empty(),
        "the allowlist is not even asked for a person who is gone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_with_no_word_a_wrong_word_or_a_changed_detail_is_not_a_request() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    let other = rig.person(5_002).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    rig.allowed.permit(other.github, REGISTER_ACTION);
    let mut forged = Vec::new();
    for (n, how) in [
        Sign::NoWord,
        Sign::WrongKey,
        Sign::DetailChangedAfterSigning,
        // Signed for another person: the word covers the actor, so copying a word to another actor fails.
        Sign::ForAnother(other),
    ]
    .into_iter()
    .enumerate()
    {
        let id = rig.repository_id();
        rig.ask(
            operator,
            register(id, 8_100 + n as u64, false),
            &detail(&format!("org/forged-{n}")),
            how,
        )
        .await;
        forged.push(id);
    }
    rig.settle().await;
    for id in &forged {
        assert!(rig.repository(*id).await.is_none(), "{id:?} was applied");
    }
    assert_eq!(rig.count("repository.registered").await, 0);
    assert_eq!(
        rig.count("repository.change_refused").await,
        0,
        "ignored, not answered"
    );
    assert!(
        rig.allowed.asked.lock().expect("lock").is_empty(),
        "nothing past the word was read"
    );

    // The sibling that shows the check can fail: a good word is applied.
    let id = rig.repository_id();
    rig.ask(
        operator,
        register(id, 8_200, false),
        &detail("org/good"),
        Sign::Good,
    )
    .await;
    rig.settle().await;
    assert!(rig.repository(id).await.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn attest_then_enable_apply_in_order_and_another_map_writes_the_switch_off_record() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    let approver = rig.person(5_002).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    rig.allowed.permit(operator.github, ATTEST_ACTION);
    rig.allowed.permit(approver.github, ENABLE_ACTION);
    let id = rig.repository_id();
    rig.ask(
        operator,
        register(id, 8_001, false),
        &detail("org/new"),
        Sign::Good,
    )
    .await;
    rig.ask(
        operator,
        Change::Attest {
            repository: id,
            commit: COMMIT.to_owned(),
        },
        "I read the map files.",
        Sign::Good,
    )
    .await;
    rig.ask(
        approver,
        Change::Enable {
            repository: id,
            commit: COMMIT.to_owned(),
        },
        "Read and agreed.",
        Sign::Good,
    )
    .await;
    rig.settle().await;
    let row = rig.repository(id).await.expect("registered");
    // Each act was asked of the allowlist again, by the numeric id of its person, for the action row, and with the
    // GitHub id of the repository that is registered (RR-28) and not with its name alone.
    let asked = rig.allowed.asked.lock().expect("lock").clone();
    for (user, action) in [(5_001, ATTEST_ACTION), (5_002, ENABLE_ACTION)] {
        assert!(
            asked.iter().any(|(who, what, name, github)| {
                *who == user && what == action && name == "org/new" && *github == Some(8_001)
            }),
            "{action} was not asked with the id of the repository: {asked:?}"
        );
    }
    assert!(row.enabled && row.open_for_new_jobs());
    assert_eq!(row.project_map.expect("a map").attested_by, operator.id);
    assert_eq!(
        row.enabled_for.expect("a record").enabled_by,
        Some(approver.id)
    );
    let attested = rig
        .records()
        .await
        .into_iter()
        .find(|(action, ..)| action == "repository.map_attested")
        .expect("the record");
    assert!(
        attested.3.contains("not a verification") && attested.3.contains("I read the map files."),
        "{}",
        attested.3
    );

    // The map is attested again: the table switches the repository off, and the record of it is the system's.
    let request = rig
        .ask(
            operator,
            Change::Attest {
                repository: id,
                commit: OTHER_COMMIT.to_owned(),
            },
            "A new map.",
            Sign::Good,
        )
        .await;
    rig.settle().await;
    assert!(!rig.repository(id).await.expect("registered").enabled);
    // The record of the effect has an action of its own. `repository.disabled` is the API's, for a person's disable
    // (finding RH-5), and the worker no longer writes it.
    assert_eq!(rig.count("repository.disabled_by_attestation").await, 1);
    assert_eq!(rig.count(DISABLED).await, 0);
    assert_eq!(
        rig.result_of(request).await.expect("applied").0,
        "repository.map_attested"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rules_of_the_map_and_of_the_enabler_are_refused_with_their_codes() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    for action in [REGISTER_ACTION, ATTEST_ACTION, ENABLE_ACTION] {
        rig.allowed.permit(operator.github, action);
    }
    let id = rig.repository_id();
    rig.ask(
        operator,
        register(id, 8_001, false),
        &detail("org/new"),
        Sign::Good,
    )
    .await;
    rig.settle().await;

    // Enable before any map was attested.
    let early = rig
        .ask(
            operator,
            Change::Enable {
                repository: id,
                commit: COMMIT.to_owned(),
            },
            "Too early.",
            Sign::Good,
        )
        .await;
    // The attestor enables a strict repository.
    rig.ask(
        operator,
        Change::Attest {
            repository: id,
            commit: COMMIT.to_owned(),
        },
        "I read it.",
        Sign::Good,
    )
    .await;
    rig.settle().await;
    let same_person = rig
        .ask(
            operator,
            Change::Enable {
                repository: id,
                commit: COMMIT.to_owned(),
            },
            "Myself.",
            Sign::Good,
        )
        .await;
    // A commit that is not the one on file.
    let moved = rig
        .ask(
            operator,
            Change::Enable {
                repository: id,
                commit: OTHER_COMMIT.to_owned(),
            },
            "Moved.",
            Sign::Good,
        )
        .await;
    // The same GitHub repository registered under another id.
    let taken = rig.repository_id();
    let duplicate = rig
        .ask(
            operator,
            register(taken, 8_001, false),
            &detail("org/other-name"),
            Sign::Good,
        )
        .await;
    rig.settle().await;
    let code = |result: Option<(String, String)>| {
        let (action, reason) = result.expect("settled");
        assert_eq!(action, REFUSED);
        reason.split(':').next().unwrap_or_default().to_owned()
    };
    assert_eq!(code(rig.result_of(early).await), "project_map_not_attested");
    assert_eq!(
        code(rig.result_of(same_person).await),
        "enabler_is_attestor"
    );
    assert_eq!(code(rig.result_of(moved).await), "project_map_changed");
    assert_eq!(code(rig.result_of(duplicate).await), "conflict");
    assert!(rig.repository(taken).await.is_none());
    assert!(
        !rig.repository(id).await.expect("registered").enabled,
        "no refusal enabled it"
    );
}

// ---- RH-1: a request has an age, and a disable cancels the requests made before it -----------------------------

/// A tenant with an operator (register, attest), an approver (enable) and a repository that is registered and
/// whose map is attested. Nothing is enabled.
async fn attested_repository(rig: &Rig) -> (Person, Person, RepositoryId) {
    let operator = rig.person(5_001).await;
    let approver = rig.person(5_002).await;
    for action in [REGISTER_ACTION, ATTEST_ACTION] {
        rig.allowed.permit(operator.github, action);
    }
    rig.allowed.permit(approver.github, ENABLE_ACTION);
    let id = rig.repository_id();
    rig.ask(
        operator,
        register(id, 8_001, false),
        &detail("org/new"),
        Sign::Good,
    )
    .await;
    rig.ask(
        operator,
        Change::Attest {
            repository: id,
            commit: COMMIT.to_owned(),
        },
        "I read the map files.",
        Sign::Good,
    )
    .await;
    rig.settle().await;
    assert!(
        rig.repository(id)
            .await
            .is_some_and(|row| row.project_map.is_some())
    );
    (operator, approver, id)
}

fn enable(id: RepositoryId) -> Change {
    Change::Enable {
        repository: id,
        commit: COMMIT.to_owned(),
    }
}

async fn code_of(rig: &Rig, request: AuditEventId) -> String {
    let (action, reason) = rig.result_of(request).await.expect("settled");
    assert_eq!(action, REFUSED, "{reason}");
    reason.split(':').next().unwrap_or_default().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_older_than_the_window_is_refused_as_expired_and_the_refusal_is_recorded() {
    let rig = Rig::new().await;
    let (_, approver, id) = attested_repository(&rig).await;
    let old = rig.ask(approver, enable(id), "Too late.", Sign::Good).await;
    // The worker was down: one second more than the window has passed since the request was made.
    rig.clock
        .advance(REQUEST_MAX_AGE + Duration::from_secs(1) - Duration::from_secs(30));
    rig.settle().await;
    assert_eq!(code_of(&rig, old).await, "expired");
    assert!(
        !rig.repository(id).await.expect("registered").enabled,
        "nothing was enabled"
    );
    assert!(
        rig.allowed
            .asked
            .lock()
            .expect("lock")
            .iter()
            .all(|(_, action, ..)| action != ENABLE_ACTION),
        "an expired request is refused before anything else is asked"
    );

    // The sibling: a request made a minute ago is applied, and so is one made at the last second of the window.
    let fresh = rig
        .ask_at(
            approver,
            enable(id),
            "Just now.",
            Sign::Good,
            &rig.clock.now().as_text(),
        )
        .await;
    rig.clock.advance(REQUEST_MAX_AGE);
    rig.settle().await;
    assert_eq!(
        rig.result_of(fresh).await.expect("applied").0,
        "repository.enabled"
    );
    assert!(rig.repository(id).await.expect("registered").enabled);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_dated_far_ahead_of_the_clock_is_refused_and_one_within_the_skew_is_applied() {
    let rig = Rig::new().await;
    let (_, approver, id) = attested_repository(&rig).await;
    let ahead = |seconds: u64| {
        rig.clock
            .now()
            .checked_add(Duration::from_secs(seconds))
            .expect("a time")
            .as_text()
    };
    let far = rig
        .ask_at(
            approver,
            enable(id),
            "Dated ahead.",
            Sign::Good,
            &ahead(600),
        )
        .await;
    rig.settle().await;
    assert_eq!(code_of(&rig, far).await, "clock_skew");
    assert!(!rig.repository(id).await.expect("registered").enabled);

    let near = rig
        .ask_at(
            approver,
            enable(id),
            "A little ahead.",
            Sign::Good,
            &ahead(60),
        )
        .await;
    rig.settle().await;
    assert_eq!(
        rig.result_of(near).await.expect("applied").0,
        "repository.enabled"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disable_after_the_request_cancels_it_and_a_request_made_after_the_disable_is_applied() {
    let rig = Rig::new().await;
    let (operator, approver, id) = attested_repository(&rig).await;
    let waiting = rig
        .ask(
            approver,
            enable(id),
            "Asked before the incident.",
            Sign::Good,
        )
        .await;
    let stale_attest = rig
        .ask(
            operator,
            Change::Attest {
                repository: id,
                commit: OTHER_COMMIT.to_owned(),
            },
            "An old map.",
            Sign::Good,
        )
        .await;
    // The incident: an operator disables the repository while the worker is not running.
    rig.disable(operator, id).await;
    rig.settle().await;
    assert_eq!(code_of(&rig, waiting).await, "disabled_since_request");
    assert_eq!(code_of(&rig, stale_attest).await, "disabled_since_request");
    let row = rig.repository(id).await.expect("registered");
    assert!(!row.enabled, "the repository stayed disabled");
    assert_eq!(
        row.project_map.expect("a map").commit.as_str(),
        COMMIT,
        "and the old map was not put back"
    );

    // The sibling: a person who still wants it asks again, after the disable, and it is applied.
    let again = rig
        .ask_at(
            approver,
            enable(id),
            "Asked again after the incident.",
            Sign::Good,
            &rig.clock.now().as_text(),
        )
        .await;
    rig.settle().await;
    assert_eq!(
        rig.result_of(again).await.expect("applied").0,
        "repository.enabled"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_of_a_disable_that_a_person_did_not_write_cancels_nothing() {
    let rig = Rig::new().await;
    let (_, approver, id) = attested_repository(&rig).await;
    let request = rig
        .ask(approver, enable(id), "Asked once.", Sign::Good)
        .await;
    // The words of a disable with the system as the actor: the worker's old record of an effect, or a forgery.
    rig.forge_disabled_by_the_system(id).await;
    rig.settle().await;
    assert_eq!(
        rig.result_of(request).await.expect("applied").0,
        "repository.enabled"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disable_that_commits_after_the_pass_read_the_log_still_cancels_the_request() {
    let rig = Rig::new().await;
    let (operator, approver, id) = attested_repository(&rig).await;
    // Two requests in one pass: the first stops in the allowlist (a registration by the operator), the second is
    // the enable. The disable commits while the first is held, after the pass has read the whole log.
    let other = rig.repository_id();
    rig.ask(
        operator,
        register(other, 8_002, false),
        &detail("org/other"),
        Sign::Good,
    )
    .await;
    let enable_request = rig
        .ask(
            approver,
            enable(id),
            "Asked before the incident.",
            Sign::Good,
        )
        .await;
    let gate = rig.allowed.hold(operator.github, REGISTER_ACTION);
    let release = Arc::clone(&gate);
    tokio::join!(rig.step.pass(rig.tenant), async {
        gate.reached.notified().await;
        rig.disable(operator, id).await;
        release.release.notify_one();
    });
    assert_eq!(
        code_of(&rig, enable_request).await,
        "disabled_since_request"
    );
    assert!(!rig.repository(id).await.expect("registered").enabled);
    assert!(
        rig.repository(other).await.is_some(),
        "the other request of the pass was applied"
    );
}

// ---- RH-4: the log is read to its end before anything is applied -----------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_applied_until_a_pass_has_read_the_log_to_its_end() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    let id = rig.repository_id();
    rig.ask(
        operator,
        register(id, 8_001, false),
        &detail("org/new"),
        Sign::Good,
    )
    .await;
    // Seven records after the request, so that no pass of two pages of two records reaches the end of the log.
    for _ in 0..7 {
        let actor = AuditActor::System(Slug::parse("worker.repository").expect("a slug"));
        let mut tx = rig
            .store
            .begin(TenantScope::new(rig.tenant))
            .await
            .expect("tx");
        tx.record_audit(rig.disabled_row(actor, rig.repository_id()))
            .await
            .expect("a record");
        tx.commit().await.expect("commit");
    }
    let step =
        Rig::step_with(&rig.store, &rig.allowed, &rig.keys, &rig.clock).with_page_limits(2, 2);
    step.pass(rig.tenant).await;
    assert!(
        rig.repository(id).await.is_none(),
        "the first pass read four records of nine and applied nothing"
    );
    step.pass(rig.tenant).await;
    assert!(rig.repository(id).await.is_none(), "eight of nine");
    // The ninth record is the last one, the page that holds it is short, and the log is read to its end.
    step.pass(rig.tenant).await;
    assert!(
        rig.repository(id).await.is_some(),
        "the pass that reached the end applied the request"
    );
}

// ---- RH-7: an enable of an enabled repository is answered as applied and names no second approver ---------------

#[tokio::test(flavor = "multi_thread")]
async fn enabling_an_enabled_repository_is_refused_as_already_applied_and_writes_no_second_approver()
 {
    let rig = Rig::new().await;
    let (_, approver, id) = attested_repository(&rig).await;
    let second_approver = rig.person(5_003).await;
    rig.allowed.permit(second_approver.github, ENABLE_ACTION);
    rig.ask(approver, enable(id), "First.", Sign::Good).await;
    rig.settle().await;
    let before = rig.repository(id).await.expect("registered");
    assert!(before.enabled);

    let again = rig
        .ask(second_approver, enable(id), "Second.", Sign::Good)
        .await;
    rig.settle().await;
    assert_eq!(code_of(&rig, again).await, "already_enabled");
    assert_eq!(
        rig.count("repository.enabled").await,
        1,
        "only the first approver is in the log"
    );
    let after = rig.repository(id).await.expect("registered");
    assert_eq!(
        after.enabled_for.expect("a record").enabled_by,
        Some(approver.id),
        "the table still names the first"
    );
    assert_eq!(after.project_map, before.project_map, "nothing else moved");
}

// ---- RH-6: the single-maintainer exception ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_single_maintainer_registration_needs_exactly_one_active_person_who_holds_the_designations()
 {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    let sole = rig.person(5_002).await;
    rig.allowed.permit(sole.github, ATTEST_ACTION);
    rig.allowed.permit(sole.github, ENABLE_ACTION);

    // One holder of both designations: the exception is for exactly this tenant.
    let alone = rig.repository_id();
    let one = rig
        .ask(
            operator,
            register(alone, 8_001, true),
            &detail("org/alone"),
            Sign::Good,
        )
        .await;
    rig.settle().await;
    assert_eq!(
        rig.result_of(one).await.expect("applied").0,
        "repository.registered"
    );
    assert!(rig.repository(alone).await.expect("row").single_maintainer);

    // A second person holds the enable designation: the strict rule can be kept, so the exception is refused.
    let colleague = rig.person(5_003).await;
    rig.allowed.permit(colleague.github, ENABLE_ACTION);
    let two_people = rig.repository_id();
    let refused = rig
        .ask(
            operator,
            register(two_people, 8_002, true),
            &detail("org/two"),
            Sign::Good,
        )
        .await;
    rig.settle().await;
    assert_eq!(
        code_of(&rig, refused).await,
        "single_maintainer_not_allowed"
    );
    assert!(rig.repository(two_people).await.is_none());

    // The sibling: the same registration under the strict rule is applied.
    let strict = rig.repository_id();
    let applied = rig
        .ask(
            operator,
            register(strict, 8_003, false),
            &detail("org/two-strict"),
            Sign::Good,
        )
        .await;
    rig.settle().await;
    assert_eq!(
        rig.result_of(applied).await.expect("applied").0,
        "repository.registered"
    );

    // Only active people are counted: the colleague leaves, and the exception is possible again.
    rig.db
        .run(&format!(
            "UPDATE principals SET disabled_at = now() WHERE id = '{}'",
            colleague.id.as_uuid()
        ))
        .await;
    let after_leaving = rig.repository_id();
    let allowed_again = rig
        .ask(
            operator,
            register(after_leaving, 8_004, true),
            &detail("org/after"),
            Sign::Good,
        )
        .await;
    rig.settle().await;
    assert_eq!(
        rig.result_of(allowed_again).await.expect("applied").0,
        "repository.registered"
    );

    // Nobody holds the designations: nobody could use the exception either.
    rig.allowed.forbid(sole.github, ATTEST_ACTION);
    rig.allowed.forbid(sole.github, ENABLE_ACTION);
    let nobody = rig.repository_id();
    let none = rig
        .ask(
            operator,
            register(nobody, 8_005, true),
            &detail("org/none"),
            Sign::Good,
        )
        .await;
    rig.settle().await;
    assert_eq!(code_of(&rig, none).await, "single_maintainer_not_allowed");
}

// ---- ADR 0026: the rules check is told about the onboarding acts ------------------------------------------------

/// Records what it was told.
#[derive(Default)]
struct Told(Mutex<Vec<(TenantId, RepositoryId)>>);

#[async_trait]
impl factory_composition::project_rules::RepositoryOnboarded for Told {
    async fn onboarded(&self, tenant: TenantId, repository: RepositoryId) {
        self.0.lock().expect("lock").push((tenant, repository));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rules_check_is_told_after_a_register_and_an_enable_and_not_after_an_attest() {
    let rig = Rig::new().await;
    let told = Arc::new(Told::default());
    rig.step.tell_when_onboarded(told.clone());
    let operator = rig.person(5_001).await;
    let approver = rig.person(5_002).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    rig.allowed.permit(operator.github, ATTEST_ACTION);
    rig.allowed.permit(approver.github, ENABLE_ACTION);
    let id = rig.repository_id();
    rig.ask(
        operator,
        register(id, 8_001, false),
        &detail("org/new"),
        Sign::Good,
    )
    .await;
    rig.settle().await;
    assert_eq!(told.0.lock().expect("lock").clone(), vec![(rig.tenant, id)]);
    rig.ask(
        operator,
        Change::Attest {
            repository: id,
            commit: COMMIT.to_owned(),
        },
        "I read the map files.",
        Sign::Good,
    )
    .await;
    rig.settle().await;
    assert_eq!(
        told.0.lock().expect("lock").len(),
        1,
        "an attest is not an onboarding act"
    );
    rig.ask(approver, enable(id), "Read and agreed.", Sign::Good)
        .await;
    rig.settle().await;
    assert_eq!(
        told.0.lock().expect("lock").clone(),
        vec![(rig.tenant, id), (rig.tenant, id)]
    );
    // A refused request tells nothing: the same enable again is refused as already applied.
    let before = told.0.lock().expect("lock").len();
    rig.ask(approver, enable(id), "Read and agreed.", Sign::Good)
        .await;
    rig.settle().await;
    assert_eq!(told.0.lock().expect("lock").len(), before);
}

// ---- RH-2 and RH-12: what the worker asks and what it writes ---------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_is_asked_of_the_allowlist_as_typed_and_a_registered_repository_is_not() {
    let rig = Rig::new().await;
    let (_, approver, id) = attested_repository(&rig).await;
    rig.ask(approver, enable(id), "Enable it.", Sign::Good)
        .await;
    rig.settle().await;
    let typed = rig.allowed.typed.lock().expect("lock").clone();
    let asked = rig.allowed.asked.lock().expect("lock").clone();
    for ((_, action, ..), typed) in asked.iter().zip(typed) {
        assert_eq!(
            typed,
            action == REGISTER_ACTION,
            "{action}: only the registration is a name and an id that a person typed"
        );
    }
    assert!(
        asked
            .iter()
            .any(|(_, action, ..)| action == REGISTER_ACTION)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_worker_refuses_a_name_or_a_branch_of_a_shape_the_api_would_not_accept() {
    let rig = Rig::new().await;
    let operator = rig.person(5_001).await;
    rig.allowed.permit(operator.github, REGISTER_ACTION);
    let mut refused = Vec::new();
    for (n, text) in [
        registration_detail("../..", "main"),
        registration_detail("org/name", "-main"),
        registration_detail("org/name", "a..b"),
        registration_detail("org/a/b", "main"),
        registration_detail("org/na;me", "main"),
    ]
    .into_iter()
    .enumerate()
    {
        let id = rig.repository_id();
        let request = rig
            .ask(
                operator,
                register(id, 8_300 + n as u64, false),
                &text,
                Sign::Good,
            )
            .await;
        refused.push((id, request));
    }
    rig.settle().await;
    for (id, request) in refused {
        assert_eq!(code_of(&rig, request).await, "malformed");
        assert!(rig.repository(id).await.is_none());
    }
    // The sibling: a name and a branch of the accepted shape are applied.
    let id = rig.repository_id();
    rig.ask(
        operator,
        register(id, 8_400, false),
        &registration_detail("org/name.v2", "release/1.0"),
        Sign::Good,
    )
    .await;
    rig.settle().await;
    assert!(rig.repository(id).await.is_some());
}
