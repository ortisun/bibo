//! Register, attest and enable as signed requests that the worker applies (finding REG-2).
//!
//! Real: PostgreSQL (the worker's login), the signing and the step. Fake and labelled so: the allowlist,
//! which the tests set person by person and which records what it was asked, so that a test shows the
//! designation was asked again, by numeric id, with the repository's GitHub id. The real allowlist file is
//! tried in `apps/api/tests/repositories.rs`.

mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_composition::decision_signing::{DecisionKeys, RepositoryChangeSigning};
use factory_composition::decisions::Unreadable;
use factory_composition::repository_changes::{
    ATTEST_ACTION, Change, ChangeAuthority, ENABLE_ACTION, REFUSED, REGISTER_ACTION, REQUESTED,
    RepositoryChangeFields, RepositoryChanges, RepositoryChangesDeps, payload_digest,
    registration_detail,
};
use factory_domain::ids::{AuditEventId, CorrelationId, PrincipalId, RepositoryId, TenantId};
use factory_domain::policy::authority::RepositoryIdentity;
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_ports::clock::IdGenerator;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, NewAuditEvent, Store,
};
use support::pg_world;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const AT: &str = "2026-11-03T10:00:00.123456789Z";

/// What the allowlist was asked: the GitHub id of the person, the action, and the name and GitHub id of the repository.
type Asked = (u64, String, String, Option<u64>);

/// The allowlist of the test: who holds which action, and what it was asked.
struct Allowed {
    permitted: Mutex<BTreeSet<(u64, String)>>,
    asked: Mutex<Vec<Asked>>,
}

impl Allowed {
    fn nobody() -> Arc<Self> {
        Arc::new(Self {
            permitted: Mutex::new(BTreeSet::new()),
            asked: Mutex::new(Vec::new()),
        })
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
        Ok(self
            .permitted
            .lock()
            .expect("lock")
            .contains(&(github_user_id, action.to_owned())))
    }
}

struct Rig {
    db: support::TestDb,
    tenant: TenantId,
    store: Arc<dyn Store>,
    keys: Arc<DecisionKeys>,
    allowed: Arc<Allowed>,
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
        let step = RepositoryChanges::new(RepositoryChangesDeps {
            store: Arc::clone(&store),
            authority: allowed.clone(),
            policy_hash: Sha256Digest::of(b"a policy"),
            keys: Arc::clone(&keys),
        });
        Self {
            db,
            tenant,
            store,
            keys,
            allowed,
            step,
            ids: factory_composition::system::RandomIds::new().expect("random"),
        }
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

    /// Writes a request the way the API does, with the word chosen by `how`.
    async fn ask(&self, who: Person, change: Change, detail: &str, how: Sign) -> AuditEventId {
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
                requested_at: AT,
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
                    requested_at: AT,
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
    let later = RepositoryChanges::new(RepositoryChangesDeps {
        store: Arc::clone(&rig.store),
        authority: rig.allowed.clone(),
        policy_hash: Sha256Digest::of(b"a policy"),
        keys: Arc::clone(&rig.keys),
    });
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
    assert_eq!(rig.count("repository.disabled").await, 1);
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
