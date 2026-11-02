//! Registering a repository, attesting its project map, enabling it and disabling it
//! (`/v1/repositories`), through the real server, a real PostgreSQL and the API login.
//!
//! What these tests show, each with the sibling that proves the check can fail:
//!
//! * the path register, attest, enable, disable, and what it does to a webhook and to a job;
//! * each role is refused and accepted for each action, and a refusal changes nothing;
//! * another tenant cannot see or change the repository;
//! * enabling without a project map is refused by the database itself, not only by the code;
//! * a replayed idempotency key repeats nothing, and the same key with another request is a
//!   conflict;
//! * the audit chain stays valid, and its text says that the map is a person's statement;
//! * a malformed commit, reason or body is refused, and a registration cannot carry the flags.
//!
//! The engine holds no GitHub credential. Nothing here makes it look at a repository, and no test
//! says that it did.

mod support;

use diesel_async::SimpleAsyncConnection;
use serde_json::{Value, json};
use support::{Env, Person, Reply, Req, allowlist_text};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const REASON: &str = "I read the map files in the merged pull request.";

fn registration(n: u64) -> Value {
    json!({
        "installation_id": 7000 + n,
        "github_repository_id": 8000 + n,
        "full_name": format!("org/new-{n}"),
        "default_branch": "main",
    })
}

fn attestation() -> Value {
    json!({"commit": COMMIT, "reason": REASON})
}

async fn post(env: &Env, person: &Person, path: &str, key: &str, body: &Value) -> Reply {
    env.send(
        Req::post(path)
            .bearer(&person.token)
            .header("Idempotency-Key", key)
            .json(body),
    )
    .await
}

async fn get(env: &Env, person: &Person, path: &str) -> Reply {
    env.send(Req::get(path).bearer(&person.token)).await
}

/// Registers repository `n` for tenant A's operator and returns its id.
async fn register(env: &Env, n: u64) -> String {
    let made = post(
        env,
        &env.a.operator,
        "/v1/repositories",
        &format!("register-{n}"),
        &registration(n),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.text());
    made.json()["repository"]["repository_id"]
        .as_str()
        .expect("an id")
        .to_owned()
}

async fn attest(env: &Env, id: &str, key: &str) -> Reply {
    post(
        env,
        &env.a.operator,
        &format!("/v1/repositories/{id}/project-map"),
        key,
        &attestation(),
    )
    .await
}

async fn enable(env: &Env, id: &str, key: &str) -> Reply {
    post(
        env,
        &env.a.approver,
        &format!("/v1/repositories/{id}/enable"),
        key,
        &json!({}),
    )
    .await
}

async fn disable(env: &Env, id: &str, key: &str) -> Reply {
    post(
        env,
        &env.a.operator,
        &format!("/v1/repositories/{id}/disable"),
        key,
        &json!({}),
    )
    .await
}

/// A repository that is registered, mapped and enabled.
async fn enabled_repository(env: &Env, n: u64) -> String {
    let id = register(env, n).await;
    assert_eq!(attest(env, &id, &format!("attest-{n}")).await.status, 200);
    assert_eq!(enable(env, &id, &format!("enable-{n}")).await.status, 200);
    id
}

async fn flag(env: &Env, id: &str, column: &str) -> Option<String> {
    env.db
        .text(&format!(
            "SELECT {column} FROM repositories WHERE id = '{id}'"
        ))
        .await
}

async fn audit_actions(env: &Env) -> String {
    env.db
        .text(
            "SELECT coalesce(string_agg(action, ',' ORDER BY sequence), '') FROM audit_events \
              WHERE action LIKE 'repository.%'",
        )
        .await
        .unwrap_or_default()
}

async fn chain_is_sound(env: &Env) -> bool {
    env.db
        .text(&format!(
            "SELECT coalesce(audit_verify_chain('{}')::text, 'sound')",
            env.a.id.as_uuid()
        ))
        .await
        .as_deref()
        == Some("sound")
}

fn delivery_id(n: u64) -> String {
    format!("0190a3b2-7c4d-4e5f-8a6b-{n:012}")
}

/// A label on an issue of repository `n`, from `sender`.
fn label_payload(n: u64, sender: u64, issue: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "action": "labeled",
        "installation": {"id": 7000 + n},
        "repository": {"id": 8000 + n, "full_name": format!("org/new-{n}")},
        "sender": {"id": sender, "login": "someone", "type": "User"},
        "issue": {"number": issue, "node_id": format!("I_{issue}"), "updated_at": "2026-10-28T10:00:00Z"},
        "label": {"name": "factory"},
    }))
    .expect("json")
}

async fn jobs_of(env: &Env, id: &str) -> i64 {
    env.db
        .number(&format!(
            "SELECT count(*) FROM jobs WHERE repository_id = '{id}'"
        ))
        .await
}

// ---- the path --------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repository_goes_from_registered_to_taking_tickets_and_back() {
    let env = Env::start().await;
    let a = &env.a;

    // 1. Register. It starts disabled, at level L0, with no protection result and no map.
    let made = post(
        &env,
        &a.operator,
        "/v1/repositories",
        "register-1",
        &registration(1),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.text());
    let body = made.json();
    assert_eq!(body["changed"], true);
    let repository = &body["repository"];
    assert_eq!(repository["enabled"], false);
    assert_eq!(repository["autonomy_ceiling"], "L0");
    assert_eq!(repository["protection_preflight_passed"], false);
    assert_eq!(repository["project_map"], Value::Null);
    assert_eq!(repository["version"], 1);
    assert_eq!(repository["full_name"], "org/new-1");
    assert_eq!(repository["github_installation_id"], 7001);
    let id = repository["repository_id"]
        .as_str()
        .expect("an id")
        .to_owned();

    // Any listed person can read it, and sees the same.
    let shown = get(&env, &a.requester, &format!("/v1/repositories/{id}")).await;
    assert_eq!(shown.status, 200, "{}", shown.text());
    assert_eq!(shown.json(), *repository);

    // A label on its issues starts nothing yet: the repository is not enabled.
    let before = env
        .send(env.delivery(
            "issues",
            &delivery_id(1),
            &label_payload(1, a.requester.github_id, 11),
        ))
        .await;
    assert_eq!(before.status, 202);
    assert_eq!(jobs_of(&env, &id).await, 0);

    // 2. Enabling without a map is refused with a typed answer and changes nothing.
    let early = enable(&env, &id, "enable-early").await;
    assert_eq!(early.status, 409, "{}", early.text());
    assert_eq!(early.json(), json!({"error": "project_map_not_attested"}));
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));
    assert_eq!(flag(&env, &id, "version").await.as_deref(), Some("1"));

    // 3. A person attests the map. The answer says that the engine did not check it.
    let attested = attest(&env, &id, "attest-1").await;
    assert_eq!(attested.status, 200, "{}", attested.text());
    let map = attested.json()["repository"]["project_map"].clone();
    assert_eq!(map["commit"], COMMIT);
    assert_eq!(map["attested_by"], a.operator.principal.as_text());
    assert_eq!(map["verified_by_engine"], false);
    assert!(
        map["attested_at"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z'))
    );
    assert_eq!(attested.json()["repository"]["enabled"], false);
    assert_eq!(attested.json()["repository"]["version"], 2);

    // 4. Enable. A label now makes a job, and so does a request through the API.
    let enabled = enable(&env, &id, "enable-1").await;
    assert_eq!(enabled.status, 200, "{}", enabled.text());
    assert_eq!(enabled.json()["repository"]["enabled"], true);
    assert_eq!(enabled.json()["repository"]["version"], 3);
    let label = env
        .send(env.delivery(
            "issues",
            &delivery_id(2),
            &label_payload(1, a.requester.github_id, 12),
        ))
        .await;
    assert_eq!(label.status, 202);
    assert_eq!(
        jobs_of(&env, &id).await,
        1,
        "an enabled repository takes the label"
    );
    let submitted = post(
        &env,
        &a.requester,
        "/v1/jobs",
        "job-1",
        &json!({"repository_id": id, "text": "Add a word count command.", "source_ref": "org/new-1#13"}),
    )
    .await;
    assert_eq!(submitted.status, 201, "{}", submitted.text());
    assert_eq!(jobs_of(&env, &id).await, 2);

    // 5. Disable. The webhook is dropped again, and a job cannot be submitted.
    let off = disable(&env, &id, "disable-1").await;
    assert_eq!(off.status, 200, "{}", off.text());
    assert_eq!(off.json()["repository"]["enabled"], false);
    assert_eq!(
        off.json()["repository"]["project_map"]["commit"],
        COMMIT,
        "the map stays when the repository is switched off"
    );
    let dropped = env
        .send(env.delivery(
            "issues",
            &delivery_id(3),
            &label_payload(1, a.requester.github_id, 14),
        ))
        .await;
    assert_eq!(dropped.status, 202, "the answer to GitHub does not change");
    assert_eq!(jobs_of(&env, &id).await, 2, "and no job was made");
    let refused = post(
        &env,
        &a.requester,
        "/v1/jobs",
        "job-2",
        &json!({"repository_id": id, "text": "Add a word count command.", "source_ref": "org/new-1#15"}),
    )
    .await;
    assert_eq!(refused.status, 404, "{}", refused.text());
    assert_eq!(jobs_of(&env, &id).await, 2);

    // 6. The sibling: enabled again, the same repository takes the label again.
    assert_eq!(enable(&env, &id, "enable-2").await.status, 200);
    let again = env
        .send(env.delivery(
            "issues",
            &delivery_id(4),
            &label_payload(1, a.requester.github_id, 16),
        ))
        .await;
    assert_eq!(again.status, 202);
    assert_eq!(jobs_of(&env, &id).await, 3);

    // Every change left one audit record, in order, written by the person, and the chain holds.
    assert_eq!(
        audit_actions(&env).await,
        "repository.registered,repository.map_attested,repository.enabled,repository.disabled,repository.enabled"
    );
    assert!(chain_is_sound(&env).await, "the audit chain is not sound");
    assert_eq!(
        env.db
            .number(&format!(
                "SELECT count(*) FROM audit_events WHERE action LIKE 'repository.%' AND actor_id = '{}'",
                a.operator.principal.as_uuid()
            ))
            .await,
        3,
        "registered, map_attested and disabled are the operator's"
    );
    let reason = env
        .db
        .text("SELECT reason FROM audit_events WHERE action = 'repository.map_attested'")
        .await
        .expect("the audit text");
    assert!(
        reason.contains("not a verification") && reason.contains("did not read the repository"),
        "{reason}"
    );
    assert!(reason.contains(REASON), "{reason}");
    env.stop().await;
}

// ---- roles ------------------------------------------------------------------------------------

/// Who may do what, from the `actions` table of `policies/approval.yaml`: the operator registers,
/// attests and disables; the approver enables. Nobody else does any of them, a security approver
/// and a requester included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_role_is_refused_and_accepted_for_each_action() {
    let env = Env::start().await;
    let a = &env.a;
    let others = [
        ("a requester", &a.requester),
        ("an approver", &a.approver),
        ("a security approver", &a.security),
        ("a person on no list", &a.outsider),
    ];

    // Register: the operator only.
    for (name, person) in others {
        let reply = post(
            &env,
            person,
            "/v1/repositories",
            "register-x",
            &registration(1),
        )
        .await;
        assert_eq!(reply.status, 403, "{name}: {}", reply.text());
        assert_eq!(reply.json(), json!({"error": "forbidden"}), "{name}");
    }
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE full_name = 'org/new-1'")
            .await,
        0,
        "no refusal registered anything"
    );
    let id = register(&env, 1).await;

    // Attest the map: the operator only.
    for (name, person) in others {
        let reply = post(
            &env,
            person,
            &format!("/v1/repositories/{id}/project-map"),
            "attest-x",
            &attestation(),
        )
        .await;
        assert_eq!(reply.status, 403, "{name}: {}", reply.text());
    }
    assert_eq!(
        flag(&env, &id, "project_map_commit").await,
        None,
        "no map was written"
    );
    assert_eq!(attest(&env, &id, "attest-1").await.status, 200);

    // Enable: the approver only. The operator, who attested the map, may not.
    let not_approvers = [
        ("a requester", &a.requester),
        ("an operator", &a.operator),
        ("a security approver", &a.security),
        ("a person on no list", &a.outsider),
    ];
    for (name, person) in not_approvers {
        let reply = post(
            &env,
            person,
            &format!("/v1/repositories/{id}/enable"),
            "enable-x",
            &json!({}),
        )
        .await;
        assert_eq!(reply.status, 403, "{name}: {}", reply.text());
    }
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));
    assert_eq!(enable(&env, &id, "enable-1").await.status, 200);
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("true"));

    // Disable: the operator only. The approver, who enabled it, may not.
    let not_operators = [
        ("a requester", &a.requester),
        ("an approver", &a.approver),
        ("a security approver", &a.security),
        ("a person on no list", &a.outsider),
    ];
    for (name, person) in not_operators {
        let reply = post(
            &env,
            person,
            &format!("/v1/repositories/{id}/disable"),
            "disable-x",
            &json!({}),
        )
        .await;
        assert_eq!(reply.status, 403, "{name}: {}", reply.text());
    }
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("true"));
    assert_eq!(disable(&env, &id, "disable-1").await.status, 200);
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));

    // Every refusal was audited as a refusal and as nothing else, within the bound per person.
    assert_eq!(
        audit_actions(&env).await,
        "repository.registered,repository.map_attested,repository.enabled,repository.disabled"
    );
    assert!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'decision.denied' AND subject LIKE 'repository.%'")
            .await
            >= 12,
        "the refusals are in the audit log"
    );
    assert!(chain_is_sound(&env).await);

    // No token, no answer.
    let anonymous = env
        .send(
            Req::post("/v1/repositories")
                .header("Idempotency-Key", "k")
                .json(&registration(2)),
        )
        .await;
    assert_eq!(anonymous.status, 401);
    // Reading is for anyone on the list, and not for a person on no list.
    let read = get(&env, &a.outsider, &format!("/v1/repositories/{id}")).await;
    assert_eq!(read.status, 403);
    env.stop().await;
}

/// API-1: an allowlist entry narrowed to other repositories holds the designation only there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_narrowed_to_other_repositories_cannot_register_or_change_this_one() {
    let env = Env::start().await;
    let a = &env.a;
    let plain = format!(
        "  - tenant: {}\n    github_user_id: {}\n    login: {}\n    designations: [operator]\n",
        a.id.as_uuid(),
        a.operator.github_id,
        a.operator.login
    );
    let all = allowlist_text(&[&env.a, &env.b]);
    assert!(all.contains(&plain), "the entry to narrow is in the file");
    let narrowed =
        |names: &str| all.replacen(&plain, &format!("{plain}    repositories: [{names}]\n"), 1);
    let path = env.checkout.join("allowlist/allowlist.yaml");
    let id = register(&env, 1).await;

    std::fs::write(&path, narrowed("\"org/elsewhere\"")).expect("narrowed elsewhere");
    let register_here = post(
        &env,
        &a.operator,
        "/v1/repositories",
        "register-2",
        &registration(2),
    )
    .await;
    assert_eq!(register_here.status, 403, "{}", register_here.text());
    for (what, request) in [
        ("attest", attest(&env, &id, "attest-n").await),
        ("disable", disable(&env, &id, "disable-n").await),
    ] {
        assert_eq!(request.status, 403, "{what}: {}", request.text());
    }
    assert_eq!(flag(&env, &id, "project_map_commit").await, None);
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE full_name = 'org/new-2'")
            .await,
        0
    );

    // The sibling: narrowed to the repository, the same calls work (the name is not case sensitive).
    std::fs::write(&path, narrowed("\"org/new-1\", \"ORG/NEW-2\"")).expect("narrowed here");
    assert_eq!(attest(&env, &id, "attest-n2").await.status, 200);
    let register_here = post(
        &env,
        &a.operator,
        "/v1/repositories",
        "register-2",
        &registration(2),
    )
    .await;
    assert_eq!(register_here.status, 201, "{}", register_here.text());
    env.stop().await;
}

// ---- tenants ----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_tenant_cannot_see_or_change_the_repository() {
    let env = Env::start().await;
    let id = register(&env, 1).await;
    let b = &env.b;
    let unknown = "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b";

    // Tenant B's people get the answer they would get for a repository that does not exist.
    let missing = get(&env, &b.operator, &format!("/v1/repositories/{unknown}")).await;
    assert_eq!(missing.status, 404);
    let foreign = get(&env, &b.operator, &format!("/v1/repositories/{id}")).await;
    assert_eq!(foreign.status, 404);
    assert_eq!(foreign.body, missing.body, "the same bytes");
    for (what, person, path, body) in [
        ("attest", &b.operator, "project-map", attestation()),
        ("enable", &b.approver, "enable", json!({})),
        ("disable", &b.operator, "disable", json!({})),
    ] {
        let reply = post(
            &env,
            person,
            &format!("/v1/repositories/{id}/{path}"),
            "foreign-1",
            &body,
        )
        .await;
        assert_eq!(reply.status, 404, "{what}: {}", reply.text());
        let nothing = post(
            &env,
            person,
            &format!("/v1/repositories/{unknown}/{path}"),
            "foreign-1",
            &body,
        )
        .await;
        assert_eq!(
            reply.body, nothing.body,
            "{what}: a foreign id looks like a missing id"
        );
    }
    assert_eq!(flag(&env, &id, "project_map_commit").await, None);
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));
    assert_eq!(flag(&env, &id, "version").await.as_deref(), Some("1"));

    // The same GitHub repository cannot be registered by the other tenant, and the answer does
    // not say whose it is. It is the same answer a tenant gets for registering its own twice.
    let squat = post(
        &env,
        &b.operator,
        "/v1/repositories",
        "squat-1",
        &registration(1),
    )
    .await;
    assert_eq!(squat.status, 409, "{}", squat.text());
    assert_eq!(squat.json(), json!({"error": "conflict"}));
    let twice = post(
        &env,
        &env.a.operator,
        "/v1/repositories",
        "again-1",
        &registration(1),
    )
    .await;
    assert_eq!(twice.status, 409, "{}", twice.text());
    assert_eq!(twice.body, squat.body);
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE github_repository_id = 8001")
            .await,
        1,
        "one registration of the GitHub repository in the whole factory"
    );

    // The sibling: the owner reads and changes it, and tenant B registers a different repository.
    assert_eq!(
        get(&env, &env.a.requester, &format!("/v1/repositories/{id}"))
            .await
            .status,
        200
    );
    assert_eq!(attest(&env, &id, "attest-1").await.status, 200);
    let other = post(
        &env,
        &b.operator,
        "/v1/repositories",
        "b-2",
        &registration(2),
    )
    .await;
    assert_eq!(other.status, 201, "{}", other.text());
    assert_eq!(
        env.db
            .text("SELECT tenant_id::text FROM repositories WHERE full_name = 'org/new-2'")
            .await,
        Some(b.id.as_uuid().to_string()),
        "the new repository belongs to the tenant of its registrant"
    );
    env.stop().await;
}

// ---- the database holds the rule too ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enabling_without_a_map_is_refused_by_the_database_itself() {
    let env = Env::start().await;
    let id = register(&env, 1).await;
    let tenant = env.a.id.as_uuid();

    // As the owner of the database, which bypasses row-level security.
    let mut admin = env.db.admin().await;
    let refused = admin
        .batch_execute(&format!(
            "UPDATE repositories SET enabled = true, version = version + 1 WHERE id = '{id}'"
        ))
        .await;
    let message = format!("{refused:?}");
    assert!(
        refused.is_err() && message.contains("repositories_enabled_needs_project_map"),
        "{message}"
    );

    // As the API login, naming the tenant by hand.
    let logins = env.db.server.logins().await;
    let mut api = env.db.connect_as(&logins.api).await;
    let refused = api
        .batch_execute(&format!(
            "BEGIN; SELECT set_config('factory.tenant_id', '{tenant}', true); \
             UPDATE repositories SET enabled = true, version = version + 1 WHERE id = '{id}'; COMMIT;"
        ))
        .await;
    let message = format!("{refused:?}");
    assert!(
        refused.is_err() && message.contains("repositories_enabled_needs_project_map"),
        "{message}"
    );
    let _ = api.batch_execute("ROLLBACK").await;

    // As the worker login.
    let mut worker = env.db.connect_as(&logins.worker).await;
    let refused = worker
        .batch_execute(&format!(
            "BEGIN; SELECT set_config('factory.tenant_id', '{tenant}', true); \
             UPDATE repositories SET enabled = true, version = version + 1 WHERE id = '{id}'; COMMIT;"
        ))
        .await;
    assert!(
        refused.is_err(),
        "the worker enabled a repository with no map"
    );
    let _ = worker.batch_execute("ROLLBACK").await;

    // A row cannot be inserted already enabled, either.
    let refused = admin
        .batch_execute(&format!(
            "INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, enabled) \
             VALUES ('{tenant}', '0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b', 1, 2, 'org/raw', 'main', true)"
        ))
        .await;
    assert!(refused.is_err(), "an enabled row was inserted with no map");
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));

    // The sibling: the same statement with a map commit and its attestor is accepted.
    admin
        .batch_execute(&format!(
            "UPDATE repositories SET enabled = true, project_map_commit = '{COMMIT}', \
                 project_map_attested_by_principal_id = '{}', version = version + 1 WHERE id = '{id}'",
            env.a.operator.principal.as_uuid()
        ))
        .await
        .expect("a repository with a map can be enabled");
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("true"));
    env.stop().await;
}

// ---- exactly once -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_idempotency_key_repeats_nothing() {
    let env = Env::start().await;
    let a = &env.a;

    // Register twice with one key: one repository, one record, the same answer but for "changed".
    let first = post(
        &env,
        &a.operator,
        "/v1/repositories",
        "r-1",
        &registration(1),
    )
    .await;
    assert_eq!(first.status, 201);
    let again = post(
        &env,
        &a.operator,
        "/v1/repositories",
        "r-1",
        &registration(1),
    )
    .await;
    assert_eq!(again.status, 200, "{}", again.text());
    assert_eq!(again.json()["changed"], false);
    assert_eq!(again.json()["repository"], first.json()["repository"]);
    let id = first.json()["repository"]["repository_id"]
        .as_str()
        .expect("id")
        .to_owned();
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE full_name = 'org/new-1'")
            .await,
        1
    );
    // The same key with another request is a conflict, and so is another person's request that
    // would have the same effect (the key belongs to its caller).
    let other = post(
        &env,
        &a.operator,
        "/v1/repositories",
        "r-1",
        &registration(2),
    )
    .await;
    assert_eq!(other.status, 409, "{}", other.text());
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE full_name = 'org/new-2'")
            .await,
        0
    );

    // Attest twice with one key: one version step, one record.
    let first = attest(&env, &id, "a-1").await;
    assert_eq!(first.status, 200);
    let version = first.json()["repository"]["version"].clone();
    let again = attest(&env, &id, "a-1").await;
    assert_eq!(again.status, 200);
    assert_eq!(again.json()["changed"], false);
    assert_eq!(
        again.json()["repository"]["version"],
        version,
        "no second change"
    );
    let different = post(
        &env,
        &a.operator,
        &format!("/v1/repositories/{id}/project-map"),
        "a-1",
        &json!({"commit": OTHER_COMMIT, "reason": REASON}),
    )
    .await;
    assert_eq!(
        different.status,
        409,
        "the same key with another commit: {}",
        different.text()
    );
    assert_eq!(
        flag(&env, &id, "project_map_commit").await.as_deref(),
        Some(COMMIT)
    );
    // A new key attests a new commit, and the earlier key still repeats nothing.
    let newer = post(
        &env,
        &a.operator,
        &format!("/v1/repositories/{id}/project-map"),
        "a-2",
        &json!({"commit": OTHER_COMMIT, "reason": REASON}),
    )
    .await;
    assert_eq!(newer.status, 200, "{}", newer.text());
    assert_eq!(attest(&env, &id, "a-1").await.json()["changed"], false);
    assert_eq!(
        flag(&env, &id, "project_map_commit").await.as_deref(),
        Some(OTHER_COMMIT),
        "replaying the first key did not put the first commit back"
    );

    // Enable and disable: a key replayed after the opposite change does not undo it.
    assert_eq!(enable(&env, &id, "e-1").await.status, 200);
    let repeat = enable(&env, &id, "e-1").await;
    assert_eq!(repeat.status, 200);
    assert_eq!(repeat.json()["changed"], false);
    assert_eq!(disable(&env, &id, "d-1").await.status, 200);
    let replay = enable(&env, &id, "e-1").await;
    assert_eq!(replay.status, 200);
    assert_eq!(replay.json()["changed"], false);
    assert_eq!(
        flag(&env, &id, "enabled").await.as_deref(),
        Some("false"),
        "an old enable key switched the repository on again"
    );
    let replay = disable(&env, &id, "d-1").await;
    assert_eq!(replay.json()["changed"], false);

    // The records: one for each change, none for a replay.
    assert_eq!(
        audit_actions(&env).await,
        "repository.registered,repository.map_attested,repository.map_attested,repository.enabled,repository.disabled"
    );
    assert!(chain_is_sound(&env).await);

    // The key belongs to its caller. The same person with another token is the same caller, and
    // finds the record. Another person who holds the designation, with the same key, writes a
    // record of their own and is not told that the first person's change is theirs.
    let second_token = env
        .issue_token(&env.a, &env.a.operator, support::Kind::Valid)
        .await;
    let same_person = env
        .send(
            Req::post(&format!("/v1/repositories/{id}/disable"))
                .bearer(&second_token)
                .header("Idempotency-Key", "d-1")
                .json(&json!({})),
        )
        .await;
    assert_eq!(same_person.status, 200);
    assert_eq!(same_person.json()["changed"], false);
    let plain = format!(
        "  - tenant: {}\n    github_user_id: {}\n    login: {}\n    designations: [approver]\n",
        a.id.as_uuid(),
        a.approver.github_id,
        a.approver.login
    );
    let all = allowlist_text(&[&env.a, &env.b]);
    assert!(all.contains(&plain), "the entry to widen is in the file");
    std::fs::write(
        env.checkout.join("allowlist/allowlist.yaml"),
        all.replacen(
            &plain,
            &plain.replace("[approver]", "[approver, operator]"),
            1,
        ),
    )
    .expect("the allowlist");
    let another_person = post(
        &env,
        &a.approver,
        &format!("/v1/repositories/{id}/disable"),
        "d-1",
        &json!({}),
    )
    .await;
    assert_eq!(another_person.status, 200, "{}", another_person.text());
    assert_eq!(
        another_person.json()["changed"],
        true,
        "another person's request with the same key is their own request"
    );
    assert_eq!(
        audit_actions(&env).await,
        "repository.registered,repository.map_attested,repository.map_attested,repository.enabled,repository.disabled,repository.disabled"
    );
    env.stop().await;
}

// ---- malformed input --------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_commit_reason_or_body_is_refused_and_leaves_no_change() {
    let env = Env::start().await;
    let a = &env.a;
    let id = register(&env, 1).await;
    let path = format!("/v1/repositories/{id}/project-map");

    let bad_commits = [
        ("an empty commit", String::new()),
        ("39 characters", COMMIT[..39].to_owned()),
        ("41 characters", format!("{COMMIT}a")),
        ("a 64-character object id", "a".repeat(64)),
        ("upper case", COMMIT.to_uppercase()),
        ("not hexadecimal", "g".repeat(40)),
        ("a leading space", format!(" {}", &COMMIT[..39])),
        ("a trailing newline", format!("{}\n", &COMMIT[..39])),
        ("a branch name", "main".to_owned()),
        ("a ref", "refs/heads/main".to_owned()),
        ("a SHA-256 label", format!("sha256:{}", "a".repeat(33))),
    ];
    for (name, commit) in bad_commits {
        let reply = post(
            &env,
            &a.operator,
            &path,
            "bad",
            &json!({"commit": commit, "reason": REASON}),
        )
        .await;
        assert_eq!(reply.status, 400, "{name}: {}", reply.text());
        assert_eq!(
            reply.json(),
            json!({"error": "bad_request", "field": "commit"}),
            "{name}"
        );
    }
    let secret = ["sfat_", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"].concat();
    let bad_reasons = [
        ("nine characters", "123456789".to_owned()),
        ("only spaces", " ".repeat(20)),
        ("501 characters", "r".repeat(501)),
        (
            "a control character",
            "I read it.\u{1b}[2J all of it".to_owned(),
        ),
        ("a NUL", "I read the map\u{0}and the code".to_owned()),
        ("a token", format!("I used {secret} to read it")),
    ];
    for (name, reason) in bad_reasons {
        let reply = post(
            &env,
            &a.operator,
            &path,
            "bad",
            &json!({"commit": COMMIT, "reason": reason}),
        )
        .await;
        assert_eq!(reply.status, 400, "{name}: {}", reply.text());
        assert_eq!(
            reply.json(),
            json!({"error": "bad_request", "field": "reason"}),
            "{name}"
        );
    }
    for (name, body) in [
        ("no reason", json!({"commit": COMMIT})),
        ("no commit", json!({"reason": REASON})),
        (
            "a commit that is a number",
            json!({"commit": 5, "reason": REASON}),
        ),
        (
            "an extra field",
            json!({"commit": COMMIT, "reason": REASON, "verified": true}),
        ),
        ("an array", json!([COMMIT])),
    ] {
        let reply = post(&env, &a.operator, &path, "bad", &body).await;
        assert_eq!(reply.status, 400, "{name}: {}", reply.text());
    }
    // A body that is not JSON, and one sent with another content type.
    let not_json = env
        .send(
            Req::post(&path)
                .bearer(&a.operator.token)
                .header("Idempotency-Key", "bad")
                .header("Content-Type", "application/json")
                .body(b"commit=abc".to_vec()),
        )
        .await;
    assert_eq!(not_json.status, 400);
    let wrong_type = env
        .send(
            Req::post(&path)
                .bearer(&a.operator.token)
                .header("Idempotency-Key", "bad")
                .header("Content-Type", "text/plain")
                .body(b"{}".to_vec()),
        )
        .await;
    assert_eq!(wrong_type.status, 415);
    let no_key = env
        .send(
            Req::post(&path)
                .bearer(&a.operator.token)
                .json(&attestation()),
        )
        .await;
    assert_eq!(no_key.status, 400);
    assert_eq!(no_key.json()["field"], "idempotency-key");
    assert_eq!(
        flag(&env, &id, "project_map_commit").await,
        None,
        "no refusal left a map"
    );
    assert_eq!(flag(&env, &id, "version").await.as_deref(), Some("1"));

    // A reason of 10 characters and a commit of 40 are accepted: the limits are where they say.
    let edge = post(
        &env,
        &a.operator,
        &path,
        "edge",
        &json!({"commit": COMMIT, "reason": "1234567890"}),
    )
    .await;
    assert_eq!(edge.status, 200, "{}", edge.text());
    let edge = post(
        &env,
        &a.operator,
        &path,
        "edge-2",
        &json!({"commit": COMMIT, "reason": "r".repeat(500)}),
    )
    .await;
    assert_eq!(edge.status, 200, "{}", edge.text());

    // A registration refuses the flags it must not carry, and the values it cannot hold.
    for (name, extra) in [
        ("enabled", json!({"enabled": true})),
        ("an autonomy ceiling", json!({"autonomy_ceiling": "L3"})),
        (
            "a passed preflight",
            json!({"protection_preflight_passed": true}),
        ),
        ("a map", json!({"project_map_commit": COMMIT})),
        (
            "a tenant",
            json!({"tenant_id": env.b.id.as_uuid().to_string()}),
        ),
        (
            "an id",
            json!({"id": "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b"}),
        ),
    ] {
        let mut body = registration(2);
        body.as_object_mut()
            .expect("an object")
            .extend(extra.as_object().expect("an object").clone());
        let reply = post(&env, &a.operator, "/v1/repositories", "flags", &body).await;
        assert_eq!(reply.status, 400, "{name}: {}", reply.text());
    }
    for (name, field, value, named) in [
        (
            "a zero installation",
            "installation_id",
            json!(0),
            "installation_id",
        ),
        (
            "a negative installation",
            "installation_id",
            json!(-1),
            "body",
        ),
        ("a text installation", "installation_id", json!("7"), "body"),
        (
            "a zero GitHub id",
            "github_repository_id",
            json!(0),
            "github_repository_id",
        ),
        (
            "a GitHub id past the database",
            "github_repository_id",
            json!(u64::MAX),
            "github_repository_id",
        ),
        ("no slash", "full_name", json!("octo"), "full_name"),
        ("two slashes", "full_name", json!("a/b/c"), "full_name"),
        ("a space", "full_name", json!("a/b c"), "full_name"),
        ("dots", "full_name", json!("../x"), "full_name"),
        (
            "an empty branch",
            "default_branch",
            json!(""),
            "default_branch",
        ),
        (
            "a branch with a space",
            "default_branch",
            json!("my branch"),
            "default_branch",
        ),
        (
            "a branch that climbs",
            "default_branch",
            json!("a/../b"),
            "default_branch",
        ),
    ] {
        let mut body = registration(2);
        body[field] = value;
        let reply = post(&env, &a.operator, "/v1/repositories", "values", &body).await;
        assert_eq!(reply.status, 400, "{name}: {}", reply.text());
        assert_eq!(reply.json()["field"], named, "{name}");
    }
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE full_name = 'org/new-2'")
            .await,
        0,
        "no refused registration left a row"
    );
    // The sibling: with none of them, the registration works.
    let good = post(
        &env,
        &a.operator,
        "/v1/repositories",
        "good",
        &registration(2),
    )
    .await;
    assert_eq!(good.status, 201, "{}", good.text());

    // A reason on a disable is optional and checked when it is there.
    let off = post(
        &env,
        &a.operator,
        &format!("/v1/repositories/{id}/disable"),
        "off-short",
        &json!({"reason": "short"}),
    )
    .await;
    assert_eq!(off.status, 400);
    let off = post(
        &env,
        &a.operator,
        &format!("/v1/repositories/{id}/disable"),
        "off-ok",
        &json!({"reason": "Switching it off while the map is rewritten."}),
    )
    .await;
    assert_eq!(off.status, 200, "{}", off.text());
    // A bad id is a missing object.
    let bad_id = post(
        &env,
        &a.operator,
        "/v1/repositories/not-a-uuid/disable",
        "x",
        &json!({}),
    )
    .await;
    assert_eq!(bad_id.status, 404);
    assert!(chain_is_sound(&env).await);
    env.stop().await;
}

/// A repository taken through the whole path by the fixtures stays usable: the shortcut the other
/// tests use is the same state the path reaches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_repository_of_the_fixtures_is_in_the_state_the_path_reaches() {
    let env = Env::start().await;
    let shown = get(
        &env,
        &env.a.requester,
        &format!("/v1/repositories/{}", env.a.repository.as_text()),
    )
    .await;
    assert_eq!(shown.status, 200, "{}", shown.text());
    assert_eq!(shown.json()["enabled"], true);
    assert_eq!(shown.json()["project_map"]["verified_by_engine"], false);
    let id = enabled_repository(&env, 1).await;
    let made = get(&env, &env.a.requester, &format!("/v1/repositories/{id}")).await;
    assert_eq!(made.json()["enabled"], true);
    assert_eq!(made.json()["project_map"]["commit"], COMMIT);
    env.stop().await;
}
