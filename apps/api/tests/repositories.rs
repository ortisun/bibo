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
//!   conflict, whichever part of the request is different (REG-5);
//! * a repository that is enabled does not stay enabled over another map, and an enable names the
//!   commit the approver read (REG-1), with a control that removes the table's rule and shows the
//!   old behaviour;
//! * an allowlist entry narrowed to other repositories cannot read this repository either (REG-4);
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

/// Posts a change. Register, attest and enable are signed requests (finding REG-2): the API answers `202`,
/// and the worker applies them. So that the tests of the path read what a person reads once the worker has
/// run, a `202` is followed by one pass of the worker's step and answered with the old status and body:
/// `201` for a registration, `200` for the others, the repository and `changed`, or `409` and the code
/// of a refusal. Use [`post_raw`] for the answer as the API gave it.
async fn post(env: &Env, person: &Person, path: &str, key: &str, body: &Value) -> Reply {
    let accepted = post_raw(env, person, path, key, body).await;
    if accepted.status != 202 {
        return accepted;
    }
    settled(env, person, accepted).await
}

async fn post_raw(env: &Env, person: &Person, path: &str, key: &str, body: &Value) -> Reply {
    env.send(
        Req::post(path)
            .bearer(&person.token)
            .header("Idempotency-Key", key)
            .json(body),
    )
    .await
}

fn reply_of(status: u16, body: &Value) -> Reply {
    Reply {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(body).expect("json"),
    }
}

/// Lets the worker apply what was asked, and answers as the route did before the request existed.
async fn settled(env: &Env, person: &Person, accepted: Reply) -> Reply {
    let body = accepted.json();
    env.apply_repository_changes().await;
    let request = body["request_id"]
        .as_str()
        .expect("a request id")
        .to_owned();
    let state = get(env, person, &format!("/v1/repository-changes/{request}")).await;
    assert_eq!(state.status, 200, "{}", state.text());
    let state = state.json();
    match state["state"].as_str() {
        Some("applied") => {
            let repository = body["repository_id"].as_str().expect("an id");
            let shown = get(env, person, &format!("/v1/repositories/{repository}")).await;
            assert_eq!(shown.status, 200, "{}", shown.text());
            let created = body["kind"] == "register" && body["changed"] == true;
            reply_of(
                if created { 201 } else { 200 },
                &json!({"repository": shown.json(), "changed": body["changed"]}),
            )
        }
        Some("refused") => reply_of(409, &json!({"error": state["code"]})),
        _ => accepted,
    }
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

/// The approver enables the repository for the commit they name.
async fn enable_for(env: &Env, id: &str, key: &str, commit: &str) -> Reply {
    post(
        env,
        &env.a.approver,
        &format!("/v1/repositories/{id}/enable"),
        key,
        &json!({"commit": commit}),
    )
    .await
}

/// The approver reads the commit on file, as `repository show` prints it, and names it. A
/// repository with no map gets a commit that was never attested.
async fn enable(env: &Env, id: &str, key: &str) -> Reply {
    let on_file = flag(env, id, "project_map_commit")
        .await
        .unwrap_or_else(|| COMMIT.to_owned());
    enable_for(env, id, key, &on_file).await
}

/// The operator attests `commit`.
async fn attest_commit(env: &Env, id: &str, key: &str, commit: &str) -> Reply {
    post(
        env,
        &env.a.operator,
        &format!("/v1/repositories/{id}/project-map"),
        key,
        &json!({"commit": commit, "reason": REASON}),
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
              WHERE action LIKE 'repository.%' AND action <> 'repository.change_requested'",
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
    // The record says which map it was enabled for and by whom. The database stamped the time.
    let record = &enabled.json()["repository"]["enabled_for"];
    assert_eq!(record["commit"], COMMIT);
    assert_eq!(record["enabled_by"], a.approver.principal.as_text());
    assert!(
        record["enabled_at"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z'))
    );
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
    assert_eq!(
        off.json()["repository"]["enabled_for"],
        Value::Null,
        "the record of the enabling goes when the repository is switched off"
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
            &json!({"commit": COMMIT}),
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
    // REG-4: reading it is narrowed too. It looks like a repository that is not there.
    let read = get(&env, &a.operator, &format!("/v1/repositories/{id}")).await;
    assert_eq!(read.status, 404, "{}", read.text());
    assert_eq!(read.json(), json!({"error": "not_found"}));

    // The sibling: narrowed to the repository, the same calls work (the name is not case sensitive).
    std::fs::write(&path, narrowed("\"org/new-1\", \"ORG/NEW-2\"")).expect("narrowed here");
    let read = get(&env, &a.operator, &format!("/v1/repositories/{id}")).await;
    assert_eq!(read.status, 200, "{}", read.text());
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
        ("enable", &b.approver, "enable", json!({"commit": COMMIT})),
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
    // Since migration 2026-11-03-002700 the API login may only switch a repository off (REG-2): a trigger
    // refuses the statement before the CHECK is reached. The CHECK is still the guard for every other writer.
    assert!(
        refused.is_err() && message.contains("the API login may only switch a repository off"),
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
    let message = format!("{refused:?}");
    assert!(
        refused.is_err() && message.contains("repositories_enabled_needs_project_map"),
        "the worker enabled a repository with no map: {message}"
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
    // REG-5: the same key and the same name with another installation, another GitHub repository
    // id or another default branch is another request. Each of them used to be answered as a
    // repeat, with the first row.
    for (what, field, value) in [
        ("another installation", "installation_id", json!(9999)),
        (
            "another GitHub repository id",
            "github_repository_id",
            json!(9998),
        ),
        ("another default branch", "default_branch", json!("develop")),
    ] {
        let mut body = registration(1);
        body[field] = value;
        let other = post(&env, &a.operator, "/v1/repositories", "r-1", &body).await;
        assert_eq!(other.status, 409, "{what}: {}", other.text());
    }
    assert_eq!(
        env.db
            .text(&format!(
                "SELECT github_installation_id || ',' || github_repository_id || ',' || default_branch FROM repositories WHERE id = '{id}'"
            ))
            .await
            .as_deref(),
        Some("7001,8001,main"),
        "no replay changed the first registration"
    );
    // The sibling: the very same request is still a repeat.
    let same = post(
        &env,
        &a.operator,
        "/v1/repositories",
        "r-1",
        &registration(1),
    )
    .await;
    assert_eq!(same.status, 200, "{}", same.text());
    assert_eq!(same.json()["changed"], false);

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

    // Enable and disable: a key replayed after the opposite change does not undo it. The same key
    // with another commit is another request.
    assert_eq!(enable(&env, &id, "e-1").await.status, 200);
    let repeat = enable(&env, &id, "e-1").await;
    assert_eq!(repeat.status, 200);
    assert_eq!(repeat.json()["changed"], false);
    let other_commit = enable_for(&env, &id, "e-1", COMMIT).await;
    assert_eq!(
        other_commit.status,
        409,
        "the same key with another commit: {}",
        other_commit.text()
    );
    assert_eq!(
        other_commit.json(),
        json!({"error": "project_map_changed"}),
        "COMMIT is not the map on file any more"
    );
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

// ---- a map that moves switches the repository off (REG-1) ----------------------------------------

/// The state the REG-1 tests start from: enabled for `COMMIT` by the approver, one job made by a
/// label so that the webhook is seen to work, and the audit log up to there.
async fn enabled_for_the_first_map(env: &Env) -> String {
    let id = enabled_repository(env, 1).await;
    let label = env
        .send(env.delivery(
            "issues",
            &delivery_id(1),
            &label_payload(1, env.a.requester.github_id, 11),
        ))
        .await;
    assert_eq!(label.status, 202);
    assert_eq!(
        jobs_of(env, &id).await,
        1,
        "the enabled repository takes the label"
    );
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attesting_another_map_switches_an_enabled_repository_off_and_it_must_be_enabled_again_by_name()
 {
    let env = Env::start().await;
    let a = &env.a;
    let id = enabled_for_the_first_map(&env).await;

    // The sibling that shows the rule is about change: the same map again, by the same person,
    // leaves it enabled and writes no record of a switch-off.
    let same = attest_commit(&env, &id, "attest-same", COMMIT).await;
    assert_eq!(same.status, 200, "{}", same.text());
    assert_eq!(same.json()["repository"]["enabled"], true);
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("true"));
    assert!(
        !audit_actions(&env).await.contains("repository.disabled"),
        "{}",
        audit_actions(&env).await
    );

    // Another commit: the repository is switched off by the same change, in the answer, in the
    // table, in the audit log and at the webhook.
    let moved = attest_commit(&env, &id, "attest-other", OTHER_COMMIT).await;
    assert_eq!(moved.status, 200, "{}", moved.text());
    let repository = &moved.json()["repository"];
    assert_eq!(repository["enabled"], false);
    assert_eq!(repository["enabled_for"], Value::Null);
    assert_eq!(repository["project_map"]["commit"], OTHER_COMMIT);
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));
    assert_eq!(
        flag(&env, &id, "enabled_project_map_commit").await,
        None,
        "the record of the enabling is empty"
    );
    let actions = audit_actions(&env).await;
    assert!(
        actions.ends_with("repository.map_attested,repository.map_attested,repository.disabled"),
        "{actions}"
    );
    let disabled = env
        .db
        .text("SELECT reason || ' / ' || actor_type FROM audit_events WHERE action = 'repository.disabled'")
        .await
        .expect("the record of the switch-off");
    assert!(
        disabled.contains("the map was attested again; enable it again"),
        "{disabled}"
    );
    assert!(
        disabled.ends_with("/ system"),
        "the switch-off the table made is recorded by the system that applied the request: {disabled}"
    );
    assert_eq!(
        env.db
            .number(&format!(
                "SELECT count(*) FROM audit_events WHERE action = 'repository.change_requested' AND actor_id = '{}'",
                a.operator.principal.as_uuid()
            ))
            .await,
        4,
        "and the person's own acts are the four requests: register, attest, attest, and the attest of the same commit that changed nothing"
    );
    assert!(chain_is_sound(&env).await);
    let dropped = env
        .send(env.delivery(
            "issues",
            &delivery_id(2),
            &label_payload(1, a.requester.github_id, 12),
        ))
        .await;
    assert_eq!(dropped.status, 202);
    assert_eq!(
        jobs_of(&env, &id).await,
        1,
        "the label is dropped: the repository is off"
    );

    // Enabling names the commit. The old one, a wrong one and one that was never attested are
    // refused with a typed answer and change nothing. The commit on file works.
    for (what, key, commit) in [
        ("the old commit", "enable-old-1", COMMIT),
        (
            "a commit that was never attested",
            "enable-never-1",
            "00112233445566778899aabbccddeeff00112233",
        ),
    ] {
        let refused = enable_for(&env, &id, key, commit).await;
        assert_eq!(refused.status, 409, "{what}: {}", refused.text());
        assert_eq!(
            refused.json(),
            json!({"error": "project_map_changed"}),
            "{what}"
        );
        assert_eq!(
            flag(&env, &id, "enabled").await.as_deref(),
            Some("false"),
            "{what}"
        );
    }
    let bad = post(
        &env,
        &a.approver,
        &format!("/v1/repositories/{id}/enable"),
        "enable-bad",
        &json!({"commit": "main"}),
    )
    .await;
    assert_eq!(bad.status, 400, "{}", bad.text());
    assert_eq!(
        bad.json(),
        json!({"error": "bad_request", "field": "commit"})
    );
    let none = post(
        &env,
        &a.approver,
        &format!("/v1/repositories/{id}/enable"),
        "enable-none",
        &json!({}),
    )
    .await;
    assert_eq!(
        none.status,
        400,
        "an enable that names no commit: {}",
        none.text()
    );
    let on = enable_for(&env, &id, "enable-new", OTHER_COMMIT).await;
    assert_eq!(on.status, 200, "{}", on.text());
    assert_eq!(
        on.json()["repository"]["enabled_for"]["commit"],
        OTHER_COMMIT
    );
    assert_eq!(
        on.json()["repository"]["enabled_for"]["enabled_by"],
        a.approver.principal.as_text()
    );
    let label = env
        .send(env.delivery(
            "issues",
            &delivery_id(3),
            &label_payload(1, a.requester.github_id, 13),
        ))
        .await;
    assert_eq!(label.status, 202);
    assert_eq!(
        jobs_of(&env, &id).await,
        2,
        "enabled for the new map, it takes the label again"
    );

    // Disable, then enable with the commit that was on file before: refused. The right one: fine.
    assert_eq!(disable(&env, &id, "disable-1").await.status, 200);
    let old = enable_for(&env, &id, "enable-old", COMMIT).await;
    assert_eq!(old.status, 409, "{}", old.text());
    assert_eq!(
        enable_for(&env, &id, "enable-right", OTHER_COMMIT)
            .await
            .status,
        200
    );

    // The enable that was answered before the map moved is not repeated as if it still held.
    assert_eq!(
        attest_commit(&env, &id, "attest-third", COMMIT)
            .await
            .status,
        200
    );
    let stale = enable_for(&env, &id, "enable-right", OTHER_COMMIT).await;
    assert_eq!(
        stale.status,
        409,
        "a retry of an enable for a map that is not on file: {}",
        stale.text()
    );
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));
    env.stop().await;
}

/// The control of the test above. The rule is in the table, and with the trigger and the check
/// removed the API does what it did before: the repository stays enabled over a map that nobody
/// enabled it for, and no record of a switch-off is written. This shows that the test above fails
/// without the table's rule, and that the table, not the handler, is what holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_without_the_table_rule_an_enabled_repository_stays_enabled_over_another_map() {
    let env = Env::start().await;
    let id = enabled_for_the_first_map(&env).await;
    let mut admin = env.db.admin().await;
    admin
        .batch_execute(
            "DROP TRIGGER repositories_project_map_guard ON repositories; \
             ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_project_map_commit_matches",
        )
        .await
        .expect("the rule is removed");

    let moved = attest_commit(&env, &id, "attest-other", OTHER_COMMIT).await;
    assert_eq!(moved.status, 200, "{}", moved.text());
    assert_eq!(
        moved.json()["repository"]["enabled"],
        true,
        "without the rule the repository stays enabled"
    );
    assert_eq!(
        flag(&env, &id, "project_map_commit").await.as_deref(),
        Some(OTHER_COMMIT)
    );
    assert_eq!(
        flag(&env, &id, "enabled_project_map_commit")
            .await
            .as_deref(),
        Some(COMMIT),
        "it is enabled for a map other than the one on file"
    );
    assert!(!audit_actions(&env).await.contains("repository.disabled"));
    env.stop().await;
}

/// The table holds the rule for a writer that is not the API: the login of the worker, in raw SQL,
/// changes the commit of an enabled repository and the row comes back disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_raw_write_of_another_map_switches_an_enabled_repository_off_for_the_workers_login_too() {
    let env = Env::start().await;
    let id = enabled_for_the_first_map(&env).await;
    let tenant = env.a.id.as_uuid();
    let logins = env.db.server.logins().await;
    let mut api = env.db.connect_as(&logins.worker).await;
    api.batch_execute(&format!(
        "BEGIN; SELECT set_config('factory.tenant_id', '{tenant}', true); \
         UPDATE repositories SET project_map_commit = '{OTHER_COMMIT}', \
             project_map_attested_by_principal_id = '{}', version = version + 1 WHERE id = '{id}'; COMMIT;",
        env.a.operator.principal.as_uuid()
    ))
    .await
    .expect("the worker login may attest a map");
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));
    assert_eq!(flag(&env, &id, "enabled_project_map_commit").await, None);
    assert_eq!(flag(&env, &id, "enabled_by_principal_id").await, None);
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

// ---- REG-6: the enabler is not the attestor, unless the repository is single-maintainer -----------

/// Gives tenant A's operator the approver designation too: the one person who can do every act.
fn the_operator_also_approves(env: &Env) {
    let operator = &env.a.operator;
    let line = format!(
        "    github_user_id: {}\n    login: {}\n    designations: [operator]\n",
        operator.github_id, operator.login
    );
    let path = env.checkout.join("allowlist/allowlist.yaml");
    let text = std::fs::read_to_string(&path).expect("the allowlist file");
    assert_eq!(
        text.matches(&line).count(),
        1,
        "the operator's entry is in the file once"
    );
    std::fs::write(
        &path,
        text.replace(&line, &line.replace("[operator]", "[operator, approver]")),
    )
    .expect("the allowlist file");
}

/// The operator (who is also an approver) enables the repository for the commit on file.
async fn enable_as_operator(env: &Env, id: &str, key: &str) -> Reply {
    let on_file = flag(env, id, "project_map_commit")
        .await
        .unwrap_or_else(|| COMMIT.to_owned());
    post(
        env,
        &env.a.operator,
        &format!("/v1/repositories/{id}/enable"),
        key,
        &json!({"commit": on_file}),
    )
    .await
}

fn single_maintainer_registration(n: u64) -> Value {
    let mut body = registration(n);
    body["single_maintainer"] = json!(true);
    body
}

/// REG-6: the person who attested the map cannot enable a strict repository, whoever they are and
/// whatever they hold. A repository registered as a single-maintainer one lets the same person do
/// both, and the audit record of its registration says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_person_who_attested_the_map_cannot_enable_a_strict_repository_but_can_enable_a_single_maintainer_one()
 {
    let env = Env::start().await;
    the_operator_also_approves(&env);

    // A strict repository (the default): the operator attests, then cannot enable.
    let strict = register(&env, 1).await;
    let shown = get(
        &env,
        &env.a.requester,
        &format!("/v1/repositories/{strict}"),
    )
    .await;
    assert_eq!(
        shown.json()["single_maintainer"],
        false,
        "strict is the default"
    );
    assert_eq!(attest(&env, &strict, "attest-1").await.status, 200);
    let refused = enable_as_operator(&env, &strict, "enable-1").await;
    assert_eq!(refused.status, 409, "{}", refused.text());
    assert_eq!(refused.json(), json!({"error": "enabler_is_attestor"}));
    assert_eq!(
        flag(&env, &strict, "enabled").await.as_deref(),
        Some("false")
    );
    assert_eq!(flag(&env, &strict, "version").await.as_deref(), Some("2"));
    assert!(
        !audit_actions(&env).await.contains("repository.enabled"),
        "a refusal leaves no record of an enabling"
    );
    // The sibling: another person with the approver designation can.
    let enabled = enable(&env, &strict, "enable-2").await;
    assert_eq!(enabled.status, 200, "{}", enabled.text());
    assert_eq!(
        enabled.json()["repository"]["enabled_for"]["enabled_by"],
        env.a.approver.principal.as_text()
    );

    // A single-maintainer repository: the same person does it all, and the registration says so.
    let made = post(
        &env,
        &env.a.operator,
        "/v1/repositories",
        "register-2",
        &single_maintainer_registration(2),
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.text());
    assert_eq!(made.json()["repository"]["single_maintainer"], true);
    let single = made.json()["repository"]["repository_id"]
        .as_str()
        .expect("an id")
        .to_owned();
    assert_eq!(attest(&env, &single, "attest-2").await.status, 200);
    let both = enable_as_operator(&env, &single, "enable-3").await;
    assert_eq!(both.status, 200, "{}", both.text());
    assert_eq!(
        both.json()["repository"]["enabled_for"]["enabled_by"],
        env.a.operator.principal.as_text(),
        "the operator attested and enabled it"
    );
    let subjects = env
        .db
        .text(
            "SELECT string_agg(subject, ' | ' ORDER BY sequence) FROM audit_events WHERE action = 'repository.registered'",
        )
        .await
        .expect("the registration records");
    assert_eq!(
        subjects.matches("single_maintainer=false").count(),
        1,
        "{subjects}"
    );
    assert_eq!(
        subjects.matches("single_maintainer=true").count(),
        1,
        "{subjects}"
    );

    // The same key with the other rule is another request (REG-5 for the new field).
    let replay = post(
        &env,
        &env.a.operator,
        "/v1/repositories",
        "register-2",
        &registration(2),
    )
    .await;
    assert_eq!(replay.status, 409, "{}", replay.text());
    // A flag that is not a boolean is a malformed body.
    let mut body = registration(3);
    body["single_maintainer"] = json!("yes");
    let bad = post(
        &env,
        &env.a.operator,
        "/v1/repositories",
        "register-3",
        &body,
    )
    .await;
    assert_eq!(bad.status, 400, "{}", bad.text());
    // Nobody changes the flag after registration: the routes take no such field.
    let mut change = attestation();
    change["single_maintainer"] = json!(false);
    let late = post(
        &env,
        &env.a.operator,
        &format!("/v1/repositories/{single}/project-map"),
        "attest-late",
        &change,
    )
    .await;
    assert_eq!(late.status, 400, "{}", late.text());
    assert_eq!(
        flag(&env, &single, "single_maintainer").await.as_deref(),
        Some("true")
    );
    assert!(chain_is_sound(&env).await);
    env.stop().await;
}

/// REG-6: a repository whose attestor or enabler is no longer an active human principal of the tenant
/// is listed as such by `show` and is treated as not enabled for new jobs. The stored flag is
/// unchanged, so a person can see what happened. The controls enable the check: the same repository
/// takes the label while both people stand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repository_whose_attestor_or_enabler_is_gone_is_not_open_for_new_jobs_and_show_says_so()
{
    for who in ["attestor", "enabler"] {
        let env = Env::start().await;
        let a = &env.a;
        let id = enabled_repository(&env, 1).await;
        let path = format!("/v1/repositories/{id}");

        // The control: both stand, the repository takes a label and a job.
        let shown = get(&env, &a.requester, &path).await.json();
        assert_eq!(shown["standing"]["attestor_is_active_human"], true);
        assert_eq!(shown["standing"]["enabler_is_active_human"], true);
        assert_eq!(shown["standing"]["open_for_new_jobs"], true);
        let label = env
            .send(env.delivery(
                "issues",
                &delivery_id(1),
                &label_payload(1, a.requester.github_id, 21),
            ))
            .await;
        assert_eq!(label.status, 202);
        assert_eq!(jobs_of(&env, &id).await, 1);

        // The person is switched off as a principal of the tenant.
        let gone = if who == "attestor" {
            &a.operator
        } else {
            &a.approver
        };
        env.db
            .run(&format!(
                "UPDATE principals SET disabled_at = now() WHERE id = '{}'",
                gone.principal.as_uuid()
            ))
            .await;
        let shown = get(&env, &a.requester, &path).await.json();
        assert_eq!(
            shown["enabled"], true,
            "{who}: the stored flag is what it was"
        );
        assert_eq!(
            shown["standing"]["attestor_is_active_human"],
            who != "attestor",
            "{who}"
        );
        assert_eq!(
            shown["standing"]["enabler_is_active_human"],
            who != "enabler",
            "{who}"
        );
        assert_eq!(shown["standing"]["open_for_new_jobs"], false, "{who}");

        // A new job does not start: not by a webhook, not by a request through the API.
        let dropped = env
            .send(env.delivery(
                "issues",
                &delivery_id(2),
                &label_payload(1, a.requester.github_id, 22),
            ))
            .await;
        assert_eq!(dropped.status, 202, "the answer to GitHub does not change");
        assert_eq!(jobs_of(&env, &id).await, 1, "{who}: no job was made");
        let refused = post(
            &env,
            &a.requester,
            "/v1/jobs",
            "job-gone",
            &json!({"repository_id": id, "text": "Add a word count command.", "source_ref": "org/new-1#23"}),
        )
        .await;
        assert_eq!(refused.status, 404, "{who}: {}", refused.text());
        assert_eq!(jobs_of(&env, &id).await, 1);
        env.stop().await;
    }
}

// ---- RR-28: an allowlist entry that lists the GitHub id follows the repository, not the name ----------

/// The operator's entry in the allowlist file, as the tests write it, and the same entry narrowed.
fn the_operators_entry(env: &Env) -> String {
    format!(
        "  - tenant: {}\n    github_user_id: {}\n    login: {}\n    designations: [operator]\n",
        env.a.id.as_uuid(),
        env.a.operator.github_id,
        env.a.operator.login
    )
}

fn narrow_operator(env: &Env, repositories: &str) {
    let plain = the_operators_entry(env);
    let all = allowlist_text(&[&env.a, &env.b]);
    assert!(all.contains(&plain), "the entry to narrow is in the file");
    std::fs::write(
        env.checkout.join("allowlist/allowlist.yaml"),
        all.replacen(
            &plain,
            &format!("{plain}    repositories:\n{repositories}"),
            1,
        ),
    )
    .expect("the narrowed allowlist");
}

/// Registers a repository with the name `org/new-1` (the name of repository 1) and the GitHub id of
/// repository `n`: a new repository created under the old name, as the finding describes.
async fn register_under_the_old_name(env: &Env, n: u64) -> String {
    let mut body = registration(n);
    body["full_name"] = json!("org/new-1");
    let made = post(
        env,
        &env.a.operator,
        "/v1/repositories",
        &format!("register-reuse-{n}"),
        &body,
    )
    .await;
    assert_eq!(made.status, 201, "{}", made.text());
    made.json()["repository"]["repository_id"]
        .as_str()
        .expect("an id")
        .to_owned()
}

/// RR-28 (the finding, the hypothesis of the re-review): an entry narrowed by name alone is inherited by a
/// repository that is created under the old name. An entry that lists GitHub's id is not, and it still
/// reaches the repository after a rename.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_narrowed_by_the_github_id_follows_the_repository_through_a_rename_and_not_to_a_new_one_under_the_old_name()
 {
    let env = Env::start().await;
    let one = register(&env, 1).await; // org/new-1, GitHub id 8001
    narrow_operator(
        &env,
        "      - name: org/new-1\n        github_repository_id: 8001\n",
    );

    // The control that the entry works: it reaches the repository it lists.
    let read = get(&env, &env.a.operator, &format!("/v1/repositories/{one}")).await;
    assert_eq!(read.status, 200, "{}", read.text());
    assert_eq!(attest(&env, &one, "attest-1").await.status, 200);

    // A new repository is created under the old name and registered (the registration is the typed
    // name and the typed id of the new repository, so it is refused to this operator before it is a row).
    let mut body = registration(2);
    body["full_name"] = json!("org/new-1");
    let refused = post(
        &env,
        &env.a.operator,
        "/v1/repositories",
        "register-2",
        &body,
    )
    .await;
    assert_eq!(refused.status, 403, "{}", refused.text());
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE github_repository_id = 8002")
            .await,
        0,
        "nothing was registered"
    );
    // An operator who reaches every repository registers it. The narrowed operator cannot read it, attest
    // it or disable it, although its name is the one the entry lists.
    std::fs::write(
        env.checkout.join("allowlist/allowlist.yaml"),
        allowlist_text(&[&env.a, &env.b]),
    )
    .expect("the plain allowlist");
    let two = register_under_the_old_name(&env, 2).await;
    narrow_operator(
        &env,
        "      - name: org/new-1\n        github_repository_id: 8001\n",
    );
    let read = get(&env, &env.a.operator, &format!("/v1/repositories/{two}")).await;
    assert_eq!(
        read.status,
        404,
        "the name is the same, the repository is not: {}",
        read.text()
    );
    assert_eq!(attest(&env, &two, "attest-2").await.status, 403);
    assert_eq!(disable(&env, &two, "disable-2").await.status, 403);
    assert_eq!(flag(&env, &two, "project_map_commit").await, None);

    // Renamed: the registered name changes, the id does not, and the entry still reaches the repository.
    env.db
        .run(&format!(
            "UPDATE repositories SET full_name = 'org/renamed', version = version + 1 WHERE id = '{one}'"
        ))
        .await;
    let read = get(&env, &env.a.operator, &format!("/v1/repositories/{one}")).await;
    assert_eq!(read.status, 200, "{}", read.text());
    assert_eq!(read.json()["full_name"], "org/renamed");
    assert_eq!(
        attest_commit(&env, &one, "attest-3", OTHER_COMMIT)
            .await
            .status,
        200
    );
    // Transferred to another owner: the same.
    env.db
        .run(&format!(
            "UPDATE repositories SET full_name = 'elsewhere/new-1', version = version + 1 WHERE id = '{one}'"
        ))
        .await;
    assert_eq!(
        get(&env, &env.a.operator, &format!("/v1/repositories/{one}"))
            .await
            .status,
        200
    );

    // The weaker form, kept and reported: an entry that lists the name alone is inherited by the new
    // repository, and that is what the warning in the allowlist reader is about.
    narrow_operator(&env, "      - org/new-1\n");
    let read = get(&env, &env.a.operator, &format!("/v1/repositories/{two}")).await;
    assert_eq!(
        read.status,
        200,
        "the entry by name alone follows the name: {}",
        read.text()
    );
    let weak = env
        .state
        .allowlist_file
        .name_only_narrowing()
        .expect("the file reads");
    assert_eq!(weak.len(), 1);
    assert_eq!(weak[0].repositories, vec!["org/new-1".to_owned()]);
    env.stop().await;
}

/// RR-28 for the other people who start work: a requester narrowed by id submits jobs for the repository
/// they were given, and a new repository under the same name takes nothing from them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_requester_narrowed_by_the_github_id_starts_no_job_in_a_new_repository_under_the_old_name()
 {
    let env = Env::start().await;
    let one = enabled_repository(&env, 1).await;
    let two = register_under_the_old_name(&env, 2).await;
    assert_eq!(attest(&env, &two, "attest-two").await.status, 200);
    assert_eq!(enable(&env, &two, "enable-two").await.status, 200);

    let requester = &env.a.requester;
    let plain = format!(
        "  - tenant: {}\n    github_user_id: {}\n    login: {}\n    designations: [requester]\n",
        env.a.id.as_uuid(),
        requester.github_id,
        requester.login
    );
    let all = allowlist_text(&[&env.a, &env.b]);
    assert!(all.contains(&plain));
    let path = env.checkout.join("allowlist/allowlist.yaml");

    // The control: narrowed by the id of repository one, the requester asks for work there, and a label
    // there makes a job.
    std::fs::write(
        &path,
        all.replacen(
            &plain,
            &format!("{plain}    repositories:\n      - name: org/new-1\n        github_repository_id: 8001\n"),
            1,
        ),
    )
    .expect("narrowed by id");
    assert_eq!(submit(&env, &one, "job-1", 31).await.status, 201);
    let label = env
        .send(env.delivery(
            "issues",
            &delivery_id(1),
            &label_payload(1, requester.github_id, 32),
        ))
        .await;
    assert_eq!(label.status, 202);
    assert_eq!(jobs_of(&env, &one).await, 2);

    // The new repository has the same name and another id: no job by the API, none by a label.
    let refused = submit(&env, &two, "job-2", 33).await;
    assert_eq!(refused.status, 403, "{}", refused.text());
    let mut payload: Value =
        serde_json::from_slice(&label_payload(2, requester.github_id, 34)).expect("json");
    payload["repository"]["full_name"] = json!("org/new-1");
    let dropped = env
        .send(env.delivery(
            "issues",
            &delivery_id(2),
            &serde_json::to_vec(&payload).expect("json"),
        ))
        .await;
    assert_eq!(dropped.status, 202);
    assert_eq!(
        jobs_of(&env, &two).await,
        0,
        "the name is not the repository"
    );

    // The weaker form is inherited, as the finding said, and is the reason for the warning.
    std::fs::write(
        &path,
        all.replacen(
            &plain,
            &format!("{plain}    repositories: [org/new-1]\n"),
            1,
        ),
    )
    .expect("narrowed by name");
    assert_eq!(submit(&env, &two, "job-3", 35).await.status, 201);
    env.stop().await;
}

/// The requester asks for a job on an issue of `org/new-1`.
async fn submit(env: &Env, repository: &str, key: &str, issue: u64) -> Reply {
    let body = json!({"repository_id": repository, "text": "Add a word count command.", "source_ref": format!("org/new-1#{issue}")});
    post(env, &env.a.requester, "/v1/jobs", key, &body).await
}

/// REG-2: the login of the API can do nothing to a repository but switch it off. A holder of that login's
/// credentials, in a session that names the tenant, cannot register, attest or enable, and cannot switch a
/// repository on, with or without a signed request. The sibling: it can switch one off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_api_login_can_do_nothing_to_a_repository_but_switch_it_off() {
    let env = Env::start().await;
    let id = enabled_for_the_first_map(&env).await;
    let tenant = env.a.id.as_uuid();
    let logins = env.db.server.logins().await;
    let raw = |statement: String| {
        format!(
            "BEGIN; SELECT set_config('factory.tenant_id', '{tenant}', true); {statement}; COMMIT;"
        )
    };
    for (what, statement) in [
        (
            "register",
            "INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch) \
             VALUES ('{tenant}', '0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b', 1, 2, 'org/raw', 'main')"
                .replace("{tenant}", &tenant.to_string()),
        ),
        (
            "attest",
            format!(
                "UPDATE repositories SET project_map_commit = '{OTHER_COMMIT}', \
                 project_map_attested_by_principal_id = '{}', version = version + 1 WHERE id = '{id}'",
                env.a.operator.principal.as_uuid()
            ),
        ),
        (
            "name the enabler",
            format!(
                "UPDATE repositories SET enabled_by_principal_id = '{}', version = version + 1 WHERE id = '{id}'",
                env.a.operator.principal.as_uuid()
            ),
        ),
        (
            "change the ceiling",
            format!("UPDATE repositories SET autonomy_ceiling = 'L3', version = version + 1 WHERE id = '{id}'"),
        ),
    ] {
        let mut api = env.db.connect_as(&logins.api).await;
        let refused = api.batch_execute(&raw(statement)).await;
        let message = format!("{refused:?}");
        assert!(
            refused.is_err() && message.contains("permission denied"),
            "{what}: {message}"
        );
    }
    // Switching on is the one thing the column grant of `enabled` would allow, and the trigger refuses it.
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("true"));
    let mut api = env.db.connect_as(&logins.api).await;
    api.batch_execute(&raw(format!(
        "UPDATE repositories SET enabled = false, version = version + 1 WHERE id = '{id}'"
    )))
    .await
    .expect("the API login may switch a repository off");
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));
    let mut api = env.db.connect_as(&logins.api).await;
    let refused = api
        .batch_execute(&raw(format!(
            "UPDATE repositories SET enabled = true, version = version + 1 WHERE id = '{id}'"
        )))
        .await;
    let message = format!("{refused:?}");
    assert!(
        refused.is_err() && message.contains("the API login may only switch a repository off"),
        "{message}"
    );
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));
    env.stop().await;
}

// ---- REG-2: register, attest and enable are signed requests that the worker applies ------------------------

async fn change_state(env: &Env, person: &Person, request: &str) -> Reply {
    get(env, person, &format!("/v1/repository-changes/{request}")).await
}

/// The API answers 202 and changes nothing; the worker applies the request and the answer to "where does
/// it stand" follows. A repeat is a repeat and another request under the same key is a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_that_widens_the_reach_is_a_signed_request_answered_202_and_applied_by_the_worker()
{
    let env = Env::start().await;
    let a = &env.a;

    // 1. Register: recorded, and not applied.
    let accepted = post_raw(
        &env,
        &a.operator,
        "/v1/repositories",
        "register-1",
        &registration(1),
    )
    .await;
    assert_eq!(accepted.status, 202, "{}", accepted.text());
    let body = accepted.json();
    assert_eq!(body["state"], "requested");
    assert_eq!(body["kind"], "register");
    assert_eq!(body["changed"], true);
    let request = body["request_id"]
        .as_str()
        .expect("a request id")
        .to_owned();
    let id = body["repository_id"].as_str().expect("an id").to_owned();
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE github_repository_id = 8001")
            .await,
        0,
        "the API changed nothing in the table"
    );
    assert_eq!(
        get(&env, &a.operator, &format!("/v1/repositories/{id}"))
            .await
            .status,
        404
    );
    let state = change_state(&env, &a.operator, &request).await;
    assert_eq!(state.status, 200, "{}", state.text());
    assert_eq!(state.json()["state"], "requested");
    // The record is the person's own act, signed, and the detail is the name and the branch.
    let row = env
        .db
        .text(&format!(
            "SELECT actor_type || ' ' || actor_id || ' ' || reason || ' ' || subject FROM audit_events WHERE event_id = '{request}'"
        ))
        .await
        .expect("the request is recorded");
    assert!(
        row.starts_with(&format!(
            "human {} name=org/new-1 branch=main change kind=register ",
            a.operator.principal.as_text()
        )),
        "{row}"
    );
    assert!(row.contains(" mac="), "{row}");

    // A repeat of the same key and request is the same request; another request under the key is a conflict.
    let again = post_raw(
        &env,
        &a.operator,
        "/v1/repositories",
        "register-1",
        &registration(1),
    )
    .await;
    assert_eq!(again.status, 202);
    assert_eq!(again.json()["request_id"], request.as_str());
    assert_eq!(again.json()["changed"], false);
    let other = post_raw(
        &env,
        &a.operator,
        "/v1/repositories",
        "register-1",
        &registration(2),
    )
    .await;
    assert_eq!(other.status, 409, "{}", other.text());
    assert_eq!(
        env.db
            .number(
                "SELECT count(*) FROM audit_events WHERE action = 'repository.change_requested'"
            )
            .await,
        1
    );

    // 2. The worker applies it. The result is the system's, and the state follows.
    env.apply_repository_changes().await;
    assert_eq!(
        change_state(&env, &a.operator, &request).await.json()["state"],
        "applied"
    );
    let shown = get(&env, &a.operator, &format!("/v1/repositories/{id}")).await;
    assert_eq!(shown.status, 200, "{}", shown.text());
    assert_eq!(shown.json()["enabled"], false);
    assert_eq!(
        env.db
            .text("SELECT actor_type FROM audit_events WHERE action = 'repository.registered'")
            .await
            .as_deref(),
        Some("system")
    );

    // 3. Attest and enable are the same: 202 and a request, applied later.
    let attest_accepted = post_raw(
        &env,
        &a.operator,
        &format!("/v1/repositories/{id}/project-map"),
        "attest-1",
        &attestation(),
    )
    .await;
    assert_eq!(attest_accepted.status, 202, "{}", attest_accepted.text());
    assert_eq!(attest_accepted.json()["kind"], "attest");
    assert_eq!(
        flag(&env, &id, "project_map_commit").await,
        None,
        "not applied yet"
    );
    env.apply_repository_changes().await;
    assert_eq!(
        flag(&env, &id, "project_map_commit").await.as_deref(),
        Some(COMMIT)
    );
    let enable_accepted = post_raw(
        &env,
        &a.approver,
        &format!("/v1/repositories/{id}/enable"),
        "enable-1",
        &json!({"commit": COMMIT}),
    )
    .await;
    assert_eq!(enable_accepted.status, 202, "{}", enable_accepted.text());
    assert_eq!(
        flag(&env, &id, "enabled").await.as_deref(),
        Some("false"),
        "not applied yet"
    );
    env.apply_repository_changes().await;
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("true"));
    let enabled_by = flag(&env, &id, "enabled_by_principal_id").await;
    assert_eq!(
        enabled_by.as_deref(),
        Some(a.approver.principal.as_text().as_str())
    );

    // 4. Disabling is direct: 200, at once.
    let off = post_raw(
        &env,
        &a.operator,
        &format!("/v1/repositories/{id}/disable"),
        "disable-1",
        &json!({}),
    )
    .await;
    assert_eq!(off.status, 200, "{}", off.text());
    assert_eq!(flag(&env, &id, "enabled").await.as_deref(), Some("false"));

    // 5. A request is seen by its own tenant only.
    let foreign = change_state(&env, &env.b.operator, &request).await;
    assert_eq!(foreign.status, 404, "{}", foreign.text());
    let nothing = change_state(&env, &a.operator, "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b").await;
    assert_eq!(nothing.status, 404);
    assert_eq!(change_state(&env, &a.outsider, &request).await.status, 403);
    assert!(chain_is_sound(&env).await);
    env.stop().await;
}

/// The worker asks the allowlist again when it applies a request (the R-4 rule). A person who was taken
/// off between the request and the worker's turn changes nothing, and the state says why in a fixed code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_worker_asks_the_allowlist_again_and_a_person_removed_since_the_request_changes_nothing()
 {
    let env = Env::start().await;
    let a = &env.a;
    let accepted = post_raw(
        &env,
        &a.operator,
        "/v1/repositories",
        "register-1",
        &registration(1),
    )
    .await;
    assert_eq!(accepted.status, 202);
    let request = accepted.json()["request_id"]
        .as_str()
        .expect("an id")
        .to_owned();
    // The operator is taken off the list after the API accepted the request.
    let plain = the_operators_entry(&env);
    let all = allowlist_text(&[&env.a, &env.b]);
    assert!(all.contains(&plain));
    std::fs::write(
        env.checkout.join("allowlist/allowlist.yaml"),
        all.replacen(&plain, "", 1),
    )
    .expect("the allowlist without the operator");
    env.apply_repository_changes().await;
    let state = change_state(&env, &a.requester, &request).await.json();
    assert_eq!(state["state"], "refused", "{state}");
    assert_eq!(state["code"], "not_permitted");
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM repositories WHERE github_repository_id = 8001")
            .await,
        0
    );
    assert_eq!(
        env.db
            .text("SELECT actor_type FROM audit_events WHERE action = 'repository.change_refused'")
            .await
            .as_deref(),
        Some("system")
    );

    // The sibling: with the entry back, the same operator's next request is applied.
    std::fs::write(env.checkout.join("allowlist/allowlist.yaml"), all).expect("the allowlist");
    let id = register(&env, 2).await;
    assert!(flag(&env, &id, "full_name").await.is_some());

    // A refusal of the worker for a rule of the map comes back in the same form.
    let early = post_raw(
        &env,
        &a.approver,
        &format!("/v1/repositories/{id}/enable"),
        "enable-early",
        &json!({"commit": COMMIT}),
    )
    .await;
    assert_eq!(
        early.status,
        409,
        "the API answers a map that was never attested at once: {}",
        early.text()
    );
    assert_eq!(early.json(), json!({"error": "project_map_not_attested"}));
    env.stop().await;
}
