use std::time::Duration;

use super::*;
use crate::clock::FakeClock;
use crate::fx::canary::{CanaryKind, CanarySet, Form, Sweeper};
use crate::fx::encoding::{Base64Alphabet, base64_encode};
use crate::fx::http::send_request;

struct World {
    github: FakeGithub,
    clock: Arc<FakeClock>,
}

/// Two repositories under one installation, three people, and a clock the test can move.
fn world() -> World {
    let clock = Arc::new(FakeClock::new());
    let github = FakeGithub::with_clock(clock.clone());
    github
        .add_repo("acme/widgets", "main")
        .add_repo("acme/secrets", "main")
        .add_installation(77, "acme", &["acme/widgets", "acme/secrets"])
        .add_user(User::person("alice", 1001, "write", "MEMBER"))
        .add_user(User::person("bob", 1002, "write", "MEMBER"))
        .add_user(User::person("mallory", 1003, "admin", "OWNER"));
    World { github, clock }
}

/// Calls the fake directly, with no socket, and returns the status and the JSON body.
fn call(
    github: &FakeGithub,
    method: &str,
    target: &str,
    credential: Option<&str>,
    body: Option<&Value>,
) -> (u16, Value) {
    let mut headers = vec![(
        "Accept".to_owned(),
        "application/vnd.github+json".to_owned(),
    )];
    if let Some(credential) = credential {
        headers.push(("Authorization".to_owned(), format!("Bearer {credential}")));
    }
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers,
        body: body.map(|b| b.to_string().into_bytes()).unwrap_or_default(),
        peer: "127.0.0.1:1".parse().unwrap(),
    };
    let response = github.handle(&request);
    let json = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    (response.status, json)
}

fn mint(github: &FakeGithub, body: Option<Value>) -> String {
    let jwt = github.sample_app_jwt();
    let (status, json) = call(
        github,
        "POST",
        "/app/installations/77/access_tokens",
        Some(&jwt),
        body.as_ref(),
    );
    assert_eq!(status, 201, "{json}");
    json["token"].as_str().unwrap().to_owned()
}

/// A token for `acme/widgets` with the permissions the factory needs for a build stage.
fn builder_token(github: &FakeGithub) -> String {
    mint(
        github,
        Some(json!({
            "repositories": ["widgets"],
            "permissions": {
                "metadata": "read", "contents": "write", "pull_requests": "write",
                "issues": "write", "checks": "write", "statuses": "write"
            }
        })),
    )
}

fn make_jwt(header: &str, claims: &str, signature: &str) -> String {
    let encode = |text: &str| base64_encode(text.as_bytes(), Base64Alphabet::UrlSafe, false);
    format!(
        "{}.{}.{}",
        encode(header),
        encode(claims),
        encode(signature)
    )
}

#[test]
fn app_endpoints_need_a_valid_jwt() {
    let w = world();
    let jwt = w.github.sample_app_jwt();
    let (status, app) = call(&w.github, "GET", "/app", Some(&jwt), None);
    assert_eq!(status, 200);
    assert_eq!(app["slug"], "factory-test-app");
    assert_eq!(app["permissions"]["contents"], "write");
    let (status, installation) = call(&w.github, "GET", "/app/installations/77", Some(&jwt), None);
    assert_eq!(status, 200);
    assert_eq!(installation["account"]["login"], "acme");
    assert_eq!(
        call(&w.github, "GET", "/app/installations/99", Some(&jwt), None).0,
        404
    );

    // No credential, and an installation token where a JWT is needed.
    assert_eq!(call(&w.github, "GET", "/app", None, None).0, 401);
    let token = builder_token(&w.github);
    assert_eq!(call(&w.github, "GET", "/app", Some(&token), None).0, 401);
}

#[test]
fn a_malformed_or_over_long_jwt_is_refused_with_githubs_message() {
    let w = world();
    let now = w.github.now();
    let app_id = w.github.app().id;
    let ok_header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "wrong algorithm",
            make_jwt(
                r#"{"alg":"HS256"}"#,
                &format!(
                    r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
                    now - 60,
                    now + 500
                ),
                "sig",
            ),
            "could not be decoded",
        ),
        (
            "none algorithm",
            make_jwt(
                r#"{"alg":"none"}"#,
                &format!(
                    r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
                    now - 60,
                    now + 500
                ),
                "sig",
            ),
            "could not be decoded",
        ),
        (
            "wrong issuer",
            make_jwt(
                ok_header,
                &format!(r#"{{"iat":{},"exp":{},"iss":"1"}}"#, now - 60, now + 500),
                "sig",
            ),
            "does not match",
        ),
        (
            "expired",
            make_jwt(
                ok_header,
                &format!(
                    r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
                    now - 900,
                    now - 10
                ),
                "sig",
            ),
            "'exp'",
        ),
        (
            "issued in the future",
            make_jwt(
                ok_header,
                &format!(
                    r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
                    now + 3_000,
                    now + 3_300
                ),
                "sig",
            ),
            "'iat'",
        ),
        (
            "lives longer than ten minutes",
            make_jwt(
                ok_header,
                &format!(
                    r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
                    now - 60,
                    now + 3_600
                ),
                "sig",
            ),
            "too far in the future",
        ),
        (
            "no iat",
            make_jwt(
                ok_header,
                &format!(r#"{{"exp":{},"iss":"{app_id}"}}"#, now + 500),
                "sig",
            ),
            "'iat'",
        ),
        ("not a jwt", "a.b.c".to_owned(), "could not be decoded"),
        (
            "empty signature",
            format!(
                "{}.{}.",
                base64_encode(ok_header.as_bytes(), Base64Alphabet::UrlSafe, false),
                base64_encode(
                    format!(
                        r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
                        now - 60,
                        now + 500
                    )
                    .as_bytes(),
                    Base64Alphabet::UrlSafe,
                    false
                )
            ),
            "could not be decoded",
        ),
    ];
    for (name, jwt, fragment) in cases {
        let (status, body) = call(&w.github, "GET", "/app", Some(&jwt), None);
        assert_eq!(status, 401, "{name}: {body}");
        assert!(
            body["message"].as_str().unwrap().contains(fragment),
            "{name}: {body}"
        );
    }
    // The baseline built by the same helper is accepted, so the refusals above are about the claim.
    let good = make_jwt(
        ok_header,
        &format!(
            r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
            now - 60,
            now + 500
        ),
        "sig",
    );
    assert_eq!(call(&w.github, "GET", "/app", Some(&good), None).0, 200);
}

#[test]
fn a_minted_token_is_narrowed_to_one_repository_and_to_the_permissions_asked_for() {
    let w = world();
    let body = json!({
        "repositories": ["widgets"],
        "permissions": {"metadata": "read", "contents": "read", "pull_requests": "write"}
    });
    let token = mint(&w.github, Some(body.clone()));

    let mints = w.github.mints();
    assert_eq!(mints.len(), 1);
    assert_eq!(mints[0].installation_id, 77);
    assert_eq!(
        mints[0].request_body,
        Some(body),
        "the exact request body is kept"
    );
    assert_eq!(
        mints[0].requested_repositories,
        Some(vec!["widgets".to_owned()])
    );
    assert_eq!(mints[0].granted_repositories, ["acme/widgets"]);
    assert_eq!(mints[0].granted_permissions["contents"], "read");
    assert!(!mints[0].granted_permissions.contains_key("issues"));

    // The repository it was minted for works; the other one in the same installation does not.
    assert_eq!(
        call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None).0,
        200
    );
    assert_eq!(
        call(&w.github, "GET", "/repos/acme/secrets", Some(&token), None).0,
        404
    );
    assert_eq!(
        call(
            &w.github,
            "GET",
            "/repos/acme/secrets/pulls",
            Some(&token),
            None
        )
        .0,
        404
    );
    let (_, list) = call(
        &w.github,
        "GET",
        "/installation/repositories",
        Some(&token),
        None,
    );
    assert_eq!(list["total_count"], 1);
    assert_eq!(list["repositories"][0]["full_name"], "acme/widgets");
    // Nothing else was minted along the way.
    assert_eq!(w.github.mints().len(), 1);
    assert_eq!(w.github.tokens()[0].repositories, ["acme/widgets"]);
}

#[test]
fn a_read_only_token_cannot_push_comment_or_open_a_pull_request() {
    let w = world();
    let number = w.github.add_issue("acme/widgets", "A", "B", "alice", &[]);
    let token = mint(
        &w.github,
        Some(json!({
            "repositories": ["widgets"],
            "permissions": {"metadata": "read", "contents": "read", "issues": "read", "pull_requests": "read"}
        })),
    );
    let sha = w.github.branch_sha("acme/widgets", "main").unwrap();
    for (method, target, body) in [
        (
            "POST",
            "/repos/acme/widgets/git/refs",
            json!({"ref": "refs/heads/factory/x", "sha": sha}),
        ),
        (
            "POST",
            &format!("/repos/acme/widgets/issues/{number}/comments"),
            json!({"body": "hi"}),
        ),
        (
            "POST",
            "/repos/acme/widgets/pulls",
            json!({"title": "t", "head": "main", "base": "main"}),
        ),
        (
            "POST",
            "/repos/acme/widgets/check-runs",
            json!({"name": "ci", "head_sha": sha}),
        ),
    ] {
        let (status, error) = call(&w.github, method, target, Some(&token), Some(&body));
        assert_eq!(status, 403, "{method} {target}: {error}");
        assert_eq!(error["message"], "Resource not accessible by integration");
    }
    // Reading works.
    assert_eq!(
        call(
            &w.github,
            "GET",
            &format!("/repos/acme/widgets/issues/{number}"),
            Some(&token),
            None
        )
        .0,
        200
    );
    assert!(w.github.pushes().is_empty());
    assert!(w.github.comments("acme/widgets", number).is_empty());
}

#[test]
fn minting_refuses_what_the_installation_or_the_app_does_not_have() {
    let w = world();
    let jwt = w.github.sample_app_jwt();
    for (name, body, fragment) in [
        (
            "a repository outside the installation",
            json!({"repositories": ["not-there"]}),
            "does not exist or is not accessible",
        ),
        (
            "a permission the App does not hold",
            json!({"permissions": {"administration": "read"}}),
            "not granted to this installation",
        ),
        (
            "a level above the App's",
            json!({"permissions": {"metadata": "write"}}),
            "not granted to this installation",
        ),
        (
            "a level that does not exist",
            json!({"permissions": {"contents": "superuser"}}),
            "not granted to this installation",
        ),
    ] {
        let (status, error) = call(
            &w.github,
            "POST",
            "/app/installations/77/access_tokens",
            Some(&jwt),
            Some(&body),
        );
        assert_eq!(status, 422, "{name}: {error}");
        assert!(
            error["message"].as_str().unwrap().contains(fragment),
            "{name}: {error}"
        );
    }
    assert_eq!(
        call(
            &w.github,
            "POST",
            "/app/installations/99/access_tokens",
            Some(&jwt),
            None
        )
        .0,
        404
    );
    assert!(
        w.github.mints().is_empty(),
        "a refused request mints nothing"
    );
    // Every refused request is still in the log.
    assert_eq!(
        w.github.count("POST /app/installations/{id}/access_tokens"),
        5
    );
}

#[test]
fn a_token_with_no_body_covers_every_repository_and_every_permission_of_the_app() {
    let w = world();
    let token = mint(&w.github, None);
    let mint_record = &w.github.mints()[0];
    assert_eq!(mint_record.requested_repositories, None);
    assert_eq!(mint_record.requested_permissions, None);
    assert_eq!(mint_record.granted_repositories.len(), 2);
    assert_eq!(mint_record.granted_permissions, w.github.app().permissions);
    assert_eq!(
        call(&w.github, "GET", "/repos/acme/secrets", Some(&token), None).0,
        200
    );
}

#[test]
fn a_revoked_token_stops_working_and_every_later_use_is_counted() {
    let w = world();
    let token = builder_token(&w.github);
    assert_eq!(
        call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None).0,
        200
    );
    assert_eq!(w.github.tokens()[0].uses, 1);

    let (status, _) = call(
        &w.github,
        "DELETE",
        "/installation/token",
        Some(&token),
        None,
    );
    assert_eq!(status, 204);
    assert_eq!(w.github.revocations().len(), 1);
    assert!(w.github.tokens()[0].revoked_at.is_some());

    let (status, error) = call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None);
    assert_eq!(status, 401);
    assert_eq!(error["message"], "Bad credentials");
    assert_eq!(w.github.tokens()[0].uses_after_revoke, 1);
    // A second revoke with the dead token fails and is not counted as a revocation.
    assert_eq!(
        call(
            &w.github,
            "DELETE",
            "/installation/token",
            Some(&token),
            None
        )
        .0,
        401
    );
    assert_eq!(w.github.revocations().len(), 1);
}

#[test]
fn a_token_lasts_an_hour_on_the_shared_clock() {
    let w = world();
    let token = builder_token(&w.github);
    w.clock.advance(Duration::from_secs(3599));
    assert_eq!(
        call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None).0,
        200
    );
    w.clock.advance(Duration::from_secs(1));
    assert_eq!(
        call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None).0,
        401
    );
    // And a JWT made before the move is too old to mint another.
    assert_eq!(w.github.tokens()[0].expires_at, w.github.now());
}

#[test]
fn issues_show_the_author_association_and_comments_come_from_the_apps_bot() {
    let w = world();
    let number = w
        .github
        .add_issue("acme/widgets", "Fix it", "Body text.", "mallory", &["bug"]);
    let token = builder_token(&w.github);

    let (status, issue) = call(
        &w.github,
        "GET",
        &format!("/repos/acme/widgets/issues/{number}"),
        Some(&token),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(issue["title"], "Fix it");
    assert_eq!(issue["user"]["id"], 1003);
    assert_eq!(issue["author_association"], "OWNER");
    assert_eq!(issue["labels"][0]["name"], "bug");

    let target = format!("/repos/acme/widgets/issues/{number}/comments");
    let (status, comment) = call(
        &w.github,
        "POST",
        &target,
        Some(&token),
        Some(&json!({"body": "On it."})),
    );
    assert_eq!(status, 201);
    assert_eq!(comment["user"]["login"], "factory-test-app[bot]");
    assert_eq!(comment["user"]["type"], "Bot");
    assert_eq!(w.github.comments("acme/widgets", number), ["On it."]);
    let (_, listed) = call(&w.github, "GET", &target, Some(&token), None);
    assert_eq!(listed.as_array().unwrap().len(), 1);

    // Empty, too long, and an issue that is not there.
    assert_eq!(
        call(
            &w.github,
            "POST",
            &target,
            Some(&token),
            Some(&json!({"body": ""}))
        )
        .0,
        422
    );
    let long = "x".repeat(65_537);
    assert_eq!(
        call(
            &w.github,
            "POST",
            &target,
            Some(&token),
            Some(&json!({"body": long}))
        )
        .0,
        422
    );
    assert_eq!(
        call(
            &w.github,
            "POST",
            "/repos/acme/widgets/issues/99/comments",
            Some(&token),
            Some(&json!({"body": "x"}))
        )
        .0,
        404
    );
    assert_eq!(w.github.comments("acme/widgets", number).len(), 1);
}

#[test]
fn the_collaborator_permission_endpoint_works_and_every_use_of_it_is_counted() {
    let w = world();
    let token = builder_token(&w.github);
    assert!(w.github.permission_lookups().is_empty());
    let (status, body) = call(
        &w.github,
        "GET",
        "/repos/acme/widgets/collaborators/mallory/permission",
        Some(&token),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["permission"], "admin");
    assert_eq!(body["user"]["id"], 1003);
    assert_eq!(
        call(
            &w.github,
            "GET",
            "/repos/acme/widgets/collaborators/nobody/permission",
            Some(&token),
            None
        )
        .0,
        404
    );
    // A test that proves "roles grant nothing" asserts this list is empty after the job.
    assert_eq!(w.github.permission_lookups().len(), 2);
}

#[test]
fn branch_protection_is_summarised_for_pushers_and_detailed_only_for_administrators() {
    let w = world();
    let app_id = w.github.app().id;
    w.github.protect_branch(
        "acme/widgets",
        "main",
        Protection::satisfying_the_policy(app_id),
    );
    let token = builder_token(&w.github);

    // The summary a token with push access sees.
    let (status, branch) = call(
        &w.github,
        "GET",
        "/repos/acme/widgets/branches/main",
        Some(&token),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(branch["protected"], true);
    assert_eq!(
        branch["protection"]["required_status_checks"]["checks"][0]["app_id"],
        app_id
    );

    // The full protection needs `administration`, which the factory's App must not hold.
    let (status, error) = call(
        &w.github,
        "GET",
        "/repos/acme/widgets/branches/main/protection",
        Some(&token),
        None,
    );
    assert_eq!(status, 403, "{error}");

    // An App that wrongly holds `administration` can read it, bypass list included.
    let over_privileged = world();
    over_privileged
        .github
        .set_app(AppConfig::factory_default().with_permission("administration", "read"));
    over_privileged.github.protect_branch(
        "acme/widgets",
        "main",
        Protection::satisfying_the_policy(over_privileged.github.app().id),
    );
    let admin_token = mint(
        &over_privileged.github,
        Some(json!({"repositories": ["widgets"], "permissions": {"administration": "read"}})),
    );
    let (status, detail) = call(
        &over_privileged.github,
        "GET",
        "/repos/acme/widgets/branches/main/protection",
        Some(&admin_token),
        None,
    );
    assert_eq!(status, 200, "{detail}");
    assert_eq!(
        detail["required_pull_request_reviews"]["required_approving_review_count"],
        1
    );
    assert!(
        detail["required_pull_request_reviews"]["bypass_pull_request_allowances"]["apps"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // An unprotected branch is a 404 with GitHub's message.
    over_privileged
        .github
        .unprotect_branch("acme/widgets", "main");
    let (status, error) = call(
        &over_privileged.github,
        "GET",
        "/repos/acme/widgets/branches/main/protection",
        Some(&admin_token),
        None,
    );
    assert_eq!(status, 404);
    assert_eq!(error["message"], "Branch not protected");
}

#[test]
fn an_app_that_holds_a_forbidden_permission_can_be_modelled() {
    // NT-AUTHZ-09: the adapter must refuse this App at onboarding. The fake only has to be able
    // to be one, and to report it honestly.
    let w = world();
    w.github.set_app(
        AppConfig::factory_default()
            .with_permission("workflows", "write")
            .with_permission("administration", "write")
            .without_permission("checks"),
    );
    let (_, app) = call(
        &w.github,
        "GET",
        "/app",
        Some(&w.github.sample_app_jwt()),
        None,
    );
    assert_eq!(app["permissions"]["workflows"], "write");
    assert_eq!(app["permissions"]["administration"], "write");
    assert!(app["permissions"].get("checks").is_none());
}

#[test]
fn refs_can_be_created_updated_and_deleted_and_protected_branches_refuse_a_push() {
    let w = world();
    let app_id = w.github.app().id;
    w.github.protect_branch(
        "acme/widgets",
        "main",
        Protection::satisfying_the_policy(app_id),
    );
    let token = builder_token(&w.github);
    let main_sha = w.github.branch_sha("acme/widgets", "main").unwrap();

    let create = json!({"ref": "refs/heads/factory/task-1", "sha": main_sha});
    let (status, _) = call(
        &w.github,
        "POST",
        "/repos/acme/widgets/git/refs",
        Some(&token),
        Some(&create),
    );
    assert_eq!(status, 201);
    let (status, error) = call(
        &w.github,
        "POST",
        "/repos/acme/widgets/git/refs",
        Some(&token),
        Some(&create),
    );
    assert_eq!(status, 422);
    assert_eq!(error["message"], "Reference already exists");
    // A reference outside `refs/heads/`, and a commit that does not exist.
    assert_eq!(
        call(
            &w.github,
            "POST",
            "/repos/acme/widgets/git/refs",
            Some(&token),
            Some(&json!({"ref": "refs/tags/x", "sha": main_sha}))
        )
        .0,
        422
    );
    assert_eq!(
        call(
            &w.github,
            "POST",
            "/repos/acme/widgets/git/refs",
            Some(&token),
            Some(&json!({"ref": "refs/heads/y", "sha": "nope"}))
        )
        .0,
        422
    );

    // Branch names with a slash work in the URL.
    let new_sha = "a".repeat(40);
    let (status, updated) = call(
        &w.github,
        "PATCH",
        "/repos/acme/widgets/git/refs/heads/factory/task-1",
        Some(&token),
        Some(&json!({"sha": new_sha})),
    );
    assert_eq!(status, 200, "{updated}");
    let (status, got) = call(
        &w.github,
        "GET",
        "/repos/acme/widgets/git/ref/heads/factory/task-1",
        Some(&token),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(got["object"]["sha"], new_sha);

    // The protected default branch refuses a direct update and a delete.
    let (status, error) = call(
        &w.github,
        "PATCH",
        "/repos/acme/widgets/git/refs/heads/main",
        Some(&token),
        Some(&json!({"sha": new_sha})),
    );
    assert_eq!(status, 403);
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .starts_with("Protected branch update failed")
    );
    assert_eq!(
        call(
            &w.github,
            "DELETE",
            "/repos/acme/widgets/git/refs/heads/main",
            Some(&token),
            None
        )
        .0,
        403
    );
    assert_eq!(
        w.github.branch_sha("acme/widgets", "main").unwrap(),
        main_sha,
        "main did not move"
    );

    assert_eq!(
        call(
            &w.github,
            "DELETE",
            "/repos/acme/widgets/git/refs/heads/factory/task-1",
            Some(&token),
            None
        )
        .0,
        204
    );
    let kinds: Vec<(String, String)> = w
        .github
        .pushes()
        .into_iter()
        .map(|p| (p.kind, p.branch))
        .collect();
    assert_eq!(
        kinds,
        [
            ("create".to_owned(), "factory/task-1".to_owned()),
            ("update".to_owned(), "factory/task-1".to_owned()),
            ("delete".to_owned(), "factory/task-1".to_owned()),
        ],
        "only the three changes that succeeded are pushes"
    );
    assert!(w.github.pushes().iter().all(|p| p.token_id == Some(1)));
}

/// A repository with a factory branch ready for a pull request.
fn with_factory_branch(w: &World) -> String {
    w.github.push_commit("acme/widgets", "factory/task-1")
}

#[test]
fn a_draft_pull_request_is_opened_once_per_head_branch() {
    let w = world();
    with_factory_branch(&w);
    let token = builder_token(&w.github);
    let open = json!({"title": "Add a thing", "body": "Details.", "head": "factory/task-1", "base": "main", "draft": true});

    let (status, pull) = call(
        &w.github,
        "POST",
        "/repos/acme/widgets/pulls",
        Some(&token),
        Some(&open),
    );
    assert_eq!(status, 201, "{pull}");
    assert_eq!(pull["draft"], true);
    assert_eq!(pull["state"], "open");
    assert_eq!(pull["head"]["ref"], "factory/task-1");
    assert_eq!(pull["user"]["login"], "factory-test-app[bot]");
    let number = pull["number"].as_u64().unwrap();

    // The second attempt for the same head branch is GitHub's 422, with its message.
    let (status, error) = call(
        &w.github,
        "POST",
        "/repos/acme/widgets/pulls",
        Some(&token),
        Some(&open),
    );
    assert_eq!(status, 422);
    assert_eq!(error["message"], "Validation Failed");
    assert!(
        error["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("A pull request already exists for acme:factory/task-1"),
        "{error}"
    );
    assert_eq!(w.github.pull_numbers("acme/widgets"), [number]);

    // The adapter finds the existing one by head, as GitHub's list endpoint allows.
    let (_, listed) = call(
        &w.github,
        "GET",
        "/repos/acme/widgets/pulls?state=open&head=acme%3Afactory%2Ftask-1",
        Some(&token),
        None,
    );
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["number"], number);
    let (_, none) = call(
        &w.github,
        "GET",
        "/repos/acme/widgets/pulls?head=acme%3Aother",
        Some(&token),
        None,
    );
    assert!(none.as_array().unwrap().is_empty());

    // Once it is closed, a new one for the same head is allowed.
    assert_eq!(
        call(
            &w.github,
            "PATCH",
            &format!("/repos/acme/widgets/pulls/{number}"),
            Some(&token),
            Some(&json!({"state": "closed"}))
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &w.github,
            "POST",
            "/repos/acme/widgets/pulls",
            Some(&token),
            Some(&open)
        )
        .0,
        201
    );
}

#[test]
fn a_pull_request_with_a_bad_head_base_or_title_is_refused() {
    let w = world();
    with_factory_branch(&w);
    let token = builder_token(&w.github);
    for (name, body) in [
        (
            "missing head branch",
            json!({"title": "t", "head": "factory/none", "base": "main"}),
        ),
        (
            "missing base branch",
            json!({"title": "t", "head": "factory/task-1", "base": "nope"}),
        ),
        (
            "same head and base",
            json!({"title": "t", "head": "main", "base": "main"}),
        ),
        (
            "no title",
            json!({"title": " ", "head": "factory/task-1", "base": "main"}),
        ),
    ] {
        let (status, error) = call(
            &w.github,
            "POST",
            "/repos/acme/widgets/pulls",
            Some(&token),
            Some(&body),
        );
        assert_eq!(status, 422, "{name}: {error}");
        assert_eq!(error["message"], "Validation Failed", "{name}");
    }
    assert!(w.github.pull_numbers("acme/widgets").is_empty());
}

#[test]
fn a_pull_request_can_be_edited_but_not_marked_ready_through_the_rest_api() {
    let w = world();
    with_factory_branch(&w);
    let token = builder_token(&w.github);
    let (_, pull) = call(
        &w.github,
        "POST",
        "/repos/acme/widgets/pulls",
        Some(&token),
        Some(&json!({"title": "Old", "head": "factory/task-1", "base": "main", "draft": true})),
    );
    let number = pull["number"].as_u64().unwrap();
    let target = format!("/repos/acme/widgets/pulls/{number}");
    let (_, edited) = call(
        &w.github,
        "PATCH",
        &target,
        Some(&token),
        Some(&json!({"title": "New", "draft": false})),
    );
    assert_eq!(edited["title"], "New");
    assert_eq!(
        edited["draft"], true,
        "the REST API does not accept `draft`; GraphQL does"
    );
    w.github.mark_ready("acme/widgets", number);
    assert_eq!(
        w.github.pull_json("acme/widgets", number).unwrap()["draft"],
        false
    );

    // A pull request is also an issue: it takes comments.
    let (status, _) = call(
        &w.github,
        "POST",
        &format!("/repos/acme/widgets/issues/{number}/comments"),
        Some(&token),
        Some(&json!({"body": "Summary."})),
    );
    assert_eq!(status, 201);
}

/// A ready pull request with the policy's protection on `main`, ready to be merged by a person.
fn mergeable_setup(w: &World, token: &str) -> (u64, String) {
    let app_id = w.github.app().id;
    w.github.protect_branch(
        "acme/widgets",
        "main",
        Protection::satisfying_the_policy(app_id),
    );
    let head = with_factory_branch(w);
    let (_, pull) = call(
        &w.github,
        "POST",
        "/repos/acme/widgets/pulls",
        Some(token),
        Some(
            &json!({"title": "Add a thing", "head": "factory/task-1", "base": "main", "draft": true}),
        ),
    );
    let number = pull["number"].as_u64().unwrap();
    w.github.mark_ready("acme/widgets", number);
    (number, head)
}

fn merge(w: &World, token: &str, number: u64, sha: &str) -> (u16, Value) {
    call(
        &w.github,
        "PUT",
        &format!("/repos/acme/widgets/pulls/{number}/merge"),
        Some(token),
        Some(&json!({"sha": sha, "merge_method": "squash"})),
    )
}

#[test]
fn merge_refuses_a_stale_head_sha_and_merges_nothing() {
    let w = world();
    let token = builder_token(&w.github);
    let (number, old_head) = mergeable_setup(&w, &token);
    let app_id = w.github.app().id;
    w.github
        .add_check_run("acme/widgets", &old_head, "ci", "success", app_id);
    w.github
        .add_review("acme/widgets", number, "alice", "APPROVED", &old_head);

    // Approved at commit A. A new push makes the head B.
    let new_head = w.github.push_commit("acme/widgets", "factory/task-1");
    assert_ne!(old_head, new_head);

    // A merge that names the commit it reviewed (A) is refused with GitHub's 409.
    let (status, error) = merge(&w, &token, number, &old_head);
    assert_eq!(status, 409, "{error}");
    assert_eq!(
        error["message"],
        "Head branch was modified. Review and try the merge again."
    );
    assert!(w.github.merges().is_empty());
    assert_eq!(w.github.merge_attempts().len(), 1);
    assert_eq!(
        w.github.pull_json("acme/widgets", number).unwrap()["merged"],
        false
    );
}

#[test]
fn merge_needs_a_ready_pull_request_with_passing_pinned_checks_and_a_current_approval() {
    let w = world();
    let token = builder_token(&w.github);
    let (number, head) = mergeable_setup(&w, &token);
    let app_id = w.github.app().id;

    // Still a draft.
    w.github
        .lock()
        .repos
        .get_mut("acme/widgets")
        .unwrap()
        .pulls
        .get_mut(&number)
        .unwrap()
        .draft = true;
    assert_eq!(
        merge(&w, &token, number, &head).1["message"],
        "Pull Request is still a draft"
    );
    w.github.mark_ready("acme/widgets", number);

    // No check run yet.
    let (status, error) = merge(&w, &token, number, &head);
    assert_eq!(status, 405);
    assert_eq!(
        error["message"],
        "Required status check \"ci\" is expected."
    );

    // A check from another App does not satisfy a check pinned to this one.
    w.github
        .add_check_run("acme/widgets", &head, "ci", "success", app_id + 1);
    assert_eq!(merge(&w, &token, number, &head).0, 405);

    // A failing check from the right App.
    w.github
        .add_check_run("acme/widgets", &head, "ci", "failure", app_id);
    assert_eq!(merge(&w, &token, number, &head).0, 405);

    // A passing one, and no approval yet.
    w.github
        .add_check_run("acme/widgets", &head, "ci", "success", app_id);
    let (status, error) = merge(&w, &token, number, &head);
    assert_eq!(status, 405);
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("approving review"),
        "{error}"
    );

    // The App approving its own pull request does not count (NT-MRG-06).
    let (status, _) = call(
        &w.github,
        "POST",
        &format!("/repos/acme/widgets/pulls/{number}/reviews"),
        Some(&token),
        Some(&json!({"event": "APPROVE"})),
    );
    assert_eq!(status, 200);
    assert_eq!(merge(&w, &token, number, &head).0, 405);

    // An approval of an older commit is stale.
    w.github
        .add_review("acme/widgets", number, "alice", "APPROVED", &"b".repeat(40));
    assert_eq!(merge(&w, &token, number, &head).0, 405);

    // A person's approval of the current commit.
    w.github
        .add_review("acme/widgets", number, "alice", "APPROVED", &head);
    let (status, merged) = merge(&w, &token, number, &head);
    assert_eq!(status, 200, "{merged}");
    assert_eq!(merged["merged"], true);
    assert_eq!(w.github.merges().len(), 1);
    assert_eq!(
        w.github.pull_json("acme/widgets", number).unwrap()["merged"],
        true
    );
    // And once more is refused.
    assert_eq!(merge(&w, &token, number, &head).0, 405);
}

#[test]
fn check_runs_and_statuses_are_validated_and_kept() {
    let w = world();
    let token = builder_token(&w.github);
    let sha = w.github.branch_sha("acme/widgets", "main").unwrap();
    let (status, run) = call(
        &w.github,
        "POST",
        "/repos/acme/widgets/check-runs",
        Some(&token),
        Some(
            &json!({"name": "factory", "head_sha": sha, "status": "completed", "conclusion": "success"}),
        ),
    );
    assert_eq!(status, 201);
    assert_eq!(run["app"]["id"], w.github.app().id);
    for bad in [
        json!({"name": "", "head_sha": sha}),
        json!({"name": "x", "head_sha": "short"}),
        json!({"name": "x", "head_sha": sha, "status": "completed"}),
    ] {
        assert_eq!(
            call(
                &w.github,
                "POST",
                "/repos/acme/widgets/check-runs",
                Some(&token),
                Some(&bad)
            )
            .0,
            422,
            "{bad}"
        );
    }
    let (status, _) = call(
        &w.github,
        "POST",
        &format!("/repos/acme/widgets/statuses/{sha}"),
        Some(&token),
        Some(&json!({"state": "success", "context": "factory"})),
    );
    assert_eq!(status, 201);
    assert_eq!(
        call(
            &w.github,
            "POST",
            &format!("/repos/acme/widgets/statuses/{sha}"),
            Some(&token),
            Some(&json!({"state": "great"}))
        )
        .0,
        422
    );
}

#[test]
fn a_scripted_failure_answers_the_next_matching_request_only() {
    let w = world();
    let token = builder_token(&w.github);
    let route = "GET /repos/{owner}/{repo}";
    for (status, message) in [
        (403, "Forbidden by the test"),
        (404, "Gone by the test"),
        (409, "Conflict by the test"),
        (422, "Invalid by the test"),
        (500, "Broken by the test"),
    ] {
        w.github.fail_next(route, status, message);
        let (got, body) = call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None);
        assert_eq!(got, status);
        assert_eq!(body["message"], message);
        // The very next request is normal.
        assert_eq!(
            call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None).0,
            200
        );
    }
    // A failure on another route does not touch this one.
    w.github
        .fail_next("POST /repos/{owner}/{repo}/pulls", 500, "x");
    assert_eq!(
        call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None).0,
        200
    );
    w.github.clear_faults();

    // A standing failure, and the wildcard.
    w.github.fail_always(route, 503, "down");
    for _ in 0..3 {
        assert_eq!(
            call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None).0,
            503
        );
    }
    w.github.clear_faults();
    w.github.fail_next("*", 500, "any");
    assert_eq!(
        call(
            &w.github,
            "GET",
            "/app",
            Some(&w.github.sample_app_jwt()),
            None
        )
        .0,
        500
    );
}

#[test]
fn a_rate_limit_answer_carries_the_headers_a_client_backs_off_on() {
    let w = world();
    let token = builder_token(&w.github);
    w.github.rate_limit_next("GET /repos/{owner}/{repo}", 30);
    let request = HttpRequest {
        method: "GET".to_owned(),
        target: "/repos/acme/widgets".to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![("Authorization".to_owned(), format!("Bearer {token}"))],
        body: Vec::new(),
        peer: "127.0.0.1:1".parse().unwrap(),
    };
    let response = w.github.handle(&request);
    assert_eq!(response.status, 429);
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(header("Retry-After").as_deref(), Some("30"));
    assert_eq!(header("x-ratelimit-remaining").as_deref(), Some("0"));
    assert_eq!(
        header("x-ratelimit-reset"),
        Some((w.github.now() + 30).to_string())
    );
    assert_eq!(
        w.github.handle(&request).status,
        200,
        "the limit applied once"
    );
}

#[test]
fn unknown_and_unauthenticated_requests_are_refused_and_logged() {
    let w = world();
    let token = builder_token(&w.github);
    assert_eq!(
        call(&w.github, "GET", "/nothing/here", Some(&token), None).0,
        404
    );
    assert_eq!(w.github.requests().last().unwrap().route, "UNROUTED");
    // A repository route with no credential, with a JWT, and with garbage.
    let (status, error) = call(&w.github, "GET", "/repos/acme/widgets", None, None);
    assert_eq!(status, 401);
    assert_eq!(error["message"], "Requires authentication");
    assert_eq!(
        call(
            &w.github,
            "GET",
            "/repos/acme/widgets",
            Some(&w.github.sample_app_jwt()),
            None
        )
        .0,
        401
    );
    let (status, error) = call(
        &w.github,
        "GET",
        "/repos/acme/widgets",
        Some("ghs_unknown"),
        None,
    );
    assert_eq!(status, 401);
    assert_eq!(error["message"], "Bad credentials");
    // The log says why, even though the body does not.
    assert!(matches!(
        w.github.requests().last().unwrap().auth,
        AuthSummary::Rejected { .. }
    ));
}

#[test]
fn the_log_masks_authorization_and_the_sweeper_finds_no_token_in_it() {
    let w = world();
    let token = builder_token(&w.github);
    call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None);
    call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None);

    let log = w.github.requests();
    let masked: Vec<&str> = log
        .iter()
        .filter(|r| r.route == "GET /repos/{owner}/{repo}")
        .map(|r| {
            r.headers
                .iter()
                .find(|(n, _)| n == "Authorization")
                .map(|(_, v)| v.as_str())
                .unwrap()
        })
        .collect();
    assert_eq!(masked.len(), 2);
    assert!(
        masked[0].starts_with("Bearer [MASKED len=40 fp="),
        "{}",
        masked[0]
    );
    assert_eq!(
        masked[0], masked[1],
        "the same token shows the same fingerprint"
    );
    assert!(!masked[0].contains(&token));

    // The sweeper, told about the minted token and the webhook secret, finds neither in the log.
    let mut set = CanarySet::generate();
    for secret in w.github.minted_secrets() {
        set = set.with(secret);
    }
    set = set.with(w.github.webhook_secret_canary());
    let sweeper = Sweeper::new(&set);
    for record in &log {
        assert!(
            sweeper
                .scan(
                    &format!("fx-gh:{}", record.seq),
                    record.as_text().as_bytes()
                )
                .is_empty(),
            "request {} leaked a secret: {}",
            record.seq,
            record.route
        );
    }
    // The whole JSON export is clean too.
    assert!(
        sweeper
            .scan("fx-gh:json", w.github.to_json().to_string().as_bytes())
            .is_empty()
    );
}

#[test]
fn text_sent_to_github_is_recorded_so_a_leak_in_it_is_found() {
    // The other half of NT-SEC-03: when the code under test puts a secret into a comment, the
    // fake keeps the body, and the sweeper finds it there.
    let w = world();
    let number = w.github.add_issue("acme/widgets", "A", "B", "alice", &[]);
    let token = builder_token(&w.github);
    let canaries = CanarySet::generate();
    let secret = canaries.get(CanaryKind::ModelApiKey).value();
    call(
        &w.github,
        "POST",
        &format!("/repos/acme/widgets/issues/{number}/comments"),
        Some(&token),
        Some(&json!({"body": format!("debug output: {secret}")})),
    );
    let sweeper = Sweeper::new(&canaries);
    let record = w
        .github
        .requests()
        .into_iter()
        .find(|r| r.route == "POST /repos/{owner}/{repo}/issues/{number}/comments")
        .unwrap();
    let hits = sweeper.scan("fx-gh:comment", record.as_text().as_bytes());
    // The key is plain letters, digits and dashes, so JSON escaping leaves it as it was.
    let hit = hits
        .iter()
        .find(|h| h.canary == "model_api_key")
        .expect("the key is found");
    assert_eq!(hit.form, Form::Raw);
}

#[test]
fn every_record_and_response_says_it_is_fake() {
    let w = world();
    let token = builder_token(&w.github);
    call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None);
    let json = w.github.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert!(json["server"].as_str().unwrap().contains("fake"));
    for record in json["requests"].as_array().unwrap() {
        assert_eq!(record["fidelity"], "fake");
    }

    let server = w.github.serve().unwrap();
    assert!(server.addr().ip().is_loopback());
    let response = send_request(
        server.addr(),
        "GET",
        "/repos/acme/widgets",
        &[("Authorization", &format!("Bearer {token}"))],
        b"",
    )
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.header("X-Factory-Fidelity"), Some("fake"));
    assert!(
        response
            .header("Server")
            .unwrap()
            .contains("factory-testkit-fake")
    );
    assert_eq!(response.json().unwrap()["full_name"], "acme/widgets");
    // The call over the socket is in the same log.
    assert_eq!(server.fake().count("GET /repos/{owner}/{repo}"), 2);
}

#[test]
fn the_log_keeps_time_from_the_shared_clock() {
    let w = world();
    let token = builder_token(&w.github);
    let before = w.github.now();
    w.clock.advance(Duration::from_secs(90));
    call(&w.github, "GET", "/repos/acme/widgets", Some(&token), None);
    let record = w.github.requests().into_iter().last().unwrap();
    assert_eq!(record.at, before + 90);
}

#[test]
fn a_label_removed_after_the_webhook_is_visible_in_the_live_state() {
    // NT-WH-06: the payload says the label is there, the API says it was removed.
    let w = world();
    let number = w.github.add_issue("acme/widgets", "A", "B", "alice", &[]);
    w.github.add_label("acme/widgets", number, "factory:go");
    let delivery = w
        .github
        .issues_labeled("acme/widgets", number, "factory:go", "alice");
    w.github.remove_label("acme/widgets", number, "factory:go");

    assert_eq!(
        delivery.payload()["issue"]["labels"][0]["name"],
        "factory:go"
    );
    let token = builder_token(&w.github);
    let (_, live) = call(
        &w.github,
        "GET",
        &format!("/repos/acme/widgets/issues/{number}"),
        Some(&token),
        None,
    );
    assert!(live["labels"].as_array().unwrap().is_empty());
}

#[test]
fn an_issue_edited_after_labelling_changes_the_live_body_and_the_updated_time() {
    // NT-AUTHZ-05.
    let w = world();
    let number = w
        .github
        .add_issue("acme/widgets", "A", "Original body.", "alice", &[]);
    let token = builder_token(&w.github);
    let target = format!("/repos/acme/widgets/issues/{number}");
    let (_, before) = call(&w.github, "GET", &target, Some(&token), None);
    w.clock.advance(Duration::from_secs(5));
    w.github
        .edit_issue_body("acme/widgets", number, "Hostile body.");
    let (_, after) = call(&w.github, "GET", &target, Some(&token), None);
    assert_eq!(after["body"], "Hostile body.");
    assert_ne!(before["updated_at"], after["updated_at"]);
}
