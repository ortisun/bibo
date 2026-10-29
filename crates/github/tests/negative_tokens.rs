//! Negative tests owned by the GitHub adapter, credential part: NT-AUTHZ-06, NT-AUTHZ-07,
//! NT-AUTHZ-09, NT-MRG-07, NT-SEC-09 and NT-SEC-10, and the checks on every token the adapter
//! mints (narrowing is verified and not assumed, early refresh, one retry on a dead token).

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::harness::{FIXTURE, OTHER, Options, World};
use common::transports::{Widening, Widens};
use factory_domain::ids::{JobId, PrincipalId};
use factory_domain::values::{Slug, Timestamp};
use factory_domain::vocabulary::StageKind;
use factory_github::{AppAudit, Level, PermissionSet};
use factory_ports::clock::Uuid;
use factory_ports::githost::{
    BypassAttestation, ChangeHost, CommentTarget, DraftPrRequest, GitHostError, GitScope, IssueRef,
    IssueSource, PreflightFailure, PreflightVerdict, ProtectionSource,
};
use factory_ports::paths::{BranchName, RepoRef};
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::github::{AppConfig, FakeGithub};
use factory_testkit::fx::http::send_request;

fn at(stage: StageKind, job: u128) -> GitScope {
    GitScope {
        stage,
        ..scope(1, job)
    }
}

fn issue(world: &World) -> IssueRef {
    let number = world.fake.add_issue(
        FIXTURE,
        "Add word count",
        "Please.",
        "octocat",
        &["factory"],
    );
    IssueRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    }
}

fn branch(name: &str) -> BranchName {
    BranchName::new(name).unwrap()
}

fn as_map(entries: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    entries
        .iter()
        .map(|(n, l)| ((*n).to_owned(), (*l).to_owned()))
        .collect()
}

fn get_with(world: &World, token: &str, path: &str) -> u16 {
    let auth = format!("Bearer {token}");
    send_request(
        world.addr(),
        "GET",
        path,
        &[("Authorization", auth.as_str())],
        b"",
    )
    .expect("a response")
    .status
}

// ---- NT-AUTHZ-06 -----------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_authz_06_a_token_is_minted_for_one_repository_and_nothing_else_is_reachable() {
    let world = World::new();
    let host = world.adapter.change_host();
    let source = world.adapter.issue_source();
    let issue_a = issue(&world);
    let scope_a = at(StageKind::Intake, 1);

    let fetch = host.fetch_target(&scope_a).await.unwrap();
    source.fetch_issue(&scope_a, &issue_a).await.unwrap();

    // Every mint named exactly the one repository and an exact permission map.
    let mints = world.fake.mints();
    assert_eq!(
        mints.len(),
        2,
        "one read credential for git, one for the stage"
    );
    for mint in &mints {
        assert_eq!(
            mint.requested_repositories,
            Some(vec!["fixture".to_owned()])
        );
        assert_eq!(mint.granted_repositories, vec![FIXTURE.to_owned()]);
    }
    assert_eq!(
        mints[0].requested_permissions,
        Some(as_map(&[("contents", "read"), ("metadata", "read")]))
    );
    assert_eq!(
        mints[1].requested_permissions,
        Some(as_map(&[
            ("contents", "read"),
            ("issues", "read"),
            ("metadata", "read"),
            ("pull_requests", "read"),
        ]))
    );

    // The credential works on A and answers 404 on B, which is in the same installation.
    assert_eq!(
        get_with(
            &world,
            fetch.credential.expose(),
            &format!("/repos/{FIXTURE}")
        ),
        200
    );
    assert_eq!(
        get_with(
            &world,
            fetch.credential.expose(),
            &format!("/repos/{OTHER}")
        ),
        404
    );

    // The adapter itself does not try B with a token for A: a reference to B is refused before
    // any call, and a tenant with no binding to a repository reaches nothing.
    let in_b = IssueRef {
        repo: RepoRef::parse(OTHER).unwrap(),
        number: 1,
    };
    assert_eq!(
        source.fetch_issue(&scope_a, &in_b).await,
        Err(GitHostError::NotFound)
    );
    let stranger = GitScope {
        stage: StageKind::Intake,
        ..scope(2, 7)
    };
    assert_eq!(
        host.fetch_target(&stranger).await.err(),
        Some(GitHostError::NotFound)
    );
    assert_eq!(
        world.fake.mints().len(),
        2,
        "no further token was minted by any of that"
    );
}

#[tokio::test]
async fn negative_nt_authz_06_a_token_that_is_wider_than_the_request_is_revoked_and_refused() {
    for widening in [
        Widening::ExtraPermission,
        Widening::HigherLevel,
        Widening::SecondRepository,
        Widening::NoRepositoryList,
    ] {
        let world = World::with(Options {
            wrap: Some(Box::new(move |inner| Widens::new(inner, widening))),
            ..Options::default()
        });
        let source = world.adapter.issue_source();
        let issue = issue(&world);
        let outcome = source.fetch_issue(&at(StageKind::Intake, 1), &issue).await;
        assert_eq!(outcome, Err(GitHostError::Forbidden), "{widening:?}");
        let tokens = world.fake.tokens();
        assert_eq!(tokens.len(), 1, "{widening:?}");
        assert!(
            tokens[0].revoked_at.is_some(),
            "the wide token was revoked: {widening:?}"
        );
        assert_eq!(
            tokens[0].uses, 1,
            "its only use was its own revocation: {widening:?}"
        );
        assert_eq!(
            world
                .fake
                .requests_to("GET /repos/{owner}/{repo}/issues/{number}")
                .len(),
            0
        );
    }
}

// ---- NT-AUTHZ-07 -----------------------------------------------------------------------------

const ALL_STAGES: [StageKind; 14] = [
    StageKind::Intake,
    StageKind::RepositoryIntelligence,
    StageKind::Specification,
    StageKind::DomainDiscovery,
    StageKind::Architecture,
    StageKind::TaskPlanning,
    StageKind::Implementation,
    StageKind::Validation,
    StageKind::Review,
    StageKind::Documenting,
    StageKind::DocumentationReview,
    StageKind::Delivery,
    StageKind::Approval,
    StageKind::Merge,
];

#[tokio::test]
async fn negative_nt_authz_07_every_stage_gets_exactly_its_permissions_and_only_delivery_writes_the_repository()
 {
    let world = World::new();
    let host = world.adapter.change_host();
    let source = world.adapter.issue_source();
    let issue = issue(&world);
    for (index, stage) in ALL_STAGES.iter().enumerate() {
        let job = u128::try_from(index).unwrap() + 1;
        let scope = at(*stage, job);
        source.fetch_issue(&scope, &issue).await.unwrap();
        let minted = world.fake.mints().pop().expect("a mint");
        let expected: std::collections::BTreeMap<String, String> = PermissionSet::for_stage(*stage)
            .entries()
            .into_iter()
            .map(|(n, l)| (n.to_owned(), l.as_str().to_owned()))
            .collect();
        assert_eq!(minted.requested_permissions, Some(expected), "{stage:?}");
        // Only the delivery stage writes to the repository. The approval stage holds `issues:
        // write` for its one acknowledgement comment and nothing else (AUT-9).
        let writes: Vec<&str> = minted
            .granted_permissions
            .iter()
            .filter(|(_, level)| level.as_str() == "write")
            .map(|(name, _)| name.as_str())
            .collect();
        match stage {
            StageKind::Delivery => assert_eq!(
                writes,
                ["checks", "contents", "issues", "pull_requests"],
                "{stage:?}"
            ),
            StageKind::Approval => assert_eq!(writes, ["issues"], "{stage:?}"),
            _ => assert!(writes.is_empty(), "{stage:?}: {writes:?}"),
        }
        if *stage != StageKind::Delivery {
            // The credential that writes the repository is never minted for it.
            let before = world.fake.mints().len();
            assert_eq!(
                host.push_target(&scope, &branch("factory/job-1"))
                    .await
                    .err(),
                Some(GitHostError::Forbidden)
            );
            assert_eq!(
                world.fake.mints().len(),
                before,
                "{stage:?}: nothing was minted for the push"
            );
        }
    }
}

#[tokio::test]
async fn negative_nt_authz_07_a_read_only_token_cannot_comment_or_open_a_pull_request() {
    let world = World::new();
    let host = world.adapter.change_host();
    let issue = issue(&world);
    let scope = at(StageKind::Implementation, 1);
    let target = CommentTarget::Issue(issue.clone());
    assert_eq!(
        host.post_comment(&scope, &target, "Hello.", "k").await,
        Err(GitHostError::Forbidden)
    );
    let posts = world
        .fake
        .requests_to("POST /repos/{owner}/{repo}/issues/{number}/comments");
    assert_eq!(posts.len(), 1);
    assert_eq!(
        posts[0].status, 403,
        "the code host refused the narrowed token"
    );
    let request = DraftPrRequest {
        head: branch("factory/job-1"),
        base: branch("main"),
        title: "Add a word count command".to_owned(),
        body: "Evidence follows.".to_owned(),
    };
    assert_eq!(
        host.open_draft_pull_request(&scope, request).await,
        Err(GitHostError::Forbidden)
    );
    assert!(world.fake.comments(FIXTURE, issue.number).is_empty());
    assert!(world.fake.pull_numbers(FIXTURE).is_empty());
}

// ---- NT-AUTHZ-09 and NT-MRG-07 ---------------------------------------------------------------

#[tokio::test]
async fn negative_nt_authz_09_an_app_that_holds_a_forbidden_permission_gets_no_token() {
    for forbidden in ["workflows", "administration", "secrets", "members"] {
        let app = AppConfig::factory_default().with_permission(forbidden, "write");
        let world = World::with(Options {
            app: Some(app),
            ..Options::default()
        });
        assert_eq!(
            world.adapter.audit_app().await.unwrap(),
            AppAudit::Refuse {
                forbidden_held: vec![forbidden.to_owned()]
            }
        );
        let host = world.adapter.change_host();
        assert_eq!(
            host.fetch_target(&at(StageKind::Intake, 1)).await.err(),
            Some(GitHostError::Forbidden),
            "{forbidden}"
        );
        assert_eq!(
            host.push_target(&at(StageKind::Delivery, 2), &branch("factory/job-1"))
                .await
                .err(),
            Some(GitHostError::Forbidden)
        );
        assert!(
            world.fake.mints().is_empty(),
            "{forbidden}: no token was minted"
        );
        assert!(
            world.fake.pushes().iter().all(|p| p.token_id.is_none()),
            "nothing was pushed with a token"
        );
    }
}

#[tokio::test]
async fn negative_nt_authz_09_an_app_that_lacks_a_required_permission_is_capped() {
    let app = AppConfig::factory_default().without_permission("checks");
    let world = World::with(Options {
        app: Some(app),
        ..Options::default()
    });
    assert_eq!(
        world.adapter.audit_app().await.unwrap(),
        AppAudit::CapAtL0 {
            missing: vec!["checks".to_owned()]
        }
    );
    let good = World::new();
    assert_eq!(good.adapter.audit_app().await.unwrap(), AppAudit::Pass);
}

fn attestation() -> BypassAttestation {
    BypassAttestation {
        by: PrincipalId::from_uuid(Uuid::from_u128(9)),
        at: Timestamp::parse("2026-10-28T09:00:00Z").unwrap(),
    }
}

fn checks() -> Vec<Slug> {
    vec![
        Slug::parse("factory-validation").unwrap(),
        Slug::parse("factory-review").unwrap(),
    ]
}

fn rules(pinned_to: Option<u64>) -> serde_json::Value {
    let check = |name: &str| serde_json::json!({"context": name, "integration_id": pinned_to});
    serde_json::json!([
        {"type": "pull_request", "parameters": {"dismiss_stale_reviews_on_push": true, "require_code_owner_review": true}},
        {"type": "required_status_checks", "parameters": {"required_status_checks": [check("factory-validation"), check("factory-review")]}},
        {"type": "non_fast_forward"},
        {"type": "deletion"}
    ])
}

#[tokio::test]
async fn negative_nt_mrg_07_a_repository_that_does_not_meet_the_requirements_runs_at_l0() {
    let world = World::new();
    let scope = at(StageKind::Intake, 1);
    let app_id = world.fake.app().id;
    let set = |value: serde_json::Value| {
        world
            .extras
            .rules
            .lock()
            .unwrap()
            .insert(FIXTURE.to_owned(), value);
    };

    // Classic protection only, or none: the rulesets say nothing, and the reason is named.
    set(serde_json::json!([]));
    match world
        .adapter
        .preflight(&scope, &checks(), Some(&attestation()))
        .await
        .unwrap()
    {
        PreflightVerdict::CapAtL0(reasons) => {
            assert_eq!(reasons.first(), Some(&PreflightFailure::NoRulesetRules));
            assert!(reasons.contains(&PreflightFailure::FactoryCheckNotRequired(
                "factory-validation".to_owned()
            )));
        }
        PreflightVerdict::Pass => panic!("a repository with no ruleset rules passed"),
    }
    let report = world
        .adapter
        .issue_source()
        .repository_protection(&scope)
        .await
        .unwrap();
    assert_eq!(report.source, ProtectionSource::NoRulesetRules);

    // Required checks that any App may satisfy, or that another App is pinned to.
    for pinned in [None, Some(app_id + 1)] {
        set(rules(pinned));
        let verdict = world
            .adapter
            .preflight(&scope, &checks(), Some(&attestation()))
            .await
            .unwrap();
        assert_eq!(
            verdict,
            PreflightVerdict::CapAtL0(vec![
                PreflightFailure::FactoryCheckNotPinned("factory-validation".to_owned()),
                PreflightFailure::FactoryCheckNotPinned("factory-review".to_owned()),
            ]),
            "{pinned:?}"
        );
    }

    // The bypass list cannot be read with the Metadata permission, so nobody has said the App is
    // on none, and the repository is capped until an admin does.
    set(rules(Some(app_id)));
    assert_eq!(
        world
            .adapter
            .preflight(&scope, &checks(), None)
            .await
            .unwrap(),
        PreflightVerdict::CapAtL0(vec![PreflightFailure::BypassNotAttested])
    );
    assert_eq!(
        world
            .adapter
            .preflight(&scope, &checks(), Some(&attestation()))
            .await
            .unwrap(),
        PreflightVerdict::Pass
    );

    // Nothing in the preflight needs the Administration permission or pushes anything.
    for mint in world.fake.mints() {
        assert!(!mint.granted_permissions.contains_key("administration"));
    }
    assert_eq!(
        world
            .fake
            .requests_to("GET /repos/{owner}/{repo}/branches/{branch}/protection")
            .len(),
        0
    );
    assert!(
        world.fake.pushes().iter().all(|p| p.token_id.is_none()),
        "nothing was pushed with a token"
    );
}

#[tokio::test]
async fn negative_nt_mrg_07_the_app_holding_workflows_is_refused_and_nothing_is_pushed() {
    let app = AppConfig::factory_default().with_permission("workflows", "write");
    let world = World::with(Options {
        app: Some(app),
        ..Options::default()
    });
    let outcome = world
        .adapter
        .preflight(&at(StageKind::Intake, 1), &checks(), Some(&attestation()))
        .await;
    assert_eq!(outcome, Err(GitHostError::Forbidden));
    assert!(
        world.fake.pushes().iter().all(|p| p.token_id.is_none()),
        "nothing was pushed with a token"
    );
}

// ---- NT-SEC-10 -------------------------------------------------------------------------------

async fn mint_two_tokens(world: &World, job: u128, issue: &IssueRef) -> String {
    let scope = at(StageKind::Intake, job);
    world
        .adapter
        .issue_source()
        .fetch_issue(&scope, issue)
        .await
        .unwrap();
    let fetch = world
        .adapter
        .change_host()
        .fetch_target(&scope)
        .await
        .unwrap();
    fetch.credential.expose().to_owned()
}

fn job(n: u128) -> JobId {
    scope(1, n).job
}

#[tokio::test]
async fn negative_nt_sec_10_tokens_are_revoked_when_a_job_succeeded_failed_was_cancelled_or_was_orphaned()
 {
    let world = World::new();
    let host = world.adapter.change_host();
    let issue = issue(&world);
    let known_before = world.redactor.registered_count();
    let mut credentials = Vec::new();
    for n in 1..=4 {
        credentials.push(mint_two_tokens(&world, n, &issue).await);
    }
    assert_eq!(world.fake.mints().len(), 8);
    assert_eq!(
        world.redactor.registered_count(),
        known_before + 8,
        "every token is known to the redactor from the moment it exists"
    );
    for credential in &credentials {
        assert!(
            world
                .redactor
                .contains_secret(credential.as_bytes())
                .unwrap()
        );
    }
    assert!(world.fake.revocations().is_empty());

    // Succeeded, failed and cancelled jobs all end with the same call from the engine.
    for n in 1..=3 {
        host.revoke_job_tokens(job(n)).await.unwrap();
        host.revoke_job_tokens(job(n)).await.unwrap();
    }
    assert_eq!(
        world.fake.revocations().len(),
        6,
        "one DELETE per token, and a repeat does nothing"
    );

    // The fourth job was orphaned: nothing ended it. The sweep finds it and leaves running jobs.
    let running: HashSet<JobId> = HashSet::new();
    assert_eq!(world.adapter.sweep_orphans(&running).await, 2);
    assert_eq!(world.fake.revocations().len(), 8);
    assert_eq!(world.adapter.sweep_orphans(&running).await, 0);
    assert_eq!(
        world.redactor.registered_count(),
        known_before,
        "and forgotten when it is revoked"
    );

    // Every token is dead on GitHub's side, and the old credentials fail.
    assert!(world.fake.tokens().iter().all(|t| t.revoked_at.is_some()));
    for credential in &credentials {
        assert_eq!(
            get_with(&world, credential, &format!("/repos/{FIXTURE}")),
            401
        );
    }
    let tried = world
        .fake
        .tokens()
        .iter()
        .filter(|t| t.uses_after_revoke >= 1)
        .count();
    assert_eq!(
        tried,
        credentials.len(),
        "every old credential that was tried was refused"
    );

    // And the factory itself refuses to use or mint for an ended job.
    let mints = world.fake.mints().len();
    for n in 1..=4 {
        let scope = at(StageKind::Intake, n);
        assert_eq!(
            world
                .adapter
                .issue_source()
                .fetch_issue(&scope, &issue)
                .await,
            Err(GitHostError::Unauthorized)
        );
        assert_eq!(
            host.fetch_target(&scope).await.err(),
            Some(GitHostError::Unauthorized)
        );
    }
    assert_eq!(world.fake.mints().len(), mints);
}

#[tokio::test]
async fn negative_nt_sec_10_a_running_job_keeps_its_tokens_through_the_sweep() {
    let world = World::new();
    let issue = issue(&world);
    mint_two_tokens(&world, 1, &issue).await;
    let running: HashSet<JobId> = [job(1)].into_iter().collect();
    assert_eq!(world.adapter.sweep_orphans(&running).await, 0);
    assert!(world.fake.revocations().is_empty());
}

#[tokio::test]
async fn negative_nt_sec_10_a_revocation_that_fails_is_kept_and_retried() {
    let world = World::new();
    let host = world.adapter.change_host();
    let issue = issue(&world);
    mint_two_tokens(&world, 1, &issue).await;
    world
        .fake
        .fail_always("DELETE /installation/token", 500, "boom");
    assert_eq!(
        host.revoke_job_tokens(job(1)).await,
        Err(GitHostError::Unavailable)
    );
    assert!(world.fake.revocations().is_empty());
    // The job is over all the same: no new call is allowed.
    assert_eq!(
        world
            .adapter
            .issue_source()
            .fetch_issue(&at(StageKind::Intake, 1), &issue)
            .await,
        Err(GitHostError::Unauthorized)
    );
    world.fake.clear_faults();
    host.revoke_job_tokens(job(1)).await.unwrap();
    assert_eq!(world.fake.revocations().len(), 2);
}

// ---- NT-SEC-09 -------------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_sec_09_the_adapter_starts_no_process_and_prints_no_credential() {
    // The static half: the crate has no way to start a process or to read or set the environment,
    // so a token cannot reach a command line or a child's environment from here. (The
    // architecture check DEP-10 enforces the same for every crate but the one that may spawn.)
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(dir).expect("the source directory") {
        let path = entry.expect("an entry").path();
        let text = std::fs::read_to_string(&path).expect("a source file");
        for needle in [
            "std::process",
            "tokio::process",
            "Command::new",
            "std::env",
            "set_var",
            "unsafe ",
        ] {
            let code_lines = text.lines().filter(|l| !l.trim_start().starts_with("//"));
            assert!(
                !code_lines.clone().any(|l| l.contains(needle)),
                "{} mentions {needle}",
                path.display()
            );
        }
    }

    // The dynamic half: a credential is printed by nothing the adapter hands out.
    let world = World::new();
    let host = world.adapter.change_host();
    let scope = at(StageKind::Delivery, 1);
    let push = host
        .push_target(&scope, &branch("factory/job-1"))
        .await
        .unwrap();
    let fetch = host.fetch_target(&scope).await.unwrap();
    let secrets = [
        push.credential.expose().to_owned(),
        fetch.credential.expose().to_owned(),
    ];
    let shown = format!(
        "{push:?} {fetch:?} {host:?} {:?} {:?}",
        world.adapter,
        world.adapter.issue_source()
    );
    for secret in &secrets {
        assert!(secret.starts_with("ghs_"), "a token in the real format");
        assert!(
            !shown.contains(secret.as_str()),
            "a token was printed: {shown}"
        );
    }
    // Errors say nothing of the credential either.
    world
        .fake
        .fail_always("GET /repos/{owner}/{repo}", 403, "oops");
    let failure = world
        .adapter
        .issue_source()
        .repository_protection(&scope)
        .await
        .unwrap_err();
    for secret in &secrets {
        assert!(!format!("{failure:?} {failure}").contains(secret.as_str()));
    }
    // Nothing the process environment holds is a token either.
    for (name, value) in std::env::vars() {
        for secret in &secrets {
            assert!(
                !value.contains(secret.as_str()),
                "the environment variable {name} holds a token"
            );
        }
    }
    // The only place a token may appear on the wire is the Authorization header, which the fake
    // masks in its own log; nothing else of any request holds one.
    for request in world.fake.requests() {
        for secret in &secrets {
            assert!(!request.as_text().contains(secret.as_str()));
        }
    }
    let _ = FakeGithub::new;
}

// ---- tokens in general -----------------------------------------------------------------------

#[tokio::test]
async fn a_token_is_reused_until_it_is_close_to_expiry_then_replaced_and_the_old_one_revoked() {
    let world = World::new();
    let source = world.adapter.issue_source();
    let issue = issue(&world);
    let scope = at(StageKind::Intake, 1);
    source.fetch_issue(&scope, &issue).await.unwrap();
    source.fetch_issue(&scope, &issue).await.unwrap();
    assert_eq!(world.fake.mints().len(), 1, "one token serves the job");

    world.clock.advance(Duration::from_secs(50 * 60));
    source.fetch_issue(&scope, &issue).await.unwrap();
    assert_eq!(
        world.fake.mints().len(),
        1,
        "fifty minutes in, the token is still good"
    );

    world.clock.advance(Duration::from_secs(6 * 60));
    source.fetch_issue(&scope, &issue).await.unwrap();
    assert_eq!(
        world.fake.mints().len(),
        2,
        "inside the refresh margin, a new token"
    );
    assert_eq!(
        world.fake.revocations().len(),
        1,
        "and the old one ended at once"
    );
    let used_after: Vec<u32> = world
        .fake
        .tokens()
        .iter()
        .map(|t| t.uses_after_revoke)
        .collect();
    assert_eq!(used_after, vec![0, 0]);
}

#[tokio::test]
async fn a_token_the_server_calls_dead_is_replaced_once_and_the_call_is_tried_again() {
    let world = World::new();
    let source = world.adapter.issue_source();
    let issue = issue(&world);
    let scope = at(StageKind::Intake, 1);
    source.fetch_issue(&scope, &issue).await.unwrap();
    world.fake.fail_next(
        "GET /repos/{owner}/{repo}/issues/{number}",
        401,
        "Bad credentials",
    );
    source.fetch_issue(&scope, &issue).await.unwrap();
    assert_eq!(world.fake.mints().len(), 2);
    // A server that keeps saying 401 does not cause a loop.
    world.fake.fail_always(
        "GET /repos/{owner}/{repo}/issues/{number}",
        401,
        "Bad credentials",
    );
    assert_eq!(
        source.fetch_issue(&scope, &issue).await,
        Err(GitHostError::Unauthorized)
    );
    assert!(world.fake.mints().len() <= 3);
}

#[test]
fn the_permission_sets_name_no_level_above_write_and_the_policy_lists_agree() {
    for set in [
        PermissionSet::read_stage(),
        PermissionSet::delivery_stage(),
        PermissionSet::approval_stage(),
    ] {
        assert!(
            set.entries()
                .iter()
                .all(|(_, level)| *level <= Level::Write)
        );
    }
}
