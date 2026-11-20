//! The preflight reads classic branch protection next to the rulesets (the owner's decision of
//! 2026-11-12: the App may hold `administration: read`), through the adapter and the fake GitHub
//! server.
//!
//! FX-GH serves classic protection on `GET .../branches/{branch}/protection` to a token that holds
//! `administration: read`, and a 404 "Branch not protected" for a branch with none. The rules are
//! served by the front of the harness. Both answers are written from GitHub's documentation and
//! are UNVERIFIED against the real GitHub: these tests show what the adapter does with that shape,
//! not that GitHub sends it.
//!
//! The cases: classic protection only, rulesets only, both, neither, a 403 on the protection
//! route, an App that cannot mint the protection read token, and the token class itself.

mod common;

use common::harness::{FIXTURE, Options, World};
use common::transports::{Overrides, answer};
use factory_domain::ids::PrincipalId;
use factory_domain::values::{Slug, Timestamp};
use factory_domain::vocabulary::StageKind;
use factory_github::Method;
use factory_ports::clock::Uuid;
use factory_ports::githost::{
    BypassAttestation, GitHostError, GitScope, IssueSource, PreflightFailure, PreflightVerdict,
    ProtectionSource,
};
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::github::{AppConfig, AuthSummary, Protection, RequiredCheck};
use serde_json::{Value, json};

const PROTECTION_ROUTE: &str = "GET /repos/{owner}/{repo}/branches/{branch}/protection";

fn intake() -> GitScope {
    GitScope {
        stage: StageKind::Intake,
        ..scope(1, 1)
    }
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

/// Rules that ask for everything the policy needs, with the factory's checks pinned to `app`.
fn strong_rules(app: u64) -> Value {
    let check = |name: &str| json!({"context": name, "integration_id": app});
    json!([
        {"type": "pull_request", "parameters": {"dismiss_stale_reviews_on_push": true, "require_code_owner_review": true, "required_approving_review_count": 1}},
        {"type": "required_status_checks", "parameters": {"required_status_checks": [check("factory-validation"), check("factory-review")]}},
        {"type": "non_fast_forward"},
        {"type": "deletion"}
    ])
}

/// Classic protection that asks for everything the policy needs, with the factory's checks pinned.
fn strong_classic(app: u64) -> Protection {
    Protection {
        required_checks: ["factory-validation", "factory-review"]
            .into_iter()
            .map(|context| RequiredCheck {
                context: context.to_owned(),
                app_id: Some(app),
            })
            .collect(),
        ..Protection::satisfying_the_policy(app)
    }
}

fn seed_rules(world: &World, rules: Value) {
    world
        .extras
        .rules
        .lock()
        .unwrap()
        .insert(FIXTURE.to_owned(), rules);
}

async fn verdict(world: &World, required_approvals: u32) -> PreflightVerdict {
    world
        .adapter
        .preflight(
            &intake(),
            &checks(),
            Some(&attestation()),
            required_approvals,
        )
        .await
        .expect("the protection is read")
}

#[tokio::test]
async fn a_branch_protected_only_by_classic_protection_passes() {
    let world = World::new();
    let app = world.fake.app().id;
    world
        .fake
        .protect_branch(FIXTURE, "main", strong_classic(app));
    let report = world
        .adapter
        .issue_source()
        .repository_protection(&intake())
        .await
        .unwrap();
    assert_eq!(report.source, ProtectionSource::ClassicProtection);
    assert!(report.requires_pull_request && report.requires_code_owner_review);
    assert!(report.dismisses_stale_approvals && report.blocks_force_push && report.blocks_deletion);
    assert_eq!(report.required_approving_reviews, Some(1));
    assert_eq!(verdict(&world, 1).await, PreflightVerdict::Pass);
    // Its count is judged as any other: one review is short of a policy that needs two.
    assert_eq!(
        verdict(&world, 2).await,
        PreflightVerdict::CapAtL0(vec![PreflightFailure::ApprovingReviewsBelowPolicy {
            found: 1,
            needed: 2
        }])
    );
}

#[tokio::test]
async fn a_branch_protected_only_by_rulesets_reads_classic_as_absent_and_passes() {
    let world = World::new();
    seed_rules(&world, strong_rules(world.fake.app().id));
    let report = world
        .adapter
        .issue_source()
        .repository_protection(&intake())
        .await
        .unwrap();
    assert_eq!(report.source, ProtectionSource::Rulesets);
    assert_eq!(verdict(&world, 1).await, PreflightVerdict::Pass);
    // The classic read was made, and its 404 meant "not protected", not an error.
    let reads = world.fake.requests_to(PROTECTION_ROUTE);
    assert!(!reads.is_empty());
    assert!(reads.iter().all(|read| read.status == 404));
}

#[tokio::test]
async fn with_both_kinds_the_stricter_setting_of_each_is_judged() {
    let world = World::new();
    let app = world.fake.app().id;
    // The rules leave force pushes open and pin no check; classic protection blocks force pushes,
    // pins the checks and asks for two reviews. Neither alone passes; together they do.
    seed_rules(
        &world,
        json!([
            {"type": "pull_request", "parameters": {"dismiss_stale_reviews_on_push": true, "require_code_owner_review": true, "required_approving_review_count": 1}},
            {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "factory-validation"}]}},
            {"type": "deletion"}
        ]),
    );
    let mut classic = strong_classic(app);
    classic.required_approvals = 2;
    classic.require_pull_request = false;
    classic.allow_deletions = true;
    world.fake.protect_branch(FIXTURE, "main", classic);
    let report = world
        .adapter
        .issue_source()
        .repository_protection(&intake())
        .await
        .unwrap();
    assert_eq!(
        report.source,
        ProtectionSource::RulesetsAndClassicProtection
    );
    assert!(report.blocks_force_push, "classic protection blocks it");
    assert!(report.blocks_deletion, "the rules block it");
    // Classic protection here requires no pull request, so its count does not apply: the rules'
    // count is the one known.
    assert_eq!(report.required_approving_reviews, Some(1));
    assert_eq!(verdict(&world, 1).await, PreflightVerdict::Pass);

    // When classic protection requires a pull request too, the larger count wins.
    let mut classic = strong_classic(app);
    classic.required_approvals = 2;
    world.fake.protect_branch(FIXTURE, "main", classic);
    let report = world
        .adapter
        .issue_source()
        .repository_protection(&intake())
        .await
        .unwrap();
    assert_eq!(report.required_approving_reviews, Some(2));
    assert_eq!(verdict(&world, 2).await, PreflightVerdict::Pass);
}

#[tokio::test]
async fn a_branch_with_neither_kind_is_capped_with_the_named_reason() {
    let world = World::new();
    let report = world
        .adapter
        .issue_source()
        .repository_protection(&intake())
        .await
        .unwrap();
    assert_eq!(report.source, ProtectionSource::NoRulesetRules);
    match verdict(&world, 1).await {
        PreflightVerdict::CapAtL0(reasons) => {
            assert_eq!(reasons.first(), Some(&PreflightFailure::NoRulesetRules));
            assert!(reasons.contains(&PreflightFailure::PullRequestNotRequired));
        }
        PreflightVerdict::Pass => panic!("an unprotected branch passed"),
    }
}

#[tokio::test]
async fn a_403_on_classic_protection_is_forbidden_and_never_unprotected() {
    // The rules alone would pass. A refused classic read still fails the read: the App lacks a
    // permission the policy requires, and a repository is not judged on half its protection.
    let world = World::with(Options {
        wrap: Some(Box::new(|inner| {
            Overrides::new(
                inner,
                vec![(
                    Method::Get,
                    "/branches/main/protection",
                    answer(
                        403,
                        &[],
                        &json!({"message": "Resource not accessible by integration"}),
                    ),
                )],
            )
        })),
        ..Options::default()
    });
    seed_rules(&world, strong_rules(world.fake.app().id));
    assert_eq!(
        world
            .adapter
            .issue_source()
            .repository_protection(&intake())
            .await
            .err(),
        Some(GitHostError::Forbidden)
    );
}

#[tokio::test]
async fn an_app_without_administration_read_gets_no_protection_token_and_no_report() {
    // The code host refuses to mint a token with a permission the App does not hold (422), which
    // the adapter reports as `Forbidden`. The App audit caps such an App at L0 as well.
    let world = World::with(Options {
        app: Some(AppConfig::factory_default().without_permission("administration")),
        ..Options::default()
    });
    seed_rules(&world, strong_rules(world.fake.app().id));
    assert_eq!(
        world
            .adapter
            .issue_source()
            .repository_protection(&intake())
            .await
            .err(),
        Some(GitHostError::Forbidden)
    );
    assert_eq!(world.fake.count(PROTECTION_ROUTE), 0);
}

#[tokio::test]
async fn only_the_protection_read_token_holds_administration_and_it_reads_nothing_else() {
    let world = World::new();
    let app = world.fake.app().id;
    seed_rules(&world, strong_rules(app));
    world
        .fake
        .protect_branch(FIXTURE, "main", strong_classic(app));
    assert_eq!(verdict(&world, 1).await, PreflightVerdict::Pass);
    let mints = world.fake.mints();
    let readers: Vec<u64> = mints
        .iter()
        .filter(|mint| {
            mint.requested_permissions
                .as_ref()
                .is_some_and(|asked| asked.contains_key("administration"))
        })
        .map(|mint| mint.token_id)
        .collect();
    assert_eq!(readers.len(), 1, "one protection read token");
    for mint in &mints {
        let asked = mint.requested_permissions.clone().unwrap_or_default();
        if readers.contains(&mint.token_id) {
            // Exactly the class: administration read and metadata read, one repository.
            assert_eq!(
                asked.into_iter().collect::<Vec<_>>(),
                [
                    ("administration".to_owned(), "read".to_owned()),
                    ("metadata".to_owned(), "read".to_owned())
                ]
            );
            assert_eq!(mint.granted_repositories, [FIXTURE.to_owned()]);
        } else {
            assert!(!asked.contains_key("administration"), "{asked:?}");
        }
    }
    // The reader was used on the protection route and nowhere else, and nothing else used it.
    for request in world.fake.requests() {
        if let AuthSummary::InstallationToken { token_id } = request.auth {
            assert_eq!(
                readers.contains(&token_id),
                request.route == PROTECTION_ROUTE,
                "{} with token {token_id}",
                request.route
            );
        }
    }
}
