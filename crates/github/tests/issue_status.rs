//! The status writer of the GitHub adapter (ports v1.2, ADR 0017): the shared contract suite, the
//! credential, the namespace rule at the adapter, removal of a label that is not there, the
//! comment that is edited and never duplicated (also after a retry and when two writers race),
//! pacing and the rate limit.
//!
//! **Everything here runs against the fake GitHub server of the test kit (FX-GH) over the loopback
//! interface. None of it ran against the real GitHub**, whose answers to these routes are not
//! verified (see the module notes of `crates/github/src/status.rs`).

mod common;

use std::time::Duration;

use common::harness::{FIXTURE, Options, World};
use common::subjects::IssueStatusWorld;
use common::transports::LosesAnswers;
use factory_domain::ids::JobId;
use factory_domain::policy::issue_workflow::StatusLabel;
use factory_domain::state::JobStatus;
use factory_domain::values::{AggregateVersion, Timestamp};
use factory_github::{MUTATION_PAUSE, Method, PageLimits};
use factory_ports::githost::{ChangeHost, GitHostError, IssueRef, Rejection};
use factory_ports::issue_status::{
    CommentWrite, IssueStatusWriter, StatusComment, StatusScope, StatusStamp,
};
use factory_ports::paths::RepoRef;
use factory_testkit::contracts::githost::scope;
use factory_testkit::contracts::issue_status;
use factory_testkit::issue_status::status_labels;

const LABEL_ADD: &str = "POST /repos/{owner}/{repo}/issues/{number}/labels";
const LABEL_REMOVE: &str = "DELETE /repos/{owner}/{repo}/issues/{number}/labels/{name}";
const COMMENT_PATCH: &str = "PATCH /repos/{owner}/{repo}/issues/comments/{id}";

fn status_scope(session: u128) -> StatusScope {
    let base = scope(1, 1);
    StatusScope {
        tenant: base.tenant,
        session: JobId::from_uuid(factory_ports::clock::Uuid::from_u128(
            (900 + session) << 80 | (0x7_u128 << 76) | (0b10_u128 << 62),
        )),
        repo: base.repo,
    }
}

fn issue(number: u64) -> IssueRef {
    IssueRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    }
}

fn label(state: JobStatus) -> StatusLabel {
    status_labels().label_for(state).clone()
}

fn comment(version: i64, words: &str) -> StatusComment {
    StatusComment::new(
        StatusStamp {
            started: Timestamp::parse("2026-11-02T09:00:00Z").unwrap(),
            version: AggregateVersion::new(version).unwrap(),
            job: JobId::from_uuid(factory_ports::clock::Uuid::from_u128(1)),
        },
        words.to_owned(),
    )
    .unwrap()
}

fn seeded(world: &World, labels: &[&str]) -> u64 {
    world
        .fake
        .add_issue(FIXTURE, "A request", "Text.", "octocat", labels)
}

fn app_comments(world: &World, number: u64) -> Vec<String> {
    let bot = world.fake.app().bot_login();
    world
        .fake
        .comments_by_author(FIXTURE, number)
        .into_iter()
        .filter(|(author, _)| *author == bot)
        .map(|(_, body)| body)
        .collect()
}

// ---- the shared contract suite ---------------------------------------------------------------

#[tokio::test]
async fn the_github_status_writer_passes_the_whole_status_writer_contract() {
    let report = issue_status::run_issue_status(|| async { IssueStatusWorld::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(
        report.passed.len(),
        issue_status::issue_status_checks().len()
    );
}

// ---- the credential --------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_stat_02_the_token_request_is_exactly_issues_write_for_one_repository() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("sets the label");
    writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(1, "Working."))
        .await
        .expect("writes the comment");
    let mints = world.fake.mints();
    assert_eq!(mints.len(), 1, "one token serves both calls: {mints:?}");
    let asked = mints[0].requested_permissions.clone().expect("narrowed");
    let asked: Vec<(&str, &str)> = asked
        .iter()
        .map(|(n, l)| (n.as_str(), l.as_str()))
        .collect();
    assert_eq!(asked, vec![("issues", "write"), ("metadata", "read")]);
    assert_eq!(
        mints[0].requested_repositories.clone(),
        Some(vec!["fixture".to_owned()]),
        "one repository"
    );
    assert_eq!(mints[0].granted_repositories, vec![FIXTURE.to_owned()]);
}

#[tokio::test]
async fn negative_nt_stat_02_a_stage_token_is_not_widened_and_the_status_token_is_not_a_stage_token()
 {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let source = world.adapter.issue_source();
    let number = seeded(&world, &["factory"]);
    // An intake stage reads the issue with its own token: issues read.
    let intake = scope(1, 1);
    let mut intake = intake;
    intake.stage = factory_domain::vocabulary::StageKind::Intake;
    use factory_ports::githost::IssueSource as _;
    source
        .fetch_issue(&intake, &issue(number))
        .await
        .expect("intake reads");
    writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("sets the label");
    let mut sets: Vec<Vec<(String, String)>> = world
        .fake
        .mints()
        .into_iter()
        .map(|m| {
            m.requested_permissions
                .unwrap_or_default()
                .into_iter()
                .collect()
        })
        .collect();
    sets.sort();
    let read = |names: &[(&str, &str)]| -> Vec<(String, String)> {
        names
            .iter()
            .map(|(n, l)| ((*n).to_owned(), (*l).to_owned()))
            .collect()
    };
    assert_eq!(
        sets,
        vec![
            read(&[("issues", "read"), ("metadata", "read")]),
            read(&[("issues", "write"), ("metadata", "read")]),
        ],
        "the intake token stays at issues read (and nothing else, LB-03), and the status token is a separate token"
    );
}

#[tokio::test]
async fn negative_nt_stat_02_an_app_without_issues_write_gets_no_status_token_and_nothing_is_written()
 {
    let app =
        factory_testkit::fx::github::AppConfig::factory_default().without_permission("issues");
    let world = World::with(Options {
        app: Some(app),
        ..Options::default()
    });
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    let result = writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await;
    assert_eq!(result, Err(GitHostError::Forbidden));
    assert!(world.fake.labels_of(FIXTURE, number).is_empty());
}

#[tokio::test]
async fn after_a_session_is_revoked_its_calls_are_refused() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    let session = status_scope(2);
    writer
        .set_status_label(&session, &issue(number), &label(JobStatus::Active))
        .await
        .expect("works while the session lives");
    world
        .adapter
        .change_host()
        .revoke_job_tokens(session.session)
        .await
        .expect("revokes");
    assert_eq!(
        writer
            .set_status_label(&session, &issue(number), &label(JobStatus::Completed))
            .await,
        Err(GitHostError::Unauthorized)
    );
    // A fresh session works again: the caller uses a new identifier for each round.
    writer
        .set_status_label(
            &status_scope(3),
            &issue(number),
            &label(JobStatus::Completed),
        )
        .await
        .expect("a fresh session");
}

// ---- the namespace rule at the adapter -------------------------------------------------------

#[tokio::test]
async fn negative_nt_stat_01_a_label_outside_the_namespace_is_refused_before_any_request_is_made() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &["factory", "design: approved"]);
    for wrong in [
        "factory",
        "design: approved",
        "design: in review",
        "bug",
        "",
    ] {
        let result = writer
            .set_status_label(
                &status_scope(1),
                &issue(number),
                &StatusLabel::forged_for_negative_tests(wrong),
            )
            .await;
        assert_eq!(
            result,
            Err(GitHostError::Rejected(Rejection::LabelNotAllowed)),
            "{wrong:?}"
        );
    }
    assert!(
        world.fake.requests().is_empty(),
        "no token was asked for and nothing was sent: {:?}",
        world.fake.requests()
    );
    assert_eq!(
        world.fake.labels_of(FIXTURE, number),
        vec!["factory".to_owned(), "design: approved".to_owned()]
    );
    // The sibling: a real status label does reach the server.
    writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("a real label works");
    assert!(world.fake.count(LABEL_ADD) == 1);
}

#[tokio::test]
async fn negative_nt_stat_01_only_labels_in_the_factory_namespace_are_taken_off() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    // A person adds a look-alike in capitals and another label with the word factory in it.
    let number = seeded(
        &world,
        &[
            "factory",
            "factory-bot",
            "design: approved",
            "FACTORY: Queued",
            "factory: queued",
            "needs factory: review",
        ],
    );
    writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("sets");
    let mut left = world.fake.labels_of(FIXTURE, number);
    left.sort();
    assert_eq!(
        left,
        vec![
            "design: approved".to_owned(),
            "factory".to_owned(),
            "factory-bot".to_owned(),
            "factory: working".to_owned(),
            "needs factory: review".to_owned(),
        ],
        "both spellings of the old status are gone and nothing else is touched"
    );
}

#[tokio::test]
async fn a_label_name_is_percent_encoded_in_the_path() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &["factory: waiting for a person"]);
    writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("sets");
    let removals = world.fake.requests_to(LABEL_REMOVE);
    assert_eq!(removals.len(), 1);
    assert!(
        removals[0]
            .path
            .ends_with("/labels/factory%3A%20waiting%20for%20a%20person"),
        "{}",
        removals[0].path
    );
}

// ---- a label that is not there ---------------------------------------------------------------

#[tokio::test]
async fn negative_nt_stat_01_taking_off_a_label_that_is_already_gone_is_not_an_error() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &["factory: queued"]);
    // Somebody takes it off between the listing and the removal: the host answers 404.
    world
        .fake
        .fail_next(LABEL_REMOVE, 404, "Label does not exist");
    let outcome = writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("a 404 on removal is fine");
    assert!(outcome.added);
    assert_eq!(outcome.removed, 0, "nothing of ours was taken off");
}

#[tokio::test]
async fn a_refusal_on_removal_is_still_an_error() {
    // The control for the test above: the same place, a different answer.
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &["factory: queued"]);
    world
        .fake
        .fail_next(LABEL_REMOVE, 403, "Resource not accessible by integration");
    let result = writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await;
    assert_eq!(result, Err(GitHostError::Forbidden));
}

#[tokio::test]
async fn a_failed_removal_is_finished_by_the_next_call() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &["factory: queued"]);
    world.fake.fail_next(LABEL_REMOVE, 500, "Server error");
    assert_eq!(
        writer
            .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
            .await,
        Err(GitHostError::Unavailable)
    );
    // The new label was added first, so the issue was never without a status.
    let mut now = world.fake.labels_of(FIXTURE, number);
    now.sort();
    assert_eq!(
        now,
        vec!["factory: queued".to_owned(), "factory: working".to_owned()]
    );
    let outcome = writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("the retry");
    assert!(!outcome.added);
    assert_eq!(outcome.removed, 1);
    assert_eq!(
        world.fake.labels_of(FIXTURE, number),
        vec!["factory: working".to_owned()]
    );
}

// ---- the comment: edited, never duplicated ---------------------------------------------------

#[tokio::test]
async fn negative_nt_stat_03_the_comment_is_edited_not_duplicated_even_when_the_answer_to_the_first_post_is_lost()
 {
    let world = World::with(Options {
        wrap: Some(Box::new(|inner| {
            LosesAnswers::once(inner, Method::Post, "/comments")
        })),
        ..Options::default()
    });
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    // The first post reaches GitHub and has its effect, and the caller sees a dropped connection.
    let first = writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(1, "Queued."))
        .await;
    assert_eq!(first, Err(GitHostError::Unavailable));
    assert_eq!(app_comments(&world, number).len(), 1, "the effect happened");
    // The retry finds the comment by its marker and edits it.
    let retry = writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(1, "Queued."))
        .await
        .expect("the retry");
    assert!(
        matches!(retry, CommentWrite::Unchanged(_)),
        "the same stamp and text: {retry:?}"
    );
    let next = writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(2, "Working."))
        .await
        .expect("the next state");
    assert!(matches!(next, CommentWrite::Updated(_)), "{next:?}");
    let comments = app_comments(&world, number);
    assert_eq!(comments.len(), 1, "one comment: {comments:?}");
    assert!(comments[0].contains("Working."));
}

#[tokio::test]
async fn a_failed_edit_leaves_the_old_comment_and_the_retry_edits_it() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(1, "Queued."))
        .await
        .expect("made");
    world.fake.fail_next(COMMENT_PATCH, 500, "Server error");
    assert_eq!(
        writer
            .upsert_status_comment(&status_scope(1), &issue(number), &comment(2, "Working."))
            .await,
        Err(GitHostError::Unavailable)
    );
    assert!(app_comments(&world, number)[0].contains("Queued."));
    writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(2, "Working."))
        .await
        .expect("the retry");
    let comments = app_comments(&world, number);
    assert_eq!(comments.len(), 1);
    assert!(comments[0].contains("Working."));
}

#[tokio::test]
async fn negative_nt_stat_03_two_updates_that_race_leave_one_comment_with_the_newest_version() {
    for round in 0..8 {
        let world = World::new();
        let writer = world.adapter.issue_status_writer();
        let number = seeded(&world, &[]);
        let older = comment(3, "Older news.");
        let newer = comment(4, "Newer news.");
        let (a, b) = if round % 2 == 0 {
            (older.clone(), newer.clone())
        } else {
            (newer.clone(), older.clone())
        };
        let (scope_a, scope_b, target) = (status_scope(1), status_scope(1), issue(number));
        let (x, y) = tokio::join!(
            writer.upsert_status_comment(&scope_a, &target, &a),
            writer.upsert_status_comment(&scope_b, &target, &b),
        );
        // A writer may be told to try again (the comment it meant to edit was deleted by the
        // other), and one try more settles it.
        for outcome in [x, y] {
            if let Err(error) = outcome {
                assert_eq!(error, GitHostError::Conflict, "round {round}");
            }
        }
        writer
            .upsert_status_comment(&status_scope(1), &issue(number), &newer)
            .await
            .expect("the settling call");
        let comments = app_comments(&world, number);
        assert_eq!(comments.len(), 1, "round {round}: {comments:?}");
        assert!(comments[0].contains("Newer news."), "round {round}");
    }
}

/// A listing cut short by the page cap, made here by a cap of no page at all: the fake server has
/// no second page to follow.
fn capped_world() -> World {
    World::with(Options {
        configure: Some(Box::new(|config| {
            config.pages = PageLimits {
                per_page: 100,
                max_pages: 0,
                event_pages: 0,
            };
        })),
        ..Options::default()
    })
}

#[tokio::test]
async fn negative_nt_stat_03_a_comment_listing_cut_short_is_not_read_as_no_comment() {
    let world = capped_world();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    let result = writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(1, "Queued."))
        .await;
    assert_eq!(result, Err(GitHostError::Unavailable));
    assert!(
        world
            .fake
            .requests_to("POST /repos/{owner}/{repo}/issues/{number}/comments")
            .is_empty(),
        "no comment was made on the strength of a listing that was not read"
    );
    // The control: with the usual cap the same call makes the comment.
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(1, "Queued."))
        .await
        .expect("made");
    assert_eq!(app_comments(&world, number).len(), 1);
}

#[tokio::test]
async fn a_label_listing_cut_short_changes_nothing() {
    let world = capped_world();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &["factory: queued"]);
    let result = writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await;
    assert_eq!(result, Err(GitHostError::Unavailable));
    assert_eq!(
        world.fake.labels_of(FIXTURE, number),
        vec!["factory: queued".to_owned()]
    );
}

#[tokio::test]
async fn negative_nt_stat_06_text_is_cleaned_before_it_is_written() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    writer
        .upsert_status_comment(
            &status_scope(1),
            &issue(number),
            &comment(
                1,
                "See ![chart](https://evil.example/a.png?d=1) and ask @maintainer <b>now</b>.",
            ),
        )
        .await
        .expect("writes");
    let body = &app_comments(&world, number)[0];
    assert!(!body.contains("!["), "no image: {body}");
    assert!(!body.contains("evil.example"), "no foreign link: {body}");
    assert!(!body.contains("<b>"), "no raw html: {body}");
    assert!(body.contains("`@maintainer`"), "a mention is inert: {body}");
    assert!(
        body.trim_end().ends_with("-->") && StatusStamp::from_text(body).is_some(),
        "the marker is added after the cleaning: {body}"
    );
}

// ---- pacing and the rate limit ---------------------------------------------------------------

#[tokio::test]
async fn negative_nt_stat_04_requests_that_change_something_are_a_second_apart_and_the_first_waits_for_nobody()
 {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &["factory: queued"]);
    // One create: one change. Nothing to wait for.
    writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(1, "Queued."))
        .await
        .expect("made");
    assert!(
        world.sleeper.waits().is_empty(),
        "{:?}",
        world.sleeper.waits()
    );
    // A label call adds one and takes one off: two changes after the first one, so two waits.
    writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("sets");
    let waits = world.sleeper.waits();
    assert_eq!(waits, vec![MUTATION_PAUSE, MUTATION_PAUSE]);
}

#[tokio::test]
async fn negative_nt_stat_04_a_short_rate_limit_is_waited_out_and_a_long_one_is_reported() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    world.fake.rate_limit_next(LABEL_ADD, 2);
    writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await
        .expect("retried after the wait");
    assert!(world.sleeper.waits().contains(&Duration::from_secs(2)));
    world.fake.clear_faults();
    for _ in 0..4 {
        world.fake.rate_limit_next(LABEL_ADD, 3600);
    }
    let blocked = writer
        .set_status_label(
            &status_scope(1),
            &issue(number),
            &label(JobStatus::Completed),
        )
        .await;
    assert!(
        matches!(blocked, Err(GitHostError::RateLimited { retry_after: Some(wait) }) if wait >= Duration::from_secs(3600)),
        "{blocked:?}"
    );
}

#[tokio::test]
async fn a_failing_host_is_reported_and_leaves_the_issue_as_it_was() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &["factory: queued"]);
    world.fake.fail_always("*", 500, "Server error");
    let result = writer
        .set_status_label(&status_scope(1), &issue(number), &label(JobStatus::Active))
        .await;
    assert!(result.is_err());
    let result = writer
        .upsert_status_comment(&status_scope(1), &issue(number), &comment(1, "Queued."))
        .await;
    assert!(result.is_err());
    assert_eq!(
        world.fake.labels_of(FIXTURE, number),
        vec!["factory: queued".to_owned()]
    );
    assert!(app_comments(&world, number).is_empty());
}

#[tokio::test]
async fn a_tenant_that_is_not_bound_to_the_repository_reaches_nothing() {
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    let mut stranger = status_scope(1);
    stranger.tenant = scope(2, 1).tenant;
    assert_eq!(
        writer
            .set_status_label(&stranger, &issue(number), &label(JobStatus::Active))
            .await,
        Err(GitHostError::NotFound)
    );
    assert!(world.fake.labels_of(FIXTURE, number).is_empty());
}

#[tokio::test]
async fn an_issue_named_in_other_letters_is_the_same_repository_and_another_repository_is_not() {
    // GitHub names are not case sensitive (finding STS-8). The scope names the repository as it
    // was registered and the issue as the request spelled it.
    let world = World::new();
    let writer = world.adapter.issue_status_writer();
    let number = seeded(&world, &[]);
    let shouted = IssueRef {
        repo: RepoRef::parse(&FIXTURE.to_uppercase()).unwrap(),
        number,
    };
    assert_ne!(
        shouted.repo,
        RepoRef::parse(FIXTURE).unwrap(),
        "the spelling differs"
    );
    writer
        .set_status_label(&status_scope(1), &shouted, &label(JobStatus::Active))
        .await
        .expect("the same repository in capitals");
    assert_eq!(
        world.fake.labels_of(FIXTURE, number),
        vec!["factory: working".to_owned()]
    );
    // The control: a repository that is not the scope's is still refused, whatever its case.
    let other = IssueRef {
        repo: RepoRef::parse("someone-else/other-repo").unwrap(),
        number,
    };
    assert_eq!(
        writer
            .set_status_label(&status_scope(2), &other, &label(JobStatus::Completed))
            .await,
        Err(GitHostError::NotFound)
    );
}

#[tokio::test]
async fn the_writer_reports_that_it_is_real_and_the_fake_world_is_the_fake_server() {
    let world = World::new();
    assert_eq!(
        world.adapter.issue_status_writer().fidelity(),
        factory_domain::vocabulary::Fidelity::Real,
        "the adapter is the real adapter; the server it talks to in these tests is FX-GH"
    );
}
