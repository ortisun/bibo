//! The replies the factory posts on one issue are capped and found again in one bounded page
//! (DG-9, parts a and b). Real: the GitHub App adapter. Fake, and labelled: the GitHub server
//! (FX-GH of the test kit), which now pages the comments of an issue and honours `since`.
//!
//! Each check has a sibling that shows it can fail, and the breaks of the adapter are in
//! `tests/mutations/comment_cap_breaks.py`.

mod common;

use std::time::Duration;

use common::harness::{FIXTURE, World};
use factory_domain::vocabulary::StageKind;
use factory_ports::githost::{
    CappedPost, ChangeHost, CommentCap, CommentTarget, GitHostError, GitScope, IssueRef, Rejection,
};
use factory_ports::paths::RepoRef;
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::canary::{CanaryKind, CanarySet};

const DAY: Duration = Duration::from_secs(24 * 3600);

fn approval(job: u128) -> GitScope {
    GitScope {
        stage: StageKind::Approval,
        ..scope(1, job)
    }
}

fn cap(max: u32) -> CommentCap {
    CommentCap::new("intake-design", max, DAY).expect("a cap")
}

fn issue(world: &World) -> (IssueRef, CommentTarget) {
    let number = world.fake.add_issue(
        FIXTURE,
        "Add word count",
        "Please.",
        "octocat",
        &["factory"],
    );
    let issue = IssueRef {
        repo: RepoRef::parse(FIXTURE).unwrap(),
        number,
    };
    let target = CommentTarget::Issue(issue.clone());
    (issue, target)
}

async fn post(world: &World, target: &CommentTarget, key: &str, cap: &CommentCap) -> CappedPost {
    world
        .adapter
        .change_host()
        .post_capped_comment(
            &approval(1),
            target,
            "The design is not approved.",
            key,
            cap,
        )
        .await
        .unwrap_or_else(|error| panic!("{key}: {error:?}"))
}

#[tokio::test]
async fn a_reply_is_posted_once_for_a_key_and_found_again_without_posting() {
    let world = World::new();
    let (issue, target) = issue(&world);
    let first = post(&world, &target, "intake-design-gate-1", &cap(5)).await;
    assert!(matches!(first, CappedPost::Posted(_)), "{first:?}");
    let second = post(&world, &target, "intake-design-gate-1", &cap(5)).await;
    assert!(matches!(second, CappedPost::AlreadyThere(_)), "{second:?}");
    assert_eq!(world.fake.comments(FIXTURE, issue.number).len(), 1);
}

#[tokio::test]
async fn the_sixth_reply_in_a_day_is_not_posted_and_the_answer_says_why() {
    let world = World::new();
    let (issue, target) = issue(&world);
    for n in 1..=5 {
        let done = post(&world, &target, &format!("intake-design-gate-{n}"), &cap(5)).await;
        assert!(matches!(done, CappedPost::Posted(_)), "{n}: {done:?}");
    }
    assert_eq!(
        post(&world, &target, "intake-design-gate-6", &cap(5)).await,
        CappedPost::CapReached
    );
    assert_eq!(world.fake.comments(FIXTURE, issue.number).len(), 5);
    // A key that was answered is still found when the cap is reached: nothing new is posted for it
    // and the caller learns the comment is there.
    let again = post(&world, &target, "intake-design-gate-3", &cap(5)).await;
    assert!(matches!(again, CappedPost::AlreadyThere(_)), "{again:?}");
    // The sibling: with a larger cap the same sixth reply is posted.
    let sixth = post(&world, &target, "intake-design-gate-6", &cap(6)).await;
    assert!(matches!(sixth, CappedPost::Posted(_)), "{sixth:?}");
}

#[tokio::test]
async fn the_cap_is_for_one_issue_and_other_issues_have_their_own() {
    let world = World::new();
    let (first, first_target) = issue(&world);
    let (second, second_target) = issue(&world);
    assert_ne!(first.number, second.number);
    for n in 1..=2 {
        post(&world, &first_target, &format!("k-{n}"), &cap(2)).await;
    }
    assert_eq!(
        post(&world, &first_target, "k-3", &cap(2)).await,
        CappedPost::CapReached
    );
    let other = post(&world, &second_target, "k-3", &cap(2)).await;
    assert!(matches!(other, CappedPost::Posted(_)), "{other:?}");
}

#[tokio::test]
async fn replies_older_than_the_window_do_not_count() {
    let world = World::new();
    let (_issue, target) = issue(&world);
    for n in 1..=2 {
        post(&world, &target, &format!("k-{n}"), &cap(2)).await;
    }
    assert_eq!(
        post(&world, &target, "k-3", &cap(2)).await,
        CappedPost::CapReached
    );
    // A day and an hour later the window has passed them by.
    world.clock.advance(DAY + Duration::from_secs(3600));
    let later = post(&world, &target, "k-3", &cap(2)).await;
    assert!(matches!(later, CappedPost::Posted(_)), "{later:?}");
}

#[tokio::test]
async fn only_the_apps_own_comments_count_and_a_pasted_marker_stops_nothing() {
    let world = World::new();
    let (issue, target) = issue(&world);
    // A person pastes what a reply of the factory carries. Take it from a real one.
    post(&world, &target, "k-1", &cap(2)).await;
    let own = world.fake.comments(FIXTURE, issue.number).remove(0);
    for _ in 0..3 {
        world
            .fake
            .add_comment(FIXTURE, issue.number, "octocat", &own);
    }
    // The three copies are not the factory's: one reply is still allowed, and the key of the copy
    // is not taken for an answer either.
    let second = post(&world, &target, "k-2", &cap(2)).await;
    assert!(matches!(second, CappedPost::Posted(_)), "{second:?}");
    assert_eq!(
        post(&world, &target, "k-3", &cap(2)).await,
        CappedPost::CapReached
    );
}

#[tokio::test]
async fn comments_that_are_not_replies_of_the_family_do_not_count() {
    let world = World::new();
    let (_issue, target) = issue(&world);
    let host = world.adapter.change_host();
    // The factory's own comments of another kind (a plain comment by key) are not replies.
    for n in 1..=3 {
        host.post_comment(&approval(1), &target, "Acknowledged.", &format!("ack-{n}"))
            .await
            .unwrap();
    }
    let reply = post(&world, &target, "k-1", &cap(1)).await;
    assert!(matches!(reply, CappedPost::Posted(_)), "{reply:?}");
    // And the other way: a reply of the family is not an acknowledgement of another family.
    let other = CommentCap::new("another-family", 1, DAY).unwrap();
    let posted = post(&world, &target, "k-2", &other).await;
    assert!(matches!(posted, CappedPost::Posted(_)), "{posted:?}");
}

#[tokio::test]
async fn a_thread_with_more_comments_than_the_look_reads_in_the_window_gets_no_reply() {
    let world = World::new();
    let (issue, target) = issue(&world);
    // People write 350 comments within the day. The adapter reads three pages of 100 (DR-4), so
    // it cannot tell whether it already answered: it posts nothing, and does not read the rest.
    for n in 0..350 {
        world
            .fake
            .add_comment(FIXTURE, issue.number, "octocat", &format!("comment {n}"));
    }
    assert_eq!(
        post(&world, &target, "k-1", &cap(5)).await,
        CappedPost::NotChecked
    );
    assert_eq!(world.fake.comments(FIXTURE, issue.number).len(), 350);
    let listings = world
        .fake
        .requests_to("GET /repos/{owner}/{repo}/issues/{number}/comments");
    assert_eq!(listings.len(), 3, "three pages, no more");
    // The sibling: with a hundred comments or fewer in the window, the reply is posted. The same
    // thread read through a window that excludes the old comments is short enough.
    let (_other, short) = issue_with_comments(&world, 40);
    let done = post(&world, &short, "k-1", &cap(5)).await;
    assert!(matches!(done, CappedPost::Posted(_)), "{done:?}");
}

#[tokio::test]
async fn a_thread_of_up_to_three_pages_is_counted_and_gets_its_reply() {
    // DR-4. One page of 100 was enough for a stranger to silence every reply on an issue. The
    // look is three pages now, so 100 comments of strangers no longer do it, and a thread that
    // fills two pages is still read to the end.
    let world = World::new();
    let (issue, target) = issue(&world);
    for n in 0..230 {
        world
            .fake
            .add_comment(FIXTURE, issue.number, "octocat", &format!("comment {n}"));
    }
    let done = post(&world, &target, "k-1", &cap(5)).await;
    assert!(matches!(done, CappedPost::Posted(_)), "{done:?}");
    let listings = world
        .fake
        .requests_to("GET /repos/{owner}/{repo}/issues/{number}/comments");
    assert_eq!(listings.len(), 3, "the third page is read to see its end");
    // The factory's own comments past the first page are still counted: the cap holds on a long
    // thread, and the same key is still found.
    let again = post(&world, &target, "k-1", &cap(5)).await;
    assert!(matches!(again, CappedPost::AlreadyThere(_)), "{again:?}");
}

#[tokio::test]
async fn each_kind_of_reply_is_counted_apart_and_one_kind_cannot_use_up_another() {
    // DR-4. A requester who is refused many times fills the cap of the refusals and no more: the
    // notice that the factory stopped before the pull request, and the notice about the
    // environment, have a cap and a family of their own.
    let world = World::new();
    let (issue, target) = issue(&world);
    let refusals = CommentCap::new("design-refusal", 3, DAY).unwrap();
    let withdrawals = CommentCap::new("design-withdrawal", 1, DAY).unwrap();
    let environment = CommentCap::new("design-environment", 1, DAY).unwrap();
    for n in 1..=3 {
        let done = post(&world, &target, &format!("refusal-{n}"), &refusals).await;
        assert!(matches!(done, CappedPost::Posted(_)), "{n}: {done:?}");
    }
    assert_eq!(
        post(&world, &target, "refusal-4", &refusals).await,
        CappedPost::CapReached
    );
    let withdrawn = post(&world, &target, "withdrawal-1", &withdrawals).await;
    assert!(matches!(withdrawn, CappedPost::Posted(_)), "{withdrawn:?}");
    let told = post(&world, &target, "environment-1", &environment).await;
    assert!(matches!(told, CappedPost::Posted(_)), "{told:?}");
    // Each kind stops at its own cap.
    assert_eq!(
        post(&world, &target, "withdrawal-2", &withdrawals).await,
        CappedPost::CapReached
    );
    assert_eq!(
        post(&world, &target, "environment-2", &environment).await,
        CappedPost::CapReached
    );
    assert_eq!(world.fake.comments(FIXTURE, issue.number).len(), 5);
}

fn issue_with_comments(world: &World, count: usize) -> (IssueRef, CommentTarget) {
    let (issue, target) = issue(world);
    for n in 0..count {
        world
            .fake
            .add_comment(FIXTURE, issue.number, "octocat", &format!("comment {n}"));
    }
    (issue, target)
}

#[tokio::test]
async fn old_comments_do_not_make_a_thread_too_long() {
    let world = World::new();
    let (issue, target) = issue(&world);
    for n in 0..130 {
        world
            .fake
            .add_comment(FIXTURE, issue.number, "octocat", &format!("comment {n}"));
    }
    // Two days on, none of them is in the window, so the page is empty and the reply goes.
    world.clock.advance(DAY * 2);
    let done = post(&world, &target, "k-1", &cap(5)).await;
    assert!(matches!(done, CappedPost::Posted(_)), "{done:?}");
}

#[tokio::test]
async fn the_listing_is_one_bounded_request_with_the_window_in_it() {
    let world = World::new();
    let (_issue, target) = issue(&world);
    post(&world, &target, "k-1", &cap(5)).await;
    let listings = world
        .fake
        .requests_to("GET /repos/{owner}/{repo}/issues/{number}/comments");
    assert_eq!(listings.len(), 1);
    let query = listings[0].query.clone().unwrap_or_default();
    assert!(query.contains("per_page=100"), "{query}");
    // The window starts a day before the fake's now (2026-10-28T10:00:00Z).
    assert!(query.contains("since=2026-10-27T10:00:00Z"), "{query}");
}

#[tokio::test]
async fn the_reply_is_posted_with_the_right_to_write_issues_and_the_metadata_only() {
    let world = World::new();
    let (_issue, target) = issue(&world);
    post(&world, &target, "k-1", &cap(5)).await;
    let mints = world.fake.mints();
    assert!(!mints.is_empty());
    for minted in &mints {
        assert_eq!(
            minted.requested_permissions,
            Some(
                [("issues", "write"), ("metadata", "read")]
                    .into_iter()
                    .map(|(n, l)| (n.to_owned(), l.to_owned()))
                    .collect()
            ),
            "{minted:?}"
        );
    }
}

#[tokio::test]
async fn text_that_looks_like_a_secret_is_refused_before_any_listing_or_post() {
    let world = World::new();
    let (issue, target) = issue(&world);
    let canaries = CanarySet::generate();
    let secret = format!(
        "Debug output: {} (end)",
        canaries.get(CanaryKind::GithubInstallationToken).value()
    );
    let result = world
        .adapter
        .change_host()
        .post_capped_comment(&approval(1), &target, &secret, "k-1", &cap(5))
        .await;
    assert_eq!(result, Err(GitHostError::UnsafeText));
    assert!(world.fake.comments(FIXTURE, issue.number).is_empty());
}

#[tokio::test]
async fn a_host_that_does_not_count_posts_nothing() {
    // The default of the port is closed: an adapter that has no way to count refuses to post.
    struct NoCounting;
    #[async_trait::async_trait]
    impl ChangeHost for NoCounting {
        fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
            factory_domain::vocabulary::Fidelity::Fake
        }
        async fn fetch_target(
            &self,
            _: &GitScope,
        ) -> Result<factory_ports::workspace::FetchTarget, GitHostError> {
            Err(GitHostError::Unavailable)
        }
        async fn push_target(
            &self,
            _: &GitScope,
            _: &factory_ports::paths::BranchName,
        ) -> Result<factory_ports::workspace::PushTarget, GitHostError> {
            Err(GitHostError::Unavailable)
        }
        async fn resolve_branch(
            &self,
            _: &GitScope,
            _: &factory_ports::paths::BranchName,
        ) -> Result<factory_ports::paths::CommitSha, GitHostError> {
            Err(GitHostError::Unavailable)
        }
        async fn open_draft_pull_request(
            &self,
            _: &GitScope,
            _: factory_ports::githost::DraftPrRequest,
        ) -> Result<factory_ports::githost::PullRequestRef, GitHostError> {
            Err(GitHostError::Unavailable)
        }
        async fn update_pull_request_body(
            &self,
            _: &GitScope,
            _: &factory_ports::githost::PullRequestRef,
            _: &str,
            _: Option<&str>,
        ) -> Result<(), GitHostError> {
            Err(GitHostError::Unavailable)
        }
        async fn post_comment(
            &self,
            _: &GitScope,
            _: &CommentTarget,
            _: &str,
            _: &str,
        ) -> Result<factory_ports::githost::CommentRef, GitHostError> {
            panic!("a capped comment must not fall back to an uncapped one");
        }
        async fn publish_check(
            &self,
            _: &GitScope,
            _: factory_ports::githost::CheckRequest,
        ) -> Result<factory_ports::githost::CheckRef, GitHostError> {
            Err(GitHostError::Unavailable)
        }
        async fn pull_request_state(
            &self,
            _: &GitScope,
            _: &factory_ports::githost::PullRequestRef,
        ) -> Result<factory_ports::githost::PullRequestState, GitHostError> {
            Err(GitHostError::Unavailable)
        }
        async fn revoke_job_tokens(
            &self,
            _: factory_domain::ids::JobId,
        ) -> Result<(), GitHostError> {
            Ok(())
        }
    }
    let world = World::new();
    let (_issue, target) = issue(&world);
    let result = NoCounting
        .post_capped_comment(&approval(1), &target, "Hello.", "k", &cap(5))
        .await;
    assert_eq!(result, Err(GitHostError::Rejected(Rejection::Other)));
}
