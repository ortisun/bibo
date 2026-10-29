//! What the fake change host keeps for the checks of the end-to-end scenarios (findings SF-04,
//! SF-06 and SF-08 of the Slice 1 run): the text of each comment, one installation token for each
//! job, kind of token, repository and permission set, and the requests the real adapter would have
//! sent. The fake is labelled `fake` in everything that reads these records.

use factory_testkit::contracts::githost::{repo, scope};
use factory_testkit::githost::{FakeChangeHost, TokenKind, permissions_asked};

use factory_domain::vocabulary::StageKind;
use factory_ports::githost::{
    ChangeHost, CommentTarget, DraftPrRequest, GitScope, IssueRef, PullRequestRef,
};
use factory_ports::paths::BranchName;

fn issue() -> CommentTarget {
    CommentTarget::Issue(IssueRef {
        repo: repo(),
        number: 7,
    })
}

fn at(stage: StageKind) -> GitScope {
    GitScope {
        stage,
        ..scope(1, 1)
    }
}

#[tokio::test]
async fn the_text_of_a_comment_is_kept_and_a_repeat_adds_none() {
    let host = FakeChangeHost::new();
    let scope = at(StageKind::Approval);
    host.post_comment(&scope, &issue(), "First note.", "key-1")
        .await
        .expect("posted");
    host.post_comment(&scope, &issue(), "Changed words.", "key-1")
        .await
        .expect("a repeat of the key");
    host.post_comment(&scope, &issue(), "Second note.", "key-2")
        .await
        .expect("posted");
    assert_eq!(
        host.comments_on(&issue()),
        vec!["First note.".to_owned(), "Second note.".to_owned()],
        "the first text of a key stays, and the order is the order of posting"
    );
}

#[tokio::test]
async fn a_token_is_minted_for_each_stage_with_one_repository_and_the_permissions_of_the_stage() {
    let host = FakeChangeHost::new();
    host.resolve_branch(
        &at(StageKind::Intake),
        &BranchName::new("main").expect("main"),
    )
    .await
    .expect("a branch");
    let delivery = at(StageKind::Delivery);
    host.open_draft_pull_request(
        &delivery,
        DraftPrRequest {
            head: BranchName::new("factory/job-1").expect("a branch"),
            base: BranchName::new("main").expect("main"),
            title: "Add a command".to_owned(),
            body: "Evidence follows.".to_owned(),
        },
    )
    .await
    .expect("opened");
    host.post_comment(&at(StageKind::Approval), &issue(), "Recorded.", "ack")
        .await
        .expect("posted");
    let tokens = host.minted_tokens();
    let kinds: Vec<(StageKind, TokenKind)> = tokens.iter().map(|t| (t.stage, t.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            (StageKind::Intake, TokenKind::Stage),
            (StageKind::Delivery, TokenKind::Stage),
            (StageKind::Approval, TokenKind::Stage),
        ]
    );
    for token in &tokens {
        assert_eq!(token.repository, repo(), "one repository");
        assert_eq!(
            token.permissions,
            permissions_asked(token.stage, token.kind)
        );
        assert!(token.id.starts_with("fake-token-"), "a label and no value");
    }
    // The reading stage cannot write; the approval stage writes issues only; delivery writes more.
    assert!(
        !tokens[0]
            .permissions
            .iter()
            .any(|(_, level)| *level == "write")
    );
    assert!(tokens[2].permissions.contains(&("issues", "write")));
    assert!(!tokens[2].permissions.contains(&("contents", "write")));
}

#[tokio::test]
async fn a_second_call_with_the_same_permissions_mints_no_second_token_and_a_revoke_ends_them() {
    let host = FakeChangeHost::new();
    let scope = at(StageKind::Approval);
    host.post_comment(&scope, &issue(), "One.", "a")
        .await
        .expect("posted");
    host.post_comment(&scope, &issue(), "Two.", "b")
        .await
        .expect("posted");
    assert_eq!(host.minted_tokens().len(), 1);
    host.revoke_job_tokens(scope.job).await.expect("revoked");
    assert!(host.minted_tokens().iter().all(|token| token.revoked));
}

#[tokio::test]
async fn the_requests_that_a_comment_and_a_pull_request_stand_for_are_recorded_and_none_merges() {
    let host = FakeChangeHost::new();
    let delivery = at(StageKind::Delivery);
    let pr = host
        .open_draft_pull_request(
            &delivery,
            DraftPrRequest {
                head: BranchName::new("factory/job-1").expect("a branch"),
                base: BranchName::new("main").expect("main"),
                title: "Add a command".to_owned(),
                body: "Evidence follows.".to_owned(),
            },
        )
        .await
        .expect("opened");
    host.post_comment(
        &delivery,
        &CommentTarget::PullRequest(pr.clone()),
        "Hi.",
        "k",
    )
    .await
    .expect("posted");
    let requests = host.recorded_requests();
    let line = |r: &factory_testkit::githost::RecordedRequest| format!("{} {}", r.method, r.path);
    let lines: Vec<String> = requests.iter().map(line).collect();
    assert!(
        lines.contains(&"POST /repos/example-org/fixture/pulls".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&format!(
            "POST /repos/example-org/fixture/issues/{}/comments",
            pr.number
        )),
        "{lines:?}"
    );
    assert!(lines.iter().all(|l| !l.contains("merge")), "{lines:?}");
    let _: &PullRequestRef = &pr;
}
