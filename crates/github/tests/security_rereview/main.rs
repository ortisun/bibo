//! Independent re-review of the text sent to GitHub (AUT-6, AUT-7), the check conclusions (AUT-8)
//! and the labelled-issue checks (AUT-11). 2026-10-29.
//!
//! Tests named `rr_` show a confirmed defect and are `#[ignore]`d, so the normal run stays green.
//! Tests named `held_` pin an attack that was tried and did not work; they run normally.
//! Everything runs against the testkit's fake GitHub on the loopback interface. Nothing here was run
//! against the real GitHub, and where a finding depends on how GitHub renders text it is said in the
//! message of the test.
//!
//! One defect:  `cargo test -p factory-github --test security_rereview --locked -- --ignored <name> --exact`
//! All defects: `cargo test -p factory-github --test security_rereview --locked -- --ignored rr_`
//! All probes:  `cargo test -p factory-github --test security_rereview --locked held_`

#[path = "../common/mod.rs"]
mod common;

use common::harness::{FIXTURE, World};
use common::spans::assert_no_live_mention;
use factory_domain::vocabulary::StageKind;
use factory_ports::githost::{ChangeHost, DraftPrRequest, GitScope};
use factory_ports::paths::BranchName;
use factory_testkit::contracts::githost::scope;

fn delivery() -> GitScope {
    GitScope {
        stage: StageKind::Delivery,
        ..scope(1, 1)
    }
}

fn draft(body: &str) -> DraftPrRequest {
    DraftPrRequest {
        head: BranchName::new("factory/job-1").unwrap(),
        base: BranchName::new("main").unwrap(),
        title: "Add a word count command".to_owned(),
        body: body.to_owned(),
    }
}

/// What the code host holds as the body of the pull request after the adapter cleaned `body`, or
/// `None` when the adapter refused the text (nothing is sent then).
async fn try_stored_body(body: &str) -> Option<String> {
    let world = World::new();
    let host = world.adapter.change_host();
    let pr = host
        .open_draft_pull_request(&delivery(), draft(body))
        .await
        .ok()?;
    Some(
        world.fake.pull_json(FIXTURE, pr.number).unwrap()["body"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

/// The same, for a body the test expects the adapter to send.
async fn stored_body(body: &str) -> String {
    try_stored_body(body)
        .await
        .unwrap_or_else(|| panic!("the body was refused: {body:?}"))
}

/// Each vector is a body; `leak` says what must not survive in the stored text. Returns the vectors
/// that still hold it, with the stored text. A body the adapter refuses holds nothing.
async fn survivors(vectors: &[(&str, String)], leak: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (name, body) in vectors {
        if let Some(stored) = try_stored_body(body).await
            && stored.contains(leak)
        {
            found.push(format!("{name}: {stored:?}"));
        }
    }
    found
}

/// Control: the shapes that the fix names and several more of the same family are cleaned.
#[tokio::test]
async fn held_images_and_foreign_links_in_every_shape_that_was_tried_are_cleaned() {
    let host = "attacker.test";
    // The credentials-in-a-URL shape is joined from pieces, so that no line of this file is itself
    // a URL with a password (the repository's secret scan would flag it).
    let (sep, colon, at) = ("://", ":", "@");
    let vectors = vec![
        (
            "a link inside a link label",
            format!("[a [b](https://{host}/x) c](https://github.com/o/r)"),
        ),
        (
            "a shortcut image reference with an angle bracket destination",
            format!("![ref]\n\n[ref]: <//{host}/p.png> \"t\""),
        ),
        ("an angle autolink", format!("<https://{host}/x>")),
        ("a www autolink", format!("see www.{host}/x now")),
        (
            "an image in a table cell",
            format!("| a |\n|---|\n| ![](//{host}/x.png) |"),
        ),
        (
            "a linked image with a reference in a list item",
            format!("[![alt][r]](https://github.com/o/r)\n\n- [r]: //{host}/b.png"),
        ),
        (
            "a destination in angle brackets with a space",
            format!("[x](<https://{host}/a b>)"),
        ),
        (
            "user information that puts a host first",
            format!("[x](https{sep}github.com{colon}443{at}{host}/)"),
        ),
        (
            "a host that only begins with the allowed name",
            format!("[x](https://github.com.{host}/)"),
        ),
        (
            "a javascript destination",
            "[x](javascript:alert(1)) and [y](data:text/html,x)".to_owned(),
        ),
        (
            "percent-encoded dots in a bare url",
            "https://attacker%2Etest/x".to_owned(),
        ),
    ];
    let leaks = survivors(&vectors, host).await;
    // `attacker%2Etest` is a different spelling of the host; look for it as well.
    let last = vectors.len() - 1;
    let encoded = survivors(&vectors[last..], "attacker%2Etest").await;
    assert!(leaks.is_empty(), "{leaks:#?}");
    assert!(encoded.is_empty(), "{encoded:#?}");
    // Raw HTML is written as text: no tag survives, whatever its case or its place.
    for body in [
        format!("<img src=//{host}/p.png>"),
        format!("<IMG SRC=//{host}/p.png>"),
        format!("<p><img src=//{host}/p.png></p>"),
        format!("<a href=//{host}>x</a>"),
        format!("<picture><source srcset=//{host}/x.png></picture>"),
    ] {
        if let Some(stored) = try_stored_body(&body).await {
            let lower = stored.to_ascii_lowercase();
            assert!(
                !lower.contains("<img")
                    && !lower.contains("<p>")
                    && !lower.contains("<a ")
                    && !lower.contains("<picture")
                    && !lower.contains("<source"),
                "a tag survived: {stored:?}"
            );
        }
    }
}

/// Control: a mention in places a fence or a quote could hide it, and with the invisible characters
/// the filter claims to remove, is made inert.
#[tokio::test]
async fn held_mentions_in_odd_places_are_made_inert() {
    for body in [
        "````\n@example-org/security-team\n```\n@example-org/security-team\n````",
        "``` \n@example-org/security-team\n~~~",
        "> @example-org/security-team",
        "# @example-org/security-team",
        "| a |\n|---|\n| @example-org/security-team |",
        "@\u{200b}example-org/security-team",
        "@example\u{200d}-org/security-team",
        "\u{feff}@example-org/security-team",
        "`@example-org/security-team` and @example-org/security-team",
        "``@example-org/security-team` @example-org/security-team",
        "\\`@example-org/security-team` x",
    ] {
        let stored = stored_body(body).await;
        assert_no_live_mention(&stored, body);
    }
}

/// RR-19. A bare URL is judged by its host as the filter splits it (at `/`, `?` and `#`), and a
/// browser splits it differently: for the `http` and `https` schemes a backslash ends the host like a
/// slash does. `https://attacker.test\.github.com/x` has the host `attacker.test\.github.com` to the
/// filter, which ends with `.github.com` and is kept; a browser, following the link GitHub makes of a
/// bare address, goes to `attacker.test`. The same text inside a Markdown link destination is read
/// differently (the backslash escapes the dot), so only the bare form is a hole. Not run against
/// GitHub: whether it links the whole address or stops at the backslash is the renderer's.
#[tokio::test]
#[ignore = "confirmed defect RR-19: a bare URL whose host ends in an allowed domain after a backslash is kept; cargo test -p factory-github --test security_rereview --locked -- --ignored rr_19 --exact"]
async fn rr_19_a_bare_url_with_a_backslash_in_its_host_is_not_kept() {
    let vectors = vec![
        (
            "a backslash before the allowed name",
            "see https://attacker.test\\.github.com/x for the result".to_owned(),
        ),
        (
            "a backslash and a path",
            "https://attacker.test\\.github.com\\x".to_owned(),
        ),
    ];
    let leaks = survivors(&vectors, "attacker.test").await;
    assert!(leaks.is_empty(), "{leaks:#?}");
}

/// RR-20. A mention is only neutralised when the character before the `@` is not a word character,
/// and the filter counts the hyphen as one. GitHub's own pattern for a mention treats a hyphen as a
/// boundary (the character class is `\W`, and a hyphen is not `\w`), so `x-@someone` notifies
/// `someone` on GitHub and is left alone here. Not run against GitHub.
#[tokio::test]
#[ignore = "confirmed defect RR-20 (renderer behaviour unverified): a mention after a hyphen is left live; cargo test -p factory-github --test security_rereview --locked -- --ignored rr_20 --exact"]
async fn rr_20_a_mention_after_a_hyphen_is_made_inert() {
    for body in [
        "see x-@example-org/security-team",
        "--@example-org/security-team",
    ] {
        let stored = stored_body(body).await;
        assert_no_live_mention(&stored, body);
    }
}
