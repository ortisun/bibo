//! Security review of the decision parsers and the allowlist file (authority and evidence review,
//! 2026-10-28).
//!
//! Every test here is a `held_*` probe: the review attacked the parser or the file reader and
//! found it sound, and the probe keeps it so. None needs a database. The parsers are pure
//! functions of text; the allowlist probes write a file under the target directory of the test.
//!
//! The comment channel is not wired into any binary (no code outside tests calls `parse_comment`;
//! see the review, section "comment-command parsing"), so these probes say what the parser would
//! do the day a webhook route feeds it.
//!
//! Run: `cargo test -p factory-composition --test approval_security_review --locked`

use std::path::PathBuf;

use factory_composition::commands::{CommandError, parse_cli, parse_comment, parse_form};
use factory_composition::seams::FileAllowlist;
use factory_domain::ids::TenantId;
use factory_domain::policy::authority::RepositoryIdentity;
use factory_domain::policy::decision::Designation;
use factory_domain::values::Timestamp;
use factory_workflow::stages::approval::Verb;

fn sha(letter: char) -> String {
    letter.to_string().repeat(40)
}

fn digest() -> String {
    format!("sha256:{}", "ab".repeat(32))
}

/// A body is a command only when its first line starts with `/factory ` and nothing before it.
#[test]
fn held_only_the_first_line_of_a_comment_with_the_exact_prefix_is_a_command() {
    let head = sha('a');
    let evidence = digest();
    for body in [
        // Quoted reply, code fence, indentation, list item, heading, other case, other slash.
        format!("> /factory approve head={head} evidence={evidence}"),
        format!("```\n/factory approve head={head} evidence={evidence}\n```"),
        format!(" /factory approve head={head} evidence={evidence}"),
        format!("\t/factory approve head={head} evidence={evidence}"),
        format!("- /factory approve head={head} evidence={evidence}"),
        format!("# /factory approve head={head} evidence={evidence}"),
        format!("/FACTORY approve head={head} evidence={evidence}"),
        format!("\u{ff0f}factory approve head={head} evidence={evidence}"),
        format!("/factory\u{a0}approve head={head} evidence={evidence}"),
        format!("\u{200b}/factory approve head={head} evidence={evidence}"),
        format!("\u{feff}/factory approve head={head} evidence={evidence}"),
        // The command is on the second line.
        format!("Looks fine to me.\n/factory approve head={head} evidence={evidence}"),
        // A blank first line.
        format!("\n/factory approve head={head} evidence={evidence}"),
    ] {
        assert_eq!(parse_comment(&body), Ok(None), "{body:?}");
    }
}

/// Text after the first line never changes the command, and the first line cannot carry a second
/// command.
#[test]
fn held_later_lines_and_later_words_do_not_add_a_second_command() {
    let head = sha('a');
    let evidence = digest();
    let body = format!(
        "/factory approve head={head} evidence={evidence}\n/factory reject head={}\r\n/factory cancel",
        sha('b')
    );
    let parsed = parse_comment(&body).unwrap().unwrap();
    assert_eq!(parsed.verb, Verb::Approve);
    assert_eq!(parsed.head.unwrap().as_str(), head);
    // A key that comes after the reason has started is part of the reason, not a binding.
    let tricky = format!(
        "/factory approve head={head} evidence={evidence} looks good head={} target=IMPLEMENTATION",
        sha('b')
    );
    let parsed = parse_comment(&tricky).unwrap().unwrap();
    assert_eq!(parsed.head.unwrap().as_str(), head);
    assert!(parsed.target.is_none());
    assert!(parsed.reason.contains("head="));
}

/// The factory takes seven verbs. Merge, ready, undraft, deploy and their lookalikes are unknown.
#[test]
fn held_no_verb_merges_marks_ready_or_deploys() {
    for verb in [
        "merge",
        "Merge",
        "ready",
        "undraft",
        "deploy",
        "release",
        "approve-and-merge",
        "approve;merge",
        "approve\u{200b}",
        "approve_",
        "",
    ] {
        let comment = parse_comment(&format!("/factory {verb} head={}", sha('a')));
        let cli = parse_cli(&[verb, "head=x"]);
        assert!(
            matches!(
                comment,
                Err(CommandError::UnknownVerb(_) | CommandError::NoVerb)
            ),
            "comment {verb:?}: {comment:?}"
        );
        assert!(
            matches!(
                cli,
                Err(CommandError::UnknownVerb(_) | CommandError::NoVerb)
            ),
            "cli {verb:?}: {cli:?}"
        );
        let form = parse_form(&[("verb", verb), ("reason", "x")]);
        assert!(
            matches!(
                form,
                Err(CommandError::UnknownVerb(_) | CommandError::NoVerb)
            ),
            "form {verb:?}: {form:?}"
        );
    }
}

/// A key may be given once, a value must be what the key says, and a head that is not forty or
/// sixty-four hexadecimal characters is refused.
#[test]
fn held_a_binding_is_given_once_and_is_well_formed() {
    let evidence = digest();
    assert_eq!(
        parse_comment(&format!(
            "/factory approve head={} head={} evidence={evidence}",
            sha('a'),
            sha('b')
        )),
        Err(CommandError::Repeated("head"))
    );
    for bad in ["", "abc", &"g".repeat(40), &"a".repeat(39), &"a".repeat(41)] {
        let result = parse_comment(&format!("/factory approve head={bad} evidence={evidence}"));
        assert!(
            matches!(result, Err(CommandError::BadValue("head"))),
            "{bad:?}: {result:?}"
        );
    }
    let result = parse_comment(&format!(
        "/factory approve head={} evidence=sha256:zz",
        sha('a')
    ));
    assert!(matches!(result, Err(CommandError::BadValue("evidence"))));
    // An upper-case head is either refused or read as the same commit, never as another one.
    let upper = parse_comment(&format!(
        "/factory approve head={} evidence={evidence}",
        sha('A')
    ));
    match upper {
        Err(CommandError::BadValue("head")) => {}
        Ok(Some(parsed)) => assert_eq!(parsed.head.unwrap().as_str(), sha('a')),
        other => panic!("{other:?}"),
    }
}

/// A reason is bounded, and a decision other than an approval has to give one.
#[test]
fn held_a_reason_is_bounded_and_required_where_it_matters() {
    assert_eq!(parse_comment("/factory reject"), Err(CommandError::Reason));
    assert_eq!(
        parse_comment("/factory cancel   "),
        Err(CommandError::Reason)
    );
    let long = "x".repeat(2001);
    assert_eq!(
        parse_comment(&format!("/factory reject {long}")),
        Err(CommandError::Reason)
    );
    let fits = "x".repeat(2000);
    assert!(parse_comment(&format!("/factory reject {fits}")).is_ok());
    // A very long body costs nothing: only the first line is read.
    let huge = format!("/factory pause maintenance\n{}", "y".repeat(5_000_000));
    assert!(parse_comment(&huge).unwrap().is_some());
}

// ---- the allowlist file ---------------------------------------------------------------------

fn checkout(name: &str, text: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("approval-security-review")
        .join(name);
    std::fs::create_dir_all(dir.join("allowlist")).expect("a directory");
    std::fs::write(dir.join("allowlist/allowlist.yaml"), text).expect("the file");
    dir
}

const TENANT: &str = "018f3a00-0000-7000-8000-00000000c001";
const OTHER: &str = "018f3a00-0000-7000-8000-00000000c002";

fn tenant() -> TenantId {
    TenantId::parse(TENANT).expect("a tenant")
}

fn now() -> Timestamp {
    Timestamp::parse("2026-10-28T12:00:00Z").expect("a time")
}

/// One typo, one unknown designation, one date that does not parse, one duplicate and one field
/// nobody knows each make the whole list unreadable. The readers fail closed: nobody holds
/// anything while the file is wrong.
#[test]
fn held_a_wrong_allowlist_file_grants_nobody_anything() {
    let good = format!(
        "version: 1\nentries:\n  - tenant: {TENANT}\n    github_user_id: 2001\n    login: bob\n    designations: [approver]\n"
    );
    let allowlist = FileAllowlist::in_checkout(&checkout("good", &good));
    assert!(
        allowlist
            .designations_on(
                tenant(),
                2001,
                Some(&RepositoryIdentity::by_name_only("acme/widgets")),
                now()
            )
            .unwrap()
            .contains(&Designation::Approver)
    );
    for (name, text) in [
        ("typo", good.replace("approver", "aprover")),
        ("date", format!("{good}    expires_at: tomorrow\n")),
        (
            "duplicate",
            format!(
                "{good}  - tenant: {TENANT}\n    github_user_id: 2001\n    login: bob\n    designations: [security_approver]\n"
            ),
        ),
        ("field", format!("{good}    bonus: yes\n")),
        ("version", good.replace("version: 1", "version: 2")),
        ("zero id", good.replace("2001", "0")),
        ("empty", String::new()),
    ] {
        let allowlist = FileAllowlist::in_checkout(&checkout(name, &text));
        assert!(
            allowlist.read().is_err(),
            "{name}: the policy reader accepted a wrong file"
        );
        assert!(
            allowlist
                .designations_on(
                    tenant(),
                    2001,
                    Some(&RepositoryIdentity::by_name_only("acme/widgets")),
                    now()
                )
                .is_err()
                || name == "duplicate",
            "{name}: the designation reader accepted a wrong file"
        );
    }
    // A file that does not exist is unreadable, not empty.
    let missing =
        FileAllowlist::in_checkout(&PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("nope"));
    assert!(missing.read().is_err());
}

/// The tenant, the numeric id, the expiry and the repository narrowing each only take authority
/// away. A login in the file is display only.
#[test]
fn held_tenant_id_expiry_and_narrowing_each_take_authority_away() {
    let text = format!(
        "version: 1\nentries:\n  - tenant: {TENANT}\n    github_user_id: 2001\n    login: bob\n    designations: [approver]\n    repositories: [acme/widgets]\n  - tenant: {TENANT}\n    github_user_id: 2002\n    login: eve\n    designations: [approver]\n    expires_at: \"2026-10-28T11:59:59Z\"\n  - tenant: {OTHER}\n    github_user_id: 2003\n    login: carol\n    designations: [approver, org_admin]\n"
    );
    let allowlist = FileAllowlist::in_checkout(&checkout("rules", &text));
    let held = |tenant: TenantId, id: u64, repository: Option<&RepositoryIdentity<'_>>| {
        allowlist
            .designations_on(tenant, id, repository, now())
            .unwrap()
    };
    assert!(
        held(
            tenant(),
            2001,
            Some(&RepositoryIdentity::by_name_only("ACME/Widgets"))
        )
        .contains(&Designation::Approver)
    );
    assert!(
        held(
            tenant(),
            2001,
            Some(&RepositoryIdentity::by_name_only("acme/other"))
        )
        .is_empty()
    );
    assert!(
        held(
            tenant(),
            2001,
            Some(&RepositoryIdentity::by_name_only("acme/widget"))
        )
        .is_empty()
    );
    assert!(held(tenant(), 2002, None).is_empty(), "expired");
    // Another tenant's person holds nothing here, and a login that equals a listed one grants
    // nothing: only the number counts.
    assert!(held(tenant(), 2003, None).is_empty());
    assert!(held(tenant(), 9999, None).is_empty());
}
