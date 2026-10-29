//! The narrowing of an allowlist entry to repositories (API-1), tried with the shapes a person edits
//! into the file.

use factory_composition::seams::FileAllowlist;
use factory_domain::ids::TenantId;

use crate::repository_root;

/// Asks the file whether the entry reaches `asked`, with `repositories` as the last lines of the entry.
fn covers(repositories: &str, asked: &str) -> bool {
    reads(repositories, asked).expect("the file reads")
}

/// The same, with `None` when the file is refused (the callers fail closed then).
fn reads(repositories: &str, asked: &str) -> Option<bool> {
    let ids = factory_composition::system::RandomIds::new().expect("the random source opens");
    let unique = factory_ports::clock::IdGenerator::new_uuid(&ids)
        .simple()
        .to_string();
    let dir = repository_root()
        .join("target/security-rereview")
        .join(format!("allowlist-{unique}"));
    std::fs::create_dir_all(dir.join("allowlist")).expect("a directory");
    let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(0x7e));
    let user = "github_user_id";
    std::fs::write(
        dir.join("allowlist/allowlist.yaml"),
        format!(
            "version: 1\nentries:\n  - tenant: {}\n    {user}: 4242\n    login: someone\n    designations: [approver]\n{repositories}",
            tenant.as_uuid()
        ),
    )
    .expect("the file");
    let answer = FileAllowlist::in_checkout(&dir)
        .covers(tenant, 4242, asked)
        .ok();
    let _ = std::fs::remove_dir_all(&dir);
    answer
}

/// Control: a list covers whole names in any case and nothing else; a pattern is a literal.
#[test]
fn held_a_list_covers_whole_names_in_any_case_and_an_empty_list_covers_none() {
    assert!(covers("    repositories: [acme/repo]\n", "acme/repo"));
    assert!(covers("    repositories: [Acme/Repo]\n", "acme/REPO"));
    assert!(!covers("    repositories: [acme/rep]\n", "acme/repo"));
    assert!(!covers("    repositories: [acme/repo2]\n", "acme/repo"));
    assert!(!covers("    repositories: [\"*\"]\n", "acme/repo"));
    assert!(!covers("    repositories: [\"acme/*\"]\n", "acme/repo"));
    assert!(!covers("    repositories: []\n", "acme/repo"));
    assert!(!covers("    repositories: [acme/repo]\n", "acme/repo-two"));
    assert!(!covers(
        "    repositories: [ \"acme/repo \" ]\n",
        "acme/repo"
    ));
}

/// A `repositories:` key with nothing after it (a YAML null) was the suspected way to widen an entry
/// by editing a list down to nothing. The reader refuses the file instead, so every caller fails
/// closed. (The price is that one such line makes every request answer `503` until it is fixed.)
#[test]
fn held_a_narrowing_with_no_value_is_refused_and_never_means_every_repository() {
    let mut widened = Vec::new();
    for text in [
        "    repositories:\n",
        "    repositories: ~\n",
        "    repositories: null\n",
        "    repositories:\n      # - acme/repo\n",
    ] {
        if reads(text, "acme/other") == Some(true) {
            widened.push(text);
        }
    }
    assert!(
        widened.is_empty(),
        "these reached a repository they do not list: {widened:?}"
    );
}
