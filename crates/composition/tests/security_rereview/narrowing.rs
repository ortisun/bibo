//! The narrowing of an allowlist entry to repositories (API-1), tried with the shapes a person edits
//! into the file.

use factory_composition::seams::{FileAllowlist, NameOnlyNarrowing};
use factory_domain::ids::TenantId;
use factory_domain::policy::authority::RepositoryIdentity;

use crate::repository_root;

/// Asks the file whether the entry reaches `asked`, with `repositories` as the last lines of the entry.
fn covers(repositories: &str, asked: &str) -> bool {
    reads(repositories, asked).expect("the file reads")
}

/// The same, with `None` when the file is refused (the callers fail closed then). The question
/// carries the name alone, as a layer that cannot know the id asks it.
fn reads(repositories: &str, asked: &str) -> Option<bool> {
    reads_identity(repositories, &RepositoryIdentity::by_name_only(asked))
}

/// Asks about a registered repository: its name and GitHub's numeric id of it (RR-28).
fn covers_registered(repositories: &str, name: &str, id: u64) -> bool {
    reads_identity(repositories, &RepositoryIdentity::registered(name, id)).expect("the file reads")
}

fn reads_identity(repositories: &str, asked: &RepositoryIdentity<'_>) -> Option<bool> {
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

// ---- RR-28: the narrowing by GitHub's numeric id of the repository --------------------------------------

const BY_ID: &str =
    "    repositories:\n      - name: acme/old-name\n        github_repository_id: 5000\n";

/// A renamed repository, a transferred one and one that was not touched are the same repository, so the
/// entry still reaches them. A new repository created under the old name is another repository.
#[test]
fn rr_28_an_entry_with_an_id_follows_a_rename_and_a_transfer_and_not_a_new_repository_under_the_old_name()
 {
    // Not renamed.
    assert!(covers_registered(BY_ID, "acme/old-name", 5000));
    // Renamed: the registered name is another and the id is the same.
    assert!(covers_registered(BY_ID, "acme/new-name", 5000));
    // Transferred to another owner.
    assert!(covers_registered(BY_ID, "elsewhere/old-name", 5000));
    // Name reuse: a new repository under the old name has another id and inherits nothing.
    assert!(!covers_registered(BY_ID, "acme/old-name", 6000));
    assert!(!covers_registered(BY_ID, "ACME/OLD-NAME", 6000));
    // The control, the defect the finding named: the same new repository under an entry that lists the
    // name alone.
    assert!(covers_registered(
        "    repositories: [acme/old-name]\n",
        "acme/old-name",
        6000
    ));
}

/// A listing in the mixed form works for each item by its own rule, and the plain list of names is read
/// as before.
#[test]
fn rr_28_a_list_may_mix_names_and_ids_and_each_item_is_judged_by_its_own_form() {
    let mixed = format!("{BY_ID}      - acme/by-name\n");
    assert!(covers_registered(&mixed, "acme/by-name", 7000));
    assert!(covers_registered(&mixed, "acme/anything", 5000));
    assert!(!covers_registered(&mixed, "acme/anything", 7000));
    // Asked by name alone, as the stages of the workflow ask: the name recorded next to the id counts.
    assert!(reads(&mixed, "acme/old-name") == Some(true));
    assert!(reads(&mixed, "acme/new-name") == Some(false));
}

/// An id that is not a GitHub repository id, an unknown key, a missing name and a wrong type each make
/// the file unreadable, so every caller fails closed.
#[test]
fn rr_28_a_malformed_listing_makes_the_file_unreadable() {
    for text in [
        "    repositories:\n      - name: acme/x\n        github_repository_id: 0\n",
        "    repositories:\n      - name: acme/x\n        github_repository_id: -5\n",
        "    repositories:\n      - name: acme/x\n        github_repository_id: abc\n",
        "    repositories:\n      - github_repository_id: 5\n",
        "    repositories:\n      - name: acme/x\n        github_repository_id: 5\n        extra: yes\n",
        "    repositories:\n      - 12\n",
    ] {
        assert_eq!(reads(text, "acme/x"), None, "{text}");
    }
}

/// The weaker form is reported, and the form with an id is not.
#[test]
fn rr_28_the_entries_that_narrow_by_name_alone_are_listed_and_the_ones_with_an_id_are_not() {
    let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(0x7e));
    let dir = repository_root()
        .join("target/security-rereview")
        .join(format!(
            "allowlist-rr28-{}",
            factory_ports::clock::IdGenerator::new_uuid(
                &factory_composition::system::RandomIds::new().expect("the random source opens")
            )
            .simple()
        ));
    std::fs::create_dir_all(dir.join("allowlist")).expect("a directory");
    std::fs::write(
        dir.join("allowlist/allowlist.yaml"),
        format!(
            "version: 1\nentries:\n  - tenant: {t}\n    github_user_id: 1\n    login: weak\n    designations: [approver]\n    repositories: [acme/a, acme/b]\n  - tenant: {t}\n    github_user_id: 2\n    login: strong\n    designations: [approver]\n    repositories:\n      - name: acme/a\n        github_repository_id: 11\n  - tenant: {t}\n    github_user_id: 3\n    login: broad\n    designations: [approver]\n",
            t = tenant.as_uuid()
        ),
    )
    .expect("the file");
    let weak = FileAllowlist::in_checkout(&dir)
        .name_only_narrowing()
        .expect("the file reads");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        weak,
        vec![NameOnlyNarrowing {
            tenant,
            github_user_id: 1,
            repositories: vec!["acme/a".to_owned(), "acme/b".to_owned()],
        }]
    );
}
