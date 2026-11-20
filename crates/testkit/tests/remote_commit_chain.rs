//! The commits above a base on the fake remote's own record, and the paths each one changes
//! (finding SF-08 of the Slice 1 run): the end-to-end evidence reads them from the host and not
//! from the stage results.

use factory_ports::paths::{BranchName, RepoRef};
use factory_testkit::workspace::FakeRemote;

fn branch(name: &str) -> BranchName {
    BranchName::new(name).expect("a branch")
}

#[test]
fn the_chain_lists_each_commit_above_the_base_oldest_first_with_the_paths_it_changed() {
    let remote = FakeRemote::new();
    let repo = RepoRef::parse("example-org/fixture").expect("a repository");
    let base = remote.commit_on_branch(&repo, &branch("main"), &[("README.md", "one")]);
    // The head branch starts where main is, then gains two commits.
    let first = remote.commit_on_branch(
        &repo,
        &branch("factory/job-1"),
        &[("README.md", "one"), ("src/lib.rs", "pub fn a() {}")],
    );
    // The first commit of a branch is its own root in this fake, so the chain is built from the
    // branch that has a parent: add two more commits.
    let second = remote.commit_on_branch(
        &repo,
        &branch("factory/job-1"),
        &[
            ("README.md", "two"),
            ("src/lib.rs", "pub fn a() {}"),
            ("tests/a.rs", "x"),
        ],
    );
    let third = remote.commit_on_branch(
        &repo,
        &branch("factory/job-1"),
        &[("README.md", "two"), ("tests/a.rs", "x")],
    );
    let chain = remote.commits_above(&repo, &branch("factory/job-1"), None);
    let shas: Vec<_> = chain.iter().map(|c| c.sha.clone()).collect();
    assert_eq!(shas, vec![first, second, third], "oldest first");
    assert_eq!(chain[1].paths, ["README.md", "tests/a.rs"]);
    assert_eq!(
        chain[2].paths,
        ["src/lib.rs"],
        "a deleted path is a changed path"
    );
    // Stopping at a base leaves out the base and everything below it.
    let above = remote.commits_above(&repo, &branch("factory/job-1"), Some(&chain[0].sha));
    assert_eq!(above.len(), 2);
    let _ = base;
}

#[test]
fn a_branch_that_does_not_exist_has_no_commits() {
    let remote = FakeRemote::new();
    let repo = RepoRef::parse("example-org/fixture").expect("a repository");
    assert!(
        remote
            .commits_above(&repo, &branch("factory/none"), None)
            .is_empty()
    );
}
