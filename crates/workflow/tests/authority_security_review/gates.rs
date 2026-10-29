//! Attacks on the approval binding and on the host-side gates.

use factory_domain::policy::paths::DiffEntry;
use factory_domain::vocabulary::RiskTier;
use factory_ports::githost::PullRequestRef;
use factory_ports::paths::{BranchName, RepoRef};
use factory_ports::workspace::ChangeKind;
use factory_workflow::gates::scope::{FileChange, protected, weakening};
use factory_workflow::stages::approval::{Outcome, Refusal, ServiceError};

use crate::approval_rig::{Rig, policy};

// ---- AUT-1: the pull request's own base branch is never compared -------------------------------

/// The approval is bound to the base *commit* (`seen.base`, `request.base`, the live tip of the
/// branch named in the request), but nothing reads which branch the pull request now targets.
/// `PullRequestState::base` is returned by the host and ignored by `ApprovalService::submit`,
/// `judge` (`Live` has no field for it) and the approval handler. Anyone with write access to the
/// repository can retarget the draft to another branch after the request is made, and an approver
/// who follows the procedure records an approval for a pull request that now merges elsewhere.
#[tokio::test]
#[ignore = "confirmed defect AUT-1: an approval is recorded for a pull request that was retargeted to another base branch"]
async fn aut_1_an_approval_is_refused_when_the_pull_request_targets_another_base_branch() {
    let rig = Rig::new(RiskTier::Low).await;
    // Someone with write access moves the draft from `main` to `release` after the request was
    // stored. The commit the request names as the base is untouched.
    rig.host
        .retarget(&BranchName::new("release").expect("a branch"));
    let result = rig.approve().await;
    assert!(
        result.is_err(),
        "the approval was applied for a pull request whose base is no longer the one shown: {result:?}"
    );
}

/// A person pushes to the branch after the request was made, and the approver approves the head
/// they were shown. `ApprovalService::submit` reads the tree of the new head from the job's object
/// store *before* it judges. That store has never seen a commit someone else pushed, so
/// `tree_of` answers `NotFound`, the service answers `Unavailable`, and `Refusal::HeadMoved` (and
/// the invalidation of the approvals on record that goes with it) is never reached. The hook then
/// retries the decision twenty times and rejects it as `gave_up`. The full run's own break test
/// for a stale head ends the same way: its audit record says `code=gave_up`, not `new_commit`.
#[tokio::test]
#[ignore = "confirmed defect AUT-2: a head moved by someone else is answered as unavailable, not as a moved head, and recorded approvals are not invalidated"]
async fn aut_2_a_head_pushed_by_someone_else_is_refused_as_a_moved_head() {
    let rig = Rig::new(RiskTier::Low).await;
    let moved = rig.push_foreign_commit();
    assert_ne!(moved.as_str(), rig.request.pr_head.as_str());
    let result = rig.approve().await;
    assert!(
        matches!(result, Err(ServiceError::Refused(Refusal::HeadMoved))),
        "expected a refusal for the moved head, got {result:?}"
    );
}

/// Control for the test above: with the pull request where it was, the same approval applies.
#[tokio::test]
async fn held_aut_1_the_same_approval_applies_when_nothing_moved() {
    let rig = Rig::new(RiskTier::Low).await;
    let result = rig.approve().await;
    assert!(matches!(result, Ok(Outcome::Applied { .. })), "{result:?}");
}

/// The pull request's head branch and number are the ones in the request: a pull request that is
/// not the one the factory opened cannot be approved by naming another number.
#[tokio::test]
async fn held_a_request_for_another_pull_request_number_reads_nothing() {
    let rig = Rig::new(RiskTier::Low).await;
    let scope = factory_ports::githost::GitScope {
        tenant: rig.w.tenant,
        job: rig.job,
        stage: factory_domain::vocabulary::StageKind::Approval,
        repo: RepoRef::parse("example-org/fixture").expect("a repo"),
    };
    let other = PullRequestRef {
        repo: RepoRef::parse("example-org/fixture").expect("a repo"),
        number: rig.request.pull_request + 7,
    };
    use factory_ports::githost::ChangeHost as _;
    assert!(rig.host.pull_request_state(&scope, &other).await.is_err());
}

// ---- AUT-4 and AUT-5: semantic checks the policy names and the code does not have --------------

fn modified(path: &str, before: &str, after: &str) -> FileChange {
    FileChange {
        path: path.to_owned(),
        kind: ChangeKind::Modified,
        before: Some(before.as_bytes().to_vec()),
        after: Some(after.as_bytes().to_vec()),
        readable: true,
    }
}

/// `policies/security.yaml` `gate_integrity.semantic_checks` lists `lint_relaxation` ("lint level
/// lowered, allow attributes added, ignore lists grown", blocks until a human approves). The
/// host-side gates are `protected::check`, `weakening::weakened` and the secret scan
/// (`stages/validation/host.rs`). None of them reads a lint attribute. A crate-level
/// `#![allow(warnings)]` outranks the `-D warnings` of the lint command, so the lint gate, which
/// reads only the exit code, reports PASSED for code that has warnings.
#[test]
#[ignore = "confirmed defect AUT-4: a new crate-level allow attribute that silences the lint gate is not seen by any host-side rule"]
fn aut_4_a_new_allow_attribute_is_seen_by_a_host_side_gate() {
    let before = "pub fn one() {}\n";
    for added in [
        "#![allow(warnings)]\npub fn one() {}\n",
        "#![allow(clippy::all)]\npub fn one() {}\n",
        "#![allow(unused)]\npub fn one() {}\n",
    ] {
        let found = weakening::weakened(&[modified("src/lib.rs", before, added)]);
        let diff = [DiffEntry::Modified {
            path: "src/lib.rs".to_owned(),
            gained_lines_only: false,
        }];
        let refused = protected::check(&policy().paths, &diff);
        assert!(
            !found.is_empty() || !refused.protected.is_empty() || !refused.tests.is_empty(),
            "no host-side rule saw {added:?}"
        );
    }
}

/// The same policy list names `build_script_added` ("new build.rs, setup.py, postinstall",
/// blocks until a security review), and `**/build.rs` is in the `sensitive_files` group that
/// carries it. A new `build.rs` runs arbitrary code at build time in every gate, and in every
/// build after the merge. The path check allows the file (sensitive files are allowed to change)
/// and nothing consumes the "sensitive" hit at gate time: the tier at approval comes from the
/// architect's design (see AUT-10 in the review).
#[test]
#[ignore = "confirmed defect AUT-5: a new build.rs is allowed by the path gate and no gate blocks it for a security review"]
fn aut_5_a_new_build_script_is_blocked_until_a_security_review() {
    let diff = [DiffEntry::Added {
        path: "build.rs".to_owned(),
    }];
    let refused = protected::check(&policy().paths, &diff);
    let content = weakening::weakened(&[FileChange {
        path: "build.rs".to_owned(),
        kind: ChangeKind::Added,
        before: None,
        after: Some(b"fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n".to_vec()),
        readable: true,
    }]);
    assert!(
        !refused.protected.is_empty() || !content.is_empty(),
        "a new build.rs passes every host-side rule"
    );
}

// ---- held: the protected paths ------------------------------------------------------------------

/// Files that change what the gates run, or who owns the code, are refused for an add and for a
/// change, by the path gate that runs on the host before any command.
#[test]
fn held_ci_gate_ownership_and_agent_instruction_files_are_refused() {
    let engine = policy();
    for path in [
        ".github/workflows/ci.yml",
        ".github/CODEOWNERS",
        "CODEOWNERS",
        "docs/CODEOWNERS",
        "clippy.toml",
        "rustfmt.toml",
        "deny.toml",
        ".cargo/config.toml",
        "rust-toolchain.toml",
        ".specify/memory/constitution.md",
        "CLAUDE.md",
        "AGENTS.md",
    ] {
        for entry in [
            DiffEntry::Added {
                path: path.to_owned(),
            },
            DiffEntry::Modified {
                path: path.to_owned(),
                gained_lines_only: true,
            },
        ] {
            let refused = protected::check(&engine.paths, std::slice::from_ref(&entry));
            assert!(
                !refused.protected.is_empty() || !refused.tests.is_empty(),
                "{path} was allowed as {entry:?}"
            );
        }
    }
}

/// A rename or a copy cannot move a protected file out of its place, or a new file into it.
#[test]
fn held_a_rename_or_copy_into_or_out_of_a_protected_path_is_refused() {
    let engine = policy();
    for entry in [
        DiffEntry::Renamed {
            from: ".github/workflows/ci.yml".to_owned(),
            to: "src/ci.yml".to_owned(),
        },
        DiffEntry::Renamed {
            from: "src/ci.yml".to_owned(),
            to: ".github/workflows/ci.yml".to_owned(),
        },
        DiffEntry::Copied {
            from: "src/ci.yml".to_owned(),
            to: "CODEOWNERS".to_owned(),
        },
    ] {
        let refused = protected::check(&engine.paths, std::slice::from_ref(&entry));
        assert!(
            !refused.protected.is_empty() || !refused.tests.is_empty(),
            "{entry:?} was allowed"
        );
    }
}
