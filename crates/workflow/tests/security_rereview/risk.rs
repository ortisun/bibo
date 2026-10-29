//! The risk of a change, measured from the paths of the diff (AUT-10), attacked with the paths of the
//! files that bring code in or run code on a person's machine.

use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::vocabulary::RiskTier;
use factory_ports::paths::RepoPath;
use factory_ports::workspace::{ChangeKind, ChangedPath};
use factory_workflow::gates::scope::hardening::PatchSignals;
use factory_workflow::stages::delivery::risk::{
    HUGE_CHANGE_FILES, assess, assess_with_patch, from_diff,
};

const SECURITY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");

fn policy() -> PolicyEngine {
    let security: SecurityPolicy = serde_json::from_str(SECURITY).expect("the security policy");
    let approval: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("the approval policy");
    PolicyEngine::new(&security, &approval).expect("a policy engine")
}

fn change(path: &str, kind: ChangeKind) -> ChangedPath {
    ChangedPath {
        path: RepoPath::new(path).unwrap_or_else(|_| panic!("a path: {path}")),
        kind,
    }
}

/// True when the policy sees nothing special in a change to this one path: not protected, not a
/// sensitive file, no new dependency. Such a change is "a single module change" to the policy.
fn ordinary(path: &str, kind: ChangeKind) -> bool {
    let facts = from_diff(&policy(), &[change(path, kind)]);
    !facts.protected_path_change && !facts.sensitive_file_change && !facts.new_dependency
}

/// Control: the files the policy names are seen, at the root and in a member.
#[test]
fn held_the_named_manifests_and_workflows_are_seen() {
    for path in [
        "Cargo.toml",
        "crates/x/Cargo.toml",
        "Cargo.lock",
        "package.json",
        "web/package.json",
        "requirements.txt",
        "Dockerfile",
        "docker/Dockerfile.dev",
        ".github/workflows/ci.yml",
        ".cargo/config.toml",
        "crates/x/build.rs",
        "deny.toml",
    ] {
        assert!(
            !ordinary(path, ChangeKind::Modified),
            "{path} is an ordinary file to the policy"
        );
    }
}

/// A rename out of a sensitive place is a deletion and an addition, and the deletion is seen.
#[test]
fn held_a_rename_is_seen_at_both_ends() {
    let facts = from_diff(
        &policy(),
        &[
            change(".github/workflows/ci.yml", ChangeKind::Deleted),
            change("docs/ci.yml", ChangeKind::Added),
        ],
    );
    assert!(facts.protected_path_change);
}

/// A change that only touches documentation is documentation-only, and a documentation file that sits
/// next to a dependency manifest makes neither documentation-only nor an ordinary change; the tier of
/// the mixed change is at least high, whatever the facts known before the diff said.
#[test]
fn held_documentation_only_is_only_documentation_and_a_mix_is_high() {
    let policy = policy();
    let docs = from_diff(&policy, &[change("docs/guide.md", ChangeKind::Modified)]);
    assert!(docs.docs_only && !docs.new_dependency);
    let mixed_paths = [
        change("docs/guide.md", ChangeKind::Modified),
        change("Cargo.toml", ChangeKind::Modified),
    ];
    let mixed = from_diff(&policy, &mixed_paths);
    assert!(!mixed.docs_only && mixed.new_dependency);
    let known = factory_domain::policy::risk::RiskFacts {
        docs_only: true,
        ..Default::default()
    };
    let assessed = assess(&policy, &known, None, &mixed_paths);
    assert!(
        assessed.assessment.tier >= RiskTier::High,
        "{:?}",
        assessed.assessment.tier
    );
}

fn assessed(changes: &[ChangedPath], signals: &PatchSignals) -> RiskTier {
    // What the job and the design showed: an ordinary change to one module.
    let known = factory_domain::policy::risk::RiskFacts {
        single_module_change_without_sensitive_or_protected_paths: true,
        ..Default::default()
    };
    assess_with_patch(&policy(), &known, None, changes, signals)
        .assessment
        .tier
}

/// The details of a patch that a list of paths does not carry: a submodule bump, a symbolic link, a
/// change of mode, a binary file, and headers that cannot be read. None is an ordinary change.
#[test]
fn rr_16_the_headers_of_a_patch_make_a_change_that_looks_ordinary_high() {
    let one_file = [change("src/lib.rs", ChangeKind::Modified)];
    assert!(
        assessed(&one_file, &PatchSignals::default()) < RiskTier::High,
        "the control is an ordinary change"
    );
    for (name, patch) in [
        (
            "a submodule bump",
            "diff --git a/lib b/lib\nnew file mode 160000\nindex 0..1\n--- /dev/null\n+++ b/lib\n@@ -0,0 +1 @@\n+Subproject commit aaaa\n",
        ),
        (
            "a symbolic link",
            "diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+target\n",
        ),
        (
            "an executable bit",
            "diff --git a/src/lib.rs b/src/lib.rs\nold mode 100644\nnew mode 100755\n",
        ),
        (
            "a binary file",
            "diff --git a/x.bin b/x.bin\nnew file mode 100644\nBinary files /dev/null and b/x.bin differ\n",
        ),
        ("headers that cannot be read", "diff --git broken\n"),
    ] {
        let signals = PatchSignals::of(patch.as_bytes());
        assert!(!signals.is_ordinary(), "{name}");
        assert!(
            assessed(&one_file, &signals) >= RiskTier::High,
            "{name} is still an ordinary change"
        );
    }
}

/// A list of changed paths longer than anyone reads is counted as high, and so is a rename of a
/// manifest that changes only the case of its name.
#[test]
fn rr_16_a_huge_change_and_a_case_only_rename_are_not_ordinary() {
    let docs: Vec<ChangedPath> = (0..=HUGE_CHANGE_FILES)
        .map(|index| change(&format!("docs/note-{index}.md"), ChangeKind::Added))
        .collect();
    assert!(assessed(&docs, &PatchSignals::default()) >= RiskTier::High);
    let rename = [
        change("crates/x/Cargo.toml", ChangeKind::Deleted),
        change("crates/x/cargo.toml", ChangeKind::Added),
    ];
    let facts = from_diff(&policy(), &rename);
    assert!(facts.new_dependency && facts.sensitive_file_change);
}

/// RR-14 (fixed). The list of dependency manifests names most files at the root only (`requirements*.txt`,
/// `pyproject.toml`, `go.mod`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Gemfile`,
/// `pom.xml`), and leaves out the files of other package managers (`Pipfile`, `go.work`, `go.sum`
/// below the root, `.npmrc` below the root). A dependency added in `services/api/requirements.txt`
/// is, to the policy, an ordinary change to one module, and gets the tier of one. (The slice builds
/// for Rust first; the policy claims more. `.gitmodules` and a root `.npmrc` are seen.)
#[test]
fn rr_14_a_dependency_or_source_change_is_not_an_ordinary_change_because_of_where_it_is() {
    let unseen: Vec<&str> = [
        "services/api/requirements.txt",
        "tools/go.mod",
        "tools/go.sum",
        "backend/pyproject.toml",
        "web/package-lock.json",
        "web/yarn.lock",
        "web/pnpm-lock.yaml",
        "app/Gemfile",
        "app/pom.xml",
        "Pipfile",
        "Pipfile.lock",
        "go.work",
        "web/.npmrc",
        ".gitmodules",
    ]
    .into_iter()
    .filter(|path| ordinary(path, ChangeKind::Modified))
    .collect();
    assert!(
        unseen.is_empty(),
        "these are ordinary files to the risk measure: {unseen:?}"
    );
}

/// RR-15 (fixed). Files that run code on a person's machine when they open the project, commit, or build it in
/// an editor are ordinary files to the risk measure: a dev container definition, editor tasks, a git
/// hook manager. The reviewer is the person who opens the branch.
#[test]
fn rr_15_a_file_that_runs_on_the_reviewers_machine_is_not_an_ordinary_change() {
    let unseen: Vec<&str> = [
        ".devcontainer/devcontainer.json",
        ".vscode/tasks.json",
        ".vscode/settings.json",
        "lefthook.yml",
    ]
    .into_iter()
    .filter(|path| ordinary(path, ChangeKind::Added))
    .collect();
    assert!(
        unseen.is_empty(),
        "these are ordinary files to the risk measure: {unseen:?}"
    );
}

/// RR-16 (fixed). A directory of vendored crates is source that is built and run, and a change inside it is a
/// change of a dependency that no gate reads: the dependency files of the supply chain gates are the
/// manifests and the lock file, and the gates are skipped when none of them changes. Edited crate
/// code and its `.cargo-checksum.json` are an ordinary change to one module.
#[test]
fn rr_16_a_vendored_dependency_is_not_an_ordinary_file() {
    let unseen: Vec<&str> = [
        "vendor/serde/src/lib.rs",
        "vendor/serde/.cargo-checksum.json",
        "third_party/foo/src/lib.rs",
    ]
    .into_iter()
    .filter(|path| ordinary(path, ChangeKind::Modified))
    .collect();
    assert!(
        unseen.is_empty(),
        "these are ordinary files to the risk measure: {unseen:?}"
    );
}
