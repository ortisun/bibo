//! Path normalization, folding, protected groups, diffs and symbolic links.

use factory_domain::policy::paths::{
    ChangeEvidence, ChangeRequirement, DiffEntry, DiffVerdict, Operation, PathDenialReason,
    PathPolicy, PathRefusal, PathVerdict, normalize,
};
use factory_domain::policy::security::ProtectionMode;
use factory_domain::policy::{BuildError, RepoKind};
use proptest::prelude::*;
use std::sync::LazyLock;

use crate::support::{security, security_from, security_json};

fn policy() -> &'static PathPolicy {
    static POLICY: LazyLock<PathPolicy> =
        LazyLock::new(|| PathPolicy::from_policy(&security()).expect("the real policy builds"));
    &POLICY
}

fn check(path: &str, op: Operation) -> PathVerdict {
    policy().check(RepoKind::Target, path, op, None, &ChangeEvidence::default())
}

fn denied_by(verdict: &PathVerdict) -> Option<(PathDenialReason, String)> {
    match verdict {
        PathVerdict::Denied(d) => Some((d.reason.clone(), d.rule.id().to_owned())),
        PathVerdict::Allowed(_) => None,
    }
}

const WRITE: Operation = Operation::Modify {
    gained_lines_only: false,
};

// ---------------------------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------------------------

#[test]
fn normalization_refuses_each_unsafe_shape_for_its_own_reason() {
    let long_component = "a".repeat(256);
    let long_path = format!("{}/x", "a/".repeat(2100));
    let deep = "a/".repeat(300) + "x";
    let table: Vec<(String, PathRefusal)> = vec![
        ("".into(), PathRefusal::Empty),
        ("./".into(), PathRefusal::Empty),
        (".//./".into(), PathRefusal::Empty),
        ("/etc/passwd".into(), PathRefusal::Absolute),
        ("../../etc/passwd".into(), PathRefusal::ParentComponent),
        ("src/../../x".into(), PathRefusal::ParentComponent),
        ("a/b/..".into(), PathRefusal::ParentComponent),
        ("%2e%2e/x".into(), PathRefusal::PercentEncoded),
        ("a/%2E%2e/x".into(), PathRefusal::PercentEncoded),
        ("a/%2f/x".into(), PathRefusal::PercentEncoded),
        ("a\0b".into(), PathRefusal::ControlCharacter),
        ("a\nb".into(), PathRefusal::ControlCharacter),
        ("a\u{7f}b".into(), PathRefusal::ControlCharacter),
        ("a\\b".into(), PathRefusal::Backslash),
        // Fullwidth full stops are `..` after folding.
        ("\u{ff0e}\u{ff0e}/x".into(), PathRefusal::ParentComponent),
        ("a/\u{2025}/x".into(), PathRefusal::ParentComponent),
        ("\u{ff0e}/x".into(), PathRefusal::DotLike),
        ("a/.../b".into(), PathRefusal::DotLike),
        ("a/. /b".into(), PathRefusal::DotLike),
        // A zero-width character cannot turn `..` into something that is not `..`.
        (".\u{200b}./x".into(), PathRefusal::ParentComponent),
        ("a/\u{200b}/b".into(), PathRefusal::DotLike),
        ("a\u{2215}b".into(), PathRefusal::SeparatorLookalike),
        ("\u{ff0f}etc".into(), PathRefusal::SeparatorLookalike),
        ("C:/x".into(), PathRefusal::Colon),
        ("a/file:stream".into(), PathRefusal::Colon),
        (".git".into(), PathRefusal::GitDirectory),
        (".git/config".into(), PathRefusal::GitDirectory),
        (".GIT/config".into(), PathRefusal::GitDirectory),
        (
            "sub/.Git/hooks/post-commit".into(),
            PathRefusal::GitDirectory,
        ),
        (".g\u{200c}it/config".into(), PathRefusal::GitDirectory),
        (".git./config".into(), PathRefusal::GitDirectory),
        (".git /config".into(), PathRefusal::GitDirectory),
        ("GIT~1/hooks".into(), PathRefusal::GitDirectory),
        ("git~12/hooks".into(), PathRefusal::GitDirectory),
        ("\u{ff0e}git/config".into(), PathRefusal::GitDirectory),
        (long_component, PathRefusal::ComponentTooLong),
        (long_path, PathRefusal::TooLong),
        (deep, PathRefusal::TooDeep),
    ];
    for (input, expected) in table {
        let shown: String = input.chars().take(40).collect();
        assert_eq!(normalize(&input), Err(expected), "input {shown:?}");
    }
}

#[test]
fn normalization_keeps_the_spelling_and_folds_the_key() {
    let table = [
        ("src/lib.rs", "src/lib.rs", "src/lib.rs"),
        ("./src//lib.rs/", "src/lib.rs", "src/lib.rs"),
        (
            ".GitHub/Workflows/CI.yml",
            ".GitHub/Workflows/CI.yml",
            ".github/workflows/ci.yml",
        ),
        (
            ".github./workflows ",
            ".github./workflows ",
            ".github/workflows",
        ),
        ("a/b\u{200d}c", "a/b\u{200d}c", "a/bc"),
        ("\u{212a}EY.PEM", "\u{212a}EY.PEM", "key.pem"),
        ("ID\u{131}_RSA", "ID\u{131}_RSA", "idi_rsa"),
        (".\u{17f}tuff", ".\u{17f}tuff", ".stuff"),
        ("GITMOD~1/x", "GITMOD~1/x", ".gitmodules/x"),
        ("\u{ff21}\u{ff22}c", "\u{ff21}\u{ff22}c", "abc"),
        ("100%.md", "100%.md", "100%.md"),
    ];
    for (input, shown, key) in table {
        let n = normalize(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!((n.as_str(), n.key()), (shown, key), "input {input:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn normalization_never_panics_and_never_lets_a_path_leave_the_root(text in "\\PC{0,200}|[./a-zA-Z%0-9\\\\ :~\u{200b}\u{ff0e}\u{ff0f}]{0,120}") {
        if let Ok(n) = normalize(&text) {
            prop_assert!(!n.as_str().is_empty() && !n.as_str().starts_with('/'));
            prop_assert!(!n.as_str().contains('\\') && !n.as_str().contains('\0'));
            for part in n.as_str().split('/') {
                prop_assert!(!part.is_empty() && part != "." && part != "..");
            }
            for part in n.key_components() {
                prop_assert!(!part.is_empty() && part != "." && part != ".." && part != ".git");
                prop_assert!(!part.contains('/') && !part.contains('\\') && !part.contains(':'));
            }
            // Resolved lexically from the root the path stays at or below depth 0.
            let mut depth = 0i64;
            for part in n.key_components() {
                depth += if part == ".." { -1 } else { 1 };
                prop_assert!(depth > 0);
            }
        }
    }

    #[test]
    fn normalization_is_idempotent(text in "[./a-zA-Z0-9_ \u{200b}\u{ff21}\u{212a}\u{131}\u{17f}-]{1,80}") {
        if let Ok(n) = normalize(&text) {
            let again = normalize(n.as_str()).expect("a normalized path normalizes again");
            prop_assert_eq!(&again, &n);
            let from_key = normalize(n.key());
            if let Ok(k) = from_key {
                prop_assert_eq!(k.key(), n.key(), "folding the key again changes it");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Groups and modes
// ---------------------------------------------------------------------------------------------

#[test]
fn each_mode_allows_and_refuses_the_operations_the_policy_says() {
    // (path, group, operation, allowed)
    let add = Operation::Add;
    let adds_lines = Operation::Modify {
        gained_lines_only: true,
    };
    let table = [
        // deny_write: nothing but a read
        (
            ".github/workflows/ci.yml",
            "ci_workflows",
            Operation::Read,
            true,
        ),
        (".github/workflows/ci.yml", "ci_workflows", add, false),
        (".github/workflows/ci.yml", "ci_workflows", WRITE, false),
        (
            ".github/workflows/ci.yml",
            "ci_workflows",
            adds_lines,
            false,
        ),
        (
            ".github/workflows/ci.yml",
            "ci_workflows",
            Operation::Delete,
            false,
        ),
        (
            ".github/workflows/ci.yml",
            "ci_workflows",
            Operation::RenameFrom,
            false,
        ),
        (
            ".github/workflows/ci.yml",
            "ci_workflows",
            Operation::ModeChange,
            false,
        ),
        (
            ".github/workflows/ci.yml",
            "ci_workflows",
            Operation::TypeChange,
            false,
        ),
        (".gitmodules", "vcs_internals_and_hooks", WRITE, false),
        ("Cargo.toml", "", WRITE, true),
        // append_only: new files only
        (
            "tests/fixtures/data.json",
            "test_fixtures_and_goldens",
            add,
            true,
        ),
        (
            "tests/fixtures/data.json",
            "test_fixtures_and_goldens",
            WRITE,
            false,
        ),
        (
            "tests/fixtures/data.json",
            "test_fixtures_and_goldens",
            adds_lines,
            false,
        ),
        (
            "tests/fixtures/data.json",
            "test_fixtures_and_goldens",
            Operation::Delete,
            false,
        ),
        // additions_only: new files, and existing files that only gain lines
        ("tests/unit.rs", "test_code", add, true),
        ("tests/unit.rs", "test_code", adds_lines, true),
        ("tests/unit.rs", "test_code", WRITE, false),
        ("tests/unit.rs", "test_code", Operation::Delete, false),
        ("tests/unit.rs", "test_code", Operation::RenameFrom, false),
        ("tests/unit.rs", "test_code", Operation::ModeChange, false),
        ("crates/x/tests/unit.rs", "test_code", WRITE, false),
        ("src/widget.test.ts", "test_code", WRITE, false),
        // hidden: not even a read, and nothing can be created there
        (".env", "secret_bearing_files", Operation::Read, false),
        (".env", "secret_bearing_files", add, false),
        (
            ".env.production",
            "secret_bearing_files",
            Operation::Read,
            false,
        ),
        (
            "keys/server.pem",
            "secret_bearing_files",
            Operation::Read,
            false,
        ),
        (
            "home/id_rsa",
            "secret_bearing_files",
            Operation::Read,
            false,
        ),
        (
            "tests/holdout/case1.rs",
            "evaluation_holdouts",
            Operation::Read,
            false,
        ),
        ("tests/holdout/case1.rs", "evaluation_holdouts", add, false),
        (
            "evals/run.py",
            "evaluation_holdouts",
            Operation::Read,
            false,
        ),
        (
            "pkg/heldout/x",
            "evaluation_holdouts",
            Operation::Read,
            false,
        ),
    ];
    for (path, group, op, allowed) in table {
        let verdict = check(path, op);
        assert_eq!(
            verdict.is_allowed(),
            allowed,
            "{path} {op:?} gave {verdict:?}"
        );
        if !allowed && !group.is_empty() {
            let (_, rule) = denied_by(&verdict).expect("denied");
            // The test_code group also matches some fixture paths, but append_only is stricter.
            assert_eq!(rule, group, "{path} {op:?}");
        }
    }
}

#[test]
fn a_reinclusion_lifts_only_its_own_group() {
    // `.env.example` is re-included in `secret_bearing_files`, so it is a free path.
    assert!(check(".env.example", Operation::Read).is_allowed());
    assert!(check(".env.example", WRITE).is_allowed());
    // The same name is not lifted from another group: under `tests/fixtures` it is still
    // append-only, and under `tests/holdout` it is still hidden.
    assert!(!check("tests/fixtures/.env.example", WRITE).is_allowed());
    assert!(!check("tests/holdout/.env.example", Operation::Read).is_allowed());
    // `.env.local` is not the re-included name.
    assert!(!check(".env.local", Operation::Read).is_allowed());
}

/// Credential files are named the same wherever they sit: a monorepo keeps its `.env` under
/// `apps/web`, a home directory copy under `a/b/.aws`. The globs of `secret_bearing_files` must
/// therefore match at any depth, and under any letter case or ignorable-character spelling.
const SECRET_FILES_AT_ANY_DEPTH: &[&str] = &[
    // the dot-env family
    ".env",
    "apps/web/.env",
    "a/b/c/d/.env",
    ".ENV",
    "apps/web/.ENV",
    "apps/web/.Env.Production",
    ".env.production",
    "apps/web/.env.local",
    "svc/api/.env.staging",
    // direnv loads its secrets from `.envrc`, which `.env.*` does not match (no dot after `env`)
    ".envrc",
    "apps/web/.envrc",
    "a/b/c/d/.ENVRC",
    "apps/web/.e\u{200b}nvrc",
    // dot files of tools that keep credentials
    ".netrc",
    "tools/ci/.netrc",
    ".pypirc",
    "packages/py/.pypirc",
    ".git-credentials",
    "a/b/.git-credentials",
    // directories of credentials, the directory and what is inside
    ".aws",
    ".aws/credentials",
    "a/b/.aws/credentials",
    "home/user/.AWS/Config",
    ".ssh",
    ".ssh/config",
    "a/b/.ssh/known_hosts",
    "ops/.SSH/authorized_keys",
    ".docker/config.json",
    "svc/.docker/config.json",
    "svc/.DOCKER/CONFIG.JSON",
    // aliases of the same names: ignorable characters, trailing dot or space, fullwidth full stop
    "apps/web/.e\u{200b}nv",
    "apps/web/.env.",
    "apps/web/.env ",
    "apps/web/\u{ff0e}env",
    "a/b/.a\u{200d}ws/credentials",
    "a/b/.ne\u{200c}trc",
];

#[test]
fn secret_bearing_files_are_hidden_below_the_repository_root_as_well() {
    for &path in SECRET_FILES_AT_ANY_DEPTH {
        for op in [Operation::Read, Operation::Add, WRITE, Operation::Delete] {
            let verdict = check(path, op);
            assert_eq!(
                denied_by(&verdict),
                Some((PathDenialReason::Hidden, "secret_bearing_files".to_owned())),
                "{path:?} {op:?} gave {verdict:?}"
            );
        }
    }
}

#[test]
fn a_name_that_only_looks_like_a_secret_file_stays_free() {
    for path in [
        "src/environment.rs",
        "apps/web/environment.rs",
        "apps/web/envelope.rs",
        "apps/web/envrc.md",
        "docs/aws.md",
        "docs/ssh.md",
        "src/dotenv.rs",
        "apps/web/.envrc.md.bak/readme",
        "infra/.docker/compose.yml",
        "src/dockerconfig.json",
        "src/.awsome/x",
        "src/netrc.rs",
        // the template is meant to be read and edited, at the root and below it
        ".env.example",
        "apps/web/.env.example",
        "a/b/.ENV.EXAMPLE",
    ] {
        assert!(
            check(path, Operation::Read).is_allowed(),
            "{path:?} must be readable: {:?}",
            check(path, Operation::Read)
        );
        assert!(
            check(path, WRITE).is_allowed(),
            "{path:?} must be writable: {:?}",
            check(path, WRITE)
        );
    }
}

#[test]
fn a_diff_that_adds_or_links_a_secret_file_below_the_root_is_blocked() {
    for &path in SECRET_FILES_AT_ANY_DEPTH {
        let blocked = diff_blocked_by(&[added(path)])
            .unwrap_or_else(|| panic!("a diff that adds {path:?} must be blocked"));
        assert!(
            blocked.iter().any(|(_, g)| g == "secret_bearing_files"),
            "{path:?}: {blocked:?}"
        );
    }
    assert!(diff_blocked_by(&[added("apps/web/environment.rs")]).is_none());
    assert!(diff_blocked_by(&[added("apps/web/.env.example")]).is_none());
    // A link next to the file would read it through the link.
    for (link, target) in [
        ("apps/web/config", ".env"),
        ("apps/web/creds", "../../.aws/credentials"),
        ("tools/link", "../apps/web/.env"),
    ] {
        assert!(
            !policy()
                .check_symlink(RepoKind::Target, link, target)
                .is_allowed(),
            "{link} -> {target} must be refused"
        );
    }
}

#[test]
fn a_reinclusion_does_not_lift_a_protection_that_another_group_gives() {
    // The real policy has no path that both a re-inclusion and a second group name, so a second
    // group is added here: `.env.example` is hidden-exempt in `secret_bearing_files` only.
    let mut json = security_json();
    json["protected_paths"]["groups"]
        .as_array_mut()
        .expect("groups")
        .push(serde_json::json!({
            "id": "project_examples", "mode": "deny_write", "applies_to": "both",
            "globs": [".env.example"], "reason": "x", "threats": ["T-12"]
        }));
    let rules = PathPolicy::from_policy(&security_from(json)).expect("builds");
    let ev = ChangeEvidence::default();
    let verdict = rules.check(RepoKind::Target, ".env.example", WRITE, None, &ev);
    assert_eq!(
        denied_by(&verdict),
        Some((PathDenialReason::DenyWrite, "project_examples".to_owned()))
    );
    // Reading is fine: the hidden group let go of it, and the second group only forbids writes.
    assert!(
        rules
            .check(RepoKind::Target, ".env.example", Operation::Read, None, &ev)
            .is_allowed()
    );
}

#[test]
fn the_most_restrictive_group_decides_when_several_match() {
    // `tests/fixtures/x.json` is append_only (fixtures) and additions_only (tests/**):
    // a modification that only adds lines is fine for the second and refused by the first.
    let verdict = check(
        "tests/fixtures/x.json",
        Operation::Modify {
            gained_lines_only: true,
        },
    );
    assert_eq!(
        denied_by(&verdict).map(|(_, rule)| rule),
        Some("test_fixtures_and_goldens".to_owned())
    );
    // `tests/holdout/a` is hidden (holdouts) and additions_only (tests/**): hidden wins.
    let (reason, rule) = denied_by(&check("tests/holdout/a", Operation::Add)).expect("denied");
    assert_eq!(
        (reason, rule.as_str()),
        (PathDenialReason::Hidden, "evaluation_holdouts")
    );
}

#[test]
fn the_directory_a_protected_glob_names_is_protected_too() {
    // `.github/**` matches what is inside `.github`; a file put in place of the directory, or a
    // link, must not slip past.
    assert!(!check(".github", WRITE).is_allowed());
    assert!(!check(".github", Operation::TypeChange).is_allowed());
    assert!(!check(".claude", Operation::Add).is_allowed());
}

#[test]
fn a_target_repository_is_not_covered_by_the_factory_self_protection_group() {
    let p = policy();
    let ev = ChangeEvidence::default();
    let target = p.check(RepoKind::Target, "policies/security.yaml", WRITE, None, &ev);
    let factory = p.check(
        RepoKind::Factory,
        "policies/security.yaml",
        WRITE,
        None,
        &ev,
    );
    assert!(target.is_allowed());
    assert_eq!(
        denied_by(&factory).map(|(_, r)| r),
        Some("factory_self_protection".to_owned())
    );
}

#[test]
fn sensitive_files_are_allowed_and_reported_with_their_checks() {
    let verdict = check("crates/app/Cargo.toml", WRITE);
    let PathVerdict::Allowed(allowance) = verdict else {
        panic!("a manifest change is allowed");
    };
    let hit = allowance
        .sensitive
        .iter()
        .find(|h| h.group == "dependency_manifests")
        .expect("dependency manifests are sensitive");
    assert!(hit.checks.iter().any(|c| c == "new_dependency"));
    assert!(hit.extra_review.iter().any(|r| r == "security_reviewer"));
}

// ---------------------------------------------------------------------------------------------
// NT-TOOL-04 and NT-GATE-04
// ---------------------------------------------------------------------------------------------

#[test]
fn negative_nt_tool_04_path_policy_refuses_traversal_encoding_and_hidden_files() {
    let hostile = [
        "../../etc/passwd",
        "/etc/passwd",
        "src/../../x",
        "%2e%2e/x",
        "a\0b",
        "a\\b",
        "\u{ff0e}\u{ff0e}/\u{ff0e}\u{ff0e}/etc/passwd",
        ".git/config",
        ".GIT/hooks/pre-commit",
    ];
    for path in hostile {
        for op in [Operation::Read, Operation::Add, WRITE] {
            let verdict = check(path, op);
            let (reason, _) = denied_by(&verdict).unwrap_or_else(|| panic!("{path:?} {op:?}"));
            assert!(
                matches!(reason, PathDenialReason::Unnormalizable(_)),
                "{path:?} {op:?}: {reason:?}"
            );
        }
    }
    // Hidden by case, by group and by directory: reads and writes alike.
    for path in [
        ".ENV",
        ".Env",
        "id_rsa",
        "tests/holdout/x",
        "TESTS/HOLDOUT/X",
    ] {
        for op in [Operation::Read, Operation::Add, WRITE] {
            let (reason, _) =
                denied_by(&check(path, op)).unwrap_or_else(|| panic!("{path} {op:?}"));
            assert_eq!(reason, PathDenialReason::Hidden, "{path} {op:?}");
        }
    }
}

/// Two checks look at a component made of dots: the one that names `..` for what it is, and the one
/// that refuses every component of dots and blanks. A path of `..` is refused by both, so the first
/// cannot be seen by a test that asks only whether the path was refused. This test asks for the
/// reason and the rule that is named, so that each check is held on its own: with the first gone,
/// `..` is still refused, as dot-like, and the rule that is audited is another.
#[test]
fn negative_nt_tool_04_each_traversal_shape_is_refused_for_its_own_reason() {
    for path in [
        "..",
        "../x",
        "a/../b",
        "a/b/..",
        "\u{ff0e}\u{ff0e}/x",
        ".\u{200b}./x",
    ] {
        for op in [Operation::Read, Operation::Add, WRITE] {
            let (reason, rule) =
                denied_by(&check(path, op)).unwrap_or_else(|| panic!("{path:?} {op:?}"));
            assert_eq!(
                reason,
                PathDenialReason::Unnormalizable(PathRefusal::ParentComponent),
                "{path:?} {op:?}"
            );
            assert_eq!(rule, "reject_dotdot", "{path:?} {op:?}");
        }
    }
    // A component of dots and blanks that is not `..` is refused for being dot-like, under the
    // rule of normalization, and not as a parent component.
    for path in ["...", "a/. /b", "a/.../b", "\u{ff0e}/x", "a/\u{200b}/b"] {
        let (reason, rule) =
            denied_by(&check(path, Operation::Read)).unwrap_or_else(|| panic!("{path:?}"));
        assert_eq!(
            reason,
            PathDenialReason::Unnormalizable(PathRefusal::DotLike),
            "{path:?}"
        );
        assert_eq!(rule, "normalization", "{path:?}");
    }
    // The control: a path whose components are ordinary is not refused for either.
    assert!(
        denied_by(&check("src/a.b/c..d/e.rs", Operation::Read)).is_none(),
        "dots inside a name are not traversal"
    );
}

fn diff_blocked_by(entries: &[DiffEntry]) -> Option<Vec<(String, String)>> {
    match policy().check_diff(RepoKind::Target, entries, None, &ChangeEvidence::default()) {
        DiffVerdict::Allowed { .. } => None,
        DiffVerdict::Blocked { denials } => Some(
            denials
                .into_iter()
                .map(|d| (d.path, d.denial.rule.id().to_owned()))
                .collect(),
        ),
    }
}

fn added(path: &str) -> DiffEntry {
    DiffEntry::Added { path: path.into() }
}

#[test]
fn negative_nt_gate_04_every_rename_and_normalization_trick_is_blocked_with_its_group() {
    // Rename out of a protected path: the source side counts.
    let renamed = diff_blocked_by(&[DiffEntry::Renamed {
        from: ".github/workflows/ci.yml".into(),
        to: "docs/ci.yml".into(),
    }])
    .expect("blocked");
    assert!(
        renamed
            .iter()
            .any(|(p, g)| p == ".github/workflows/ci.yml" && g == "ci_workflows")
    );
    // Rename into a protected path: the destination side counts.
    let into = diff_blocked_by(&[DiffEntry::Renamed {
        from: "docs/ci.yml".into(),
        to: ".github/workflows/ci.yml".into(),
    }])
    .expect("blocked");
    assert!(
        into.iter()
            .any(|(p, g)| p == ".github/workflows/ci.yml" && g == "ci_workflows")
    );
    // A copy into a protected path: the destination counts.
    assert!(
        diff_blocked_by(&[DiffEntry::Copied {
            from: "docs/ci.yml".into(),
            to: ".github/workflows/copy.yml".into(),
        }])
        .is_some()
    );

    let blocked_with_group = [
        (added(".GitHub/Workflows/ci.yml"), "ci_workflows"),
        (added(".GITHUB/workflows/ci.yml"), "ci_workflows"),
        // NFD spelling of a name next to a protected directory; the protected part is ASCII.
        (added(".github/workflows/cafe\u{301}.yml"), "ci_workflows"),
        (added(".github./workflows /ci.yml"), "ci_workflows"),
        (added(".gi\u{200b}thub/workflows/ci.yml"), "ci_workflows"),
        (added(".\u{ff27}ithub/workflows/ci.yml"), "ci_workflows"),
        (added("\u{212a}EY.PEM"), "secret_bearing_files"),
        (
            DiffEntry::ModeChanged {
                path: "scripts/ci.sh".into(),
            },
            "gate_and_toolchain_config",
        ),
        (
            DiffEntry::TypeChanged {
                path: ".github/workflows".into(),
            },
            "ci_workflows",
        ),
        (
            DiffEntry::Symlink {
                path: ".github/workflows".into(),
                target: "../docs".into(),
            },
            "ci_workflows",
        ),
        (
            DiffEntry::Deleted {
                path: ".github/workflows/ci.yml".into(),
            },
            "ci_workflows",
        ),
        (
            DiffEntry::Modified {
                path: ".github/workflows/ci.yml".into(),
                gained_lines_only: true,
            },
            "ci_workflows",
        ),
        (
            DiffEntry::Modified {
                path: ".claude/settings.json".into(),
                gained_lines_only: false,
            },
            "agent_instruction_files",
        ),
        (
            added("./.github//workflows/../workflows/ci.yml"),
            "reject_dotdot",
        ),
        (added(".GIT/config"), "reject_dot_git_components"),
        (added("sub/.git/config"), "reject_dot_git_components"),
        (
            DiffEntry::Gitlink {
                path: "vendor/lib".into(),
            },
            "reject_gitlinks",
        ),
    ];
    for (entry, group) in blocked_with_group {
        let blocked = diff_blocked_by(std::slice::from_ref(&entry))
            .unwrap_or_else(|| panic!("{entry:?} must be blocked"));
        if !group.is_empty() {
            assert!(
                blocked.iter().any(|(_, g)| g == group),
                "{entry:?}: wanted {group}, got {blocked:?}"
            );
        }
    }
    // Controls: names that only look like a protected one.
    for control in [
        ".github-docs/readme.md",
        "src/github.rs",
        "docs/githubs.md",
        ".gitignore.bak/x",
        "src/gitmodules.rs",
    ] {
        assert!(
            diff_blocked_by(&[added(control)]).is_none(),
            "{control} must be allowed"
        );
    }
    // A delete and recreate of a protected file is blocked on both sides.
    assert!(
        diff_blocked_by(&[
            DiffEntry::Deleted {
                path: "CODEOWNERS".into()
            },
            added("CODEOWNERS"),
        ])
        .is_some_and(|d| d.len() == 2)
    );
}

#[test]
fn a_rename_counts_as_two_paths_and_a_copy_reads_its_source() {
    // Moving a free file into a free place is fine.
    assert!(
        diff_blocked_by(&[DiffEntry::Renamed {
            from: "src/a.rs".into(),
            to: "src/b.rs".into()
        }])
        .is_none()
    );
    // Copying from a hidden path would leak its content: refused on the source.
    let leak = diff_blocked_by(&[DiffEntry::Copied {
        from: ".env".into(),
        to: "docs/example.txt".into(),
    }])
    .expect("blocked");
    assert!(
        leak.iter()
            .any(|(p, g)| p == ".env" && g == "secret_bearing_files")
    );
    // Copying a protected but readable file is fine.
    assert!(
        diff_blocked_by(&[DiffEntry::Copied {
            from: ".github/workflows/ci.yml".into(),
            to: "docs/ci-example.yml".into()
        }])
        .is_none()
    );
}

#[test]
fn symlinks_must_stay_inside_the_workspace_and_away_from_hidden_paths() {
    let p = policy();
    let target = |link: &str, to: &str| p.check_symlink(RepoKind::Target, link, to);
    for (link, to) in [
        ("docs/link", "../README.md"),
        ("docs/link", "sibling.md"),
        ("link", "src/lib.rs"),
        ("a/b/c/link", "../../x"),
        ("docs/ci", "../.github/workflows/ci.yml"),
    ] {
        assert!(target(link, to).is_allowed(), "{link} -> {to}");
    }
    for (link, to, reason) in [
        ("src/link", "/etc/passwd", PathDenialReason::SymlinkEscapes),
        (
            "src/link",
            "../../etc/passwd",
            PathDenialReason::SymlinkEscapes,
        ),
        ("link", "../x", PathDenialReason::SymlinkEscapes),
        ("a/link", "../../x", PathDenialReason::SymlinkEscapes),
        ("src/link", "a\\b", PathDenialReason::SymlinkEscapes),
        ("src/link", "", PathDenialReason::SymlinkEscapes),
        ("src/link", "%2e%2e/x", PathDenialReason::SymlinkEscapes),
        (
            "src/link",
            "\u{ff0e}\u{ff0e}/../x",
            PathDenialReason::SymlinkEscapes,
        ),
        (
            "src/link",
            "../.env",
            PathDenialReason::SymlinkIntoProtected,
        ),
        (
            "src/link",
            "../tests/holdout/case",
            PathDenialReason::SymlinkIntoProtected,
        ),
        (
            "src/link",
            "../.git/hooks/post-commit",
            PathDenialReason::SymlinkIntoProtected,
        ),
        (
            "src/link",
            "../.GIT/config",
            PathDenialReason::SymlinkIntoProtected,
        ),
    ] {
        let verdict = target(link, to);
        assert_eq!(
            denied_by(&verdict).map(|(r, _)| r),
            Some(reason),
            "{link} -> {to}"
        );
    }
    // A link whose own path is unsafe is refused for that.
    assert!(!target("../link", "x").is_allowed());
}

#[test]
fn a_diff_with_too_many_files_is_blocked_without_being_read() {
    let max = security().path_access.max_files_changed_per_task;
    let entries: Vec<DiffEntry> = (0..=max).map(|i| added(&format!("src/f{i}.rs"))).collect();
    let verdict = policy().check_diff(RepoKind::Target, &entries, None, &ChangeEvidence::default());
    let DiffVerdict::Blocked { denials } = verdict else {
        panic!("blocked");
    };
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].denial.reason, PathDenialReason::TooManyFiles);
}

// ---------------------------------------------------------------------------------------------
// Write scope and deny overrides (NT-POL-04, path half)
// ---------------------------------------------------------------------------------------------

#[test]
fn negative_nt_pol_04_a_protected_group_beats_write_allow() {
    // `write_allow` is `**`, so everything matches it, and the protected group still wins.
    assert_eq!(security().path_access.write_allow[0].0, "**");
    let verdict = check(".github/workflows/ci.yml", WRITE);
    assert_eq!(
        denied_by(&verdict).map(|(r, _)| r),
        Some(PathDenialReason::DenyWrite)
    );
}

#[test]
fn negative_nt_pol_04_a_protected_change_needs_all_three_elements() {
    let p = policy();
    let all = [
        ChangeRequirement::SpecAuthorization,
        ChangeRequirement::IndependentPolicyReview,
        ChangeRequirement::HumanApproval,
    ];
    assert_eq!(p.change_requirements(), all);
    // With nothing, the refusal lists all three. A flag cannot stand in for the human approval:
    // it is a recorded decision that only the authority evaluator can produce.
    let none = ChangeEvidence::default();
    let PathVerdict::Denied(d) = p.check(
        RepoKind::Target,
        ".github/workflows/ci.yml",
        WRITE,
        None,
        &none,
    ) else {
        panic!("denied");
    };
    assert_eq!(d.missing, all);
    let two_flags = ChangeEvidence {
        spec_authorization: true,
        independent_policy_review: true,
        human_approval: None,
    };
    let PathVerdict::Denied(d) = p.check(
        RepoKind::Target,
        ".github/workflows/ci.yml",
        WRITE,
        None,
        &two_flags,
    ) else {
        panic!("denied");
    };
    assert_eq!(d.missing, [ChangeRequirement::HumanApproval]);
    // A hidden path is never lifted: the refusal does not even list requirements.
    let PathVerdict::Denied(d) =
        p.check(RepoKind::Target, ".env", Operation::Read, None, &two_flags)
    else {
        panic!("denied");
    };
    assert_eq!(d.reason, PathDenialReason::Hidden);
    assert!(d.missing.is_empty());
}

#[test]
fn the_task_scope_narrows_write_allow_and_never_widens_a_protected_path() {
    let p = policy();
    let scope = p
        .write_scope(&["src/widget/**", ".github/**"])
        .expect("scope compiles");
    let ev = ChangeEvidence::default();
    let at = |path: &str| p.check(RepoKind::Target, path, WRITE, Some(&scope), &ev);
    assert!(at("src/widget/a.rs").is_allowed());
    assert_eq!(
        denied_by(&at("src/other/a.rs")).map(|(r, _)| r),
        Some(PathDenialReason::OutsideTaskScope)
    );
    // Owning a protected path does not make it writable.
    assert_eq!(
        denied_by(&at(".github/workflows/ci.yml")).map(|(r, _)| r),
        Some(PathDenialReason::DenyWrite)
    );
    // A read is not limited to the scope.
    assert!(
        p.check(
            RepoKind::Target,
            "src/other/a.rs",
            Operation::Read,
            Some(&scope),
            &ev
        )
        .is_allowed()
    );
    // Scope entries are checked the same way as policy globs.
    assert!(matches!(
        p.write_scope(&["src/caf\u{e9}/**"]),
        Err(BuildError::NonAsciiGlob { .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// The rules build only from a policy the engine can honour
// ---------------------------------------------------------------------------------------------

#[test]
fn a_policy_that_turns_a_protection_off_does_not_build() {
    for key in [
        "reject_dotdot",
        "reject_absolute",
        "reject_nul_and_backslash",
        "reject_dot_git_components",
        "reject_gitlinks",
        "case_insensitive",
        "count_rename_source_and_destination",
        "mode_and_type_changes_are_modifications",
    ] {
        let mut json = security_json();
        json["matching"][key] = serde_json::Value::Bool(false);
        let result = PathPolicy::from_policy(&security_from(json));
        assert!(
            matches!(result, Err(BuildError::ProtectionDisabled { .. })),
            "{key}"
        );
    }
}

#[test]
fn a_policy_with_a_non_ascii_glob_or_an_unreadable_hidden_set_does_not_build() {
    let mut json = security_json();
    json["protected_paths"]["groups"][0]["globs"][0] = "docs/caf\u{e9}/**".into();
    assert!(matches!(
        PathPolicy::from_policy(&security_from(json)),
        Err(BuildError::NonAsciiGlob { .. })
    ));

    let mut json = security_json();
    json["path_access"]["deny_read_globs_ref"] =
        "protected_paths.groups[secret_bearing_files]".into();
    assert!(matches!(
        PathPolicy::from_policy(&security_from(json)),
        Err(BuildError::Contradiction(_))
    ));

    let mut json = security_json();
    json["protected_paths"]["default_change_requires"] = serde_json::json!([]);
    assert!(matches!(
        PathPolicy::from_policy(&security_from(json)),
        Err(BuildError::Contradiction(_))
    ));
}

#[test]
fn every_group_of_the_real_policy_classifies_a_sample_of_its_own_glob() {
    // Build a literal path from each non-wildcard glob and check it lands in a group at least as
    // strict as the group that owns the glob. This catches a glob that does not match what it
    // says, and a group that a stricter group silently covers wrongly.
    let policy = security();
    let rules = PathPolicy::from_policy(&policy).expect("builds");
    let strictness = |m: ProtectionMode| match m {
        ProtectionMode::Hidden => 4,
        ProtectionMode::DenyWrite => 3,
        ProtectionMode::AppendOnly => 2,
        ProtectionMode::AdditionsOnly => 1,
    };
    for group in &policy.protected_paths.groups {
        for glob in &group.globs {
            if glob.is_reinclusion() {
                continue;
            }
            let sample = glob
                .pattern()
                .replace("**/", "a/b/")
                .replace("/**", "/x/y")
                .replace('*', "z");
            let Ok(path) = normalize(&sample) else {
                continue; // `.git` samples are refused outright, which is stricter.
            };
            let class = rules
                .classify(
                    match group.applies_to {
                        factory_domain::policy::security::AppliesTo::FactoryRepo => {
                            RepoKind::Factory
                        }
                        _ => RepoKind::Target,
                    },
                    &path,
                )
                .unwrap_or_else(|| panic!("{} ({}) is not protected", sample, group.id));
            assert!(
                strictness(class.0) >= strictness(group.mode),
                "{sample} ({}) landed in {class:?}",
                group.id
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Folding equivalence
// ---------------------------------------------------------------------------------------------

fn vary(text: &str, bits: &[bool]) -> String {
    // Upper-case some letters, insert an ignorable character, turn some letters fullwidth, add a
    // trailing dot to a component.
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        let b = bits.get(i % bits.len().max(1)).copied().unwrap_or(false);
        let b2 = bits
            .get((i + 7) % bits.len().max(1))
            .copied()
            .unwrap_or(false);
        if c == '/' {
            if b {
                out.push('.');
            }
            out.push('/');
            if b2 {
                out.push_str("./");
            }
            continue;
        }
        let c = if b { c.to_ascii_uppercase() } else { c };
        if b2 && c.is_ascii_alphabetic() {
            out.push(char::from_u32(u32::from(c) + 0xfee0).unwrap_or(c));
        } else {
            out.push(c);
        }
        if b && b2 {
            out.push('\u{200c}');
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    #[test]
    fn a_protected_path_stays_protected_under_any_folding_variation(
        bits in proptest::collection::vec(any::<bool>(), 1..40),
        which in 0usize..6,
    ) {
        let samples = [
            (".github/workflows/ci.yml", Operation::Add),
            ("scripts/ci.sh", Operation::Delete),
            ("CODEOWNERS", Operation::ModeChange),
            ("tests/fixtures/data.json", Operation::Delete),
            ("tests/holdout/case.rs", Operation::Read),
            (".env", Operation::Read),
        ];
        let (base, op) = samples[which];
        let varied = vary(base, &bits);
        let verdict = check(&varied, op);
        prop_assert!(
            !verdict.is_allowed(),
            "{base:?} varied to {varied:?} was allowed: {verdict:?}"
        );
    }

    #[test]
    fn every_verdict_is_total_and_a_free_path_stays_free(text in "\\PC{0,120}") {
        // No panic for any text; and an allowed path is one that normalized.
        if check(&text, Operation::Read).is_allowed() {
            prop_assert!(normalize(&text).is_ok());
        }
    }
}
