//! `factory_ports::paths::PathRules` is what the workspace adapters and the fakes call, and
//! `factory_domain::policy::paths::PathPolicy` is what the policy evaluation calls. The two are
//! built from the same policy groups and must not disagree in the dangerous direction: whatever
//! the ports rules protect, the domain rules protect at least as strictly. The domain crate cannot
//! import the ports crate, so this crate, which depends on both, holds the check.
//!
//! The reverse is allowed to differ on purpose. The domain rules also fold the characters git
//! ignores in a name, fullwidth letters and a few more spellings, so they may protect a path the
//! ports rules do not.

mod support;

use factory_contracts::policy::security::{AppliesTo, ProtectionMode};
use factory_contracts::policy::{PolicyLoader, ProtectedPolicySource, SecurityPolicy};
use factory_domain::policy::RepoKind;
use factory_domain::policy::paths::PathPolicy;
use factory_ports::paths::{PathMode, PathRule, PathRules, RepoGlob, RepoPath};
use support::repo_root;

fn policy() -> SecurityPolicy {
    let source = ProtectedPolicySource::protected_default_branch(&repo_root(), &[])
        .expect("the repository root exists");
    PolicyLoader::load_security(&source)
        .expect("the security policy loads")
        .document
}

/// The ports rules for a target repository, built from the policy in policy order.
fn ports_rules(policy: &SecurityPolicy) -> PathRules {
    let mut rules = Vec::new();
    for group in &policy.protected_paths.groups {
        if matches!(group.applies_to, AppliesTo::FactoryRepo) {
            continue;
        }
        let mode = match group.mode {
            ProtectionMode::Hidden => PathMode::Hidden,
            ProtectionMode::DenyWrite => PathMode::DenyWrite,
            ProtectionMode::AppendOnly => PathMode::AppendOnly,
            ProtectionMode::AdditionsOnly => PathMode::AdditionsOnly,
        };
        for glob in &group.globs {
            let Ok(parsed) = RepoGlob::new(glob.pattern()) else {
                continue;
            };
            let rule = if glob.is_reinclusion() {
                PathRule::Reinclude {
                    glob: parsed,
                    group: group.id.clone(),
                }
            } else {
                PathRule::Mode { glob: parsed, mode }
            };
            rules.push((group.id.clone(), rule));
        }
    }
    PathRules::new(rules)
}

fn strictness(mode: PathMode) -> u8 {
    match mode {
        PathMode::Hidden => 5,
        PathMode::DenyWrite => 4,
        PathMode::AppendOnly => 3,
        PathMode::AdditionsOnly => 2,
        PathMode::Sensitive => 1,
    }
}

fn domain_strictness(mode: ProtectionMode) -> u8 {
    match mode {
        ProtectionMode::Hidden => 5,
        ProtectionMode::DenyWrite => 4,
        ProtectionMode::AppendOnly => 3,
        ProtectionMode::AdditionsOnly => 2,
    }
}

fn samples(policy: &SecurityPolicy) -> Vec<String> {
    let mut out = Vec::new();
    for group in &policy.protected_paths.groups {
        for glob in &group.globs {
            let literal = glob
                .pattern()
                .replace("**/", "a/b/")
                .replace("/**", "/x/y")
                .replace('*', "z")
                .replace('?', "q");
            out.push(literal.clone());
            out.push(literal.to_uppercase());
            out.push(format!("sub/{literal}"));
            out.push(literal.replace('/', "//"));
        }
    }
    out.extend(
        [
            "src/lib.rs",
            ".github-docs/readme.md",
            "src/github.rs",
            ".env.example",
            "tests/unit.rs",
            "docs/a.md",
            "tests/fixtures/x.json",
            "tests/holdout/y",
            "a/b/c.snap",
        ]
        .map(str::to_owned),
    );
    out
}

#[test]
fn the_domain_rules_protect_at_least_what_the_ports_rules_protect() {
    let policy = policy();
    let ports = ports_rules(&policy);
    let domain = PathPolicy::from_policy(&policy).expect("the domain rules build");
    let mut compared = 0usize;
    for text in samples(&policy) {
        // The ports type refuses a path that is not a safe relative path; such a path never
        // reaches `classify` there, and the domain rules refuse it as well.
        let Ok(path) = RepoPath::new(&text) else {
            continue;
        };
        let Some(ports_mode) = ports.classify(&path) else {
            continue;
        };
        compared += 1;
        let normalized =
            factory_domain::policy::paths::normalize(path.as_str()).unwrap_or_else(|e| {
                panic!("{text:?} is a safe path for ports and refused by domain: {e}")
            });
        let (mode, group) = domain
            .classify(RepoKind::Target, &normalized)
            .unwrap_or_else(|| {
                panic!("{text:?}: ports protect it as {ports_mode:?}, domain does not")
            });
        assert!(
            domain_strictness(mode) >= strictness(ports_mode),
            "{text:?}: ports say {ports_mode:?}, domain says {mode:?} (group {group})"
        );
    }
    assert!(
        compared > 100,
        "the comparison covered only {compared} paths"
    );
}
