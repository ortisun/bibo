//! The protected-path evaluation of a change set.
//!
//! The change set is computed by host git from two trees in the trusted store, with rename
//! detection off, so a rename arrives as the deletion of the old path and the addition of the new
//! one and each end meets the rules on its own. A change of mode or of type (a file that becomes a
//! link) is a modification.
//!
//! Every decision about a path comes from [`PathRules::classify`], which folds case and Unicode
//! and knows the aliases of `.git`. When the provider is also given the compiled policy
//! ([`PathPolicyLayer`]), the same change set goes through `PathPolicy::check_diff` as well, and
//! the stricter of the two answers stands. Nothing here matches a glob.

use factory_domain::policy::paths::{DiffEntry, DiffVerdict, PathDenialReason, normalize};
use factory_ports::paths::{PathMode, PathRules, RepoPath};
use factory_ports::workspace::{ChangeKind, ChangedPath, PathViolation};

use super::audit::report_path;
use super::provider::PathPolicyLayer;

/// What the evaluation needs to know about one changed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChangeFacts {
    pub path: RepoPath,
    pub kind: ChangeKind,
    /// The git mode before, if the path existed.
    pub old_mode: Option<String>,
    /// The git mode after, if the path exists.
    pub new_mode: Option<String>,
    pub old_sha: Option<String>,
    pub new_sha: Option<String>,
    /// True when the file only gained lines (no line removed or changed, same mode and type).
    pub gained_lines_only: bool,
    /// The link text, for a path that is a link after the change.
    pub link_target: Option<String>,
}

impl ChangeFacts {
    /// True for a change from one kind of entry to another, such as a file that became a link.
    fn type_changed(&self) -> bool {
        match (&self.old_mode, &self.new_mode) {
            (Some(old), Some(new)) => entry_type(old) != entry_type(new),
            _ => false,
        }
    }

    pub(crate) fn changed_path(&self) -> ChangedPath {
        ChangedPath {
            path: self.path.clone(),
            kind: self.kind,
        }
    }
}

/// `file`, `link` or `gitlink`, from a git mode.
fn entry_type(mode: &str) -> &'static str {
    match mode {
        "120000" => "link",
        "160000" => "gitlink",
        _ => "file",
    }
}

/// The answer for a change set.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Evaluation {
    /// Every path that broke its mode. Empty when the change may go on.
    pub violations: Vec<PathViolation>,
    /// The changed paths the rules classify as sensitive.
    pub sensitive: Vec<RepoPath>,
    /// The first path that is a submodule entry or a `.gitmodules` file.
    pub gitlink: Option<RepoPath>,
}

fn is_gitmodules(path: &RepoPath) -> bool {
    normalize(path.as_str()).is_ok_and(|n| n.key_components().last() == Some(".gitmodules"))
}

/// Decides every change against the rules.
pub(crate) fn evaluate(
    rules: &PathRules,
    layer: Option<&PathPolicyLayer>,
    facts: &[ChangeFacts],
) -> Evaluation {
    let mut out = Evaluation::default();
    for fact in facts {
        let involves_gitlink = [&fact.old_mode, &fact.new_mode]
            .iter()
            .any(|m| m.as_deref() == Some("160000"));
        if out.gitlink.is_none()
            && (involves_gitlink || (fact.kind != ChangeKind::Deleted && is_gitmodules(&fact.path)))
        {
            out.gitlink = Some(fact.path.clone());
        }
        let mode = rules.classify(&fact.path);
        let broke = match mode {
            Some(PathMode::DenyWrite) => true,
            Some(PathMode::AppendOnly) => fact.kind != ChangeKind::Added,
            Some(PathMode::AdditionsOnly) => match fact.kind {
                ChangeKind::Added => false,
                ChangeKind::Modified => fact.type_changed() || !fact.gained_lines_only,
                ChangeKind::Deleted => true,
            },
            Some(PathMode::Hidden | PathMode::Sensitive) | None => false,
        };
        if broke {
            out.violations.push(PathViolation {
                path: fact.path.clone(),
                mode: mode.unwrap_or(PathMode::DenyWrite),
            });
        }
        if mode == Some(PathMode::Sensitive) {
            out.sensitive.push(fact.path.clone());
        }
    }
    if let Some(layer) = layer {
        for violation in layer_violations(layer, facts) {
            if !out.violations.contains(&violation) {
                out.violations.push(violation);
            }
        }
    }
    out.violations.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn diff_entries(facts: &[ChangeFacts]) -> Vec<DiffEntry> {
    facts
        .iter()
        .map(|fact| {
            let path = fact.path.as_str().to_owned();
            match fact.kind {
                ChangeKind::Added => match &fact.link_target {
                    Some(target) => DiffEntry::Symlink {
                        path,
                        target: target.clone(),
                    },
                    None => DiffEntry::Added { path },
                },
                ChangeKind::Deleted => DiffEntry::Deleted { path },
                ChangeKind::Modified => {
                    if fact.type_changed() {
                        DiffEntry::TypeChanged { path }
                    } else if fact.old_sha == fact.new_sha {
                        DiffEntry::ModeChanged { path }
                    } else if let Some(target) = &fact.link_target {
                        DiffEntry::Symlink {
                            path,
                            target: target.clone(),
                        }
                    } else {
                        DiffEntry::Modified {
                            path,
                            gained_lines_only: fact.gained_lines_only,
                        }
                    }
                }
            }
        })
        .collect()
}

fn layer_violations(layer: &PathPolicyLayer, facts: &[ChangeFacts]) -> Vec<PathViolation> {
    let DiffVerdict::Blocked { denials } = layer.check_diff(&diff_entries(facts)) else {
        return Vec::new();
    };
    denials
        .into_iter()
        .map(|denied| {
            let mode = match denied.denial.reason {
                PathDenialReason::Hidden => PathMode::Hidden,
                PathDenialReason::AppendOnly => PathMode::AppendOnly,
                PathDenialReason::AdditionsOnly => PathMode::AdditionsOnly,
                _ => PathMode::DenyWrite,
            };
            let path = if denied.path.is_empty() {
                report_path(b"_too_many_files_")
            } else {
                RepoPath::new(&denied.path).unwrap_or_else(|_| report_path(denied.path.as_bytes()))
            };
            PathViolation { path, mode }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_ports::paths::{PathRule, RepoGlob};

    fn rules() -> PathRules {
        let mode = |glob: &str, mode: PathMode| {
            (
                "g".to_owned(),
                PathRule::Mode {
                    glob: RepoGlob::new(glob).expect("glob"),
                    mode,
                },
            )
        };
        PathRules::new(vec![
            mode(".github/**", PathMode::DenyWrite),
            mode("CHANGELOG.md", PathMode::AppendOnly),
            mode("docs/notes.md", PathMode::AdditionsOnly),
            mode("Cargo.toml", PathMode::Sensitive),
        ])
    }

    fn fact(path: &str, kind: ChangeKind) -> ChangeFacts {
        ChangeFacts {
            path: RepoPath::new(path).expect("path"),
            kind,
            old_mode: (kind != ChangeKind::Added).then(|| "100644".to_owned()),
            new_mode: (kind != ChangeKind::Deleted).then(|| "100644".to_owned()),
            old_sha: Some("a".repeat(40)),
            new_sha: Some("b".repeat(40)),
            gained_lines_only: false,
            link_target: None,
        }
    }

    fn broken(facts: &[ChangeFacts]) -> Vec<(String, PathMode)> {
        evaluate(&rules(), None, facts)
            .violations
            .into_iter()
            .map(|v| (v.path.as_str().to_owned(), v.mode))
            .collect()
    }

    #[test]
    fn each_mode_allows_and_refuses_what_the_policy_says() {
        assert_eq!(
            broken(&[
                fact(".github/ci.yml", ChangeKind::Added),
                fact("CHANGELOG.md", ChangeKind::Modified),
                fact("docs/notes.md", ChangeKind::Deleted),
                fact("src/free.rs", ChangeKind::Modified),
            ]),
            vec![
                (".github/ci.yml".to_owned(), PathMode::DenyWrite),
                ("CHANGELOG.md".to_owned(), PathMode::AppendOnly),
                ("docs/notes.md".to_owned(), PathMode::AdditionsOnly),
            ]
        );
        assert!(broken(&[fact("CHANGELOG.md", ChangeKind::Added)]).is_empty());
        let mut gain = fact("docs/notes.md", ChangeKind::Modified);
        gain.gained_lines_only = true;
        assert!(broken(&[gain.clone()]).is_empty());
        // A mode or type change is a modification, whatever the line counts say.
        gain.new_mode = Some("120000".to_owned());
        assert_eq!(broken(&[gain]).len(), 1);
    }

    #[test]
    fn a_rename_is_two_paths_and_both_ends_meet_the_rules() {
        // `.github/ci.yml` renamed to `elsewhere.yml` arrives as a deletion and an addition.
        let violations = broken(&[
            fact(".github/ci.yml", ChangeKind::Deleted),
            fact("elsewhere.yml", ChangeKind::Added),
        ]);
        assert_eq!(
            violations,
            vec![(".github/ci.yml".to_owned(), PathMode::DenyWrite)]
        );
        // The other direction: a free file renamed into a protected directory.
        let violations = broken(&[
            fact("free.yml", ChangeKind::Deleted),
            fact(".github/free.yml", ChangeKind::Added),
        ]);
        assert_eq!(
            violations,
            vec![(".github/free.yml".to_owned(), PathMode::DenyWrite)]
        );
    }

    #[test]
    fn a_case_variant_and_a_composed_form_meet_the_same_rule() {
        assert_eq!(
            broken(&[fact(".GitHub/Workflows/ci.yml", ChangeKind::Added)]),
            vec![(".GitHub/Workflows/ci.yml".to_owned(), PathMode::DenyWrite)]
        );
    }

    #[test]
    fn sensitive_paths_are_reported_and_allowed() {
        let evaluation = evaluate(&rules(), None, &[fact("Cargo.toml", ChangeKind::Modified)]);
        assert!(evaluation.violations.is_empty());
        assert_eq!(evaluation.sensitive.len(), 1);
    }

    #[test]
    fn a_gitmodules_file_or_a_gitlink_is_reported() {
        let evaluation = evaluate(
            &rules(),
            None,
            &[fact("sub/.gitmodules", ChangeKind::Added)],
        );
        assert!(evaluation.gitlink.is_some());
        let mut link = fact("vendor/x", ChangeKind::Added);
        link.new_mode = Some("160000".to_owned());
        assert!(evaluate(&rules(), None, &[link]).gitlink.is_some());
        assert!(
            evaluate(&rules(), None, &[fact("a.rs", ChangeKind::Added)])
                .gitlink
                .is_none()
        );
    }
}
