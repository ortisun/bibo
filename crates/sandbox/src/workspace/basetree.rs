//! What the base commit holds, as the host reads it from the trusted store, and which of those
//! paths the sandbox's checkout is meant to hold.
//!
//! A base commit can hold things that never reach the sandbox: paths the rules hide, entries that
//! cannot be named safely, links that point out of the checkout, submodule entries. Such a path is
//! **absent by design**. The audit must not read its absence as a deletion, and must refuse a file
//! that appears there.

use std::collections::{BTreeMap, BTreeSet};

use factory_ports::paths::{PathMode, PathRules, RepoGlob, RepoPath};
use factory_ports::workspace::WorkspacePurpose;

use crate::workspace::AuditLimits;

/// One entry of the base tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BaseEntry {
    /// The git mode as text: `100644`, `100755`, `120000`.
    pub mode: String,
    /// The object id of the blob.
    pub sha: String,
    /// The size of the blob in bytes.
    pub size: u64,
}

/// A line of `git ls-tree -r -z --long`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeLine {
    pub mode: String,
    pub kind: String,
    pub sha: String,
    /// `None` for a gitlink, which has no size.
    pub size: Option<u64>,
    pub path: Vec<u8>,
}

/// Parses the output of `git ls-tree -r -z --long`. A malformed line is a failure, because the
/// audit must not guess.
pub(crate) fn parse_ls_tree(output: &[u8]) -> Option<Vec<TreeLine>> {
    let mut lines = Vec::new();
    for record in output.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let tab = record.iter().position(|b| *b == b'\t')?;
        let (meta, path) = (&record[..tab], &record[tab + 1..]);
        let meta = std::str::from_utf8(meta).ok()?;
        let mut parts = meta.split_whitespace();
        let mode = parts.next()?.to_owned();
        let kind = parts.next()?.to_owned();
        let sha = parts.next()?.to_owned();
        let size = match parts.next()? {
            "-" => None,
            number => Some(number.parse().ok()?),
        };
        lines.push(TreeLine {
            mode,
            kind,
            sha,
            size,
            path: path.to_vec(),
        });
    }
    Some(lines)
}

/// The base tree split into what the checkout holds and what it does not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BaseTree {
    /// Entries the checkout holds, by exact path.
    pub visible: BTreeMap<String, BaseEntry>,
    /// Paths of the base commit that the checkout does not hold, and that must stay absent.
    pub absent: BTreeSet<String>,
    /// Submodule entries. They are kept in every commit and nothing may appear below them.
    pub gitlinks: BTreeSet<String>,
}

/// Why a base tree cannot be checked out at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BaseTreeError {
    /// A file is over the limit, or there are too many entries.
    TooLarge,
    /// Two paths differ only by case or Unicode form, so a case-insensitive host file system
    /// would write one through the other.
    Collision,
}

impl BaseTree {
    /// Splits `lines` for `purpose`. A hidden path is absent, except in a verify checkout that
    /// names it in its holdouts.
    ///
    /// `links` holds the target text of every symbolic link of the base, by path. A link whose
    /// target leaves the checkout (lexically or by following other links) is not written; the
    /// base commit keeps it.
    pub(crate) fn build(
        lines: &[TreeLine],
        links: &BTreeMap<String, String>,
        rules: &PathRules,
        purpose: &WorkspacePurpose,
        limits: &AuditLimits,
    ) -> Result<Self, BaseTreeError> {
        if lines.len() > limits.max_entries {
            return Err(BaseTreeError::TooLarge);
        }
        let holdouts: &[RepoGlob] = match purpose {
            WorkspacePurpose::Agent => &[],
            WorkspacePurpose::Verify { holdouts } => holdouts,
        };
        let mut tree = Self::default();
        let mut folded: BTreeMap<String, String> = BTreeMap::new();
        let mut total: u64 = 0;
        for line in lines {
            let Ok(text) = std::str::from_utf8(&line.path) else {
                tree.absent
                    .insert(String::from_utf8_lossy(&line.path).into_owned());
                continue;
            };
            if line.mode == "160000" {
                tree.gitlinks.insert(text.to_owned());
                continue;
            }
            let Ok(path) = RepoPath::new(text) else {
                tree.absent.insert(text.to_owned());
                continue;
            };
            let hidden = rules.classify(&path) == Some(PathMode::Hidden);
            let holdout = holdouts.iter().any(|glob| glob.matches_folded(&path));
            if hidden && !holdout {
                tree.absent.insert(text.to_owned());
                continue;
            }
            if line.kind != "blob" {
                tree.absent.insert(text.to_owned());
                continue;
            }
            let size = line.size.unwrap_or(0);
            if line.mode == "120000" && !links.contains_key(text) {
                tree.absent.insert(text.to_owned());
                continue;
            }
            if size > limits.max_file_bytes {
                return Err(BaseTreeError::TooLarge);
            }
            total = total.saturating_add(size);
            if total > limits.max_total_bytes {
                return Err(BaseTreeError::TooLarge);
            }
            tree.visible.insert(
                text.to_owned(),
                BaseEntry {
                    mode: line.mode.clone(),
                    sha: line.sha.clone(),
                    size,
                },
            );
        }
        // A link that leaves the checkout, alone or through other links, is not written.
        let table: BTreeMap<String, String> = tree
            .visible
            .iter()
            .filter(|(_, entry)| entry.mode == "120000")
            .filter_map(|(path, _)| links.get(path).map(|t| (path.clone(), t.clone())))
            .collect();
        for (path, target) in &table {
            if crate::workspace::audit::symlink_leaves(&table, path, target, rules) {
                tree.visible.remove(path);
                tree.absent.insert(path.clone());
            }
        }
        // Collisions: two names that a case-insensitive file system treats as one.
        for path in tree.visible.keys() {
            let mut prefix = String::new();
            for component in path.split('/') {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                let key = fold_key(&prefix);
                match folded.get(&key) {
                    Some(existing) if existing != &prefix => {
                        return Err(BaseTreeError::Collision);
                    }
                    Some(_) => {}
                    None => {
                        folded.insert(key, prefix.clone());
                    }
                }
            }
        }
        Ok(tree)
    }

    /// True when a path below a submodule entry exists in the checkout.
    pub(crate) fn gitlink_above(&self, path: &str) -> Option<&str> {
        let mut prefix = String::new();
        for component in path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if let Some(found) = self.gitlinks.get(prefix.as_str()) {
                return Some(found.as_str());
            }
        }
        None
    }
}

/// The folded spelling of a path: the one the policy's own normalization compares on, or the
/// lower-cased text when the normalization refuses the path.
fn fold_key(path: &str) -> String {
    factory_domain::policy::paths::normalize(path)
        .map_or_else(|_| path.to_lowercase(), |n| n.key().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_ports::paths::PathRule;

    fn line(mode: &str, path: &str, size: u64) -> TreeLine {
        TreeLine {
            mode: mode.to_owned(),
            kind: if mode == "160000" { "commit" } else { "blob" }.to_owned(),
            sha: "a".repeat(40),
            size: (mode != "160000").then_some(size),
            path: path.as_bytes().to_vec(),
        }
    }

    fn hide(glob: &str) -> PathRules {
        PathRules::new(vec![(
            "g".to_owned(),
            PathRule::Mode {
                glob: RepoGlob::new(glob).expect("a glob"),
                mode: PathMode::Hidden,
            },
        )])
    }

    #[test]
    fn a_listing_is_parsed_with_its_sizes_and_gitlinks() {
        let out = b"100644 blob aaaa    12\tsrc/lib.rs\x00160000 commit bbbb       -\tvendor/x\x00";
        let parsed = parse_ls_tree(out).expect("parsed");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].size, Some(12));
        assert_eq!(parsed[1].size, None);
        assert!(parse_ls_tree(b"garbage").is_none());
    }

    #[test]
    fn hidden_paths_and_gitlinks_are_absent_by_design_and_holdouts_are_visible_in_verify() {
        let lines = [
            line("100644", "src/lib.rs", 3),
            line("100644", "tests/holdout/a.rs", 3),
            line("160000", "vendor/lib", 0),
        ];
        let rules = hide("tests/holdout/**");
        let limits = AuditLimits::default();
        let agent = BaseTree::build(
            &lines,
            &BTreeMap::new(),
            &rules,
            &WorkspacePurpose::Agent,
            &limits,
        )
        .expect("a");
        assert!(agent.visible.contains_key("src/lib.rs"));
        assert!(agent.absent.contains("tests/holdout/a.rs"));
        assert!(agent.gitlinks.contains("vendor/lib"));
        assert_eq!(agent.gitlink_above("vendor/lib/x.c"), Some("vendor/lib"));
        let verify = BaseTree::build(
            &lines,
            &BTreeMap::new(),
            &rules,
            &WorkspacePurpose::Verify {
                holdouts: vec![RepoGlob::new("tests/holdout/**").expect("a glob")],
            },
            &limits,
        )
        .expect("v");
        assert!(verify.visible.contains_key("tests/holdout/a.rs"));
    }

    #[test]
    fn a_base_with_names_that_collide_on_a_case_insensitive_host_is_refused() {
        let lines = [line("100644", "a/x", 1), line("100644", "A/y", 1)];
        let result = BaseTree::build(
            &lines,
            &BTreeMap::new(),
            &PathRules::default(),
            &WorkspacePurpose::Agent,
            &AuditLimits::default(),
        );
        assert_eq!(result, Err(BaseTreeError::Collision));
    }

    #[test]
    fn a_base_file_over_the_limit_is_refused_when_the_workspace_is_made() {
        let lines = [line("100644", "big.bin", 6 * 1024 * 1024)];
        let result = BaseTree::build(
            &lines,
            &BTreeMap::new(),
            &PathRules::default(),
            &WorkspacePurpose::Agent,
            &AuditLimits::default(),
        );
        assert_eq!(result, Err(BaseTreeError::TooLarge));
    }
}
