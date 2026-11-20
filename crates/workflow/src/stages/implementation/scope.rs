//! The scope check: every path a task changed is a path the task owns.
//!
//! The plan names the globs each task may write (`owned_files`). The audited ingestion lists the
//! paths a task really changed. This module compares them and nothing else. A glob or a path that
//! cannot be read is a failure, never a pass, because a check that skips what it cannot parse
//! would let that path through.

use factory_ports::paths::{RepoGlob, RepoPath};

/// A path a task changed that it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfScope {
    /// The task.
    pub task: String,
    /// The path.
    pub path: String,
}

/// The paths in `changed` that no glob of `owned` matches.
#[must_use]
pub fn outside(task: &str, owned: &[String], changed: &[String]) -> Vec<OutOfScope> {
    let globs: Vec<Option<RepoGlob>> = owned.iter().map(|g| RepoGlob::new(g).ok()).collect();
    changed
        .iter()
        .filter(|path| {
            let Ok(path) = RepoPath::new(path) else {
                return true;
            };
            !globs.iter().flatten().any(|glob| glob.matches(&path))
        })
        .map(|path| OutOfScope {
            task: task.to_owned(),
            path: path.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned() -> Vec<String> {
        vec!["src/main.rs".to_owned(), "tests/**".to_owned()]
    }

    #[test]
    fn a_path_a_glob_matches_is_in_scope() {
        let changed = vec!["src/main.rs".to_owned(), "tests/it/a.rs".to_owned()];
        assert!(outside("t", &owned(), &changed).is_empty());
    }

    #[test]
    fn a_path_no_glob_matches_is_named() {
        let changed = vec!["src/main.rs".to_owned(), "src/other.rs".to_owned()];
        let found = outside("t", &owned(), &changed);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "src/other.rs");
        assert_eq!(found[0].task, "t");
    }

    #[test]
    fn a_task_that_owns_nothing_may_change_nothing() {
        let changed = vec!["src/main.rs".to_owned()];
        assert_eq!(outside("t", &[], &changed).len(), 1);
    }

    #[test]
    fn a_path_that_cannot_be_read_is_out_of_scope() {
        let changed = vec!["../escape".to_owned(), "/etc/passwd".to_owned()];
        assert_eq!(outside("t", &owned(), &changed).len(), 2);
    }

    #[test]
    fn a_glob_that_cannot_be_read_grants_nothing() {
        let broken = vec!["[".to_owned()];
        assert_eq!(outside("t", &broken, &["src/main.rs".to_owned()]).len(), 1);
    }
}
