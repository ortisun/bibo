//! A fresh home directory for every run.
//!
//! Both tools keep configuration under `$HOME` (`~/.claude/settings.json`, `~/.codex/config.toml`),
//! and Claude Code reads the user settings source on purpose (`--setting-sources user`). Several
//! runs can share one sandbox, for example the skill runs of the specification stage, so a home
//! directory that outlives a run would let one run's agent plant the configuration of the next. Each
//! run gets a new directory with a name the earlier run could not have known: the attempt, a counter
//! and the clock. It is made with mode 0700 inside the scratch tmpfs.

use std::fmt::Display;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The program that makes the directory.
const MKDIR: &str = "/usr/bin/mkdir";

/// Hands out home directory paths under one root.
#[derive(Debug)]
pub struct HomeAllocator {
    root: String,
    counter: AtomicU64,
}

impl HomeAllocator {
    /// Homes go under `root`, which is the scratch tmpfs (`/tmp`).
    #[must_use]
    pub fn new(root: &str) -> Self {
        Self {
            root: root.trim_end_matches('/').to_owned(),
            counter: AtomicU64::new(0),
        }
    }

    /// The path of the next home. Nothing is created yet.
    #[must_use]
    pub fn next(&self, attempt: impl Display) -> String {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("{}/h-{attempt}-{nanos:x}-{n}", self.root)
    }
}

/// The argument vector that makes a home directory with mode 0700.
#[must_use]
pub fn make_home_argv(path: &str) -> Vec<String> {
    vec![
        MKDIR.to_owned(),
        "-m".to_owned(),
        "0700".to_owned(),
        path.to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_home_is_new_and_stays_under_the_root() {
        let homes = HomeAllocator::new("/tmp/");
        let a = homes.next("attempt-1");
        let b = homes.next("attempt-1");
        assert_ne!(a, b);
        assert!(a.starts_with("/tmp/h-attempt-1-"));
        assert!(!a.contains(".."));
    }

    #[test]
    fn the_mkdir_vector_has_the_mode_and_no_shell() {
        let argv = make_home_argv("/tmp/h-x");
        assert_eq!(argv, ["/usr/bin/mkdir", "-m", "0700", "/tmp/h-x"]);
    }
}
