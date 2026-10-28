//! The trusted tree diff, as entries the path policy can decide.
//!
//! The control plane reads the changed paths and both versions of each file from the job's object
//! store, on the host, after the sandbox is gone. This module turns that into the
//! [`DiffEntry`] list that `PathPolicy::check_diff` decides. Whether an existing file only gained
//! lines is computed from the two file versions ([`lines::gained_lines_only`]), never taken from
//! a patch or from anything the sandbox said.

use factory_domain::policy::paths::DiffEntry;
use factory_ports::workspace::ChangeKind;

use super::lines;
use super::patch::{Facts, GITLINK_MODE, PatchFact, SYMLINK_MODE};

/// One changed path with both of its versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    /// The path, as the object store names it.
    pub path: String,
    /// Whether it was added, modified or deleted.
    pub kind: ChangeKind,
    /// The file at the base commit, for a modified or deleted file.
    pub before: Option<Vec<u8>>,
    /// The file at the head commit, for an added or modified file.
    pub after: Option<Vec<u8>>,
    /// False when a version could not be read (it was too large, or the store failed). A gate
    /// that needs the content is `BLOCKED` for such a file.
    pub readable: bool,
}

impl FileChange {
    /// What the file held before, empty for a new file.
    #[must_use]
    pub fn before_or_empty(&self) -> &[u8] {
        self.before.as_deref().unwrap_or_default()
    }

    /// What the file holds now, empty for a deleted file.
    #[must_use]
    pub fn after_or_empty(&self) -> &[u8] {
        self.after.as_deref().unwrap_or_default()
    }
}

/// The diff entries of a change.
#[must_use]
pub fn entries(files: &[FileChange], facts: &Facts) -> Vec<DiffEntry> {
    let mut found = Vec::new();
    for file in files {
        let fact = facts.find(&file.path);
        let path = file.path.clone();
        match file.kind {
            ChangeKind::Deleted => found.push(DiffEntry::Deleted { path }),
            ChangeKind::Added => found.push(added_entry(path, fact)),
            ChangeKind::Modified => modified_entries(file, fact, &mut found),
        }
    }
    // A rename or a copy the patch names is two paths for the policy, and it must not hide
    // behind an add and a delete.
    for fact in facts.files() {
        if let Some(from) = &fact.renamed_from {
            found.push(DiffEntry::Renamed {
                from: from.clone(),
                to: fact.new_path.clone(),
            });
        }
        if let Some(from) = &fact.copied_from {
            found.push(DiffEntry::Copied {
                from: from.clone(),
                to: fact.new_path.clone(),
            });
        }
    }
    found
}

fn added_entry(path: String, fact: Option<&PatchFact>) -> DiffEntry {
    match fact.and_then(|fact| fact.new_mode.map(PatchFact::kind_of)) {
        Some(GITLINK_MODE) => DiffEntry::Gitlink { path },
        Some(SYMLINK_MODE) => DiffEntry::Symlink {
            target: fact
                .and_then(|fact| fact.link_target.clone())
                .unwrap_or_default(),
            path,
        },
        _ => DiffEntry::Added { path },
    }
}

fn modified_entries(file: &FileChange, fact: Option<&PatchFact>, found: &mut Vec<DiffEntry>) {
    let path = file.path.clone();
    let modes = fact.and_then(|fact| Some((fact.old_mode?, fact.new_mode?)));
    let content_changed = file.before != file.after;
    if let Some((old, new)) = modes {
        if PatchFact::kind_of(new) == GITLINK_MODE {
            found.push(DiffEntry::Gitlink { path });
            return;
        }
        if PatchFact::kind_of(old) != PatchFact::kind_of(new) {
            found.push(DiffEntry::TypeChanged { path: path.clone() });
            if PatchFact::kind_of(new) == SYMLINK_MODE {
                found.push(DiffEntry::Symlink {
                    target: fact
                        .and_then(|fact| fact.link_target.clone())
                        .unwrap_or_default(),
                    path,
                });
            }
            return;
        }
        if old != new {
            found.push(DiffEntry::ModeChanged { path: path.clone() });
            if !content_changed {
                return;
            }
        }
    }
    let gained_lines_only =
        file.readable && lines::gained_lines_only(file.before_or_empty(), file.after_or_empty());
    found.push(DiffEntry::Modified {
        path,
        gained_lines_only,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::scope::patch;

    fn change(
        path: &str,
        kind: ChangeKind,
        before: Option<&str>,
        after: Option<&str>,
    ) -> FileChange {
        FileChange {
            path: path.to_owned(),
            kind,
            before: before.map(|text| text.as_bytes().to_vec()),
            after: after.map(|text| text.as_bytes().to_vec()),
            readable: true,
        }
    }

    #[test]
    fn added_modified_and_deleted_files_become_their_entries() {
        let files = [
            change("a.txt", ChangeKind::Added, None, Some("x\n")),
            change("b.txt", ChangeKind::Modified, Some("x\n"), Some("x\ny\n")),
            change("c.txt", ChangeKind::Modified, Some("x\ny\n"), Some("x\n")),
            change("d.txt", ChangeKind::Deleted, Some("x\n"), None),
        ];
        let entries = entries(&files, &Facts::default());
        assert_eq!(
            entries,
            vec![
                DiffEntry::Added {
                    path: "a.txt".into()
                },
                DiffEntry::Modified {
                    path: "b.txt".into(),
                    gained_lines_only: true
                },
                DiffEntry::Modified {
                    path: "c.txt".into(),
                    gained_lines_only: false
                },
                DiffEntry::Deleted {
                    path: "d.txt".into()
                },
            ]
        );
    }

    #[test]
    fn an_unreadable_file_is_never_counted_as_gaining_lines_only() {
        let mut file = change("t.rs", ChangeKind::Modified, Some("x\n"), Some("x\ny\n"));
        file.readable = false;
        assert_eq!(
            entries(&[file], &Facts::default()),
            vec![DiffEntry::Modified {
                path: "t.rs".into(),
                gained_lines_only: false
            }]
        );
    }

    #[test]
    fn a_mode_change_a_new_symlink_and_a_gitlink_are_found_in_the_headers() {
        let facts = patch::parse(
            "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\ndiff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+../x\ndiff --git a/g b/g\nnew file mode 160000\n"
                .as_bytes(),
        );
        let files = [
            change(
                "run.sh",
                ChangeKind::Modified,
                Some("echo\n"),
                Some("echo\n"),
            ),
            change("l", ChangeKind::Added, None, Some("../x")),
            change("g", ChangeKind::Added, None, Some("")),
        ];
        assert_eq!(
            entries(&files, &facts),
            vec![
                DiffEntry::ModeChanged {
                    path: "run.sh".into()
                },
                DiffEntry::Symlink {
                    path: "l".into(),
                    target: "../x".into()
                },
                DiffEntry::Gitlink { path: "g".into() },
            ]
        );
    }

    #[test]
    fn a_file_that_became_a_symlink_is_a_type_change_and_a_symlink() {
        let facts = patch::parse(
            "diff --git a/f b/f\nold mode 100644\nnew mode 120000\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-text\n+../../etc/passwd\n"
                .as_bytes(),
        );
        let files = [change(
            "f",
            ChangeKind::Modified,
            Some("text\n"),
            Some("../../etc/passwd"),
        )];
        let found = entries(&files, &facts);
        assert!(found.contains(&DiffEntry::TypeChanged { path: "f".into() }));
        assert!(found.contains(&DiffEntry::Symlink {
            path: "f".into(),
            target: "../../etc/passwd".into()
        }));
    }

    #[test]
    fn a_rename_in_the_headers_is_two_paths_for_the_policy() {
        let facts = patch::parse(
            "diff --git a/.github/ci.yml b/docs/ci.yml\nsimilarity index 100%\nrename from .github/ci.yml\nrename to docs/ci.yml\n"
                .as_bytes(),
        );
        let found = entries(&[], &facts);
        assert_eq!(
            found,
            vec![DiffEntry::Renamed {
                from: ".github/ci.yml".into(),
                to: "docs/ci.yml".into()
            }]
        );
    }
}
