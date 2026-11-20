//! What the two documentation stages read from the job's object store on the host.
//!
//! Every read is made by the control plane with the trusted view, on a commit it names, and never
//! from a sandbox. The sandbox that wrote the documents is gone before anything is read.

use std::collections::{BTreeMap, BTreeSet};

use factory_ports::paths::{CommitSha, RepoGlob, RepoPath};
use factory_ports::workspace::{JobRepo, ReadView, WorkspaceError};

use crate::gates::docs::claims::{env_names_in_source, flags_in_source};

/// The most paths one listing returns.
const MAX_PATHS: usize = 20_000;
/// The most bytes of one page that is read.
const MAX_PAGE_BYTES: u64 = 1024 * 1024;
/// The most bytes of one source file that is read for its environment variable names.
const MAX_SOURCE_BYTES: u64 = 512 * 1024;

/// The tree at one commit, as far as the documentation checks need it.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    /// Every path.
    pub files: BTreeSet<String>,
    /// The text of every Markdown page.
    pub pages: BTreeMap<String, String>,
    /// The environment variable names the source contains.
    pub env: BTreeSet<String>,
    /// The long flags the program's source holds as quoted literals. Test files are left out, so
    /// a flag that only a test names does not count as the program's.
    pub flags: BTreeSet<String>,
    /// `Cargo.toml`, when there is one.
    pub manifest: Option<String>,
}

fn glob(text: &str) -> Result<RepoGlob, WorkspaceError> {
    RepoGlob::new(text).map_err(|_| WorkspaceError::UnknownCommit)
}

async fn text(
    repo: &dyn JobRepo,
    commit: &CommitSha,
    path: &str,
    max: u64,
) -> Result<String, WorkspaceError> {
    let path = RepoPath::new(path).map_err(|_| WorkspaceError::UnknownCommit)?;
    let bytes = repo
        .read_file_at(commit, &path, max, ReadView::Trusted)
        .await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads the tree at `commit`.
///
/// # Errors
/// [`WorkspaceError`] when the commit is not in the store or a read fails.
pub async fn read_tree(repo: &dyn JobRepo, commit: &CommitSha) -> Result<Tree, WorkspaceError> {
    let mut tree = Tree::default();
    let all = repo
        .list_at(commit, &glob("**")?, MAX_PATHS, ReadView::Trusted)
        .await?;
    tree.files = all.iter().map(|path| path.as_str().to_owned()).collect();
    for path in &tree.files {
        if path.ends_with(".md") {
            let page = text(repo, commit, path, MAX_PAGE_BYTES).await?;
            tree.pages.insert(path.clone(), page);
        } else if path.ends_with(".rs") {
            let source = text(repo, commit, path, MAX_SOURCE_BYTES).await?;
            tree.env.extend(env_names_in_source(&source));
            if !path.starts_with("tests/") && !path.contains("/tests/") {
                tree.flags.extend(flags_in_source(&source));
            }
        }
    }
    if tree.files.contains("Cargo.toml") {
        tree.manifest = Some(text(repo, commit, "Cargo.toml", MAX_PAGE_BYTES).await?);
    }
    Ok(tree)
}

/// The name of the command line program a `Cargo.toml` builds: the first `[[bin]]` name, or the
/// package name when the package has a `src/main.rs`.
#[must_use]
pub fn program_name(manifest: &str, files: &BTreeSet<String>) -> Option<String> {
    let mut section = "";
    let mut package: Option<String> = None;
    let mut binary: Option<String> = None;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line;
            continue;
        }
        let Some(("name", value)) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim())) else {
            continue;
        };
        let value = value.trim_matches('"').to_owned();
        match section {
            "[package]" => package = Some(value),
            "[[bin]]" if binary.is_none() => binary = Some(value),
            _ => {}
        }
    }
    binary.or_else(|| package.filter(|_| files.contains("src/main.rs")))
}

/// For each of `paths` that an existing page names, the pages that name it.
#[must_use]
pub fn pages_naming(
    pages: &BTreeMap<String, String>,
    paths: &[&str],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut named: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in paths {
        for (page, text) in pages {
            if page != path && text.contains(path) {
                named
                    .entry((*path).to_owned())
                    .or_default()
                    .insert(page.clone());
            }
        }
    }
    named
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_program_is_the_binary_name_or_the_package_of_a_main() {
        let files: BTreeSet<String> = ["src/main.rs".to_owned()].into();
        let package = "[package]\nname = \"word-count\"\nversion = \"0.1.0\"\n";
        assert_eq!(program_name(package, &files).as_deref(), Some("word-count"));
        let binary = format!("{package}\n[[bin]]\nname = \"wc-rs\"\npath = \"src/main.rs\"\n");
        assert_eq!(program_name(&binary, &files).as_deref(), Some("wc-rs"));
        assert_eq!(program_name(package, &BTreeSet::new()), None);
    }

    #[test]
    fn a_page_that_names_a_changed_file_is_found() {
        let pages: BTreeMap<String, String> = [
            ("docs/layout.md".to_owned(), "See src/output.rs.".to_owned()),
            ("README.md".to_owned(), "Nothing here.".to_owned()),
        ]
        .into();
        let found = pages_naming(&pages, &["src/output.rs", "src/other.rs"]);
        assert_eq!(found.len(), 1);
        assert!(found["src/output.rs"].contains("docs/layout.md"));
    }
}
