//! Reading the workflow files of the default branch (threat T-48).
//!
//! The preflight needs the text of every file directly in `.github/workflows` whose name ends in
//! `.yml` or `.yaml`, at one commit of the default branch. Three reads give it:
//!
//! 1. `GET /repos/{owner}/{repo}/branches/{branch}` for the commit at the tip of the default
//!    branch, so that the list and every file come from the same commit;
//! 2. `GET /repos/{owner}/{repo}/contents/.github/workflows?ref={commit}` for the list;
//! 3. `GET /repos/{owner}/{repo}/contents/{path}?ref={commit}` for each file.
//!
//! All three use the fetch credential: `contents: read` and `metadata: read` for the one
//! repository, the same credential a fetch of the repository gets. The App holds that permission
//! already; nothing new is asked of GitHub. The stage token of the preflight (the intake's,
//! `issues: read`) is not used and is not widened.
//!
//! This module judges nothing. It returns the text, and a file whose text it could not get comes
//! back with no text, which the classifier (`factory_contracts::workflows`) counts as exposed. A
//! list it could not read whole is an error, never the part it read.
//!
//! UNVERIFIED against the real GitHub, all of it written from the documentation of the contents
//! API and none recorded:
//!
//! * that the list of a directory is an array of objects with `type`, `name` and `path`, and that
//!   a path that is a file answers with an object;
//! * that a directory that does not exist answers 404 to a token that can read the contents of
//!   the repository (the read of the branch, which needs the same permission, has succeeded by
//!   then, so a 404 here is taken to mean "no such directory" and not "no access");
//! * that the list holds at most 1,000 entries and says nothing when it was cut, which is why a
//!   list of [`MAX_LISTED`] or more is refused;
//! * that a file answers `encoding: "base64"` with the text in `content`, and that a file over
//!   1 MB answers with another encoding and an empty `content`;
//! * that GitHub runs workflows only from files directly in `.github/workflows`, not from its
//!   subdirectories, and only with these two extensions; and what it does with a symbolic link
//!   there (it is returned with no text, so it counts as exposed).

use factory_ports::githost::{GitHostError, WorkflowFile};
use serde_json::Value;

use crate::encoding::base64_decode;

/// The directory GitHub reads workflows from.
pub(crate) const WORKFLOW_DIRECTORY: &str = ".github/workflows";

/// A list this long may have been cut by the host, so it is refused.
const MAX_LISTED: usize = 1000;

/// The most workflow files that are read. A repository with more is refused: the preflight caps
/// it and says the workflows could not be read.
const MAX_WORKFLOWS: usize = 100;

/// One workflow file of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Listed {
    /// The path, always `.github/workflows/<name>`.
    pub path: String,
    /// False when the entry is not a plain file (a symbolic link, a submodule): its text is not
    /// asked for.
    pub is_file: bool,
}

fn is_workflow_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".yml") || lower.ends_with(".yaml")
}

/// The workflow files in the answer for the directory, ordered by path.
///
/// # Errors
/// `Unavailable` when the answer is not a list of entries, when an entry does not say what it is,
/// when a path is not the directory plus the name, and when the list is long enough to have been
/// cut or names more than [`MAX_WORKFLOWS`] workflow files.
pub(crate) fn listed_workflows(listing: &Value) -> Result<Vec<Listed>, GitHostError> {
    let entries = listing.as_array().ok_or(GitHostError::Unavailable)?;
    if entries.len() >= MAX_LISTED {
        return Err(GitHostError::Unavailable);
    }
    let mut found = Vec::new();
    for entry in entries {
        let (Some(kind), Some(name), Some(path)) = (
            entry["type"].as_str(),
            entry["name"].as_str(),
            entry["path"].as_str(),
        ) else {
            return Err(GitHostError::Unavailable);
        };
        if path != format!("{WORKFLOW_DIRECTORY}/{name}") || name.contains('/') {
            return Err(GitHostError::Unavailable);
        }
        // A subdirectory holds no workflow GitHub runs. Anything else with a workflow's name is
        // kept: a plain file is read, the rest comes back with no text.
        if kind == "dir" || !is_workflow_name(name) {
            continue;
        }
        found.push(Listed {
            path: path.to_owned(),
            is_file: kind == "file",
        });
    }
    if found.len() > MAX_WORKFLOWS {
        return Err(GitHostError::Unavailable);
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(found)
}

/// The text in the answer for one file, or `None` when the answer does not carry it: another
/// encoding, text that is not base64 or not UTF-8, or an answer for something that is not a file.
pub(crate) fn text_of(file: &Value) -> Option<String> {
    if file["type"].as_str() != Some("file") || file["encoding"].as_str() != Some("base64") {
        return None;
    }
    let bytes = base64_decode(file["content"].as_str()?)?;
    String::from_utf8(bytes).ok()
}

/// A workflow file with the text that was read for it, if any.
pub(crate) fn workflow_file(listed: &Listed, text: Option<String>) -> WorkflowFile {
    WorkflowFile {
        path: listed.path.clone(),
        text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(kind: &str, name: &str) -> Value {
        json!({"type": kind, "name": name, "path": format!("{WORKFLOW_DIRECTORY}/{name}"), "size": 10})
    }

    #[test]
    fn the_list_keeps_workflow_files_and_leaves_out_the_rest() {
        let listing = json!([
            entry("file", "z.yaml"),
            entry("file", "ci.yml"),
            entry("file", "README.md"),
            entry("dir", "templates"),
            entry("dir", "odd.yml"),
            entry("symlink", "link.yml"),
            entry("file", "UPPER.YML"),
        ]);
        let found = listed_workflows(&listing).unwrap();
        let shown: Vec<(&str, bool)> = found
            .iter()
            .map(|listed| (listed.path.as_str(), listed.is_file))
            .collect();
        assert_eq!(
            shown,
            [
                (".github/workflows/UPPER.YML", true),
                (".github/workflows/ci.yml", true),
                (".github/workflows/link.yml", false),
                (".github/workflows/z.yaml", true),
            ]
        );
        assert_eq!(listed_workflows(&json!([])).unwrap(), []);
    }

    #[test]
    fn a_list_that_cannot_be_trusted_whole_is_an_error() {
        for bad in [
            json!({"type": "file", "name": "workflows"}),
            json!(null),
            json!([{"name": "ci.yml", "path": ".github/workflows/ci.yml"}]),
            json!([{"type": "file", "name": "ci.yml", "path": "elsewhere/ci.yml"}]),
            json!([{"type": "file", "name": "a/ci.yml", "path": ".github/workflows/a/ci.yml"}]),
            json!([{"type": "file", "name": 7, "path": ".github/workflows/7"}]),
        ] {
            assert_eq!(
                listed_workflows(&bad),
                Err(GitHostError::Unavailable),
                "{bad}"
            );
        }
        let many = |count: usize, extension: &str| {
            Value::Array(
                (0..count)
                    .map(|n| entry("file", &format!("f{n}.{extension}")))
                    .collect(),
            )
        };
        assert!(listed_workflows(&many(MAX_WORKFLOWS, "yml")).is_ok());
        assert!(listed_workflows(&many(MAX_WORKFLOWS + 1, "yml")).is_err());
        assert!(listed_workflows(&many(MAX_LISTED - 1, "txt")).is_ok());
        assert!(listed_workflows(&many(MAX_LISTED, "txt")).is_err());
    }

    #[test]
    fn the_text_of_a_file_is_read_from_base64_and_from_nothing_else() {
        // "on: push\n" with the line break GitHub puts in long content.
        let good = json!({"type": "file", "encoding": "base64", "content": "b246IHB1\nc2gK\n"});
        assert_eq!(text_of(&good).as_deref(), Some("on: push\n"));
        for bad in [
            json!({"type": "file", "encoding": "none", "content": ""}),
            json!({"type": "file", "encoding": "base64"}),
            json!({"type": "file", "encoding": "base64", "content": "***"}),
            // The bytes 0xFF 0xFE are not UTF-8.
            json!({"type": "file", "encoding": "base64", "content": "//4="}),
            json!({"type": "symlink", "encoding": "base64", "content": "b246IHB1c2gK"}),
            json!([]),
        ] {
            assert_eq!(text_of(&bad), None, "{bad}");
        }
    }
}
