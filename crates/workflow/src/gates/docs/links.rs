//! The link check: do the internal links and anchors of the documents resolve on the branch.
//!
//! A target is internal when it has no scheme. Its path is resolved against the directory of the
//! page that holds it (or against the repository root when it starts with `/`), and it must name
//! a file of the tree. An anchor must be a heading of the page it points at.
//!
//! **External links are not fetched.** The sandbox has no network, and a page that is reachable
//! today says nothing about the documentation. They are counted and named in the report as not
//! checked, and none of them is ever called valid (open decision 3 of the documentation policy,
//! ADR 0009 item 18).

use std::collections::{BTreeMap, BTreeSet};

use super::markdown::{self, anchors, scan};

/// A link that does not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broken {
    /// The page that holds the link.
    pub file: String,
    /// The line.
    pub line: usize,
    /// The target as written.
    pub target: String,
    /// Why it does not resolve.
    pub reason: &'static str,
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkReport {
    /// How many internal links were resolved.
    pub internal_checked: usize,
    /// The external targets that were not checked, once each, in order of appearance.
    pub external_unchecked: Vec<String>,
    /// The links that do not resolve.
    pub broken: Vec<Broken>,
}

/// The branch as the check sees it.
#[derive(Debug, Clone, Copy)]
pub struct Tree<'a> {
    /// Every path of the tree.
    pub files: &'a BTreeSet<String>,
    /// The text of every Markdown page, by path. An anchor is read from here.
    pub pages: &'a BTreeMap<String, String>,
}

/// Checks the links of `pages` (path, text) against `tree`.
#[must_use]
pub fn check(pages: &[(&str, &str)], tree: &Tree<'_>) -> LinkReport {
    let mut report = LinkReport::default();
    for (path, text) in pages {
        let page = scan(text);
        for link in &page.links {
            let target = link.target.as_str();
            if is_external(target) {
                if !report.external_unchecked.iter().any(|t| t == target) {
                    report.external_unchecked.push(target.to_owned());
                }
                continue;
            }
            report.internal_checked += 1;
            if let Some(reason) = unresolved(path, target, tree) {
                report.broken.push(Broken {
                    file: (*path).to_owned(),
                    line: link.line,
                    target: target.to_owned(),
                    reason,
                });
            }
        }
    }
    report
}

/// A scheme before the first slash or hash means the target leaves the repository.
fn is_external(target: &str) -> bool {
    if target.starts_with("//") {
        return true;
    }
    let head = target.split(['/', '#', '?']).next().unwrap_or("");
    head.contains(':') && head.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
}

fn unresolved(from: &str, target: &str, tree: &Tree<'_>) -> Option<&'static str> {
    let without_query = target.split('?').next().unwrap_or("");
    let (path_part, anchor) = match without_query.split_once('#') {
        Some((path, anchor)) => (path, Some(anchor)),
        None => (without_query, None),
    };
    let resolved = if path_part.is_empty() {
        from.to_owned()
    } else {
        match join(from, path_part) {
            Some(path) => path,
            None => return Some("the target leaves the repository"),
        }
    };
    // A directory link is fine when a file lives under it.
    let prefix = format!("{}/", resolved.trim_end_matches('/'));
    let exists =
        tree.files.contains(&resolved) || tree.files.iter().any(|f| f.starts_with(&prefix));
    if !exists {
        return Some("the target file does not exist on the branch");
    }
    if let Some(anchor) = anchor.filter(|a| !a.is_empty()) {
        let wanted = percent_decode(anchor).to_lowercase();
        // `#L10` points at a line of a file on a code host. It is not a heading.
        if markdown_line_anchor(&wanted) {
            return None;
        }
        let Some(text) = tree.pages.get(&resolved) else {
            return Some("the page the anchor points into could not be read");
        };
        if !anchors(&scan(text)).contains(&wanted) {
            return Some("the anchor is not a heading of the page");
        }
    }
    None
}

/// `#L10` and `#L10-L20` point at lines of a file on a code host. They are not headings.
fn markdown_line_anchor(anchor: &str) -> bool {
    let rest = anchor.strip_prefix('l').unwrap_or("");
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == 'l')
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && at + 2 < bytes.len()
            && let Ok(digits) = std::str::from_utf8(&bytes[at + 1..at + 3])
            && let Ok(hex) = u8::from_str_radix(digits, 16)
        {
            out.push(hex);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `dir(from) / target`, with `.` and `..` folded. `None` when the result leaves the root.
fn join(from: &str, target: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    if !target.starts_with('/') {
        parts.extend(from.split('/').collect::<Vec<_>>().split_last()?.1);
    }
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

/// The anchors of a page, for a caller that wants to show them.
#[must_use]
pub fn anchors_of(text: &str) -> BTreeSet<String> {
    markdown::anchors(&scan(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> (BTreeSet<String>, BTreeMap<String, String>) {
        let pages: BTreeMap<String, String> = [
            ("README.md", "# Tool\n\n## Usage\n"),
            ("docs/guide.md", "# Guide\n\n## Flags\n"),
        ]
        .into_iter()
        .map(|(p, t)| (p.to_owned(), t.to_owned()))
        .collect();
        let mut files: BTreeSet<String> = pages.keys().cloned().collect();
        files.insert("src/main.rs".to_owned());
        (files, pages)
    }

    #[test]
    fn relative_links_and_anchors_resolve() {
        let (files, pages) = tree();
        let tree = Tree {
            files: &files,
            pages: &pages,
        };
        let page = "[g](docs/guide.md#flags) [u](#usage) [s](src/main.rs#L3) [d](docs)";
        let report = check(&[("README.md", page)], &tree);
        assert!(report.broken.is_empty(), "{:?}", report.broken);
        assert_eq!(report.internal_checked, 4);
    }

    #[test]
    fn a_dead_file_and_a_dead_anchor_are_broken() {
        let (files, pages) = tree();
        let tree = Tree {
            files: &files,
            pages: &pages,
        };
        let page = "[a](docs/missing.md) [b](docs/guide.md#nope) [c](../../etc/passwd)";
        let report = check(&[("README.md", page)], &tree);
        assert_eq!(report.broken.len(), 3);
    }

    #[test]
    fn a_link_from_a_subdirectory_resolves_against_that_directory() {
        let (files, pages) = tree();
        let tree = Tree {
            files: &files,
            pages: &pages,
        };
        let ok = check(&[("docs/guide.md", "[r](../README.md#usage)")], &tree);
        assert!(ok.broken.is_empty());
        let bad = check(&[("docs/guide.md", "[r](README.md)")], &tree);
        assert_eq!(bad.broken.len(), 1);
    }

    #[test]
    fn external_links_are_counted_and_never_checked() {
        let (files, pages) = tree();
        let tree = Tree {
            files: &files,
            pages: &pages,
        };
        let page =
            "[a](https://example.test/a) [b](https://example.test/a) [m](mailto:x@example.test)";
        let report = check(&[("README.md", page)], &tree);
        assert_eq!(report.external_unchecked.len(), 2);
        assert_eq!(report.internal_checked, 0);
        assert!(report.broken.is_empty());
    }
}
