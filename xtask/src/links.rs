//! `cargo xtask check-links`: every relative link in the Markdown files of the repository points
//! at a file that exists and, when it names a heading, at a heading that exists.
//!
//! The documentation policy asks for validated links. This reads text and uses `std` only. It
//! checks inline links and images (`[t](path)`), reference definitions (`[label]: path`), the
//! reference uses that have no definition (`[t][label]`), and `href` and `src` attributes of raw
//! HTML. It skips fenced code, inline code and HTML comments, and it does not fetch URLs: a link
//! with a scheme (`https:`, `mailto:`) is not checked. Anchors are the headings written with `#`
//! in the target, in the GitHub spelling, and `<a id="...">` or `<a name="...">` tags. A heading
//! underlined with `===` or `---` is not seen, so a link to one reports a missing anchor.

use crate::finding::Finding;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Check every Markdown file under `root`, skipping `skipped` directory names and nested
/// checkouts (a directory with a `.git` entry of its own).
pub fn check(root: &Path, skipped: &[String]) -> Result<(usize, usize, Vec<Finding>), String> {
    let mut files = Vec::new();
    walk(root, skipped, &mut files)?;
    files.sort();
    let mut anchors: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let mut findings = Vec::new();
    let mut checked = 0;
    for file in &files {
        let text =
            fs::read_to_string(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        let shown = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        for link in links_in(&text) {
            checked += 1;
            if let Some(problem) = judge(root, file, &link, &mut anchors) {
                findings.push(Finding::new(
                    "LINK",
                    format!("{shown}:{}", link.line),
                    problem,
                ));
            }
        }
    }
    Ok((files.len(), checked, findings))
}

/// One link found in a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub line: usize,
    pub target: String,
    /// True for `[text][label]` whose label has no definition: `target` is the label.
    pub undefined_reference: bool,
}

fn walk(dir: &Path, skipped: &[String], files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        // A link is never followed: it could loop or lead outside the repository.
        let Ok(kind) = fs::symlink_metadata(&path).map(|m| m.file_type()) else {
            continue;
        };
        if kind.is_dir() {
            // A directory with a `.git` entry of its own is another checkout (a git worktree or
            // a clone). Its documents are not part of this repository.
            let has_own_git = path.join(".git").symlink_metadata().is_ok();
            if !skipped.contains(&name) && !has_own_git {
                walk(&path, skipped, files)?;
            }
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "md") {
            files.push(path);
        }
    }
    Ok(())
}

/// The problem with a link, or `None` when it is fine.
fn judge(
    root: &Path,
    file: &Path,
    link: &Link,
    anchors: &mut BTreeMap<PathBuf, BTreeSet<String>>,
) -> Option<String> {
    if link.undefined_reference {
        return Some(format!(
            "the reference [{}] has no definition in this file",
            link.target
        ));
    }
    let target = link.target.trim();
    if target.is_empty() || has_scheme(target) || target.starts_with("//") {
        return None;
    }
    let (path_part, fragment) = match target.split_once('#') {
        Some((path, fragment)) => (path, Some(fragment)),
        None => (target, None),
    };
    let path_part = path_part.split('?').next().unwrap_or_default();
    let resolved = if path_part.is_empty() {
        file.to_path_buf()
    } else {
        let decoded = percent_decode(path_part);
        match decoded.strip_prefix('/') {
            Some(from_root) => root.join(from_root),
            None => file.parent().unwrap_or(root).join(decoded),
        }
    };
    if !resolved.exists() {
        return Some(format!("the link target {target:?} does not exist"));
    }
    let fragment = percent_decode(fragment.filter(|f| !f.is_empty())?);
    if resolved.extension().is_none_or(|e| e != "md") {
        return None; // `file.rs#L10` and friends: nothing to check
    }
    let known = anchors.entry(resolved.clone()).or_insert_with(|| {
        fs::read_to_string(&resolved)
            .map(|text| anchors_of(&text))
            .unwrap_or_default()
    });
    (!known.contains(&fragment.to_lowercase())).then(|| {
        format!("the link {target:?} points at a heading that does not exist in the target")
    })
}

fn has_scheme(target: &str) -> bool {
    let Some((scheme, _)) = target.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        if bytes[i] == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            )
        {
            out.push((high * 16 + low) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Lines of a document with code blocks, code spans and HTML comments blanked, each with its
/// 1-based number.
fn prose_lines(text: &str) -> Vec<(usize, String)> {
    let mut lines = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    let mut in_comment = false;
    for (index, raw) in text.lines().enumerate() {
        let trimmed = raw.trim_start();
        let indent = raw.len() - trimmed.len();
        let run = trimmed
            .chars()
            .take_while(|c| *c == '`' || *c == '~')
            .count();
        let marker = trimmed.chars().next().filter(|c| matches!(c, '`' | '~'));
        match (fence, marker) {
            (Some((open, length)), Some(m))
                if m == open && run >= length && trimmed[run..].trim().is_empty() =>
            {
                fence = None;
                continue;
            }
            (Some(_), _) => continue,
            (None, Some(m)) if run >= 3 && indent < 4 => {
                fence = Some((m, run));
                continue;
            }
            _ => {}
        }
        let mut line = String::new();
        let mut rest = raw;
        loop {
            if in_comment {
                match rest.find("-->") {
                    Some(end) => {
                        in_comment = false;
                        rest = &rest[end + 3..];
                    }
                    None => break,
                }
            } else {
                match rest.find("<!--") {
                    Some(start) => {
                        line.push_str(&rest[..start]);
                        in_comment = true;
                        rest = &rest[start + 4..];
                    }
                    None => {
                        line.push_str(rest);
                        break;
                    }
                }
            }
        }
        lines.push((index + 1, strip_code_spans(&line)));
    }
    lines
}

/// Replace the contents of `code` spans with spaces. A span opens with a run of backticks and
/// closes with a run of the same length.
fn strip_code_spans(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '`' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let run = chars[i..].iter().take_while(|c| **c == '`').count();
        let mut j = i + run;
        let mut close = None;
        while j < chars.len() {
            if chars[j] == '`' {
                let length = chars[j..].iter().take_while(|c| **c == '`').count();
                if length == run {
                    close = Some(j + length);
                    break;
                }
                j += length;
            } else {
                j += 1;
            }
        }
        match close {
            Some(end) => {
                out.extend(std::iter::repeat_n(' ', end - i));
                i = end;
            }
            None => {
                out.extend(std::iter::repeat_n('`', run));
                i += run;
            }
        }
    }
    out
}

/// Every link of a document.
pub fn links_in(text: &str) -> Vec<Link> {
    let lines = prose_lines(text);
    let mut definitions: BTreeSet<String> = BTreeSet::new();
    let mut links = Vec::new();
    for (number, line) in &lines {
        if let Some((label, target)) = definition(line) {
            definitions.insert(label);
            links.push(Link {
                line: *number,
                target,
                undefined_reference: false,
            });
        }
    }
    for (number, line) in &lines {
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == ']' && chars.get(i + 1) == Some(&'(') {
                if let Some((target, end)) = inline_target(&chars, i + 2) {
                    links.push(Link {
                        line: *number,
                        target,
                        undefined_reference: false,
                    });
                    i = end;
                    continue;
                }
            } else if chars[i] == ']' && chars.get(i + 1) == Some(&'[') {
                let close = chars[i + 2..].iter().position(|c| *c == ']');
                if let Some(length) = close {
                    let label: String = chars[i + 2..i + 2 + length].iter().collect();
                    let label = label.trim().to_lowercase();
                    if !label.is_empty() && !definitions.contains(&label) {
                        links.push(Link {
                            line: *number,
                            target: label,
                            undefined_reference: true,
                        });
                    }
                    i += 2 + length;
                    continue;
                }
            }
            i += 1;
        }
        for attribute in ["href=\"", "src=\""] {
            let mut rest = line.as_str();
            while let Some(at) = rest.find(attribute) {
                let after = &rest[at + attribute.len()..];
                let end = after.find('"').unwrap_or(after.len());
                links.push(Link {
                    line: *number,
                    target: after[..end].to_string(),
                    undefined_reference: false,
                });
                rest = &after[end..];
            }
        }
    }
    links
}

/// `[label]: target "title"` at the start of a line.
fn definition(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let rest = trimmed.strip_prefix('[')?;
    let close = rest.find("]:")?;
    let label = rest[..close].trim().to_lowercase();
    if label.is_empty() || label.starts_with('^') {
        return None;
    }
    let target = rest[close + 2..].trim_start();
    let target = if let Some(inner) = target.strip_prefix('<') {
        inner.split('>').next()?.to_string()
    } else {
        target.split_whitespace().next()?.to_string()
    };
    Some((label, target))
}

/// The target of an inline link whose `(` is just before `start`, and the index after the `)`.
fn inline_target(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    while chars.get(i) == Some(&' ') {
        i += 1;
    }
    if chars.get(i) == Some(&'<') {
        let end = chars[i + 1..].iter().position(|c| *c == '>')? + i + 1;
        let close = chars[end..].iter().position(|c| *c == ')')? + end;
        return Some((chars[i + 1..end].iter().collect(), close + 1));
    }
    let mut depth = 0usize;
    let mut j = i;
    while j < chars.len() {
        match chars[j] {
            '(' => depth += 1,
            ')' if depth == 0 => break,
            ')' => depth -= 1,
            ' ' | '\t' if depth == 0 => break, // the title starts here
            _ => {}
        }
        j += 1;
    }
    let target: String = chars[i..j].iter().collect();
    let close = chars[j..].iter().position(|c| *c == ')')? + j;
    Some((target, close + 1))
}

/// The anchors a document offers: its `#` headings in the GitHub spelling (with `-1`, `-2` for
/// repeats) and the ids of `<a id>` and `<a name>` tags.
pub fn anchors_of(text: &str) -> BTreeSet<String> {
    let mut anchors = BTreeSet::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let raw_lines: Vec<&str> = text.lines().collect();
    let prose: BTreeSet<usize> = prose_lines(text).into_iter().map(|(n, _)| n).collect();
    for (index, raw) in raw_lines.iter().enumerate() {
        if !prose.contains(&(index + 1)) {
            continue;
        }
        let trimmed = raw.trim_start();
        let hashes = trimmed.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes) && trimmed[hashes..].starts_with(' ') {
            let title = trimmed[hashes..].trim().trim_end_matches('#').trim_end();
            let base = slug(title);
            let count = seen.entry(base.clone()).or_insert(0);
            let name = if *count == 0 {
                base.clone()
            } else {
                format!("{base}-{count}")
            };
            *count += 1;
            anchors.insert(name);
        }
        for attribute in ["id=\"", "name=\""] {
            let mut rest = *raw;
            while let Some(at) = rest.find(attribute) {
                let after = &rest[at + attribute.len()..];
                let end = after.find('"').unwrap_or(after.len());
                anchors.insert(after[..end].to_lowercase());
                rest = &after[end..];
            }
        }
    }
    anchors
}

/// The GitHub anchor of a heading: markup removed, lower case, letters, digits, hyphens and
/// underscores kept, spaces turned into hyphens, everything else dropped.
fn slug(heading: &str) -> String {
    let mut plain = String::new();
    let mut chars = heading.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '`' | '*' | '~' => {}
            '<' => {
                for next in chars.by_ref() {
                    if next == '>' {
                        break;
                    }
                }
            }
            '[' => {} // the link text stays, the bracket goes
            ']' => {
                if chars.peek() == Some(&'(') {
                    for next in chars.by_ref() {
                        if next == ')' {
                            break;
                        }
                    }
                }
            }
            other => plain.push(other),
        }
    }
    plain
        .to_lowercase()
        .chars()
        .filter_map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                Some(c)
            } else if c.is_whitespace() {
                Some('-')
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(text: &str) -> Vec<String> {
        links_in(text).into_iter().map(|l| l.target).collect()
    }

    #[test]
    fn inline_links_images_definitions_and_html_are_read() {
        let text = "See [a](one.md), ![img](pics/x.png \"title\"), [b](<two words.md>)\n[ref]: three.md\nand <a href=\"four.md\">x</a> and [c][ref]\n";
        assert_eq!(
            targets(text),
            [
                "three.md",
                "one.md",
                "pics/x.png",
                "two words.md",
                "four.md"
            ]
        );
    }

    #[test]
    fn code_comments_and_fences_are_skipped() {
        let text = "`[a](skip1.md)` and ``[b](skip2.md)``\n<!-- [c](skip3.md)\n[d](skip4.md) -->\n```\n[e](skip5.md)\n```\n~~~~\n```\n[f](skip6.md)\n~~~~\n[g](kept.md)\n";
        assert_eq!(targets(text), ["kept.md"]);
    }

    #[test]
    fn parentheses_inside_a_target_are_balanced() {
        assert_eq!(targets("[x](a_(b).md) tail"), ["a_(b).md"]);
    }

    #[test]
    fn an_undefined_reference_is_reported_and_a_defined_one_is_not() {
        let links = links_in("[x][nope] and [y][yes]\n[yes]: here.md\n");
        assert!(
            links
                .iter()
                .any(|l| l.undefined_reference && l.target == "nope")
        );
        assert!(
            !links
                .iter()
                .any(|l| l.undefined_reference && l.target == "yes")
        );
    }

    #[test]
    fn heading_anchors_follow_the_github_spelling() {
        let anchors = anchors_of(
            "# Title\n## 5.2 Store\n## What's `in` it? (yes)\n## Title\n<a id=\"Custom\"></a>\n```\n# not a heading\n```\n",
        );
        for wanted in ["title", "52-store", "whats-in-it-yes", "title-1", "custom"] {
            assert!(anchors.contains(wanted), "{wanted} not in {anchors:?}");
        }
        assert!(!anchors.contains("not-a-heading"));
    }

    #[test]
    fn a_scheme_is_not_a_relative_path() {
        assert!(has_scheme("https://example.com"));
        assert!(has_scheme("mailto:a@b.c"));
        assert!(!has_scheme("docs/a:b.md"));
        assert!(!has_scheme("./c:/x"));
    }

    #[test]
    fn percent_escapes_are_decoded() {
        assert_eq!(percent_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(percent_decode("100%"), "100%");
    }
}
