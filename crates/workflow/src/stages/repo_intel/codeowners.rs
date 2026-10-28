//! CODEOWNERS: who owns which paths, read as data.
//!
//! The file is the repository's own and therefore untrusted text. This module reads only the shape
//! of each line (a pattern and one or more owners) and keeps the line number, so every owner in the
//! map has a place it was read from. It follows no instruction in the file, because the file is
//! never an instruction. A line that is not a pattern with owners is dropped.

/// The places GitHub looks for the file, in the order it prefers them.
pub const LOCATIONS: [&str; 3] = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];

/// The most rules kept, so a hostile file cannot make the map grow without bound.
pub const MAX_RULES: usize = 500;

/// One line of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRule {
    /// The path pattern.
    pub pattern: String,
    /// The owners: `@user`, `@org/team` or an email address.
    pub owners: Vec<String>,
    /// The line, from 1.
    pub line: u32,
}

fn is_owner(word: &str) -> bool {
    let name = word.strip_prefix('@');
    match name {
        Some(name) => {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
        }
        None => {
            word.contains('@')
                && !word.starts_with('@')
                && word.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b'+')
                })
        }
    }
}

/// Reads the rules of a CODEOWNERS file.
#[must_use]
pub fn parse(text: &str) -> Vec<OwnerRule> {
    let mut rules = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let Some(pattern) = words.next() else {
            continue;
        };
        let owners: Vec<String> = words
            .take_while(|word| is_owner(word))
            .map(str::to_owned)
            .collect();
        if owners.is_empty() || pattern.len() > 256 {
            continue;
        }
        if let Ok(line_number) = u32::try_from(index + 1) {
            rules.push(OwnerRule {
                pattern: pattern.to_owned(),
                owners,
                line: line_number,
            });
        }
        if rules.len() >= MAX_RULES {
            break;
        }
    }
    rules
}
