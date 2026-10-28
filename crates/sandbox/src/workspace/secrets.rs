//! The secret scan of the bytes that are about to be committed.
//!
//! The scan runs on the content of the new blobs **read back from the object store**, so it sees
//! exactly the bytes a commit will hold. A finding names the rule, the file and the line. It never
//! holds the matched text.

use factory_domain::redaction::{Redactor, Severity};
use factory_domain::values::Slug;
use factory_ports::paths::{Finding, RepoPath};

/// Why a scan could not be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanFailure {
    /// The redactor refused the input (too large, or its own bookkeeping failed). The content
    /// must not go on.
    Refused,
}

/// Scans one file. Only blocking findings count: a flag is a signal that does not stop work.
pub(crate) fn scan(
    redactor: &Redactor,
    path: &RepoPath,
    bytes: &[u8],
) -> Result<Vec<Finding>, ScanFailure> {
    let report = redactor.scan(bytes).map_err(|_| ScanFailure::Refused)?;
    let mut findings = Vec::new();
    for found in report
        .findings()
        .iter()
        .filter(|f| f.severity == Severity::Blocking)
    {
        let offset = usize::try_from(found.start)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let line = bytes[..offset].iter().filter(|b| **b == b'\n').count() + 1;
        findings.push(Finding {
            rule: slug(&found.id),
            path: Some(path.clone()),
            line: u32::try_from(line).ok(),
        });
    }
    // A blocking report with no listed finding (the list is capped) still blocks.
    if findings.is_empty() && report.has_blocking() {
        findings.push(Finding {
            rule: slug("secret"),
            path: Some(path.clone()),
            line: None,
        });
    }
    Ok(findings)
}

fn slug(id: &str) -> Slug {
    let mut text: String = id
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    text.truncate(64);
    let trimmed = text.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    Slug::parse(trimmed).unwrap_or_else(|_| Slug::parse("secret").expect("a fixed slug"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::redaction::PatternAction;

    fn redactor() -> Redactor {
        Redactor::builder()
            .pattern("github_token", "ghs_[A-Za-z0-9]{36}", PatternAction::Block)
            .build()
            .expect("a redactor")
    }

    #[test]
    fn a_finding_names_the_rule_the_file_and_the_line_and_never_the_text() {
        let secret = format!("{}{}", "ghs_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
        let text = format!("line one\nconst T: &str = \"{secret}\";\n");
        let path = RepoPath::new("src/leak.rs").expect("path");
        let findings = scan(&redactor(), &path, text.as_bytes()).expect("scanned");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, Some(2));
        assert_eq!(findings[0].path, Some(path));
        assert_eq!(findings[0].rule.as_str(), "github-token");
        assert!(!format!("{findings:?}").contains(&secret));
    }

    #[test]
    fn a_clean_file_has_no_finding() {
        let path = RepoPath::new("a.rs").expect("path");
        assert!(
            scan(&redactor(), &path, b"fn main() {}\n")
                .expect("scanned")
                .is_empty()
        );
    }
}
