//! The secret scan of the change.
//!
//! The scan reads the lines the change adds, not whole files: a secret that was already in the
//! base is not this builder's, and a secret on a new line is. It uses the one redactor of the
//! factory (`Redactor::contains_secret`), so a pattern added to the policy reaches this gate with
//! no change here. A finding names the path and never the text.
//!
//! The scan runs before anything is committed or sent, and a secret in the change is never
//! waived (`gate_integrity.nonwaivable_gates` lists `secret_scan`). A file the redactor cannot
//! scan (it is over the size limit) is not clean: the gate is `BLOCKED`.

use factory_domain::redaction::Redactor;

use super::Violation;
use super::diff::FileChange;
use super::lines;

/// What the scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scan {
    /// Nothing in the new lines is a secret.
    Clean,
    /// These paths gained a secret.
    Found(Vec<Violation>),
    /// These paths could not be scanned.
    Unscannable(Vec<String>),
}

/// Scans the new lines of every changed file.
#[must_use]
pub fn scan(redactor: &Redactor, files: &[FileChange]) -> Scan {
    let mut found = Vec::new();
    let mut unscannable = Vec::new();
    for file in files {
        if !file.readable {
            unscannable.push(file.path.clone());
            continue;
        }
        let Some(after) = &file.after else {
            continue;
        };
        let mut text: Vec<u8> = Vec::new();
        for (_, line) in lines::added(file.before_or_empty(), after) {
            text.extend_from_slice(line);
            text.push(b'\n');
        }
        match redactor.contains_secret(&text) {
            Ok(false) => {}
            Ok(true) => found.push(Violation {
                check: "secret-in-diff",
                message: format!(
                    "The path {} gains text that matches a secret pattern. The text is not shown.",
                    file.path
                ),
                path: Some(file.path.clone()),
                line: None,
            }),
            Err(_) => unscannable.push(file.path.clone()),
        }
    }
    if !found.is_empty() {
        Scan::Found(found)
    } else if !unscannable.is_empty() {
        Scan::Unscannable(unscannable)
    } else {
        Scan::Clean
    }
}
