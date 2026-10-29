//! Small readers that several assertions share.

use serde_json::Value;

use crate::evidence::{RunEvidence, StageRunRecord};

/// The status a stage run has when it passed.
pub const PASSED: &str = "PASSED";
/// The status a stage run has when a rule skipped it.
pub const SKIPPED: &str = "SKIPPED";

/// Every run of a stage kind, in the order the evidence lists them.
pub fn runs_of<'a>(ev: &'a RunEvidence, kind: &str) -> Vec<&'a StageRunRecord> {
    ev.stage_runs
        .iter()
        .filter(|run| run.kind == kind)
        .collect()
}

/// The run that settles a stage: the one `PASSED` run of the kind, or, when none passed, the one
/// `SKIPPED` run whose skip the ledger records. ADR 0010 (decision 2) lets a stage that a rule
/// skips satisfy the stages that require it and the completion of the job, so a skipped stage
/// has no passed run and is settled all the same. A skip with no ledger entry settles nothing:
/// nobody can say which rule skipped the stage. `None` when there is no such run, or more than one.
pub fn the_passed_run<'a>(ev: &'a RunEvidence, kind: &str) -> Option<&'a StageRunRecord> {
    let one = |status: &str| -> Option<&'a StageRunRecord> {
        let mut found = ev
            .stage_runs
            .iter()
            .filter(|run| run.kind == kind && run.status == status);
        let first = found.next()?;
        found.next().is_none().then_some(first)
    };
    if ev
        .stage_runs
        .iter()
        .any(|run| run.kind == kind && run.status == PASSED)
    {
        return one(PASSED);
    }
    one(SKIPPED).filter(|run| !ledger_sequences_for(ev, &run.id).is_empty())
}

/// True when `run` settles its stage by being skipped, not by passing.
pub fn is_skipped(run: &StageRunRecord) -> bool {
    run.status == SKIPPED
}

/// The timeline position where a stage run became `PASSED` (or `SKIPPED`, which settles a stage
/// in the same way).
pub fn passed_at(ev: &RunEvidence, run: &StageRunRecord) -> Option<u64> {
    ev.timeline
        .iter()
        .filter(|entry| {
            entry.subject == "stage_run"
                && entry.subject_id == run.id
                && (entry.to == PASSED || entry.to == SKIPPED)
        })
        .map(|entry| entry.seq)
        .max()
}

/// The position in the timeline where the job first reached a status.
pub fn job_reached(ev: &RunEvidence, status: &str) -> Option<u64> {
    ev.timeline
        .iter()
        .filter(|entry| entry.subject == "job" && entry.to == status)
        .map(|entry| entry.seq)
        .min()
}

/// The text at a JSON pointer, or `None`.
pub fn text_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// The ledger sequences of the entries about one stage run, in order.
pub fn ledger_sequences_for(ev: &RunEvidence, stage_run_id: &str) -> Vec<u64> {
    let mut sequences: Vec<u64> = ev
        .ledger
        .iter()
        .filter(|entry| text_at(entry, "/metadata/stage_run_id") == Some(stage_run_id))
        .filter_map(|entry| entry.pointer("/metadata/sequence").and_then(Value::as_u64))
        .collect();
    sequences.sort_unstable();
    sequences
}

/// A path is documentation when a README, a changelog or a file under `docs/` is meant.
pub fn is_documentation_path(path: &str) -> bool {
    path == "README.md" || path == "CHANGELOG.md" || path.starts_with("docs/")
}

/// True when `text` mentions the issue `number` as `#number`, and not as the start of a longer
/// number such as `#123` for issue 12.
pub fn mentions_issue(text: &str, number: u64) -> bool {
    let needle = format!("#{number}");
    let mut from = 0;
    while let Some(found) = text[from..].find(&needle) {
        let end = from + found + needle.len();
        let next = text[end..].chars().next();
        if !next.is_some_and(|c| c.is_ascii_digit()) {
            return true;
        }
        from = end;
    }
    false
}

/// A glob in the small dialect of the owned-files lists: `**` matches anything, `*` matches
/// anything except `/`, every other character matches itself.
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    fn go(pattern: &[u8], path: &[u8]) -> bool {
        match pattern.first() {
            None => path.is_empty(),
            Some(b'*') if pattern.get(1) == Some(&b'*') => {
                let rest = &pattern[2..];
                let rest = rest.strip_prefix(b"/").unwrap_or(rest);
                (0..=path.len()).any(|skip| go(rest, &path[skip..]))
            }
            Some(b'*') => {
                let rest = &pattern[1..];
                let limit = path.iter().position(|b| *b == b'/').unwrap_or(path.len());
                (0..=limit).any(|skip| go(rest, &path[skip..]))
            }
            Some(byte) => path.first() == Some(byte) && go(&pattern[1..], &path[1..]),
        }
    }
    go(pattern.as_bytes(), path.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_issue_reference_is_not_the_start_of_a_longer_number() {
        assert!(mentions_issue("Closes #12.", 12));
        assert!(mentions_issue("Refs #12", 12));
        assert!(!mentions_issue("Closes #123", 12));
        assert!(mentions_issue("#123 and #12", 12));
        assert!(!mentions_issue("no reference", 12));
    }

    #[test]
    fn the_small_glob_dialect_matches_paths() {
        assert!(glob_matches("src/main.rs", "src/main.rs"));
        assert!(!glob_matches("src/main.rs", "src/lib.rs"));
        assert!(glob_matches("src/*.rs", "src/main.rs"));
        assert!(!glob_matches("src/*.rs", "src/a/main.rs"));
        assert!(glob_matches("tests/**", "tests/golden/sample.txt"));
        assert!(glob_matches("**/*.md", "docs/guide.md"));
    }
}
