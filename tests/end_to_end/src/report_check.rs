//! The check of the acceptance report (`docs/reports/slice-1-acceptance.md`), which the package
//! `s1-end-to-end-run` writes. The report must not claim more than the recordings show.
//!
//! The rules, which that package follows when it writes the report:
//!
//! * A line that says `PASSED` for a scenario cites a recording: a Markdown link to a file under
//!   `fixtures/recordings/e2e/` that exists, inside a recording directory that has a manifest.
//! * The same line carries the digest of that manifest (`sha256:` and 64 hexadecimal digits), and
//!   the digest is the one the manifest has now. Editing the recording after the report was
//!   written, or editing a file and the manifest together, is caught here.
//! * Every file of the recording still has the hash the manifest lists.
//! * A `PASSED` line for E1 or E2 says `real`, and a `PASSED` line for any other scenario says
//!   `test mode` or `fake`, so a fake result is never presented as a real one.
//! * A scenario that could not run says `BLOCKED` and names what is missing.

use std::path::Path;

/// The problems in the report text, one sentence for each. `root` is the repository root, against
/// which the recording links are resolved.
#[must_use]
pub fn problems(report: &str, root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for (number, line) in report.lines().enumerate() {
        let number = number + 1;
        let scenario = scenario_id(line);
        if line.contains("PASSED") {
            let Some(scenario) = scenario.clone() else {
                continue;
            };
            let links = recording_links(line);
            if links.is_empty() {
                found.push(format!("line {number}: {scenario} says PASSED and cites no recording under fixtures/recordings/e2e/"));
            }
            for link in &links {
                recording_problems(root, link, line, number, &scenario, &mut found);
            }
            let lower = line.to_lowercase();
            let real_scenario = scenario == "E1" || scenario == "E2";
            if real_scenario && !lower.contains("real") {
                found.push(format!(
                    "line {number}: {scenario} says PASSED and does not say it used real adapters"
                ));
            }
            if real_scenario && (lower.contains("test mode") || lower.contains("fake")) {
                found.push(format!(
                    "line {number}: {scenario} says PASSED with fakes, which is not the real proof"
                ));
            }
            if !real_scenario && !(lower.contains("test mode") || lower.contains("fake")) {
                found.push(format!("line {number}: {scenario} says PASSED and does not say it used fakes in test mode"));
            }
        }
        if line.contains("BLOCKED")
            && scenario.is_some()
            && !line.to_lowercase().contains("missing")
            && !line.to_lowercase().contains("needs")
            && !line.to_lowercase().contains("set ")
            && !line.to_lowercase().contains("cannot")
        {
            found.push(format!(
                "line {number}: BLOCKED does not name what is missing"
            ));
        }
    }
    found
}

/// The checks on one cited recording file.
fn recording_problems(
    root: &Path,
    link: &str,
    line: &str,
    number: usize,
    scenario: &str,
    found: &mut Vec<String>,
) {
    let path = root.join(link);
    if !path.is_file() {
        found.push(format!(
            "line {number}: the recording {link} does not exist"
        ));
        return;
    }
    let Some(dir) = path.parent() else { return };
    let Some(digest) = crate::recording::manifest_digest(dir) else {
        found.push(format!(
            "line {number}: {link} is not inside a recording directory with a {}",
            crate::recording::MANIFEST
        ));
        return;
    };
    let cited = digests(line);
    if cited.is_empty() {
        found.push(format!(
            "line {number}: {scenario} says PASSED and does not cite the manifest digest of its recording ({digest})"
        ));
    } else if !cited.contains(&digest) {
        found.push(format!(
            "line {number}: the recording {link} has the manifest digest {digest}, and the report cites {}; the recording changed after the report was written",
            cited.join(", ")
        ));
    }
    if let Err(why) = crate::recording::verify_files(dir) {
        found.push(format!(
            "line {number}: the recording {link} is damaged: {why}"
        ));
    }
}

/// The `sha256:` digests written on a line, 64 hexadecimal digits each.
fn digests(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("sha256:") {
        let after = &rest[at + "sha256:".len()..];
        let hex: String = after.chars().take_while(char::is_ascii_hexdigit).collect();
        if hex.len() == 64 {
            out.push(format!("sha256:{}", hex.to_lowercase()));
        }
        rest = &after[hex.len()..];
    }
    out
}

/// The scenario id at the start of a table row or list item, such as `E3`.
fn scenario_id(line: &str) -> Option<String> {
    let trimmed = line.trim_start_matches(['|', '-', '*', ' ']);
    let mut chars = trimmed.chars();
    if chars.next() != Some('E') {
        return None;
    }
    let digits: String = chars.take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("E{digits}"))
    }
}

/// The relative paths of the Markdown links on a line that point under `fixtures/recordings/e2e/`.
fn recording_links(line: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("](") {
        let after = &rest[start + 2..];
        let Some(end) = after.find(')') else { break };
        let target = &after[..end];
        if let Some(at) = target.find("fixtures/recordings/e2e/") {
            links.push(target[at..].to_owned());
        }
        rest = &after[end..];
    }
    links
}

/// Proves the report check on small reports it builds itself: an honest one is accepted, and each
/// way of claiming more than the recordings show is a problem. Returns `(what was shown, whether
/// it held)` for each case. `scripts/e2e.sh --self-test-report` prints them.
#[must_use]
pub fn self_test() -> Vec<(String, bool)> {
    let root = std::env::temp_dir().join(format!("e2e-report-self-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("fixtures/recordings/e2e/E3");
    let made = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::write(dir.join("evidence.json"), "{}\n"))
        .and_then(|()| std::fs::write(dir.join("mode.json"), "{}\n"))
        .ok()
        .and_then(|()| crate::recording::reseal(&dir).ok());
    let mut cases: Vec<(String, bool)> = Vec::new();
    let Some(digest) = made.and(crate::recording::manifest_digest(&dir)) else {
        cases.push((
            "the self test could not write its sample recording".to_owned(),
            false,
        ));
        return cases;
    };
    let row = |scenario: &str, words: &str, cite: &str| {
        format!(
            "| {scenario} | PASSED, {words} | [recording](../../fixtures/recordings/e2e/{cite}/evidence.json) | manifest {digest} |"
        )
    };
    let mut case = |name: &str, report: &str, expect: Option<&str>| {
        let found = problems(report, &root);
        let holds = match expect {
            None => found.is_empty(),
            Some(needle) => found.iter().any(|problem| problem.contains(needle)),
        };
        cases.push((name.to_owned(), holds));
    };
    case(
        "an honest PASSED line that cites its recording and the digest of its manifest is accepted",
        &row("E3", "test mode with fakes", "E3"),
        None,
    );
    case(
        "a PASSED line that cites no recording is a problem",
        "| E3 | PASSED, test mode with fakes | none |",
        Some("cites no recording"),
    );
    case(
        "a PASSED line whose recording does not exist is a problem",
        &row("E4", "test mode with fakes", "E4"),
        Some("does not exist"),
    );
    case(
        "a PASSED line without the digest of the manifest is a problem",
        "| E3 | PASSED, test mode with fakes | [r](../../fixtures/recordings/e2e/E3/evidence.json) |",
        Some("does not cite the manifest digest"),
    );
    case(
        "a test-mode result presented as the real proof is a problem",
        &row("E1", "real adapters, test mode", "E3"),
        Some("not the real proof"),
    );
    case(
        "a BLOCKED line that names nothing is a problem",
        "| E1 | BLOCKED |",
        Some("does not name what is missing"),
    );
    case(
        "a BLOCKED line that names what is missing is accepted",
        "| E1 | BLOCKED | missing: the model API key |",
        None,
    );
    // A file edited after the report was written.
    let _ = std::fs::write(dir.join("mode.json"), "{\"edited\": true}\n");
    case(
        "a recording whose file changed after the run is a problem",
        &row("E3", "test mode with fakes", "E3"),
        Some("is damaged"),
    );
    // A file and the manifest edited together, so that the recording agrees with itself again.
    let _ = crate::recording::reseal(&dir);
    case(
        "a recording edited together with its manifest is caught by the digest in the report",
        &row("E3", "test mode with fakes", "E3"),
        Some("changed after the report was written"),
    );
    let _ = std::fs::remove_dir_all(&root);
    cases
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::manifest_digest;

    /// A root with a recording directory of two files and a manifest that matches them.
    fn root_with(scenario: &str) -> (std::path::PathBuf, String) {
        let root =
            std::env::temp_dir().join(format!("e2e-report-{}-{}", std::process::id(), scenario));
        let dir = root.join("fixtures/recordings/e2e").join(scenario);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("evidence.json"), "{}\n").expect("file");
        std::fs::write(dir.join("mode.json"), "{}\n").expect("file");
        crate::recording::reseal(&dir).expect("a manifest");
        let digest = manifest_digest(&dir).expect("a digest");
        (root, digest)
    }

    fn row(scenario: &str, words: &str, digest: &str) -> String {
        format!(
            "| {scenario} | PASSED, {words} | [recording](../../fixtures/recordings/e2e/{scenario}/evidence.json) | manifest {digest} |"
        )
    }

    #[test]
    fn a_passed_line_with_a_recording_its_digest_and_the_right_label_is_fine() {
        let (root, digest) = root_with("E3");
        assert_eq!(
            problems(&row("E3", "test mode, fakes", &digest), &root),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_passed_line_without_a_recording_is_a_problem() {
        let problems = problems("| E1 | PASSED | real |", Path::new("/nonexistent"));
        assert!(problems[0].contains("cites no recording"));
    }

    #[test]
    fn a_recording_that_does_not_exist_is_a_problem() {
        let report =
            "| E4 | PASSED | test mode | [r](fixtures/recordings/e2e/none/evidence.json) |";
        assert!(problems(report, Path::new("/nonexistent"))[0].contains("does not exist"));
    }

    #[test]
    fn a_passed_line_that_cites_no_digest_is_a_problem() {
        let (root, _) = root_with("E5");
        let report = "| E5 | PASSED, test mode | [r](fixtures/recordings/e2e/E5/evidence.json) |";
        assert!(
            problems(report, &root)
                .iter()
                .any(|p| p.contains("does not cite the manifest digest"))
        );
    }

    #[test]
    fn a_recording_changed_after_the_report_was_written_is_caught_even_if_its_manifest_was_fixed() {
        let (root, digest) = root_with("E6");
        let report = row("E6", "test mode", &digest);
        assert!(problems(&report, &root).is_empty());
        // Someone edits a file and rewrites the manifest so that the two agree.
        let dir = root.join("fixtures/recordings/e2e/E6");
        std::fs::write(dir.join("evidence.json"), "{\"edited\": true}\n").expect("edit");
        crate::recording::reseal(&dir).expect("reseal");
        let text = problems(&report, &root).join("\n");
        assert!(
            text.contains("changed after the report was written"),
            "{text}"
        );
    }

    #[test]
    fn a_file_changed_without_fixing_the_manifest_is_caught() {
        let (root, digest) = root_with("E7");
        let dir = root.join("fixtures/recordings/e2e/E7");
        std::fs::write(dir.join("mode.json"), "{\"edited\": true}\n").expect("edit");
        let text = problems(&row("E7", "test mode", &digest), &root).join("\n");
        assert!(text.contains("is damaged"), "{text}");
    }

    #[test]
    fn a_fake_result_presented_as_real_is_a_problem() {
        let (root, digest) = root_with("E2");
        let report = row("E2", "real adapters with fakes", &digest);
        assert!(
            problems(&report, &root)
                .iter()
                .any(|p| p.contains("not the real proof"))
        );
    }

    #[test]
    fn a_test_mode_scenario_that_does_not_say_so_is_a_problem() {
        let (root, digest) = root_with("E8");
        let report =
            format!("| E8 | PASSED | [r](fixtures/recordings/e2e/E8/evidence.json) | {digest} |");
        assert!(
            problems(&report, &root)
                .iter()
                .any(|p| p.contains("does not say it used fakes"))
        );
    }

    #[test]
    fn a_blocked_line_must_name_what_is_missing() {
        assert!(problems("| E1 | BLOCKED |", Path::new("/x"))[0].contains("does not name"));
        assert!(problems("| E1 | BLOCKED | missing API key |", Path::new("/x")).is_empty());
    }
}
