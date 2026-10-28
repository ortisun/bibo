//! The check of the acceptance report (`docs/reports/slice-1-acceptance.md`), which the package
//! `s1-end-to-end-run` writes. The report must not claim more than the recordings show.
//!
//! The rules, which that package follows when it writes the report:
//!
//! * A line that says `PASSED` for a scenario cites a recording: a Markdown link to a file under
//!   `fixtures/recordings/e2e/` that exists.
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
            for link in links {
                if !root.join(&link).is_file() {
                    found.push(format!(
                        "line {number}: the recording {link} does not exist"
                    ));
                }
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
        {
            found.push(format!(
                "line {number}: BLOCKED does not name what is missing"
            ));
        }
    }
    found
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

#[cfg(test)]
mod tests {
    use super::*;

    fn root_with(file: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "e2e-report-{}-{}",
            std::process::id(),
            file.replace('/', "_")
        ));
        let path = dir.join(file);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("dir");
        std::fs::write(&path, "{}").expect("file");
        dir
    }

    #[test]
    fn a_passed_line_with_a_recording_and_the_right_label_is_fine() {
        let root = root_with("fixtures/recordings/e2e/E1.json");
        let report = "| E1 | PASSED | real adapters | [recording](../../fixtures/recordings/e2e/E1.json) |\n| E3 | PASSED | test mode, fakes | [recording](../../fixtures/recordings/e2e/E1.json) |";
        assert_eq!(problems(report, &root), Vec::<String>::new());
    }

    #[test]
    fn a_passed_line_without_a_recording_is_a_problem() {
        let problems = problems("| E1 | PASSED | real |", Path::new("/nonexistent"));
        assert!(problems[0].contains("cites no recording"));
    }

    #[test]
    fn a_recording_that_does_not_exist_is_a_problem() {
        let report = "| E4 | PASSED | test mode | [r](fixtures/recordings/e2e/none.json) |";
        assert!(problems(report, Path::new("/nonexistent"))[0].contains("does not exist"));
    }

    #[test]
    fn a_fake_result_presented_as_real_is_a_problem() {
        let root = root_with("fixtures/recordings/e2e/E2.json");
        let report =
            "| E2 | PASSED | real adapters with fakes | [r](fixtures/recordings/e2e/E2.json) |";
        assert!(
            problems(report, &root)
                .iter()
                .any(|p| p.contains("not the real proof"))
        );
    }

    #[test]
    fn a_test_mode_scenario_that_does_not_say_so_is_a_problem() {
        let root = root_with("fixtures/recordings/e2e/E3.json");
        let report = "| E3 | PASSED | [r](fixtures/recordings/e2e/E3.json) |";
        assert!(
            problems(report, &root)
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
