//! The builder's report, read into a typed value.
//!
//! The first defence is the schema check of `builder-report.v1.schema.json` on the raw bytes
//! (`AgentOutputCheck`). This is the second: a strict read that refuses any field the schema does
//! not name and any value of the wrong type, so a stand-in for the first check that accepts too
//! much still cannot get a loose document through.
//!
//! The report is a record for people. The factory measures the diff, the scope and the gates
//! itself, and nothing in this report is evidence. What the stage keeps of it is its status (to
//! stop on `BLOCKED` and `NEEDS_HUMAN`), the commands it lists (marked as reported by the builder
//! in the evidence manifest), and the instructions the builder says it ignored. The summary is
//! read and dropped: it is the builder's account of its own work, and no reviewer may see it.

use serde_json::{Map, Value};

/// How the builder says the task ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The builder says the acceptance criteria are met.
    Done,
    /// The builder cannot continue.
    Blocked,
    /// A decision belongs to a person.
    NeedsHuman,
}

/// One command the builder says it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedCommand {
    /// The argument vector.
    pub argv: Vec<String>,
    /// The exit code the builder says it saw.
    pub exit_code: i64,
}

/// What the stage keeps of a builder report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderReport {
    /// How the builder says the task ended.
    pub status: Status,
    /// The task the builder says it worked on.
    pub task_id: String,
    /// The paths the builder says it changed. The stage measures the real list.
    pub files_changed: Vec<String>,
    /// The commands the builder says it ran.
    pub commands_run: Vec<ReportedCommand>,
    /// The tests the builder says it added.
    pub tests_added: Vec<String>,
    /// How many dependencies the builder asks for. A person decides each of them.
    pub dependency_requests: usize,
    /// Instructions found in the data that the builder says it did not follow.
    pub ignored_instructions: Vec<String>,
    /// Why the builder is blocked (`BLOCKED`) or what it asks a person (`NEEDS_HUMAN`), in its
    /// words. Untrusted text; it reaches the person and nothing else.
    pub for_a_person: Option<String>,
}

/// Why a report was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the builder report does not follow its schema")]
pub struct ReportProblem;

const FIELDS: [&str; 11] = [
    "schema_version",
    "status",
    "task_id",
    "summary",
    "files_changed",
    "commands_run",
    "tests_added",
    "dependency_requests",
    "blocked_reason",
    "human_question",
    "ignored_instructions",
];

impl BuilderReport {
    /// Reads a report that already passed the schema check.
    ///
    /// # Errors
    /// [`ReportProblem`] for an unknown field, a wrong type, a missing field, or a status that
    /// does not agree with the fields it needs (`BLOCKED` needs a reason, `NEEDS_HUMAN` a
    /// question, `DONE` at least one changed file).
    pub fn read(value: &Value) -> Result<Self, ReportProblem> {
        let object = value.as_object().ok_or(ReportProblem)?;
        if object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
            return Err(ReportProblem);
        }
        if object.get("schema_version").and_then(Value::as_i64) != Some(1) {
            return Err(ReportProblem);
        }
        let status = match text(object, "status")? {
            "DONE" => Status::Done,
            "BLOCKED" => Status::Blocked,
            "NEEDS_HUMAN" => Status::NeedsHuman,
            _ => return Err(ReportProblem),
        };
        let task_id = text(object, "task_id")?.to_owned();
        // The summary must be present and a string. Its content goes nowhere.
        text(object, "summary")?;
        let files_changed = strings(object, "files_changed")?;
        let tests_added = strings(object, "tests_added")?;
        let ignored_instructions = strings(object, "ignored_instructions")?;
        let commands_run = commands(object)?;
        let dependency_requests = object
            .get("dependency_requests")
            .and_then(Value::as_array)
            .ok_or(ReportProblem)?
            .len();
        let for_a_person = match status {
            Status::Blocked => Some(text(object, "blocked_reason")?.to_owned()),
            Status::NeedsHuman => Some(text(object, "human_question")?.to_owned()),
            Status::Done => {
                if files_changed.is_empty() {
                    return Err(ReportProblem);
                }
                None
            }
        };
        Ok(Self {
            status,
            task_id,
            files_changed,
            commands_run,
            tests_added,
            dependency_requests,
            ignored_instructions,
            for_a_person,
        })
    }
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, ReportProblem> {
    object.get(key).and_then(Value::as_str).ok_or(ReportProblem)
}

fn strings(object: &Map<String, Value>, key: &str) -> Result<Vec<String>, ReportProblem> {
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or(ReportProblem)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(ReportProblem))
        .collect()
}

fn commands(object: &Map<String, Value>) -> Result<Vec<ReportedCommand>, ReportProblem> {
    object
        .get("commands_run")
        .and_then(Value::as_array)
        .ok_or(ReportProblem)?
        .iter()
        .map(|item| {
            let command = item.as_object().ok_or(ReportProblem)?;
            if command
                .keys()
                .any(|key| key != "argv" && key != "exit_code")
            {
                return Err(ReportProblem);
            }
            let argv = strings(command, "argv")?;
            if argv.is_empty() {
                return Err(ReportProblem);
            }
            let exit_code = command
                .get("exit_code")
                .and_then(Value::as_i64)
                .ok_or(ReportProblem)?;
            Ok(ReportedCommand { argv, exit_code })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DONE: &str = include_str!("../../../../../agents/builder/fixtures/valid/task-done.json");
    const BLOCKED: &str =
        include_str!("../../../../../agents/builder/fixtures/valid/task-blocked.json");

    fn done() -> Value {
        serde_json::from_str(DONE).expect("JSON")
    }

    #[test]
    fn the_valid_fixtures_of_the_agent_are_read() {
        let report = BuilderReport::read(&done()).expect("a done report");
        assert_eq!(report.status, Status::Done);
        assert!(!report.files_changed.is_empty());
        let blocked: Value = serde_json::from_str(BLOCKED).expect("JSON");
        assert_eq!(
            BuilderReport::read(&blocked).expect("blocked").status,
            Status::Blocked
        );
    }

    #[test]
    fn a_field_the_schema_does_not_name_is_refused() {
        let mut value = done();
        value["verdict"] = json!("PASS");
        assert_eq!(BuilderReport::read(&value), Err(ReportProblem));
    }

    #[test]
    fn a_status_without_the_field_it_needs_is_refused() {
        let mut value = done();
        value["status"] = json!("BLOCKED");
        assert_eq!(BuilderReport::read(&value), Err(ReportProblem));
        value["status"] = json!("NEEDS_HUMAN");
        assert_eq!(BuilderReport::read(&value), Err(ReportProblem));
        let mut value = done();
        value["files_changed"] = json!([]);
        assert_eq!(BuilderReport::read(&value), Err(ReportProblem));
    }

    #[test]
    fn a_command_without_an_exit_code_or_with_an_extra_field_is_refused() {
        let mut value = done();
        value["commands_run"] = json!([{ "argv": ["cargo", "test"] }]);
        assert_eq!(BuilderReport::read(&value), Err(ReportProblem));
        value["commands_run"] = json!([{ "argv": ["cargo"], "exit_code": 0, "claimed": true }]);
        assert_eq!(BuilderReport::read(&value), Err(ReportProblem));
    }

    #[test]
    fn the_summary_is_required_and_is_not_kept() {
        let mut value = done();
        value.as_object_mut().expect("object").remove("summary");
        assert_eq!(BuilderReport::read(&value), Err(ReportProblem));
        let report = BuilderReport::read(&done()).expect("a report");
        // The type has no field that could hold the summary.
        assert!(!format!("{report:?}").contains("summary"));
    }
}
