//! The documentation writer's report, read into a typed value.
//!
//! The first defence is the schema check of `documentation-report.v1.schema.json` on the raw
//! bytes (`AgentOutputCheck`). This is the second: a strict read that refuses any field the schema
//! does not name and any value of the wrong type.
//!
//! The report is a record for people. The factory measures the documents, the changed paths and
//! the links itself, and nothing in this report is evidence. What the stage keeps is its status,
//! the claims with the file each one cites (checked against the tree), what the writer says it
//! covered, and the instructions it says it ignored. **The summary is read and dropped**: it is the
//! writer's account of its own work, and the independent reviewer never sees it.

use serde_json::{Map, Value};

/// Why a report was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the writer report does not follow its schema")]
pub struct ReportProblem;

/// What the stage keeps of a writer report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterReport {
    /// True when the writer asks for a person.
    pub needs_human: bool,
    /// The files the writer says it wrote. The stage measures the real list.
    pub files_written: Vec<String>,
    /// How the writer says it handled each plan item: the item and the status.
    pub coverage: Vec<(String, String)>,
    /// Each claim and the file that is cited for it.
    pub claims: Vec<(String, String)>,
    /// Instructions found in the data that the writer says it did not follow.
    pub ignored_instructions: Vec<String>,
}

const FIELDS: [&str; 8] = [
    "schema_version",
    "status",
    "summary",
    "files_written",
    "plan_coverage",
    "claims",
    "human_question",
    "ignored_instructions",
];

fn texts(value: &Value) -> Result<Vec<String>, ReportProblem> {
    value
        .as_array()
        .ok_or(ReportProblem)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(ReportProblem))
        .collect()
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, ReportProblem> {
    object.get(name).ok_or(ReportProblem)
}

impl WriterReport {
    /// Reads a validated report.
    ///
    /// # Errors
    /// [`ReportProblem`] for a field the schema does not name or a value of the wrong type.
    pub fn read(value: &Value) -> Result<Self, ReportProblem> {
        let object = value.as_object().ok_or(ReportProblem)?;
        if object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
            return Err(ReportProblem);
        }
        let needs_human = match field(object, "status")?.as_str() {
            Some("DONE") => false,
            Some("NEEDS_HUMAN") => true,
            _ => return Err(ReportProblem),
        };
        // The summary is the writer's account of its own work. It is checked for its type and
        // dropped here.
        field(object, "summary")?.as_str().ok_or(ReportProblem)?;
        let mut coverage = Vec::new();
        for item in field(object, "plan_coverage")?
            .as_array()
            .ok_or(ReportProblem)?
        {
            let item = item.as_object().ok_or(ReportProblem)?;
            coverage.push((
                field(item, "plan_item")?
                    .as_str()
                    .ok_or(ReportProblem)?
                    .to_owned(),
                field(item, "status")?
                    .as_str()
                    .ok_or(ReportProblem)?
                    .to_owned(),
            ));
        }
        let mut claims = Vec::new();
        for item in field(object, "claims")?.as_array().ok_or(ReportProblem)? {
            let item = item.as_object().ok_or(ReportProblem)?;
            claims.push((
                field(item, "claim")?
                    .as_str()
                    .ok_or(ReportProblem)?
                    .to_owned(),
                field(item, "evidence_path")?
                    .as_str()
                    .ok_or(ReportProblem)?
                    .to_owned(),
            ));
        }
        Ok(Self {
            needs_human,
            files_written: texts(field(object, "files_written")?)?,
            coverage,
            claims,
            ignored_instructions: texts(field(object, "ignored_instructions")?)?,
        })
    }

    /// The code of the request for a person, when the writer asks for one.
    #[must_use]
    pub fn asks_a_person(&self) -> Option<&'static str> {
        self.needs_human.then_some("documentation-needs-human")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report() -> Value {
        json!({
            "schema_version": 1,
            "status": "DONE",
            "summary": "The README now describes the new flag with an example.",
            "files_written": ["README.md"],
            "plan_coverage": [{ "plan_item": "usage-json", "status": "covered", "files": ["README.md"] }],
            "claims": [{ "claim": "The flag prints JSON.", "evidence_path": "src/main.rs" }],
            "ignored_instructions": []
        })
    }

    #[test]
    fn a_report_is_read_and_its_summary_is_dropped() {
        let read = WriterReport::read(&report()).expect("a valid report");
        assert_eq!(
            read.claims,
            [("The flag prints JSON.".to_owned(), "src/main.rs".to_owned())]
        );
        assert!(!format!("{read:?}").contains("The README now describes"));
        assert_eq!(read.asks_a_person(), None);
    }

    #[test]
    fn a_report_with_an_unknown_field_is_refused() {
        let mut bad = report();
        bad["self_assessment"] = json!("trust me");
        assert!(WriterReport::read(&bad).is_err());
    }

    #[test]
    fn a_request_for_a_person_is_recognised() {
        let mut ask = report();
        ask["status"] = json!("NEEDS_HUMAN");
        let read = WriterReport::read(&ask).expect("valid");
        assert_eq!(read.asks_a_person(), Some("documentation-needs-human"));
    }
}
