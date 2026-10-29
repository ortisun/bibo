//! The audit coverage matrix: for each event type the policy requires, who owns it and where it is
//! produced. The data is `audit_events` in `docs/security/p0-coverage.json`, which the checker
//! `docs/security/tools/check_p0_coverage.py` verifies against the sources (it reads files, which
//! this crate may not). This module reads the same data at compile time and hands it to the tests.

use serde_json::Value;

const DATA: &str = include_str!("../../../../docs/security/p0-coverage.json");

/// Where an event type is produced today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Production {
    /// The engine writes it through `AuditAction`.
    Engine,
    /// A stage handler notes it through `StageContext::note_audit`.
    Handler,
    /// A component writes the facts under other names than the required type.
    DifferentlyNamed,
    /// The component keeps its own stream, which is not the audit log of the store.
    OtherStream,
    /// Nothing in production code writes it.
    Nothing,
}

/// One row of the matrix.
#[derive(Debug, Clone)]
pub struct Row {
    pub kind: String,
    pub owner: String,
    pub production: Production,
}

pub fn rows() -> Vec<Row> {
    let document: Value = serde_json::from_str(DATA).expect("p0-coverage.json is valid JSON");
    document["audit_events"]
        .as_array()
        .expect("the data file has audit_events")
        .iter()
        .map(|row| Row {
            kind: row["type"].as_str().expect("a type").to_owned(),
            owner: row["owner"].as_str().expect("an owner").to_owned(),
            production: match row["production"].as_str().expect("a production") {
                "engine" => Production::Engine,
                "handler" => Production::Handler,
                "differently_named" => Production::DifferentlyNamed,
                "other_stream" => Production::OtherStream,
                "none" => Production::Nothing,
                other => panic!("unknown production {other}"),
            },
        })
        .collect()
}
