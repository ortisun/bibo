//! Keywords that no shipped invalid example reaches, shown with documents derived from valid
//! examples by one change each.
//!
//! The work package says every keyword the schemas use (`if`/`then`/`else`, `dependentSchemas`,
//! `contains`, `oneOf`, `not`) must behave as in `check-jsonschema`, "proven by the same
//! examples". The shipped invalid examples reach `then`, `contains`, `oneOf` and `not`. They do
//! not reach `dependentSchemas` (one use, in the gate report schema) or the `else` branch of the
//! ledger entry conditional. The cases here fill those two gaps. They sit in this crate because
//! `schemas/` is not owned by this work package. The hand-off lists the gap.
//!
//! The documents are built in code, so each change is visible next to the rule it breaks.

mod support;

use factory_contracts::schema_engine::Keyword;
use factory_contracts::schemas::SCHEMA_VERSION;
use factory_contracts::validator::{IssueKind, SchemaOutputValidator};
use factory_ports::registry::ContractKind;
use serde_json::Value;
use support::{example_dir, read_example};

/// Takes a valid example, changes it in one way, and says which rule must report it where.
fn derived(
    kind: ContractKind,
    file: &str,
    change: impl FnOnce(&mut Value),
    path: &str,
    rule: Keyword,
) {
    let mut document = read_example(&example_dir(kind, "valid").join(file));
    change(&mut document);
    let issues = SchemaOutputValidator::new()
        .expect("the embedded schemas compile")
        .check(kind, SCHEMA_VERSION, &document)
        .expect_err("the changed document must be refused");
    assert!(
        issues
            .iter()
            .any(|i| i.path == path && i.kind == IssueKind::Schema(rule)),
        "{file}: expected {rule:?} at {path} but found {issues:#?}"
    );
}

/// `dependentSchemas` in the gate report schema says that a `blocked_reason` is allowed only
/// when the outcome is BLOCKED, and a `not_applicable_reason` only when it is NOT_APPLICABLE.
#[test]
fn dependent_schemas_refuse_a_reason_that_does_not_fit_the_outcome() {
    derived(
        ContractKind::GateReport,
        "build-and-test-passed.json",
        |document| {
            document["blocked_reason"] =
                Value::String("The scanner could not start in this environment.".to_owned());
        },
        "outcome",
        Keyword::Const,
    );
    derived(
        ContractKind::GateReport,
        "build-and-test-passed.json",
        |document| {
            document["not_applicable_reason"] =
                Value::String("There is nothing in this change that this gate checks.".to_owned());
        },
        "outcome",
        Keyword::Const,
    );
}

/// `else` in the ledger entry schema says an entry that is not the first must name the hash of
/// the entry before it. The shipped example for this conditional covers `then` only.
#[test]
fn the_else_branch_requires_a_previous_hash_on_every_entry_after_the_first() {
    derived(
        ContractKind::EvidenceLedgerEntry,
        "approver-accepts-residual-risk.json",
        |document| document["prev_entry_hash"] = Value::Null,
        "prev_entry_hash",
        Keyword::Type,
    );
}
