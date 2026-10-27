//! `oneOf` and `anyOf`: when no shape matches, the report names the shape that was closest.
//!
//! The evidence items in the ledger schema are a `oneOf` of eight shapes told apart by `type`.
//! When an author chose a shape and got something inside it wrong, a bare "does not match any of
//! the allowed shapes" is no help: the agent has to guess which of eight shapes was meant and what
//! is wrong with it. The reference validator, `check-jsonschema`, prints the generic error and then
//! a "best deep match". The engine reports the generic violation first and the closest shape's own
//! violations after it. The rule is in `schema_engine::closest_shape`.
//!
//! Each case below was also run through `check-jsonschema` 0.39.0. The comparison is in the work
//! package report.

mod support;

use factory_contracts::schema_engine::Keyword;
use factory_contracts::schemas::SCHEMA_VERSION;
use factory_contracts::validator::{IssueKind, SchemaOutputValidator};
use factory_ports::registry::ContractKind;
use serde_json::{Value, json};
use support::{example_dir, read_example};

/// A first-entry ledger document with its `evidence` replaced by one item. The claim is a
/// simulation result, so no other rule of the schema (such as the evidence types a measured fact
/// needs) adds violations of its own. The document comes from the example whose only fault is a
/// seed, with the evidence replaced.
fn ledger_with_evidence(item: Value) -> Value {
    let mut document = read_example(
        &example_dir(ContractKind::EvidenceLedgerEntry, "invalid")
            .join("seed-above-the-largest-exact-integer.json"),
    );
    document["evidence"] = json!([item]);
    document
}

type Found = Vec<(String, Keyword, Option<String>)>;

/// What the validator reports for an evidence item, as `(path, rule, property)` in order.
fn report_for(item: Value) -> Found {
    SchemaOutputValidator::new()
        .expect("the embedded schemas compile")
        .check(
            ContractKind::EvidenceLedgerEntry,
            SCHEMA_VERSION,
            &ledger_with_evidence(item),
        )
        .expect_err("the evidence item must be refused")
        .into_iter()
        .map(|issue| {
            let IssueKind::Schema(rule) = issue.kind else {
                panic!("unexpected {issue:?}");
            };
            (issue.path, rule, issue.property)
        })
        // The ledger schema has other rules about the evidence list as a whole (an item of a
        // suitable type must be present). They are not what these cases are about.
        .filter(|(path, _, _)| path.starts_with("evidence["))
        .collect()
}

fn experiment(change: impl FnOnce(&mut Value)) -> Value {
    let mut item = json!({
        "type": "experiment",
        "experiment_id": "sort-order-seeds",
        "run_ids": ["018f3a95-0003-7a01-8b01-1c01d01e01f3"],
        "seeds": [42, 7]
    });
    change(&mut item);
    item
}

fn generic() -> (String, Keyword, Option<String>) {
    ("evidence[0]".to_owned(), Keyword::OneOf, None)
}

#[test]
fn a_seed_beyond_the_largest_exact_integer_is_reported_inside_its_evidence_shape() {
    let found = report_for(experiment(|item| {
        item["seeds"][1] = json!(9_007_199_254_740_992_u64);
    }));
    assert_eq!(
        found,
        [
            generic(),
            ("evidence[0].seeds[1]".to_owned(), Keyword::Maximum, None)
        ]
    );
    let found = report_for(experiment(|item| {
        item["seeds"][0] = json!(-9_007_199_254_740_992_i64);
    }));
    assert_eq!(
        found[1],
        ("evidence[0].seeds[0]".to_owned(), Keyword::Minimum, None)
    );
}

#[test]
fn a_missing_property_of_the_chosen_evidence_shape_is_reported() {
    let found = report_for(experiment(|item| {
        item.as_object_mut().expect("object").remove("run_ids");
    }));
    assert_eq!(
        found,
        [
            generic(),
            (
                "evidence[0]".to_owned(),
                Keyword::Required,
                Some("run_ids".to_owned())
            )
        ]
    );
}

#[test]
fn a_property_of_the_wrong_type_in_the_chosen_evidence_shape_is_reported() {
    let found = report_for(experiment(|item| item["seeds"] = json!("forty-two")));
    assert_eq!(
        found,
        [
            generic(),
            ("evidence[0].seeds".to_owned(), Keyword::Type, None)
        ]
    );
}

#[test]
fn an_evidence_item_that_matches_no_shape_gets_only_the_generic_violation() {
    for item in [
        json!({"type": "horoscope", "seeds": [1]}),
        json!("just a sentence"),
        json!([1, 2]),
        json!(null),
    ] {
        assert_eq!(report_for(item.clone()), [generic()], "{item}");
    }
}

#[test]
fn an_item_with_no_type_leaves_every_shape_a_candidate_and_the_first_explains_what_is_missing() {
    let found = report_for(json!({}));
    assert_eq!(found[0], generic());
    assert!(found.len() > 1);
    assert!(
        found[1..].iter().all(|f| f.1 == Keyword::Required),
        "{found:?}"
    );
}

/// `result` is checked by one shape only, so a bad value there does not tell shapes apart: the
/// shape whose `type` matched is the one meant. (`type` fails in seven of the eight shapes, which
/// is what marks it as the property that tells them apart.)
#[test]
fn a_bad_value_of_a_property_that_does_not_tell_shapes_apart_is_reported() {
    let found = report_for(json!({
        "type": "test",
        "gate_report_id": "018f3a80-1c22-7a44-9b55-6c7d8e9fa0b3",
        "gate_report_sha256": "sha256:f46413546b49a12b2eb6ec29a33c7e41fb245bbc9b6cfd8d06b3394e3e434c78",
        "result": "maybe"
    }));
    assert_eq!(
        found,
        [
            generic(),
            ("evidence[0].result".to_owned(), Keyword::Enum, None)
        ]
    );
}
