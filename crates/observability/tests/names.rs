//! The span and attribute names are a contract. These tests pin the rules for a name, check that
//! the constants equal the tables on the conventions page, and check the shape validator that
//! other packages use against real spans.

mod common;

use common::{CONVENTIONS, names_in, table};
use factory_observability::names::{
    self, ATTRIBUTES, Cardinality, SPANS, ShapeError, ValueType, attr, span,
};
use std::collections::BTreeSet;

fn is_snake_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.starts_with(|c: char| c.is_ascii_lowercase())
        && segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn there_is_one_span_for_each_part_of_a_job() {
    let names: Vec<&str> = SPANS.iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        [
            span::JOB,
            span::STAGE_RUN,
            span::ATTEMPT,
            span::AGENT,
            span::TOOL_CALL,
            span::GATE
        ]
    );
}

#[test]
fn span_names_are_factory_dot_snake_case() {
    for spec in SPANS {
        let rest = spec
            .name
            .strip_prefix("factory.")
            .unwrap_or_else(|| panic!("span {} lacks the factory. prefix", spec.name));
        assert!(
            is_snake_segment(rest),
            "span name {} is not snake case",
            spec.name
        );
    }
}

#[test]
fn attribute_keys_are_factory_dot_snake_case_or_listed_standard_keys() {
    for spec in ATTRIBUTES {
        match spec.key.strip_prefix("factory.") {
            Some(rest) => assert!(
                is_snake_segment(rest),
                "attribute key {} is not snake case",
                spec.key
            ),
            None => assert!(
                names::STANDARD_ATTRIBUTES.contains(&spec.key),
                "attribute key {} has no factory. prefix and is not a listed standard key",
                spec.key
            ),
        }
    }
}

#[test]
fn attribute_keys_and_span_names_are_unique() {
    let keys: BTreeSet<&str> = ATTRIBUTES.iter().map(|a| a.key).collect();
    assert_eq!(
        keys.len(),
        ATTRIBUTES.len(),
        "an attribute key appears twice"
    );
    let names: BTreeSet<&str> = SPANS.iter().map(|s| s.name).collect();
    assert_eq!(names.len(), SPANS.len(), "a span name appears twice");
    assert!(
        keys.is_disjoint(&names),
        "a span name is also an attribute key"
    );
}

#[test]
fn every_required_attribute_is_declared_for_its_span() {
    for spec in SPANS {
        for required in spec.required {
            let attribute = ATTRIBUTES
                .iter()
                .find(|a| a.key == *required)
                .unwrap_or_else(|| panic!("{} requires unknown attribute {required}", spec.name));
            assert!(
                attribute.spans.contains(&spec.name),
                "{} requires {required}, but the attribute does not list that span",
                spec.name
            );
        }
    }
}

#[test]
fn every_factory_span_carries_the_correlation_id_and_the_job_id() {
    for spec in SPANS {
        assert!(
            spec.required.contains(&attr::CORRELATION_ID),
            "{} does not require the correlation id",
            spec.name
        );
        assert!(
            spec.required.contains(&attr::JOB_ID),
            "{} does not require the job id",
            spec.name
        );
    }
}

#[test]
fn identifiers_digests_and_measurements_are_unbounded() {
    // Registry identifiers (agent_id, gate_id) name a kind of thing and come from a closed
    // catalog, so they are bounded. Identifiers of one run of something are not.
    let instance_identifiers = [
        attr::CORRELATION_ID,
        attr::TENANT_ID,
        attr::JOB_ID,
        attr::STAGE_RUN_ID,
        attr::ATTEMPT_ID,
    ];
    for spec in ATTRIBUTES {
        let must_be_unbounded = instance_identifiers.contains(&spec.key)
            || spec.key.ends_with("_sha256")
            || spec.value_type != ValueType::String;
        if must_be_unbounded && spec.key != attr::ATTEMPT_NUMBER {
            assert_eq!(
                spec.cardinality,
                Cardinality::Unbounded,
                "{} is an identifier, a digest or a measurement but is marked bounded",
                spec.key
            );
        }
    }
}

#[test]
fn st_07_allowlist_contains_every_declared_attribute_and_nothing_else() {
    for spec in ATTRIBUTES {
        assert!(
            names::is_allowed_attribute(spec.key),
            "{} is not allowed",
            spec.key
        );
    }
    for rogue in [
        "prompt",
        "issue_body",
        "password",
        "factory.prompt",
        "http.url",
    ] {
        assert!(
            !names::is_allowed_attribute(rogue),
            "{rogue} must not be on the allowlist"
        );
    }
}

#[test]
fn conventions_page_span_table_equals_the_constants() {
    let rows = table(CONVENTIONS, "spans");
    let from_page: Vec<(String, BTreeSet<String>)> = rows
        .iter()
        .map(|row| (row[0].clone(), names_in(&row[1])))
        .collect();
    let from_code: Vec<(String, BTreeSet<String>)> = SPANS
        .iter()
        .map(|s| {
            (
                s.name.to_string(),
                s.required.iter().map(|r| r.to_string()).collect(),
            )
        })
        .collect();
    assert_eq!(from_page, from_code);
}

#[test]
fn conventions_page_attribute_table_equals_the_constants() {
    let rows = table(CONVENTIONS, "attributes");
    let from_page: Vec<(String, String, String, BTreeSet<String>)> = rows
        .iter()
        .map(|row| {
            (
                row[0].clone(),
                row[1].clone(),
                row[2].clone(),
                names_in(&row[3]),
            )
        })
        .collect();
    let from_code: Vec<(String, String, String, BTreeSet<String>)> = ATTRIBUTES
        .iter()
        .map(|a| {
            (
                a.key.to_string(),
                a.value_type.as_str().to_string(),
                a.cardinality.as_str().to_string(),
                a.spans.iter().map(|s| s.to_string()).collect(),
            )
        })
        .collect();
    assert_eq!(from_page, from_code);
}

#[test]
fn value_types_have_stable_names() {
    assert_eq!(ValueType::String.as_str(), "string");
    assert_eq!(ValueType::Int.as_str(), "int");
    assert_eq!(ValueType::Double.as_str(), "double");
}

#[test]
fn shape_check_accepts_a_span_with_every_required_attribute() {
    let present: Vec<&str> = names::span_spec(span::GATE)
        .expect("the gate span is declared")
        .required
        .to_vec();
    assert_eq!(names::check_span_shape(span::GATE, present), Ok(()));
}

#[test]
fn shape_check_names_every_missing_attribute() {
    let result = names::check_span_shape(span::GATE, [attr::CORRELATION_ID, attr::JOB_ID]);
    match result {
        Err(ShapeError::MissingAttributes(missing)) => {
            assert!(missing.contains(&attr::GATE_ID));
            assert!(missing.contains(&attr::OUTCOME));
            assert!(!missing.contains(&attr::CORRELATION_ID));
        }
        other => panic!("expected missing attributes, got {other:?}"),
    }
}

#[test]
fn shape_check_rejects_attributes_that_are_not_on_the_allowlist() {
    let mut present: Vec<&str> = names::span_spec(span::JOB).unwrap().required.to_vec();
    present.push("issue_body");
    assert_eq!(
        names::check_span_shape(span::JOB, present),
        Err(ShapeError::ForbiddenAttributes(vec![
            "issue_body".to_string()
        ]))
    );
}

#[test]
fn shape_check_rejects_an_unknown_span() {
    assert_eq!(
        names::check_span_shape("factory.mystery", Vec::<&str>::new()),
        Err(ShapeError::UnknownSpan("factory.mystery".to_string()))
    );
}
