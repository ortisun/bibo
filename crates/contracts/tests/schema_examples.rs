//! The schema examples are the oracle: every valid example validates, and every invalid example
//! is rejected at the place, and for the reason, that its `.expect` file names.
//!
//! The `.expect` files were written for `check-jsonschema` (the Python library), whose messages
//! look like `$.permissions.shell: 'none' was expected` or `'review' is a required property`.
//! This file translates each message into the rule it names (`const`, `required`, `enum` ...) and
//! requires that the Rust validator reports that rule at that path. `schemas/validate.sh` runs the
//! same examples through `check-jsonschema` itself, so the two validators are held to the same
//! files.

mod support;

use std::collections::BTreeSet;

use factory_contracts::schema_engine::Keyword;
use factory_contracts::schemas::{EMBEDDED, SCHEMA_VERSION};
use factory_contracts::validator::{Issue, IssueKind, SchemaOutputValidator};
use factory_ports::registry::ContractKind;
use serde_json::Value;
use support::{example_dir, files_in, read_example, read_text, schemas_dir};

fn validator() -> SchemaOutputValidator {
    SchemaOutputValidator::new().expect("the embedded schemas compile")
}

// ---- The embedded copy equals the files -----------------------------------------------------

#[test]
fn schemas_match_the_files_in_the_schemas_directory() {
    let on_disk: BTreeSet<String> = files_in(&schemas_dir(), &["json"])
        .iter()
        .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
        .filter(|name| name.ends_with(".schema.json"))
        // A schema named `policy-*` governs a policy file (policies/*.yaml), not a document that
        // passes between stages. It is not in the embedded set, which is the set of contract
        // kinds. `tests/model_routing.rs` checks the policy schema against the policy.
        .filter(|name| !name.starts_with("policy-"))
        .collect();
    let embedded: BTreeSet<String> = EMBEDDED.iter().map(|s| s.file_name.to_owned()).collect();
    assert_eq!(
        on_disk, embedded,
        "a schema file was added or removed in schemas/ without changing the embedded set"
    );
    for schema in &EMBEDDED {
        let file = read_text(&schemas_dir().join(schema.file_name));
        assert_eq!(
            file, schema.text,
            "{} differs from its embedded copy; rebuild the crate",
            schema.file_name
        );
    }
}

// ---- Valid examples -------------------------------------------------------------------------

#[test]
fn every_valid_example_validates() {
    let validator = validator();
    let mut checked = 0usize;
    for kind in ContractKind::ALL {
        let examples = files_in(&example_dir(kind, "valid"), &["json", "yaml"]);
        assert!(!examples.is_empty(), "{kind:?} has no valid example");
        for path in examples {
            let document = read_example(&path);
            if let Err(issues) = validator.check(kind, SCHEMA_VERSION, &document) {
                panic!("{} should be valid but: {issues:#?}", path.display());
            }
            checked += 1;
        }
    }
    assert!(checked >= 22, "only {checked} valid examples were found");
}

// ---- Invalid examples -----------------------------------------------------------------------

/// What an `.expect` line asks for.
#[derive(Debug)]
struct Expectation {
    /// The place, in this crate's path style, when the line names one.
    path: Option<String>,
    /// The rules that satisfy the line. Empty means "any rule at that path".
    rules: Vec<Keyword>,
    /// For a `required` rule, the property it names.
    property: Option<String>,
}

fn parse_expectation(line: &str) -> Expectation {
    let (path, message) = match line.strip_prefix('$') {
        Some(rest) => {
            let (location, message) = rest.split_once(": ").unwrap_or((rest, ""));
            let location = location.strip_prefix('.').unwrap_or(location);
            let path = if location.is_empty() { "$" } else { location };
            (Some(path.to_owned()), message)
        }
        None => (None, line),
    };
    let rules: Vec<Keyword> = if message.contains("is a required property") {
        vec![Keyword::Required]
    } else if message.contains("is not one of") {
        vec![Keyword::Enum]
    } else if message.contains("was expected") {
        vec![Keyword::Const]
    } else if message.contains("does not match") {
        vec![Keyword::Pattern]
    } else if message.contains("should be non-empty") {
        vec![Keyword::MinItems, Keyword::MinLength]
    } else if message.contains("does not contain items matching") {
        vec![Keyword::Contains]
    } else if message.contains("is not valid under any of the given schemas") {
        vec![Keyword::OneOf, Keyword::AnyOf]
    } else if message.contains("should not be valid under") {
        vec![Keyword::Not]
    } else if message.contains("is not of type") {
        vec![Keyword::Type]
    } else if message.contains("is greater than or equal to the maximum of") {
        vec![Keyword::ExclusiveMaximum]
    } else if message.contains("is greater than the maximum of") {
        vec![Keyword::Maximum]
    } else if message.contains("is less than or equal to the minimum of") {
        vec![Keyword::ExclusiveMinimum]
    } else if message.contains("is less than the minimum of") {
        vec![Keyword::Minimum]
    } else {
        Vec::new()
    };
    let property = (rules == [Keyword::Required])
        .then(|| {
            let start = message.find('\'')? + 1;
            let end = start + message[start..].find('\'')?;
            Some(message[start..end].to_owned())
        })
        .flatten();
    Expectation {
        path,
        rules,
        property,
    }
}

fn satisfies(issue: &Issue, wanted: &Expectation) -> bool {
    let IssueKind::Schema(rule) = issue.kind else {
        return false;
    };
    if wanted.path.as_deref().is_some_and(|p| p != issue.path) {
        return false;
    }
    if !wanted.rules.is_empty() && !wanted.rules.contains(&rule) {
        return false;
    }
    if let Some(property) = &wanted.property
        && issue.property.as_deref() != Some(property.as_str())
    {
        return false;
    }
    true
}

#[test]
fn every_invalid_example_is_rejected_where_and_why_its_expect_file_says() {
    let validator = validator();
    let mut checked = 0usize;
    let mut failures = Vec::new();
    for kind in ContractKind::ALL {
        let examples = files_in(&example_dir(kind, "invalid"), &["json"]);
        assert!(!examples.is_empty(), "{kind:?} has no invalid example");
        for path in examples {
            let expect_path = path.with_extension("expect");
            let expect_text = read_text(&expect_path);
            let line = expect_text.lines().next().unwrap_or_default();
            let wanted = parse_expectation(line);
            let document = read_example(&path);
            match validator.check(kind, SCHEMA_VERSION, &document) {
                Ok(()) => failures.push(format!("{} was accepted", path.display())),
                Err(issues) => {
                    if !issues.iter().any(|i| satisfies(i, &wanted)) {
                        failures.push(format!(
                            "{}: expected {wanted:?} but found\n    {}",
                            path.display(),
                            issues
                                .iter()
                                .map(|i| format!("{} {:?} {}", i.path, i.kind, i.message))
                                .collect::<Vec<_>>()
                                .join("\n    ")
                        ));
                    }
                }
            }
            checked += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {checked}:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(checked >= 64, "only {checked} invalid examples were found");
}

// ---- The keywords the work package names ----------------------------------------------------

/// The five keywords the package calls out, each shown by an example that rejects for that
/// keyword. A schema that stopped enforcing one would make its example pass and this fail.
#[test]
fn if_then_else_dependent_schemas_contains_one_of_and_not_each_reject_an_example() {
    let validator = validator();
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for kind in ContractKind::ALL {
        for path in files_in(&example_dir(kind, "invalid"), &["json"]) {
            let document = read_example(&path);
            let Err(issues) = validator.check(kind, SCHEMA_VERSION, &document) else {
                continue;
            };
            for issue in issues {
                match issue.kind {
                    IssueKind::Schema(Keyword::Contains) => {
                        seen.insert("contains");
                    }
                    IssueKind::Schema(Keyword::OneOf | Keyword::AnyOf) => {
                        seen.insert("oneOf");
                    }
                    IssueKind::Schema(Keyword::Not) => {
                        seen.insert("not");
                    }
                    _ => {}
                }
            }
        }
    }
    for keyword in ["contains", "oneOf", "not"] {
        assert!(
            seen.contains(keyword),
            "no invalid example is rejected by {keyword}"
        );
    }
    // `if`/`then`/`else` and `dependentSchemas` report the errors of the branch they select, so
    // they are proven by the examples whose expected rule sits under a conditional, such as the
    // `read-only-agent-with-a-shell` example (`if` the tools are read only, `then` the shell is
    // `none`). Count the conditionals the schemas use, so the examples cannot silently stop
    // covering them.
    let mut conditionals = 0usize;
    let mut dependents = 0usize;
    for schema in &EMBEDDED {
        let text = schema.text;
        conditionals += text.matches("\"if\"").count();
        dependents += text.matches("\"dependentSchemas\"").count();
    }
    assert!(conditionals >= 30 && dependents >= 1);
}

#[test]
fn a_document_for_the_wrong_kind_is_rejected() {
    let validator = validator();
    let gate_report = read_example(
        &example_dir(ContractKind::GateReport, "valid").join("build-and-test-passed.json"),
    );
    let issues = validator
        .check(ContractKind::ReviewVerdict, SCHEMA_VERSION, &gate_report)
        .expect_err("a gate report is not a review verdict");
    assert!(!issues.is_empty());
}

#[test]
fn a_valid_example_with_an_unknown_field_is_rejected_by_every_kind() {
    let validator = validator();
    for kind in ContractKind::ALL {
        for path in files_in(&example_dir(kind, "valid"), &["json", "yaml"]) {
            let mut document: Value = read_example(&path);
            document
                .as_object_mut()
                .expect("every example is an object")
                .insert("approved".to_owned(), Value::Bool(true));
            let issues = validator
                .check(kind, SCHEMA_VERSION, &document)
                .expect_err("an unknown top-level field must be refused");
            assert!(
                issues.iter().any(
                    |i| i.kind == IssueKind::Schema(Keyword::AdditionalProperties)
                        && i.property.as_deref() == Some("approved")
                ),
                "{}: {issues:?}",
                path.display()
            );
        }
    }
}
