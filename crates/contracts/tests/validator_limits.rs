//! NT-TOOL-09, structured output abuse. Adapter output with an unknown field, wrong types, nesting
//! 10,000 deep, a 10 MB body, invalid UTF-8 or a traversal path is rejected, and the size, the
//! encoding and the depth are rejected before any parse that could exhaust memory.
//!
//! The "before the parse" claim is shown by the kind of error: a body that is both too large and
//! not JSON is reported as too large, a body that is both too deep and not JSON is reported as too
//! deep. A validator that parsed first would report the syntax. The property tests then check the
//! limits against generated inputs, and that no input makes the validator panic.

mod support;

use factory_contracts::schemas::SCHEMA_VERSION;
use factory_contracts::validator::{
    Issue, IssueKind, OutputLimits, SchemaOutputValidator, prescan,
};
use factory_ports::registry::{ContractKind, OutputValidator};
use proptest::prelude::*;
use serde_json::{Value, json};
use support::{example_dir, files_in, read_example};

fn validator() -> SchemaOutputValidator {
    SchemaOutputValidator::new().expect("the embedded schemas compile")
}

fn review_verdict() -> Value {
    read_example(
        &example_dir(ContractKind::ReviewVerdict, "valid")
            .join("changes-required-missing-test.json"),
    )
}

fn kinds(issues: &[Issue]) -> Vec<IssueKind> {
    issues.iter().map(|i| i.kind).collect()
}

fn reject_bytes(kind: ContractKind, bytes: &[u8]) -> Vec<Issue> {
    validator()
        .parse_and_validate(kind, SCHEMA_VERSION, bytes)
        .expect_err("the body must be refused")
}

#[test]
fn negative_nt_tool_09_the_valid_document_is_accepted_so_the_rejections_below_mean_something() {
    let body = serde_json::to_vec(&review_verdict()).expect("serialize");
    let value = validator()
        .parse_and_validate(ContractKind::ReviewVerdict, SCHEMA_VERSION, &body)
        .expect("a valid verdict passes through the byte entry point");
    assert_eq!(value, review_verdict());
}

#[test]
fn negative_nt_tool_09_an_unknown_field_is_rejected_and_named() {
    let mut document = review_verdict();
    document["approved"] = Value::Bool(true);
    let body = serde_json::to_vec(&document).expect("serialize");
    let issues = reject_bytes(ContractKind::ReviewVerdict, &body);
    let unknown = issues
        .iter()
        .find(|i| {
            i.kind
                == IssueKind::Schema(
                    factory_contracts::schema_engine::Keyword::AdditionalProperties,
                )
        })
        .expect("an unknown-field issue");
    assert_eq!(unknown.property.as_deref(), Some("approved"));
    assert_eq!(unknown.path, "$");
    assert!(unknown.message.contains("`approved`") && unknown.message.contains("remove it"));
}

#[test]
fn negative_nt_tool_09_wrong_types_are_rejected() {
    for (field, bad) in [
        ("verdict", json!(7)),
        ("verdict", json!(["PASS"])),
        ("findings", json!("none")),
        ("findings", json!({"a": 1})),
        ("inputs_reviewed", json!(true)),
        ("schema_version", json!("1")),
    ] {
        let mut document = review_verdict();
        document[field] = bad;
        let body = serde_json::to_vec(&document).expect("serialize");
        let issues = reject_bytes(ContractKind::ReviewVerdict, &body);
        assert!(
            issues.iter().any(|i| i.path == field),
            "{field}: {issues:?}"
        );
    }
}

#[test]
fn negative_nt_tool_09_nesting_10000_deep_is_rejected_before_parsing() {
    let arrays = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    let objects = format!("{}1{}", "{\"a\":".repeat(10_000), "}".repeat(10_000));
    // Not closed, so the text is not JSON at all. A parser would say so. The depth scan says
    // "too deep" first.
    let unclosed = "[".repeat(10_000);
    for body in [arrays, objects, unclosed] {
        let issues = reject_bytes(ContractKind::ReviewVerdict, body.as_bytes());
        assert_eq!(kinds(&issues), [IssueKind::TooDeep], "{}", &body[..20]);
    }
}

#[test]
fn negative_nt_tool_09_a_10_mb_body_is_rejected_for_its_size_without_being_read() {
    let ten_mb = 10 * 1024 * 1024;
    // Valid JSON, far over the limit.
    let big_string = format!("{{\"title\": \"{}\"}}", "a".repeat(ten_mb));
    assert_eq!(
        kinds(&reject_bytes(
            ContractKind::ReviewVerdict,
            big_string.as_bytes()
        )),
        [IssueKind::TooLarge]
    );
    // Not JSON, not UTF-8 and too deep as well, and still reported as too large.
    let mut garbage = vec![b'['; ten_mb];
    garbage[5] = 0xff;
    let issues = reject_bytes(ContractKind::ReviewVerdict, &garbage);
    assert_eq!(kinds(&issues), [IssueKind::TooLarge]);
    assert!(
        issues[0].message.contains("10485760 bytes"),
        "{}",
        issues[0].message
    );
}

#[test]
fn negative_nt_tool_09_invalid_utf8_is_rejected() {
    for body in [
        b"\xff\xfe{}".to_vec(),
        b"{\"a\": \"\xc3\x28\"}".to_vec(),
        b"{\"a\": \"\xed\xa0\x80\"}".to_vec(), // a lone surrogate
        b"{\"a\": \"\xc0\xaf\"}".to_vec(),     // an overlong encoding
    ] {
        let issues = reject_bytes(ContractKind::ReviewVerdict, &body);
        assert_eq!(kinds(&issues), [IssueKind::NotUtf8], "{body:?}");
    }
}

#[test]
fn negative_nt_tool_09_a_traversal_path_is_rejected() {
    let kind = ContractKind::ProjectManifest;
    let valid = read_example(&example_dir(kind, "valid").join("word-count-minimal.json"));
    // The minimal manifest has no path field, so add the documentation block that has them.
    let with_paths = |path: &str, changelog: &str| {
        let mut document = valid.clone();
        document["documentation"] = json!({
            "required_documents": [{"path": path, "purpose": "Explains what the tool does and how to use it."}],
            "changelog_path": changelog
        });
        serde_json::to_vec(&document).expect("serialize")
    };
    let accepted = with_paths("README.md", "CHANGELOG.md");
    validator()
        .parse_and_validate(kind, SCHEMA_VERSION, &accepted)
        .expect("ordinary paths are accepted");
    for bad in [
        "../../etc/passwd",
        "a/../../b",
        "/etc/passwd",
        "docs\\..\\..\\x",
        ".git/hooks/pre-commit",
        "docs/.GIT/config",
        "docs//readme.md",
        "docs/./readme.md",
        "docs/readme\u{0}.md",
        "docs/line\nbreak.md",
    ] {
        let issues = reject_bytes(kind, &with_paths(bad, "CHANGELOG.md"));
        let unsafe_path: Vec<&Issue> = issues
            .iter()
            .filter(|i| i.kind == IssueKind::UnsafePath)
            .collect();
        assert_eq!(unsafe_path.len(), 1, "{bad:?}: {issues:?}");
        assert_eq!(
            unsafe_path[0].path,
            "documentation.required_documents[0].path"
        );
        assert!(
            !unsafe_path[0].message.contains("passwd"),
            "no echo: {bad:?}"
        );
    }
    let issues = reject_bytes(kind, &with_paths("README.md", "../CHANGELOG.md"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == IssueKind::UnsafePath && i.path == "documentation.changelog_path")
    );
}

#[test]
fn negative_nt_tool_09_duplicate_keys_and_trailing_data_are_rejected() {
    let doc = br#"{"verdict": "PASS", "verdict": "BLOCK"}"#;
    let issues = reject_bytes(ContractKind::ReviewVerdict, doc);
    assert_eq!(kinds(&issues), [IssueKind::DuplicateKey]);
    let issues = reject_bytes(ContractKind::ReviewVerdict, br#"{} {"approved": true}"#);
    assert_eq!(kinds(&issues), [IssueKind::NotJson]);
}

#[test]
fn negative_nt_tool_09_messages_never_echo_what_the_document_said() {
    let secret = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut document = review_verdict();
    document["verdict"] = json!(secret);
    document["findings"] = json!([{ secret: secret }]);
    document[secret] = json!(secret);
    let kind = ContractKind::ProjectManifest;
    let mut manifest = read_example(&example_dir(kind, "valid").join("word-count-minimal.json"));
    manifest["documentation"] =
        json!({"required_documents": [{"path": format!("../{secret}"), "purpose": secret}]});
    for (kind, value) in [(ContractKind::ReviewVerdict, document), (kind, manifest)] {
        let body = serde_json::to_vec(&value).expect("serialize");
        for issue in reject_bytes(kind, &body) {
            assert!(
                !issue.message.contains("sk-ant") && !issue.path.contains("sk-ant"),
                "{issue:?}"
            );
            assert!(
                issue
                    .property
                    .as_deref()
                    .is_none_or(|p| !p.contains("sk-ant")),
                "{issue:?}"
            );
        }
    }
    // A syntax error and a duplicate key do not echo either.
    let body = format!("{{\"{secret}\": 1, \"{secret}\": 2}}");
    for issue in reject_bytes(ContractKind::ReviewVerdict, body.as_bytes()) {
        assert!(
            !issue.message.contains("sk-ant") && !issue.path.contains("sk-ant"),
            "{issue:?}"
        );
    }
}

#[test]
fn negative_nt_tool_09_a_value_that_is_too_deep_is_refused_by_the_port_without_recursion() {
    // Built by hand, 200 deep: deep enough to be over the limit, shallow enough that dropping it
    // is safe. A document nested 10,000 deep is only ever seen as bytes.
    let mut value = json!(1);
    for _ in 0..200 {
        value = json!({ "a": value });
    }
    let violations = validator()
        .validate(ContractKind::ReviewVerdict, SCHEMA_VERSION, &value)
        .expect_err("too deep");
    assert_eq!(violations.len(), 1);
    assert!(violations[0].message.contains("deeper than 32 levels"));
}

#[test]
fn negative_nt_tool_09_the_port_refuses_a_large_value() {
    let value = json!({ "title": "a".repeat(OutputLimits::AGENT_OUTPUT.max_bytes() + 1) });
    let violations = validator()
        .validate(ContractKind::ReviewVerdict, SCHEMA_VERSION, &value)
        .expect_err("too large");
    assert_eq!(violations.len(), 1);
    assert!(violations[0].message.contains("larger than"));
}

#[test]
fn negative_nt_tool_09_every_valid_example_fits_the_default_limits() {
    let validator = validator();
    let mut deepest = 0usize;
    for kind in ContractKind::ALL {
        for path in files_in(&example_dir(kind, "valid"), &["json", "yaml"]) {
            let document = read_example(&path);
            let body = serde_json::to_vec(&document).expect("serialize");
            validator
                .parse_and_validate(kind, SCHEMA_VERSION, &body)
                .unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));
            let depth = body
                .iter()
                .scan((0usize, 0usize), |(d, max), b| {
                    match b {
                        b'[' | b'{' => {
                            *d += 1;
                            *max = (*max).max(*d);
                        }
                        b']' | b'}' => *d = d.saturating_sub(1),
                        _ => {}
                    }
                    Some(*max)
                })
                .last()
                .unwrap_or(0);
            deepest = deepest.max(depth);
        }
    }
    assert!(
        deepest + 8 <= OutputLimits::AGENT_OUTPUT.max_depth(),
        "the deepest example is {deepest} levels; the default limit is {}",
        OutputLimits::AGENT_OUTPUT.max_depth()
    );
}

// ---- Properties -----------------------------------------------------------------------------

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        "[a-z ]{0,8}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 64, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("[a-z_]{1,6}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any body longer than the limit is "too large", whatever it holds.
    #[test]
    fn negative_nt_tool_09_property_any_body_over_the_limit_is_too_large(
        extra in 1usize..2048,
        byte in any::<u8>(),
    ) {
        let limits = OutputLimits::new(1024, 8, 100).expect("limits");
        let validator = SchemaOutputValidator::with_limits(limits).expect("compile");
        let body = vec![byte; limits.max_bytes() + extra];
        let issues = validator
            .parse_and_validate(ContractKind::GateReport, SCHEMA_VERSION, &body)
            .expect_err("over the limit");
        prop_assert_eq!(kinds(&issues), vec![IssueKind::TooLarge]);
    }

    /// Well-formed nesting is refused exactly when it is deeper than the limit.
    #[test]
    fn negative_nt_tool_09_property_nesting_is_refused_exactly_beyond_the_limit(
        depth in 1usize..400,
        objects in any::<bool>(),
    ) {
        let limits = OutputLimits::new(OutputLimits::CEILING.max_bytes(), 32, 100_000).expect("limits");
        let body = if objects {
            format!("{}1{}", "{\"a\":".repeat(depth), "}".repeat(depth))
        } else {
            format!("{}{}", "[".repeat(depth), "]".repeat(depth))
        };
        let outcome = prescan(body.as_bytes(), limits);
        if depth > limits.max_depth() {
            prop_assert_eq!(outcome.expect_err("too deep").kind, IssueKind::TooDeep);
        } else {
            prop_assert!(outcome.is_ok());
        }
    }

    /// Whatever the bytes are, the validator returns and never panics, and its messages are
    /// short and contain no control characters.
    #[test]
    fn negative_nt_tool_09_property_arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let validator = validator();
        if let Err(issues) = validator.parse_and_validate(ContractKind::GateReport, SCHEMA_VERSION, &bytes) {
            for issue in issues {
                prop_assert!(issue.message.len() < 400, "{}", issue.message);
                prop_assert!(!issue.message.chars().any(char::is_control));
            }
        }
    }

    /// A well-formed document inside the limits is never refused for a limit, an encoding, a
    /// syntax or a duplicate-key reason.
    #[test]
    fn negative_nt_tool_09_property_well_formed_documents_pass_the_pre_parse_checks(value in json_value()) {
        let body = serde_json::to_vec(&value).expect("serialize");
        if let Err(issues) = validator().parse_and_validate(ContractKind::GateReport, SCHEMA_VERSION, &body) {
            for issue in issues {
                prop_assert!(
                    matches!(issue.kind, IssueKind::Schema(_) | IssueKind::UnsafePath),
                    "{issue:?} for {value}"
                );
            }
        }
    }
}
