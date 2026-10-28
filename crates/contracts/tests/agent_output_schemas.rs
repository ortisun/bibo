//! An agent's output is checked against ITS OWN schema (`agents/schemas/`), which the manifest
//! names. The eleven contract kinds of `SchemaOutputValidator` do not cover these schemas, so
//! `AgentSchema` and `AgentSchemaLoader` do, with the same hard limits, the same strict JSON
//! parse (a repeated key is refused) and the same repair-friendly messages.
//!
//! The tests run on the real definitions in `agents/`: the three agents named in the work package
//! (`intake-classifier`, `planner` and `code-reviewer`) in detail, and all nine in one sweep.
//!
//! Deliberate breaks, each caught by the test named after it (the `break_` tests):
//! skip the limits, accept a repeated key, let the schema reference reach a path outside
//! `agents/schemas`, skip the hash check, ignore a keyword the engine does not know.

mod support;

use std::fs;

use factory_contracts::agent_schema::{
    AgentSchema, AgentSchemaLoader, SchemaFileError, SchemaFileErrorKind,
};
use factory_contracts::registry::FileAgentRegistry;
use factory_contracts::schema_engine::Keyword;
use factory_contracts::validator::{Issue, IssueKind, OutputLimits};
use factory_domain::contracts::AgentManifest;
use factory_domain::values::Sha256Digest;
use factory_ports::registry::{AgentId, AgentRegistry, VersionReq};
use serde_json::{Value, json};
use support::{TempDir, repo_root};

const NINE_AGENTS: [&str; 9] = [
    "intake-classifier",
    "specification-writer",
    "specification-reviewer",
    "architect",
    "planner",
    "builder",
    "code-reviewer",
    "documentation-writer",
    "documentation-reviewer",
];

fn manifest_of(agent: &str) -> AgentManifest {
    let registry = FileAgentRegistry::load(&repo_root()).expect("the repository definitions load");
    registry
        .manifest(
            &AgentId::parse(agent).expect("an agent id"),
            &VersionReq::Any,
        )
        .unwrap_or_else(|e| panic!("{agent}: {e}"))
}

fn loader() -> AgentSchemaLoader {
    AgentSchemaLoader::new(repo_root())
}

fn output_schema_of(agent: &str) -> AgentSchema {
    loader()
        .load(&manifest_of(agent))
        .unwrap_or_else(|e| panic!("{agent}: {e}"))
        .outputs
}

fn fixture_bytes(agent: &str, kind: &str) -> Vec<(String, Vec<u8>)> {
    let dir = repo_root()
        .join("agents")
        .join(agent)
        .join("fixtures")
        .join(kind);
    let mut found: Vec<(String, Vec<u8>)> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| {
            (
                p.file_stem()
                    .expect("a stem")
                    .to_string_lossy()
                    .into_owned(),
                fs::read(&p).expect("a readable fixture"),
            )
        })
        .collect();
    found.sort();
    assert!(!found.is_empty(), "{agent} has no fixtures under {kind}/");
    found
}

fn valid_fixture(agent: &str, name: &str) -> Value {
    let bytes = fixture_bytes(agent, "valid")
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("{agent} has no valid fixture {name}"))
        .1;
    serde_json::from_slice(&bytes).expect("a fixture is JSON")
}

fn bytes_of(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serializes")
}

fn refuse(schema: &AgentSchema, bytes: &[u8]) -> Vec<Issue> {
    schema
        .parse_and_validate(bytes)
        .expect_err("the document must be refused")
}

fn kinds(issues: &[Issue]) -> Vec<IssueKind> {
    issues.iter().map(|i| i.kind).collect()
}

fn load_error(result: Result<AgentSchema, SchemaFileError>) -> SchemaFileError {
    result.expect_err("the schema must be refused at load")
}

// ---- the real definitions ------------------------------------------------------------------

#[test]
fn every_agent_manifest_in_the_registry_gives_its_compiled_schemas() {
    for agent in NINE_AGENTS {
        let manifest = manifest_of(agent);
        let schemas = loader()
            .load(&manifest)
            .unwrap_or_else(|e| panic!("{agent}: {e}"));
        assert_eq!(
            schemas.outputs.sha256(),
            &manifest.outputs_schema.sha256,
            "{agent}: the output schema is the file the manifest pins"
        );
        assert_eq!(
            schemas.inputs.sha256(),
            &manifest.inputs_schema.sha256,
            "{agent}: the input schema is the file the manifest pins"
        );
    }
}

#[test]
fn valid_outputs_of_intake_planner_and_code_reviewer_are_accepted_from_bytes() {
    for agent in ["intake-classifier", "planner", "code-reviewer"] {
        let schema = output_schema_of(agent);
        for (name, bytes) in fixture_bytes(agent, "valid") {
            let validated = schema
                .validate_bytes(&bytes)
                .unwrap_or_else(|v| panic!("{agent}/valid/{name} was refused: {v:?}"));
            assert_eq!(
                validated.sha256,
                Sha256Digest::of(&bytes),
                "the hash is of the exact bytes checked"
            );
            assert_eq!(validated.size_bytes, bytes.len() as u64);
            assert_eq!(
                validated.value,
                serde_json::from_slice::<Value>(&bytes).expect("JSON"),
                "the value is the parse of exactly those bytes"
            );
        }
    }
}

#[test]
fn invalid_outputs_of_intake_planner_and_code_reviewer_are_refused_with_a_reason() {
    for agent in ["intake-classifier", "planner", "code-reviewer"] {
        let schema = output_schema_of(agent);
        for (name, bytes) in fixture_bytes(agent, "invalid") {
            let violations = schema
                .validate_bytes(&bytes)
                .expect_err(&format!("{agent}/invalid/{name} was accepted"));
            assert!(!violations.is_empty(), "{agent}/invalid/{name}");
            for violation in &violations {
                assert!(
                    violation.message.len() > 15,
                    "{agent}/invalid/{name}: a message must say what to change: {violation:?}"
                );
            }
        }
    }
}

#[test]
fn all_nine_agents_accept_their_valid_fixtures_and_refuse_their_invalid_ones() {
    for agent in NINE_AGENTS {
        let schema = output_schema_of(agent);
        for (name, bytes) in fixture_bytes(agent, "valid") {
            assert!(
                schema.parse_and_validate(&bytes).is_ok(),
                "{agent}/valid/{name} must pass"
            );
        }
        for (name, bytes) in fixture_bytes(agent, "invalid") {
            assert!(
                schema.parse_and_validate(&bytes).is_err(),
                "{agent}/invalid/{name} must be refused"
            );
        }
    }
}

#[test]
fn the_intake_conditions_are_enforced_and_the_messages_say_what_to_change() {
    let schema = output_schema_of("intake-classifier");
    // NEEDS_HUMAN without the question.
    let mut broken = valid_fixture("intake-classifier", "feature-with-json-flag");
    broken["status"] = json!("NEEDS_HUMAN");
    let issues = refuse(&schema, &bytes_of(&broken));
    let missing = issues
        .iter()
        .find(|i| i.kind == IssueKind::Schema(Keyword::Required))
        .expect("a missing-field issue");
    assert_eq!(missing.property.as_deref(), Some("human_question"));
    assert!(missing.message.contains("human_question"), "{missing}");

    // An unknown field is named and the message says to remove it.
    let mut extra = valid_fixture("intake-classifier", "feature-with-json-flag");
    extra["approved"] = json!(true);
    let issues = refuse(&schema, &bytes_of(&extra));
    let unknown = issues
        .iter()
        .find(|i| i.kind == IssueKind::Schema(Keyword::AdditionalProperties))
        .expect("an unknown-field issue");
    assert_eq!(unknown.property.as_deref(), Some("approved"));
    assert!(unknown.message.contains("remove it"), "{unknown}");

    // A value outside the closed set of request kinds.
    let mut kind = valid_fixture("intake-classifier", "feature-with-json-flag");
    kind["request_kind"] = json!("deploy-to-production");
    let issues = refuse(&schema, &bytes_of(&kind));
    assert_eq!(issues[0].path, "request_kind");
    assert_eq!(issues[0].kind, IssueKind::Schema(Keyword::Enum));
}

#[test]
fn the_planner_envelope_and_the_reviewer_verdict_are_checked_on_their_own_schemas() {
    let planner = output_schema_of("planner");
    let mut envelope = valid_fixture("planner", "needs-a-person");
    envelope["status"] = json!("DONE");
    assert!(
        refuse(&planner, &bytes_of(&envelope))
            .iter()
            .any(|i| i.path == "status")
    );

    let reviewer = output_schema_of("code-reviewer");
    let mut verdict = valid_fixture("code-reviewer", "pass");
    verdict["verdict"] = json!("APPROVED_BY_ME");
    assert!(
        refuse(&reviewer, &bytes_of(&verdict))
            .iter()
            .any(|i| i.path == "verdict")
    );
}

#[test]
fn an_error_never_repeats_a_value_from_the_document() {
    let canary = format!("zz-canary-{}", 31_337 * 7);
    let schema = output_schema_of("intake-classifier");
    let mut doc = valid_fixture("intake-classifier", "feature-with-json-flag");
    doc["status"] = json!(canary);
    doc["request_kind"] = json!(canary);
    doc["summary"] = json!(canary);
    doc[&canary] = json!(canary);
    let violations = schema.validate_bytes(&bytes_of(&doc)).expect_err("refused");
    assert!(!violations.is_empty());
    for violation in &violations {
        assert!(
            !violation.message.contains(&canary) && !violation.path.contains(&canary),
            "a value from the document came back: {violation:?}"
        );
    }
    // A syntax error does not quote the input either.
    let body = format!("{{\"status\": {canary}}}");
    let issues = refuse(&schema, body.as_bytes());
    assert_eq!(issues[0].kind, IssueKind::NotJson);
    assert!(!issues[0].message.contains(&canary));
}

// ---- limits and the strict parse -----------------------------------------------------------

#[test]
fn break_skip_the_limits_a_body_over_the_size_limit_is_refused_before_it_is_read() {
    let schema = output_schema_of("intake-classifier");
    // Too large AND not JSON: the size is reported, so nothing parsed it.
    let body = vec![b'x'; OutputLimits::AGENT_OUTPUT.max_bytes() + 1];
    let issues = refuse(&schema, &body);
    assert_eq!(kinds(&issues), [IssueKind::TooLarge]);
    // The same through the port-shaped method.
    assert!(schema.validate_bytes(&body).is_err());
    // A valid document at exactly the limit is not refused for size.
    let small = OutputLimits::new(2048, 8, 100).expect("limits");
    let tight = loader()
        .with_output_limits(small)
        .load(&manifest_of("intake-classifier"))
        .expect("loads")
        .outputs;
    let doc = bytes_of(&valid_fixture(
        "intake-classifier",
        "feature-with-json-flag",
    ));
    assert!(doc.len() < 2048, "the fixture fits the tight limit");
    assert!(tight.parse_and_validate(&doc).is_ok());
    let mut padded = doc.clone();
    padded.resize(2049, b' ');
    assert_eq!(kinds(&refuse(&tight, &padded)), [IssueKind::TooLarge]);
}

#[test]
fn break_skip_the_limits_a_body_nested_ten_thousand_deep_is_refused_before_it_is_parsed() {
    let schema = output_schema_of("intake-classifier");
    let mut body = "[".repeat(10_000).into_bytes();
    body.extend(std::iter::repeat_n(b']', 10_000));
    assert_eq!(kinds(&refuse(&schema, &body)), [IssueKind::TooDeep]);
    // Too deep AND not JSON is still reported as too deep.
    let open_only = "{\"a\":".repeat(5_000);
    assert_eq!(
        kinds(&refuse(&schema, open_only.as_bytes())),
        [IssueKind::TooDeep]
    );
}

#[test]
fn break_skip_the_limits_a_wide_document_is_stopped_by_the_value_budget() {
    let limits = OutputLimits::new(1 << 20, 8, 50).expect("limits");
    let schema = loader()
        .with_output_limits(limits)
        .load(&manifest_of("intake-classifier"))
        .expect("loads")
        .outputs;
    let body = format!("[{}]", vec!["1"; 200].join(","));
    assert_eq!(
        kinds(&refuse(&schema, body.as_bytes())),
        [IssueKind::TooManyNodes]
    );
}

#[test]
fn a_body_that_is_not_utf8_or_has_trailing_data_is_refused() {
    let schema = output_schema_of("code-reviewer");
    let mut bad = bytes_of(&valid_fixture("code-reviewer", "pass"));
    bad.insert(10, 0xff);
    assert_eq!(kinds(&refuse(&schema, &bad)), [IssueKind::NotUtf8]);
    let mut trailing = bytes_of(&valid_fixture("code-reviewer", "pass"));
    trailing.extend_from_slice(b" {}");
    assert_eq!(kinds(&refuse(&schema, &trailing)), [IssueKind::NotJson]);
    assert_eq!(kinds(&refuse(&schema, b"")), [IssueKind::NotJson]);
}

#[test]
fn break_accept_duplicate_keys_a_repeated_key_is_refused_and_named() {
    let schema = output_schema_of("intake-classifier");
    // A last-wins parser would read this as CLASSIFIED and hide the NEEDS_HUMAN the agent first wrote.
    let doc = valid_fixture("intake-classifier", "feature-with-json-flag");
    let text = serde_json::to_string(&doc).expect("serializes");
    let repeated = text.replacen(
        "\"status\":\"CLASSIFIED\"",
        "\"status\":\"NEEDS_HUMAN\",\"status\":\"CLASSIFIED\"",
        1,
    );
    assert_ne!(repeated, text, "the test document really repeats the key");
    let issues = refuse(&schema, repeated.as_bytes());
    assert_eq!(kinds(&issues), [IssueKind::DuplicateKey]);
    assert_eq!(issues[0].property.as_deref(), Some("status"));
    assert!(issues[0].message.contains("keep one"), "{}", issues[0]);
    // And inside a nested object.
    let nested = text.replacen(
        "\"material\":false",
        "\"material\":false,\"material\":true",
        1,
    );
    assert_ne!(nested, text);
    let issues = refuse(&schema, nested.as_bytes());
    assert_eq!(kinds(&issues), [IssueKind::DuplicateKey]);
    assert_eq!(issues[0].path, "ambiguity");
}

#[test]
fn a_path_named_property_that_leaves_the_repository_is_refused() {
    let text = r#"{
        "type": "object",
        "additionalProperties": false,
        "required": ["changed_path"],
        "properties": { "changed_path": { "type": "string" } }
    }"#;
    let schema = AgentSchema::from_text(text, OutputLimits::AGENT_OUTPUT).expect("compiles");
    assert!(
        schema
            .parse_and_validate(br#"{"changed_path":"src/lib.rs"}"#)
            .is_ok()
    );
    for bad in ["../../etc/passwd", "/etc/passwd", ".git/config", "a\\b"] {
        let body = json!({ "changed_path": bad });
        let issues = refuse(&schema, &bytes_of(&body));
        assert_eq!(kinds(&issues), [IssueKind::UnsafePath], "{bad}");
    }
}

#[test]
fn check_applies_the_same_limits_to_a_value_that_was_parsed_already() {
    let limits = OutputLimits::new(1 << 20, 5, 1000).expect("limits");
    let schema = loader()
        .with_output_limits(limits)
        .load(&manifest_of("intake-classifier"))
        .expect("loads")
        .outputs;
    let mut value = json!(1);
    for _ in 0..8 {
        value = json!([value]);
    }
    assert_eq!(
        kinds(&schema.check(&value).expect_err("deep")),
        [IssueKind::TooDeep]
    );
    let ok = valid_fixture("intake-classifier", "feature-with-json-flag");
    assert!(schema.check(&ok).is_ok());
}

// ---- schemas that cannot be used are refused at load, not at validate -----------------------

fn compile(text: &str) -> Result<AgentSchema, SchemaFileError> {
    AgentSchema::from_text(text, OutputLimits::AGENT_OUTPUT)
}

#[test]
fn break_ignore_unknown_keywords_a_schema_with_a_keyword_the_engine_refuses_fails_at_load() {
    for keyword in [
        r#""unevaluatedProperties": false"#,
        r#""patternProperties": {"^x": {"type": "string"}}"#,
        r#""propertyNames": {"maxLength": 5}"#,
        r##""$dynamicRef": "#meta""##,
        r#""dependentRequired": {"a": ["b"]}"#,
        r#""minProperties": 1"#,
        r#""multipleOf": 3"#,
    ] {
        let text = format!(r#"{{"type": "object", {keyword}}}"#);
        let error = load_error(compile(&text));
        assert_eq!(
            error.kind,
            SchemaFileErrorKind::Unsupported,
            "{keyword}: {error}"
        );
        assert!(
            error.message.contains("does not support"),
            "the message names the problem: {error}"
        );
    }
    // The same inside a nested definition.
    let nested =
        r#"{"type":"object","properties":{"a":{"type":"string","uniqueKeywordNobodyKnows":1}}}"#;
    assert_eq!(
        load_error(compile(nested)).kind,
        SchemaFileErrorKind::Unsupported
    );
}

#[test]
fn a_schema_with_a_remote_reference_or_a_bad_pattern_or_a_wrong_shape_fails_at_load() {
    assert_eq!(
        load_error(compile(r#"{"$ref": "https://example.org/other.json"}"#)).kind,
        SchemaFileErrorKind::BadReference
    );
    assert_eq!(
        load_error(compile(r##"{"$ref": "#/$defs/missing"}"##)).kind,
        SchemaFileErrorKind::BadReference
    );
    assert_eq!(
        load_error(compile(r#"{"type":"string","pattern":"(unclosed"}"#)).kind,
        SchemaFileErrorKind::BadPattern
    );
    assert_eq!(
        load_error(compile(r#"{"type":"object","required":"status"}"#)).kind,
        SchemaFileErrorKind::BadShape
    );
}

#[test]
fn break_accept_duplicate_keys_a_schema_that_repeats_a_key_is_refused_at_load() {
    // A last-wins reader would drop `additionalProperties: false` here and accept every field.
    let text = r#"{"type":"object","additionalProperties":false,"additionalProperties":true}"#;
    let error = load_error(compile(text));
    assert_eq!(error.kind, SchemaFileErrorKind::DuplicateKey, "{error}");
}

#[test]
fn a_schema_that_is_not_json_not_utf8_too_large_or_too_deep_fails_at_load() {
    assert_eq!(
        load_error(compile("not json")).kind,
        SchemaFileErrorKind::Syntax
    );
    assert_eq!(
        load_error(AgentSchema::from_bytes(
            b"{\"type\":\xff}",
            OutputLimits::AGENT_OUTPUT
        ))
        .kind,
        SchemaFileErrorKind::NotUtf8
    );
    let big = format!(r#"{{"description": "{}"}}"#, "x".repeat(300 * 1024));
    assert_eq!(
        load_error(compile(&big)).kind,
        SchemaFileErrorKind::TooLarge
    );
    let deep = format!("{}{}", "[".repeat(500), "]".repeat(500));
    assert_eq!(load_error(compile(&deep)).kind, SchemaFileErrorKind::Syntax);
}

#[test]
fn a_schema_compiled_from_text_checks_the_documents_it_describes() {
    let schema = compile(
        r#"{"type":"object","additionalProperties":false,"required":["n"],
            "properties":{"n":{"type":"integer","minimum":1}}}"#,
    )
    .expect("compiles");
    assert!(schema.parse_and_validate(br#"{"n": 3}"#).is_ok());
    assert!(schema.parse_and_validate(br#"{"n": 0}"#).is_err());
    assert!(schema.parse_and_validate(br#"{"n": 3, "m": 1}"#).is_err());
    assert_eq!(
        schema.sha256(),
        &Sha256Digest::of(
            br#"{"type":"object","additionalProperties":false,"required":["n"],
            "properties":{"n":{"type":"integer","minimum":1}}}"#
        )
    );
}

// ---- the loader: references, hashes and paths ----------------------------------------------

fn copy_schema_into(root: &TempDir, name: &str) {
    let source = repo_root()
        .join("agents")
        .join("schemas")
        .join(format!("{name}.v1.schema.json"));
    root.write(
        &format!("agents/schemas/{name}.v1.schema.json"),
        fs::read(source).expect("the real schema"),
    );
}

#[test]
fn load_named_reads_the_schema_under_agents_schemas_and_checks_the_declared_hash() {
    let root = TempDir::new("agent-schema-hash");
    copy_schema_into(&root, "intake-classification");
    let real = fs::read(repo_root().join("agents/schemas/intake-classification.v1.schema.json"))
        .expect("the real schema");
    let loader = AgentSchemaLoader::new(root.path());
    let schema = loader
        .load_named("intake-classification", 1, Some(&Sha256Digest::of(&real)))
        .expect("loads with the right hash");
    assert_eq!(schema.sha256(), &Sha256Digest::of(&real));
    assert!(loader.load_named("intake-classification", 1, None).is_ok());
}

#[test]
fn break_skip_the_hash_check_a_schema_that_changed_after_the_manifest_is_refused() {
    let root = TempDir::new("agent-schema-changed");
    copy_schema_into(&root, "intake-classification");
    // The file now differs from what the manifest pinned.
    let path = root
        .path()
        .join("agents/schemas/intake-classification.v1.schema.json");
    let mut text = fs::read_to_string(&path).expect("read");
    text.push('\n');
    fs::write(&path, text).expect("write");
    let manifest = manifest_of("intake-classifier");
    let error = AgentSchemaLoader::new(root.path())
        .load_ref(&manifest.outputs_schema)
        .expect_err("the hash differs");
    assert_eq!(error.kind, SchemaFileErrorKind::HashMismatch, "{error}");
    assert!(error.message.contains("changed"), "{error}");
}

#[test]
fn a_missing_schema_file_is_reported_as_missing() {
    let root = TempDir::new("agent-schema-missing");
    fs::create_dir_all(root.path().join("agents/schemas")).expect("dirs");
    let error = AgentSchemaLoader::new(root.path())
        .load_named("intake-classification", 1, None)
        .expect_err("missing");
    assert_eq!(error.kind, SchemaFileErrorKind::Missing, "{error}");
}

#[test]
fn break_allow_path_escape_a_name_or_version_that_reaches_outside_the_schema_directory_is_refused()
{
    let root = TempDir::new("agent-schema-escape");
    copy_schema_into(&root, "intake-classification");
    // A file outside `agents/schemas` that would be valid if it were reached.
    root.write(
        "secret.v1.schema.json",
        fs::read(repo_root().join("agents/schemas/intake-classification.v1.schema.json"))
            .expect("the real schema"),
    );
    let loader = AgentSchemaLoader::new(root.path());
    for name in [
        "../../secret",
        "..",
        "../secret",
        "/etc/passwd",
        "a/b",
        "a\\b",
        "",
        "UPPER",
        "intake-classification/../../secret",
        "intake-classification\0",
    ] {
        let error = loader
            .load_named(name, 1, None)
            .expect_err(&format!("{name:?} must be refused"));
        assert_eq!(
            error.kind,
            SchemaFileErrorKind::UnsafePath,
            "{name:?}: {error}"
        );
    }
    assert_eq!(
        loader
            .load_named("intake-classification", 0, None)
            .expect_err("version 0")
            .kind,
        SchemaFileErrorKind::UnsafePath
    );
}

#[cfg(unix)]
#[test]
fn break_allow_path_escape_a_symbolic_link_out_of_the_repository_is_refused() {
    use std::os::unix::fs::symlink;

    let outside = TempDir::new("agent-schema-outside");
    outside.write(
        "intake-classification.v1.schema.json",
        fs::read(repo_root().join("agents/schemas/intake-classification.v1.schema.json"))
            .expect("the real schema"),
    );

    // The schema directory itself is a link to a directory outside the root.
    let linked_dir = TempDir::new("agent-schema-linked-dir");
    fs::create_dir_all(linked_dir.path().join("agents")).expect("dirs");
    symlink(outside.path(), linked_dir.path().join("agents/schemas")).expect("symlink");
    let error = AgentSchemaLoader::new(linked_dir.path())
        .load_named("intake-classification", 1, None)
        .expect_err("a linked directory outside the root");
    assert_eq!(error.kind, SchemaFileErrorKind::UnsafePath, "{error}");

    // The schema file is a link to a file outside the root.
    let linked_file = TempDir::new("agent-schema-linked-file");
    fs::create_dir_all(linked_file.path().join("agents/schemas")).expect("dirs");
    symlink(
        outside.path().join("intake-classification.v1.schema.json"),
        linked_file
            .path()
            .join("agents/schemas/intake-classification.v1.schema.json"),
    )
    .expect("symlink");
    let error = AgentSchemaLoader::new(linked_file.path())
        .load_named("intake-classification", 1, None)
        .expect_err("a linked file outside the root");
    assert_eq!(error.kind, SchemaFileErrorKind::UnsafePath, "{error}");

    // A link to a file inside the root is not followed either: a pinned file is a plain file.
    let inner = TempDir::new("agent-schema-inner-link");
    inner.write(
        "elsewhere/real.json",
        fs::read(repo_root().join("agents/schemas/intake-classification.v1.schema.json"))
            .expect("the real schema"),
    );
    fs::create_dir_all(inner.path().join("agents/schemas")).expect("dirs");
    symlink(
        inner.path().join("elsewhere/real.json"),
        inner
            .path()
            .join("agents/schemas/intake-classification.v1.schema.json"),
    )
    .expect("symlink");
    let error = AgentSchemaLoader::new(inner.path())
        .load_named("intake-classification", 1, None)
        .expect_err("a link is not a plain file");
    assert_eq!(error.kind, SchemaFileErrorKind::Unreadable, "{error}");
}

#[test]
fn a_file_whose_id_names_another_schema_is_refused() {
    let root = TempDir::new("agent-schema-id");
    // The planner-result schema stored under the intake name.
    root.write(
        "agents/schemas/intake-classification.v1.schema.json",
        fs::read(repo_root().join("agents/schemas/planner-result.v1.schema.json"))
            .expect("the real schema"),
    );
    let error = AgentSchemaLoader::new(root.path())
        .load_named("intake-classification", 1, None)
        .expect_err("the id differs");
    assert_eq!(error.kind, SchemaFileErrorKind::IdMismatch, "{error}");
}

#[test]
fn the_loader_names_the_file_and_never_a_path_outside_the_repository_in_its_errors() {
    let root = TempDir::new("agent-schema-message");
    fs::create_dir_all(root.path().join("agents/schemas")).expect("dirs");
    let error = AgentSchemaLoader::new(root.path())
        .load_named("intake-classification", 1, None)
        .expect_err("missing");
    assert!(
        error.file.starts_with("agents/schemas/"),
        "the error names the repository-relative file: {}",
        error.file
    );
    assert!(
        !error
            .to_string()
            .contains(&root.path().display().to_string()),
        "the host path of the checkout is not shown: {error}"
    );
}
