//! The restricted YAML reader against the parser contract written at the top of
//! `policies/security.yaml`: a YAML 1.2 subset, a single document, no anchors, aliases, tags or
//! merge keys, no duplicate keys, bounded size and depth, and scalars whose meaning cannot differ
//! between YAML 1.1 and 1.2 readers.
//!
//! Each forbidden feature has a test that fails if the check is removed. `deliberate_breaks.md`
//! style notes are in the hand-off; the tests here are the proof.

use factory_contracts::yaml::{self, AmbiguousScalar, YamlErrorKind, YamlLimits};
use serde::Deserialize;
use serde_json::{Value, json};

fn limits() -> YamlLimits {
    YamlLimits::DEFINITION
}

fn read_json(text: &str) -> Value {
    yaml::read(text, limits())
        .unwrap_or_else(|e| panic!("should read: {e}\n{text}"))
        .to_json()
}

fn refusal(text: &str) -> yaml::YamlError {
    match yaml::read(text, limits()) {
        Ok(doc) => panic!("should be refused but read as {}\n{text}", doc.to_json()),
        Err(error) => error,
    }
}

#[test]
fn yaml_plain_block_and_flow_collections_read_into_json() {
    assert_eq!(
        read_json("a: 1\nb: [x, z]\nc:\n  d: true\n  e: 1.5\n"),
        json!({"a": 1, "b": ["x", "z"], "c": {"d": true, "e": 1.5}})
    );
    assert_eq!(
        read_json("{a: [1, 2], b: {c: d}}\n"),
        json!({"a": [1, 2], "b": {"c": "d"}})
    );
}

#[test]
fn yaml_quoted_and_block_scalars_are_always_strings() {
    let doc = read_json(
        "a: \"yes\"\nb: 'no'\nc: \"12\"\nd: \"1e3\"\ne: |\n  line one\n  line two\nf: >\n  folded\n  text\n",
    );
    assert_eq!(doc["a"], "yes");
    assert_eq!(doc["b"], "no");
    assert_eq!(doc["c"], "12");
    assert_eq!(doc["d"], "1e3");
    assert_eq!(doc["e"], "line one\nline two\n");
    assert_eq!(doc["f"], "folded text\n");
}

#[test]
fn yaml_plain_words_that_are_not_ambiguous_stay_strings() {
    let doc = read_json(
        "a: none\nb: designed\nc: L0\nd: 127.0.0.0/8\ne: --bare\nf: 1.1.2.3\ng: \"1.1.2\"\nh: sha256\ni: a-b_c\n",
    );
    for key in ["a", "b", "c", "d", "e", "f", "g", "h", "i"] {
        assert!(doc[key].is_string(), "{key}");
    }
}

#[test]
fn yaml_integers_and_floats_have_one_canonical_spelling() {
    let doc = read_json("a: 0\nb: -3\nc: 600\nd: 0.8\ne: 4.2\nf: 18446744073709551615\n");
    assert_eq!(doc["a"], 0);
    assert_eq!(doc["b"], -3);
    assert_eq!(doc["c"], 600);
    assert_eq!(doc["d"], 0.8);
    assert_eq!(doc["e"], 4.2);
    assert_eq!(doc["f"], 18_446_744_073_709_551_615_u64);
}

#[test]
fn yaml_line_numbers_are_one_based_and_follow_the_source() {
    let error = refusal("a: 1\n\n# comment\nb:\n  c: 2\n  c: 3\n");
    assert_eq!(error.kind, YamlErrorKind::DuplicateKey);
    assert_eq!(error.line, Some(6));
    assert!(error.to_string().contains("`c`"), "{error}");
    assert!(error.to_string().contains("line 6"), "{error}");
}

// ---- Forbidden features ---------------------------------------------------------------------

#[test]
fn yaml_anchor_is_refused_and_names_the_line() {
    let error = refusal("a: 1\nb: &x [1, 2]\n");
    assert_eq!(error.kind, YamlErrorKind::Anchor);
    assert_eq!(error.line, Some(2));
}

#[test]
fn yaml_alias_is_refused() {
    // The anchor comes first and is refused first. A bare alias has no anchor to point at, so
    // the parser itself refuses it. Both end in an error and no value is built.
    let error = refusal("a: &x 1\nb: *x\n");
    assert!(matches!(
        error.kind,
        YamlErrorKind::Anchor | YamlErrorKind::Alias
    ));
    let error = refusal("b: *x\n");
    assert!(
        matches!(error.kind, YamlErrorKind::Alias | YamlErrorKind::Syntax),
        "{error}"
    );
}

#[test]
fn yaml_a_billion_laughs_document_is_refused_at_its_first_anchor() {
    let text = "a: &a [x,x,x,x]\nb: &b [*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b]\nd: [*c,*c,*c,*c]\n";
    let error = refusal(text);
    assert_eq!(error.kind, YamlErrorKind::Anchor);
    assert_eq!(error.line, Some(1));
}

#[test]
fn yaml_merge_key_is_refused_even_without_an_anchor() {
    let error = refusal("base:\n  a: 1\nuse:\n  <<: {a: 2}\n  c: 2\n");
    assert_eq!(error.kind, YamlErrorKind::MergeKey);
    assert_eq!(error.line, Some(4));
    // Quoted, it is only a string key.
    assert_eq!(read_json("\"<<\": 1\n"), json!({"<<": 1}));
}

#[test]
fn yaml_every_tag_is_refused() {
    for text in [
        "a: !!str 12\n",
        "a: !!binary aGk=\n",
        "a: !custom foo\n",
        "a: !<tag:example.com,2026:x> foo\n",
        "!!map {a: 1}\n",
        "a: !!seq [1]\n",
    ] {
        let error = refusal(text);
        assert_eq!(error.kind, YamlErrorKind::Tag, "{text}");
    }
}

#[test]
fn yaml_duplicate_keys_are_refused_in_block_and_flow_maps_at_any_depth() {
    for (text, line) in [
        ("a: 1\na: 2\n", 2),
        ("x:\n  z:\n    a: 1\n    a: 2\n", 4),
        ("{a: 1, a: 2}\n", 1),
        ("list:\n  - k: 1\n    k: 2\n", 3),
    ] {
        let error = refusal(text);
        assert_eq!(error.kind, YamlErrorKind::DuplicateKey, "{text}");
        assert_eq!(error.line, Some(line), "{text}");
    }
    // The same key in two different maps is fine.
    assert_eq!(
        read_json("a: {k: 1}\nb: {k: 2}\n"),
        json!({"a": {"k": 1}, "b": {"k": 2}})
    );
}

#[test]
fn yaml_a_key_that_differs_only_in_quoting_is_still_a_duplicate() {
    let error = refusal("a: 1\n\"a\": 2\n");
    assert_eq!(error.kind, YamlErrorKind::DuplicateKey);
}

#[test]
fn yaml_a_second_document_is_refused() {
    let error = refusal("a: 1\n---\nb: 2\n");
    assert_eq!(error.kind, YamlErrorKind::MultipleDocuments);
    assert_eq!(error.line, Some(2));
    // One explicit document, with a start and an end marker, is fine.
    assert_eq!(read_json("---\na: 1\n...\n"), json!({"a": 1}));
}

#[test]
fn yaml_empty_and_comment_only_input_is_refused() {
    for text in ["", "\n\n", "# only a comment\n", "---\n"] {
        let error = refusal(text);
        assert!(
            matches!(error.kind, YamlErrorKind::Empty | YamlErrorKind::Null),
            "{text:?} gave {error}"
        );
    }
}

#[test]
fn yaml_a_directive_is_refused() {
    let error = refusal("%YAML 1.1\n---\na: 1\n");
    assert_eq!(error.kind, YamlErrorKind::Directive);
    assert_eq!(error.line, Some(1));
    let error = refusal("%TAG !e! tag:example.com,2026:\n---\na: 1\n");
    assert_eq!(error.kind, YamlErrorKind::Directive);
}

#[test]
fn yaml_a_complex_key_is_refused() {
    let error = refusal("? [a, b]\n: 1\n");
    assert_eq!(error.kind, YamlErrorKind::ComplexKey);
}

// ---- Ambiguous scalars ----------------------------------------------------------------------

#[test]
fn yaml_scalars_that_yaml_1_1_reads_as_booleans_are_refused_when_plain() {
    for word in [
        "y", "Y", "n", "N", "yes", "Yes", "YES", "no", "No", "NO", "on", "On", "ON", "off", "Off",
        "OFF",
    ] {
        let error = refusal(&format!("k: {word}\n"));
        assert_eq!(
            error.kind,
            YamlErrorKind::Ambiguous(AmbiguousScalar::LegacyBoolean),
            "{word}"
        );
        assert_eq!(error.line, Some(1));
        assert!(error.to_string().contains("quote"), "{error}");
        // Quoted, it is the string it looks like.
        assert_eq!(read_json(&format!("k: \"{word}\"\n")), json!({"k": word}));
    }
}

#[test]
fn yaml_true_and_false_are_booleans_only_in_lower_case() {
    assert_eq!(
        read_json("a: true\nb: false\n"),
        json!({"a": true, "b": false})
    );
    for word in ["True", "TRUE", "False", "FALSE"] {
        let error = refusal(&format!("k: {word}\n"));
        assert_eq!(
            error.kind,
            YamlErrorKind::Ambiguous(AmbiguousScalar::BooleanSpelling),
            "{word}"
        );
    }
}

#[test]
fn yaml_null_in_every_spelling_and_a_missing_value_are_refused() {
    for text in [
        "k: ~\n",
        "k: null\n",
        "k: Null\n",
        "k: NULL\n",
        "k:\n",
        "k: \n",
        "[a, ~]\n",
    ] {
        let error = refusal(text);
        assert_eq!(error.kind, YamlErrorKind::Null, "{text:?}");
    }
    assert_eq!(
        read_json("k: \"null\"\nj: ''\n"),
        json!({"k": "null", "j": ""})
    );
}

#[test]
fn yaml_numbers_that_readers_disagree_on_are_refused_when_plain() {
    for text in [
        "1e3", "1E3", "1e-3", "0o7", "0O7", "0777", "007", "0x1F", "0X1f", "0b11", "1_000", "1:30",
        "+1", "+1.5", "1.", ".5", "-.5", ".inf", "-.inf", ".nan", ".NaN", "1.5e3", "00", "-007",
    ] {
        let error = refusal(&format!("k: {text}\n"));
        assert_eq!(
            error.kind,
            YamlErrorKind::Ambiguous(AmbiguousScalar::Number),
            "{text}"
        );
        assert_eq!(read_json(&format!("k: \"{text}\"\n")), json!({"k": text}));
    }
}

#[test]
fn yaml_dates_and_times_are_refused_when_plain() {
    for text in [
        "2027-01-31",
        "2026-10-27T10:00:00Z",
        "2026-10-27 10:00:00",
        "2026-1-5",
    ] {
        let error = refusal(&format!("k: {text}\n"));
        assert_eq!(
            error.kind,
            YamlErrorKind::Ambiguous(AmbiguousScalar::Timestamp),
            "{text}"
        );
    }
    assert_eq!(read_json("k: \"2027-01-31\"\n"), json!({"k": "2027-01-31"}));
}

#[test]
fn yaml_a_plain_key_must_not_be_ambiguous_either() {
    for key in ["no", "yes", "on", "1", "~", "null", "1e3", "0x1"] {
        let error = refusal(&format!("{key}: 1\n"));
        assert!(
            matches!(
                error.kind,
                YamlErrorKind::Ambiguous(_) | YamlErrorKind::Null
            ),
            "{key} gave {error}"
        );
        assert_eq!(read_json(&format!("\"{key}\": 1\n")), json!({key: 1}));
    }
}

#[test]
fn yaml_an_integer_too_large_for_64_bits_is_refused() {
    let error = refusal("k: 18446744073709551616\n");
    assert_eq!(
        error.kind,
        YamlErrorKind::Ambiguous(AmbiguousScalar::Number)
    );
}

// ---- Limits ---------------------------------------------------------------------------------

#[test]
fn yaml_input_over_the_size_limit_is_refused_before_it_is_parsed() {
    let limits = YamlLimits::new(64, 8, 100, 32).expect("small limits");
    // Not valid YAML at all, and too large: the size is reported, which shows the size check
    // ran before the parser.
    let text = format!("{}\n", "{[: ".repeat(100));
    let error = yaml::read(&text, limits).expect_err("too large");
    assert_eq!(error.kind, YamlErrorKind::TooLarge);
    assert_eq!(error.line, None);
}

#[test]
fn yaml_nesting_over_the_limit_is_refused_in_block_and_flow_style() {
    let limits = YamlLimits::new(1 << 20, 4, 1000, 64).expect("limits");
    let block = "a:\n  b:\n    c:\n      d:\n        e: 1\n";
    assert_eq!(
        yaml::read(block, limits).expect_err("deep").kind,
        YamlErrorKind::TooDeep
    );
    assert!(
        yaml::read("a:\n  b:\n    c:\n      d: 1\n", limits).is_ok(),
        "depth 4 is allowed"
    );
    assert_eq!(
        yaml::read("[[[[[1]]]]]\n", limits).expect_err("deep").kind,
        YamlErrorKind::TooDeep
    );
}

#[test]
fn yaml_a_flow_sequence_nested_10000_deep_is_refused_without_overflowing_the_stack() {
    let text = format!("{}{}\n", "[".repeat(10_000), "]".repeat(10_000));
    let error = yaml::read(&text, YamlLimits::POLICY).expect_err("deep");
    assert_eq!(error.kind, YamlErrorKind::TooDeep);
    let text = format!("{}a{}\n", "{a: ".repeat(10_000), "}".repeat(10_000));
    let error = yaml::read(&text, YamlLimits::POLICY).expect_err("deep");
    assert_eq!(error.kind, YamlErrorKind::TooDeep);
}

#[test]
fn yaml_a_document_with_too_many_values_is_refused() {
    let limits = YamlLimits::new(1 << 20, 8, 50, 64).expect("limits");
    let text = format!("[{}]\n", vec!["1"; 60].join(", "));
    assert_eq!(
        yaml::read(&text, limits).expect_err("wide").kind,
        YamlErrorKind::TooManyNodes
    );
}

#[test]
fn yaml_a_scalar_over_the_length_limit_is_refused() {
    let limits = YamlLimits::new(1 << 20, 8, 1000, 16).expect("limits");
    let error = yaml::read("k: abcdefghijklmnopqrstuvwxyz\n", limits).expect_err("long");
    assert_eq!(error.kind, YamlErrorKind::ScalarTooLong);
    assert_eq!(error.line, Some(1));
}

#[test]
fn yaml_limits_cannot_be_zero_or_above_the_ceiling() {
    assert!(YamlLimits::new(0, 8, 8, 8).is_err());
    assert!(YamlLimits::new(8, 0, 8, 8).is_err());
    assert!(YamlLimits::new(YamlLimits::CEILING.max_bytes() + 1, 8, 8, 8).is_err());
    assert!(YamlLimits::new(8, YamlLimits::CEILING.max_depth() + 1, 8, 8).is_err());
}

#[test]
fn yaml_syntax_errors_carry_a_line() {
    let error = refusal("a: [1, 2\nb: 3\n");
    assert_eq!(error.kind, YamlErrorKind::Syntax);
    assert!(error.line.is_some());
}

// ---- Typed decoding -------------------------------------------------------------------------

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Inner {
    size: u32,
    #[serde(default)]
    flag: bool,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Outer {
    name: String,
    items: Vec<Inner>,
    mode: Mode,
    limit: Option<f64>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Strict,
    Lenient,
}

#[test]
fn yaml_decodes_into_typed_structs_with_enums_options_and_floats() {
    let value: Outer = yaml::from_str(
        "name: x\nmode: strict\nitems:\n  - size: 3\n  - {size: 4, flag: true}\nlimit: 2\n",
        limits(),
    )
    .expect("decodes");
    assert_eq!(value.mode, Mode::Strict);
    assert_eq!(
        value.items,
        vec![
            Inner {
                size: 3,
                flag: false
            },
            Inner {
                size: 4,
                flag: true
            }
        ]
    );
    assert_eq!(
        value.limit,
        Some(2.0),
        "an integer is accepted for a float field"
    );
}

#[test]
fn yaml_an_unknown_key_is_refused_and_names_the_key_and_line() {
    let error = yaml::from_str::<Outer>(
        "name: x\nmode: strict\nitems:\n  - size: 3\n    colour: red\nlimit: 1\n",
        limits(),
    )
    .expect_err("unknown key");
    assert_eq!(error.kind, YamlErrorKind::Decode);
    assert_eq!(error.line, Some(5), "{error}");
    assert_eq!(error.key.as_deref(), Some("items[0].colour"), "{error}");
    assert!(error.to_string().contains("colour"), "{error}");
}

#[test]
fn yaml_a_wrong_type_names_the_key_path_and_line() {
    let error = yaml::from_str::<Outer>(
        "name: x\nmode: strict\nitems:\n  - size: three\nlimit: 1\n",
        limits(),
    )
    .expect_err("wrong type");
    assert_eq!(error.kind, YamlErrorKind::Decode);
    assert_eq!(error.line, Some(4));
    assert_eq!(error.key.as_deref(), Some("items[0].size"));
}

#[test]
fn yaml_a_missing_key_names_the_object_that_lacks_it() {
    let error = yaml::from_str::<Outer>("name: x\nmode: strict\nlimit: 1\n", limits())
        .expect_err("missing items");
    assert_eq!(error.kind, YamlErrorKind::Decode);
    assert!(error.to_string().contains("items"), "{error}");
    assert_eq!(error.line, Some(1));
}

#[test]
fn yaml_an_enum_value_outside_the_set_is_refused_with_the_key() {
    let error = yaml::from_str::<Outer>("name: x\nmode: reckless\nitems: []\nlimit: 1\n", limits())
        .expect_err("bad variant");
    assert_eq!(error.key.as_deref(), Some("mode"));
    assert_eq!(error.line, Some(2));
}

#[test]
fn yaml_a_string_field_does_not_accept_a_number() {
    let error = yaml::from_str::<Outer>("name: 12\nmode: strict\nitems: []\n", limits())
        .expect_err("a number for a string");
    assert_eq!(error.key.as_deref(), Some("name"));
}

#[test]
fn yaml_the_typed_value_and_the_json_value_describe_the_same_document() {
    let text = "name: x\nmode: lenient\nitems:\n  - size: 1\nlimit: 0.5\n";
    let typed: Outer = yaml::from_str(text, limits()).expect("typed");
    let from_json: Outer = serde_json::from_value(read_json(text)).expect("json");
    assert_eq!(typed, from_json);
}
