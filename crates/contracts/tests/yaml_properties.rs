//! Properties of the restricted YAML reader over generated input: it never panics, a refusal
//! always names a place or a limit, nesting is refused exactly beyond the limit, and a document
//! built from safe parts reads back as the value it was built from.

use factory_contracts::yaml::{self, YamlErrorKind, YamlLimits};
use proptest::prelude::*;
use serde_json::{Value, json};

fn small_limits() -> YamlLimits {
    YamlLimits::new(4096, 6, 400, 64).expect("limits")
}

/// A key that is plain text under the reader's rules: lower-case letters, and not a word YAML 1.1
/// reads as a boolean.
fn safe_key() -> impl Strategy<Value = String> {
    "[a-z][a-z_]{2,7}".prop_filter("not a boolean word", |k| {
        !matches!(k.as_str(), "yes" | "off")
    })
}

fn safe_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        (-1000i64..1000).prop_map(|n| json!(n)),
        "[A-Za-z][A-Za-z ]{0,12}[A-Za-z]"
            .prop_filter("not a word the reader refuses", |s| {
                !matches!(
                    s.to_ascii_lowercase().as_str(),
                    "yes" | "no" | "on" | "off" | "null" | "true" | "false"
                )
            })
            .prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..4).prop_map(Value::Array),
            prop::collection::btree_map(safe_key(), inner, 1..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Whatever the text is, the reader returns and never panics, and a refusal carries either a
    /// line or a limit, never an empty message.
    #[test]
    fn yaml_arbitrary_text_never_panics(text in "\\PC{0,300}") {
        match yaml::read(&text, small_limits()) {
            Ok(_) => {}
            Err(error) => {
                prop_assert!(!error.detail().is_empty());
                prop_assert!(error.line.is_some() || matches!(
                    error.kind,
                    YamlErrorKind::TooLarge | YamlErrorKind::TooManyNodes | YamlErrorKind::Empty
                ), "{error}");
            }
        }
    }

    /// Text built from YAML punctuation, which is where parsers fail, never panics either.
    #[test]
    fn yaml_punctuation_soup_never_panics(text in "[ \\[\\]{}:,#&*!|>%@`'\"?\\-\\n\\t.a-z0-9]{0,200}") {
        let _ = yaml::read(&text, small_limits());
    }

    /// Nesting is refused exactly when it is deeper than the limit.
    #[test]
    fn yaml_nesting_is_refused_exactly_beyond_the_limit(depth in 1usize..40, flow in any::<bool>()) {
        let limits = small_limits();
        let text = if flow {
            format!("{}1{}\n", "[".repeat(depth), "]".repeat(depth))
        } else {
            // Block mappings, one level of indentation each.
            let mut lines = Vec::new();
            for level in 0..depth {
                lines.push(format!("{}k{level}:", "  ".repeat(level)));
            }
            lines.push(format!("{}v: 1", "  ".repeat(depth)));
            format!("{}\n", lines.join("\n"))
        };
        let outcome = yaml::read(&text, limits);
        // The block form has `depth + 1` levels of mapping once the leaf mapping is counted.
        let levels = if flow { depth } else { depth + 1 };
        if levels > limits.max_depth() {
            prop_assert_eq!(outcome.expect_err("deep").kind, YamlErrorKind::TooDeep);
        } else {
            prop_assert!(outcome.is_ok(), "{outcome:?}");
        }
    }

    /// Input over the byte limit is refused for its size whatever it contains.
    #[test]
    fn yaml_input_over_the_limit_is_too_large(extra in 1usize..500, filler in "[ -~]{1,8}") {
        let limits = small_limits();
        let mut text = String::new();
        while text.len() <= limits.max_bytes() + extra {
            text.push_str(&filler);
        }
        prop_assert_eq!(yaml::read(&text, limits).expect_err("large").kind, YamlErrorKind::TooLarge);
    }

    /// A document built from safe parts, written as block YAML, reads back as the same value, and
    /// a typed decode into `serde_json::Value` agrees with `to_json`.
    #[test]
    fn yaml_safe_documents_round_trip(value in safe_value()) {
        let value = match value {
            Value::Object(_) => value,
            other => json!({ "root": other }),
        };
        let text = block_yaml(&value);
        let read = yaml::read(&text, YamlLimits::DEFINITION).unwrap_or_else(|e| panic!("{e}\n{text}"));
        prop_assert_eq!(read.to_json(), value.clone(), "{}", text);
        let decoded: Value = read.decode().expect("decodes into a JSON value");
        prop_assert_eq!(decoded, value);
    }

    /// Repeating any key of a safe mapping is refused as a duplicate, naming the key.
    #[test]
    fn yaml_a_repeated_key_is_always_a_duplicate(keys in prop::collection::btree_set(safe_key(), 1..6), pick in 0usize..6) {
        let keys: Vec<String> = keys.into_iter().collect();
        let repeated = keys[pick % keys.len()].clone();
        let mut lines: Vec<String> = keys.iter().map(|k| format!("{k}: 1")).collect();
        lines.push(format!("{repeated}: 2"));
        let error = yaml::read(&lines.join("\n"), YamlLimits::DEFINITION).expect_err("duplicate");
        prop_assert_eq!(error.kind, YamlErrorKind::DuplicateKey);
        prop_assert_eq!(error.line, Some(lines.len()));
        prop_assert!(error.detail().contains(&repeated));
    }
}

/// Block YAML for the safe values above: plain keys, quoted strings.
fn block_yaml(value: &Value) -> String {
    fn scalar(value: &Value) -> String {
        match value {
            Value::String(text) => serde_json::to_string(text).expect("string"),
            other => other.to_string(),
        }
    }
    fn write(value: &Value, indent: usize, out: &mut String) {
        let pad = " ".repeat(indent);
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    match child {
                        Value::Object(_) | Value::Array(_) => {
                            out.push_str(&format!("{pad}{key}:\n"));
                            write(child, indent + 2, out);
                        }
                        other => out.push_str(&format!("{pad}{key}: {}\n", scalar(other))),
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    match item {
                        Value::Object(_) | Value::Array(_) => {
                            out.push_str(&format!("{pad}-\n"));
                            write(item, indent + 2, out);
                        }
                        other => out.push_str(&format!("{pad}- {}\n", scalar(other))),
                    }
                }
            }
            other => out.push_str(&format!("{pad}{}\n", scalar(other))),
        }
    }
    let mut out = String::new();
    write(value, 0, &mut out);
    out
}
