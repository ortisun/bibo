//! The small language the allow schemas are written in, and the walker that applies them.
//!
//! A schema is a tree of [`Rule`]s. Every rule is closed: an object may hold only the keys its
//! rule names, a tagged object may hold only a tag its rule lists, and a value must have the
//! type and size the rule says. There is no "anything else" rule except [`Rule::Free`], which is
//! used in exactly two places: the arguments of a tool call that the model made, and the schema
//! of a tool's parameters (which has its own check, [`Rule::Schema`]).
//!
//! A refusal names a class from the closed set [`Violation`]. It never carries the key, the value
//! or the position that caused it, because those are text the sandbox chose.

use serde_json::{Map, Value};

use super::Violation;

/// The longest text the broker lets a field hold: the body limit is the real bound, this only
/// keeps a rule from being written without one.
pub(super) const TEXT: usize = 16 * 1024 * 1024;

/// One rule of a schema.
#[derive(Debug)]
pub(super) enum Rule {
    /// A string of at most this many bytes.
    Str(usize),
    /// A name: 1 to 128 ASCII letters, digits, `_`, `-`, `.` or `:` (tool names and identifiers).
    Name,
    /// A boolean.
    Bool,
    /// Any JSON number. The output token limit is one: the broker clamps it afterwards.
    Number,
    /// An integer in the range.
    Int(i64, i64),
    /// A number in the range, bounds included.
    Float(f64, f64),
    /// One of these strings.
    Enum(&'static [&'static str]),
    /// This string.
    Const(&'static str),
    /// Any JSON value (the parser already bounds its depth): the arguments of a tool call.
    Free,
    /// A JSON Schema document, checked for references that point away from the document.
    Schema,
    /// An array of at most `max` items, each following the rule.
    Array(&'static Rule, usize),
    /// An object with only these fields.
    Object(&'static Fields),
    /// An object whose `type` picks one of several field sets.
    Tagged(&'static Tagged),
    /// A `data:image/` URL of at most this many bytes. Any other string is an address the
    /// provider would have to fetch.
    DataUrl(usize),
    /// A string of at most `max` bytes, or else a value that follows the other rule.
    StrOr(usize, &'static Rule),
    /// An object of short strings: at most `entries` pairs, keys up to 64 bytes, values up to
    /// `value` bytes.
    StrMap { entries: usize, value: usize },
}

/// The fields of an object: each name with its rule, and the names that must be present.
#[derive(Debug)]
pub(super) struct Fields {
    pub fields: &'static [(&'static str, Rule)],
    pub required: &'static [&'static str],
}

/// A family of objects told apart by one key (always `type` here).
#[derive(Debug)]
pub(super) struct Tagged {
    pub tag: &'static str,
    pub variants: &'static [(&'static str, &'static Fields)],
    /// The variant used when the tag is absent (a client tool has no `type`; a Responses
    /// message may have none).
    pub default: Option<&'static str>,
    /// What an unlisted tag means.
    pub unknown: Violation,
}

/// Names the class of a key the schema does not list. The result only picks a label for the
/// audit line; every unlisted key is refused whatever its label.
pub(super) fn classify_key(key: &str) -> Violation {
    let lower = key.to_ascii_lowercase();
    if lower.starts_with("mcp") || lower == "connectors" || lower.contains("server_url") {
        Violation::RemoteMcp
    } else if matches!(
        lower.as_str(),
        "container"
            | "files"
            | "file_ids"
            | "betas"
            | "web_search_options"
            | "background"
            | "previous_response_id"
            | "conversation"
            | "prompt"
            | "service_tier"
    ) {
        Violation::ServerFeature
    } else if matches!(
        lower.as_str(),
        "url" | "image_url" | "file_url" | "file_id" | "uri"
    ) {
        Violation::RemoteContent
    } else {
        Violation::UnknownField
    }
}

/// Names the class of a tag the schema does not list.
fn classify_tag(tag: &str, fixed: Violation) -> Violation {
    let lower = tag.to_ascii_lowercase();
    if lower.starts_with("mcp") {
        Violation::RemoteMcp
    } else if matches!(lower.as_str(), "url" | "file" | "file_id" | "file_url")
        || lower.ends_with("_file")
        || lower.ends_with("_url")
    {
        Violation::RemoteContent
    } else {
        fixed
    }
}

fn name_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}

/// Checks `value` against `rule`.
///
/// # Errors
/// The [`Violation`] class of the first thing found wrong.
pub(super) fn check(value: &Value, rule: &Rule) -> Result<(), Violation> {
    match rule {
        Rule::Str(max) => match value.as_str() {
            Some(text) if text.len() <= *max => Ok(()),
            _ => Err(Violation::BadValue),
        },
        Rule::Name => match value.as_str() {
            Some(text) if name_ok(text) => Ok(()),
            _ => Err(Violation::BadValue),
        },
        Rule::Bool => value.is_boolean().then_some(()).ok_or(Violation::BadValue),
        Rule::Number => value.is_number().then_some(()).ok_or(Violation::BadValue),
        Rule::Int(low, high) => match value.as_i64() {
            Some(n) if (*low..=*high).contains(&n) => Ok(()),
            _ => Err(Violation::BadValue),
        },
        Rule::Float(low, high) => match value.as_f64() {
            Some(n) if n >= *low && n <= *high => Ok(()),
            _ => Err(Violation::BadValue),
        },
        Rule::Enum(listed) => match value.as_str() {
            Some(text) if listed.contains(&text) => Ok(()),
            _ => Err(Violation::BadValue),
        },
        Rule::Const(expected) => match value.as_str() {
            Some(text) if text == *expected => Ok(()),
            _ => Err(Violation::BadValue),
        },
        Rule::DataUrl(max) => match value.as_str() {
            Some(text) if text.len() <= *max && text.starts_with("data:image/") => Ok(()),
            Some(_) => Err(Violation::RemoteContent),
            None => Err(Violation::BadValue),
        },
        Rule::Free => Ok(()),
        Rule::Schema => check_schema(value),
        Rule::Array(item, max) => {
            let items = value.as_array().ok_or(Violation::BadValue)?;
            if items.len() > *max {
                return Err(Violation::BadValue);
            }
            items.iter().try_for_each(|one| check(one, item))
        }
        Rule::Object(fields) => {
            check_fields(value.as_object().ok_or(Violation::BadValue)?, fields, None)
        }
        Rule::Tagged(tagged) => check_tagged(value.as_object().ok_or(Violation::BadValue)?, tagged),
        Rule::StrOr(max, other) => {
            if value.is_string() {
                check(value, &Rule::Str(*max))
            } else {
                check(value, other)
            }
        }
        Rule::StrMap {
            entries,
            value: max,
        } => {
            let map = value.as_object().ok_or(Violation::BadValue)?;
            if map.len() > *entries {
                return Err(Violation::BadValue);
            }
            for (key, one) in in_key_order(map) {
                if key.len() > 64 || one.as_str().is_none_or(|text| text.len() > *max) {
                    return Err(Violation::BadValue);
                }
            }
            Ok(())
        }
    }
}

/// The pairs of an object in key order, so that the class a refusal names does not depend on how
/// the map was built.
pub(super) fn in_key_order(object: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut pairs: Vec<(&String, &Value)> = object.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    pairs
}

fn check_fields(
    object: &Map<String, Value>,
    fields: &Fields,
    tag: Option<&str>,
) -> Result<(), Violation> {
    for (key, value) in in_key_order(object) {
        if Some(key.as_str()) == tag {
            continue;
        }
        match fields.fields.iter().find(|(name, _)| name == key) {
            Some((_, rule)) => check(value, rule)?,
            None => return Err(classify_key(key)),
        }
    }
    for required in fields.required {
        if !object.contains_key(*required) {
            return Err(Violation::BadValue);
        }
    }
    Ok(())
}

fn check_tagged(object: &Map<String, Value>, tagged: &Tagged) -> Result<(), Violation> {
    let chosen = match object.get(tagged.tag) {
        Some(Value::String(tag)) => tag.as_str(),
        Some(_) => return Err(Violation::BadValue),
        None => tagged.default.ok_or(Violation::BadValue)?,
    };
    let Some((_, fields)) = tagged.variants.iter().find(|(name, _)| *name == chosen) else {
        return Err(classify_tag(chosen, tagged.unknown));
    };
    check_fields(object, fields, Some(tagged.tag))
}

/// A JSON Schema document is data the model reads, with one exception: a reference to another
/// document. The broker refuses any `$ref`-family string that does not point inside the document,
/// so no provider-side resolver can be sent to fetch a schema from an address the sandbox chose.
/// A property that happens to be named `$ref` holds an object and is walked like any other.
fn check_schema(value: &Value) -> Result<(), Violation> {
    match value {
        Value::Object(map) => {
            for (key, inner) in in_key_order(map) {
                if matches!(key.as_str(), "$ref" | "$dynamicRef" | "$recursiveRef")
                    && let Value::String(target) = inner
                    && !target.starts_with('#')
                {
                    return Err(Violation::RemoteReference);
                }
                check_schema(inner)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(check_schema),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    static LEAF: Fields = Fields {
        fields: &[("n", Rule::Int(1, 5)), ("s", Rule::Name)],
        required: &["n"],
    };
    static OTHER: Fields = Fields {
        fields: &[("u", Rule::Bool)],
        required: &[],
    };
    static TAGGED: Tagged = Tagged {
        tag: "type",
        variants: &[("leaf", &LEAF), ("other", &OTHER)],
        default: Some("other"),
        unknown: Violation::UnknownBlock,
    };

    #[test]
    fn an_object_holds_only_the_keys_its_rule_names() {
        let rule = Rule::Object(&LEAF);
        assert_eq!(check(&json!({"n": 3}), &rule), Ok(()));
        assert_eq!(
            check(&json!({"n": 3, "extra": 1}), &rule),
            Err(Violation::UnknownField)
        );
        assert_eq!(
            check(&json!({"n": 3, "mcp_servers": []}), &rule),
            Err(Violation::RemoteMcp)
        );
        assert_eq!(
            check(&json!({"n": 3, "container": {}}), &rule),
            Err(Violation::ServerFeature)
        );
        assert_eq!(
            check(&json!({"n": 3, "url": "x"}), &rule),
            Err(Violation::RemoteContent)
        );
        assert_eq!(check(&json!({"s": "a"}), &rule), Err(Violation::BadValue));
        assert_eq!(check(&json!({"n": 9}), &rule), Err(Violation::BadValue));
        assert_eq!(check(&json!({"n": 1.5}), &rule), Err(Violation::BadValue));
        assert_eq!(check(&json!([]), &rule), Err(Violation::BadValue));
    }

    #[test]
    fn a_tagged_object_takes_only_a_listed_tag_and_the_fields_of_that_variant() {
        let rule = Rule::Tagged(&TAGGED);
        assert_eq!(check(&json!({"type": "leaf", "n": 1}), &rule), Ok(()));
        assert_eq!(
            check(&json!({"u": true}), &rule),
            Ok(()),
            "the default variant"
        );
        assert_eq!(
            check(&json!({"type": "leaf", "u": true}), &rule),
            Err(Violation::UnknownField)
        );
        assert_eq!(
            check(&json!({"type": "web_search"}), &rule),
            Err(Violation::UnknownBlock)
        );
        assert_eq!(
            check(&json!({"type": "mcp"}), &rule),
            Err(Violation::RemoteMcp)
        );
        assert_eq!(
            check(&json!({"type": "url"}), &rule),
            Err(Violation::RemoteContent)
        );
        assert_eq!(check(&json!({"type": 3}), &rule), Err(Violation::BadValue));
    }

    #[test]
    fn a_schema_may_point_inside_itself_and_nowhere_else() {
        let ok = json!({"properties": {"a": {"$ref": "#/$defs/b"}, "$ref": {"type": "string"}}});
        assert_eq!(check(&ok, &Rule::Schema), Ok(()));
        for remote in [
            json!({"properties": {"a": {"$ref": "https://attacker.test/s.json"}}}),
            json!({"items": [{"$ref": "file:///etc/passwd"}]}),
            json!({"$dynamicRef": "http://attacker.test/"}),
            json!({"$recursiveRef": "//attacker.test/x"}),
            json!({"allOf": [{"$ref": "other.json"}]}),
        ] {
            assert_eq!(
                check(&remote, &Rule::Schema),
                Err(Violation::RemoteReference),
                "{remote}"
            );
        }
    }

    #[test]
    fn a_map_of_short_strings_is_bounded() {
        let rule = Rule::StrMap {
            entries: 2,
            value: 4,
        };
        assert_eq!(check(&json!({"a": "xxxx"}), &rule), Ok(()));
        assert_eq!(
            check(&json!({"a": "xxxxx"}), &rule),
            Err(Violation::BadValue)
        );
        assert_eq!(check(&json!({"a": 1}), &rule), Err(Violation::BadValue));
        assert_eq!(
            check(&json!({"a": "x", "b": "x", "c": "x"}), &rule),
            Err(Violation::BadValue)
        );
    }

    #[test]
    fn names_numbers_and_enums_are_exact() {
        assert_eq!(check(&json!("a_b-c.d:e"), &Rule::Name), Ok(()));
        for bad in [
            json!(""),
            json!("a b"),
            json!("a/b"),
            json!("é"),
            json!(1),
            json!("x".repeat(129)),
        ] {
            assert_eq!(check(&bad, &Rule::Name), Err(Violation::BadValue), "{bad}");
        }
        assert_eq!(check(&json!(0.5), &Rule::Float(0.0, 1.0)), Ok(()));
        assert_eq!(
            check(&json!(1.5), &Rule::Float(0.0, 1.0)),
            Err(Violation::BadValue)
        );
        assert_eq!(check(&json!("a"), &Rule::Enum(&["a", "b"])), Ok(()));
        assert_eq!(
            check(&json!("c"), &Rule::Enum(&["a", "b"])),
            Err(Violation::BadValue)
        );
        assert_eq!(check(&json!("hi"), &Rule::StrOr(5, &Rule::Bool)), Ok(()));
        assert_eq!(check(&json!(true), &Rule::StrOr(5, &Rule::Bool)), Ok(()));
        assert_eq!(
            check(&json!("hello!"), &Rule::StrOr(5, &Rule::Bool)),
            Err(Violation::BadValue)
        );
    }
}
