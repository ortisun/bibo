//! The redaction seam. The caller injects the redactor; this crate never builds its own policy.

use serde_json::{Map, Value};

/// Replaces every secret in a text. The factory's [`factory_domain::redaction::Redactor`]
/// implements it with the patterns of `policies/security.yaml` and the exact values registered
/// at start (the database password among them).
pub trait Redact: Send + Sync {
    /// The text with every secret replaced.
    ///
    /// # Errors
    /// [`RedactionFailed`] when the text cannot be checked; the caller then drops the text.
    fn redact(&self, text: &str) -> Result<String, RedactionFailed>;
}

/// The text could not be checked for secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionFailed;

impl Redact for factory_domain::redaction::Redactor {
    fn redact(&self, text: &str) -> Result<String, RedactionFailed> {
        self.redact_str(text)
            .map(|redacted| redacted.output.into_owned())
            .map_err(|_| RedactionFailed)
    }
}

/// Redacts every string of a JSON value, object keys included. Each string is redacted on its
/// own, so the result stays valid JSON whatever the redactor puts in.
///
/// # Errors
/// [`RedactionFailed`] when any string cannot be checked.
pub fn redact_json(value: &mut Value, redactor: &dyn Redact) -> Result<(), RedactionFailed> {
    match value {
        Value::String(text) => {
            *text = redactor.redact(text)?;
        }
        Value::Array(items) => {
            for item in items {
                redact_json(item, redactor)?;
            }
        }
        Value::Object(map) => {
            let taken = std::mem::take(map);
            let mut rebuilt = Map::with_capacity(taken.len());
            for (key, mut item) in taken {
                redact_json(&mut item, redactor)?;
                rebuilt.insert(redactor.redact(&key)?, item);
            }
            *map = rebuilt;
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::redaction::Redactor;
    use serde_json::json;

    fn redactor_knowing(planted: &str) -> Redactor {
        let redactor = Redactor::builder().build().expect("a redactor");
        redactor
            .register("planted", planted)
            .expect("register the planted value");
        redactor
    }

    #[test]
    fn every_string_and_key_is_redacted_and_the_json_stays_valid() {
        let planted = "planted-value-planted-value";
        let redactor = redactor_knowing(planted);
        let mut value = json!({
            "a": planted,
            planted: 1,
            "nested": [{"b": format!("x {planted} y")}, 7, null, true],
        });
        redact_json(&mut value, &redactor).expect("redacted");
        let text = value.to_string();
        assert!(!text.contains(planted), "{text}");
        assert!(text.contains("[REDACTED:planted]"), "{text}");
        let again: Value = serde_json::from_str(&text).expect("still JSON");
        assert_eq!(again["nested"][1], json!(7));
    }

    struct Refuses;
    impl Redact for Refuses {
        fn redact(&self, _text: &str) -> Result<String, RedactionFailed> {
            Err(RedactionFailed)
        }
    }

    #[test]
    fn a_failing_redactor_fails_the_whole_value() {
        let mut value = json!({"a": ["b"]});
        assert_eq!(redact_json(&mut value, &Refuses), Err(RedactionFailed));
    }
}
