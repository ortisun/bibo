//! The redaction seam. The caller injects the redactor; this crate never builds its own policy.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use factory_domain::redaction::{Redactor, Registered, SecretHandle};
use serde_json::{Map, Value};

/// Replaces every secret in a text, and learns exact values to replace.
///
/// [`FactoryRedactor`] implements it over the factory's [`Redactor`] (the patterns of
/// `policies/security.yaml` plus the exact values registered at start).
pub trait Redact: Send + Sync {
    /// The text with every secret replaced.
    ///
    /// # Errors
    /// [`RedactionFailed`] when the text cannot be checked; the caller then drops the text.
    fn redact(&self, text: &str) -> Result<String, RedactionFailed>;

    /// Registers an exact value (an upstream credential, a run token) so that every later
    /// [`Redact::redact`] replaces it.
    ///
    /// # Errors
    /// [`RegisterFailed`] when the value cannot be registered. The gateway then refuses to use
    /// the credential or to open the run.
    fn register_secret(&self, label: &str, value: &str) -> Result<SecretKey, RegisterFailed>;

    /// Forgets a value registered with [`Redact::register_secret`], such as a run token after the
    /// run closed.
    fn forget_secret(&self, key: SecretKey);
}

/// The text could not be checked for secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the text could not be checked for secrets")]
pub struct RedactionFailed;

/// A value could not be registered for exact-value redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegisterFailed {
    /// The value is too short to be told apart from ordinary text.
    #[error("the value is too short to be redacted reliably")]
    TooShort,
    /// The redactor refused the label or the value (a limit, an invalid label).
    #[error("the redactor refused the value")]
    Refused,
}

/// The key of a registered value, to forget it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretKey(u64);

impl SecretKey {
    /// A key for an implementation of [`Redact`] outside this crate.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The number the implementation gave.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// [`Redact`] over the factory's [`Redactor`].
pub struct FactoryRedactor {
    redactor: Redactor,
    handles: Mutex<HashMap<u64, SecretHandle>>,
    next: AtomicU64,
}

impl FactoryRedactor {
    /// Wraps a redactor. Values registered through the gateway are registered in this redactor,
    /// so every other sink that shares it redacts them too.
    #[must_use]
    pub fn new(redactor: Redactor) -> Self {
        Self {
            redactor,
            handles: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        }
    }
}

impl std::fmt::Debug for FactoryRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactoryRedactor")
            .field("redactor", &self.redactor)
            .finish_non_exhaustive()
    }
}

impl Redact for FactoryRedactor {
    fn redact(&self, text: &str) -> Result<String, RedactionFailed> {
        self.redactor
            .redact_str(text)
            .map(|redacted| redacted.output.into_owned())
            .map_err(|_| RedactionFailed)
    }

    fn register_secret(&self, label: &str, value: &str) -> Result<SecretKey, RegisterFailed> {
        match self.redactor.register(label, value) {
            Ok(Registered::Added(handle)) => {
                let key = self.next.fetch_add(1, Ordering::Relaxed);
                self.handles
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(key, handle);
                Ok(SecretKey(key))
            }
            Ok(Registered::TooShort) => Err(RegisterFailed::TooShort),
            Err(_) => Err(RegisterFailed::Refused),
        }
    }

    fn forget_secret(&self, key: SecretKey) {
        let handle = self
            .handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key.0);
        if let Some(handle) = handle {
            self.redactor.forget(handle);
        }
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
    use serde_json::json;

    #[test]
    fn a_registered_value_is_redacted_and_forgotten() {
        let redactor = FactoryRedactor::new(Redactor::builder().build().expect("a redactor"));
        let planted = "planted-value-for-the-gateway-test";
        let key = redactor
            .register_secret("gateway_test", planted)
            .expect("registered");
        let out = redactor
            .redact(&format!("a {planted} b"))
            .expect("redacted");
        assert!(!out.contains(planted), "{out}");
        assert!(out.contains("[REDACTED:gateway_test]"), "{out}");
        redactor.forget_secret(key);
        let out = redactor.redact(planted).expect("redacted");
        assert_eq!(out, planted);
    }

    #[test]
    fn a_short_value_is_not_registered() {
        let redactor = FactoryRedactor::new(Redactor::builder().build().expect("a redactor"));
        assert_eq!(
            redactor.register_secret("short", "ab"),
            Err(RegisterFailed::TooShort)
        );
    }

    #[test]
    fn every_string_and_key_of_a_json_value_is_redacted() {
        let redactor = FactoryRedactor::new(Redactor::builder().build().expect("a redactor"));
        let planted = "planted-value-in-json-for-a-test";
        redactor
            .register_secret("planted", planted)
            .expect("registered");
        let mut value = json!({"a": planted, planted: [format!("x {planted}")]});
        redact_json(&mut value, &redactor).expect("redacted");
        assert!(!value.to_string().contains(planted), "{value}");
    }
}
