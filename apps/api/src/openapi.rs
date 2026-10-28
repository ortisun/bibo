//! The OpenAPI document of the API.
//!
//! The contract is the file `openapi.json` in this package, written first and served as it is on
//! `GET /openapi.json`. [`ROUTES`](crate::routes::ROUTES) is the list the router is built from.
//! `tests/openapi_contract.rs` fails when the two disagree: a route that is not documented, a
//! documented operation that is not served, an operation id that differs, a security requirement
//! that differs from how the route authenticates, or a status the table promises that the document
//! does not list.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde_json::Value;

/// The document text, as written.
pub const DOCUMENT_TEXT: &str = include_str!("../openapi.json");

/// The document, parsed once.
///
/// # Panics
/// Never in a build that passed its tests: a unit test parses the same text.
#[must_use]
pub fn document() -> &'static Value {
    static PARSED: OnceLock<Value> = OnceLock::new();
    PARSED.get_or_init(|| serde_json::from_str(DOCUMENT_TEXT).unwrap_or(Value::Null))
}

/// Every operation the document describes, as `(METHOD, path)`.
#[must_use]
pub fn operations(document: &Value) -> BTreeSet<(String, String)> {
    const METHODS: [&str; 8] = [
        "get", "put", "post", "delete", "options", "head", "patch", "trace",
    ];
    let mut found = BTreeSet::new();
    if let Some(paths) = document.get("paths").and_then(Value::as_object) {
        for (path, item) in paths {
            for method in METHODS {
                if item.get(method).is_some() {
                    found.insert((method.to_ascii_uppercase(), path.clone()));
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_text_parses_and_names_its_version() {
        let parsed: Value = serde_json::from_str(DOCUMENT_TEXT).expect("openapi.json is JSON");
        assert_eq!(parsed["openapi"], "3.0.3");
        assert!(!operations(&parsed).is_empty());
    }
}
