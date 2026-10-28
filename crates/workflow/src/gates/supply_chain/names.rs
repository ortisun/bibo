//! The list of popular package names that a new name is compared with.
//!
//! The list is **data**: `data/popular-crates.v1.json`, with the date it was made and where it
//! came from. It is compared by `DependencyPolicy::decide` (one edit away from a name on the
//! list means a security approver) and by the integrity checks (a transitive package one edit
//! away from a name on the list is a warning). It never approves anything.

use serde_json::Value;

/// The bundled list, as text.
const BUNDLED: &str = include_str!("data/popular-crates.v1.json");

/// The bundled list could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the list of popular package names is not valid")]
pub struct DataError;

/// A list of popular names with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopularNames {
    names: Vec<String>,
    list_date: String,
    provenance: String,
}

impl PopularNames {
    /// The list that ships with the factory.
    ///
    /// # Errors
    /// [`DataError`] when the bundled file is damaged, which a test of this crate rules out.
    pub fn bundled() -> Result<Self, DataError> {
        Self::from_json(BUNDLED)
    }

    /// Reads a list written in the shape of the bundled file.
    ///
    /// # Errors
    /// [`DataError`] when the text is not that shape, has no date, no provenance, or no names.
    pub fn from_json(text: &str) -> Result<Self, DataError> {
        let doc: Value = serde_json::from_str(text).map_err(|_| DataError)?;
        let field = |name: &str| {
            doc.get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .ok_or(DataError)
        };
        let names: Vec<String> = doc
            .get("names")
            .and_then(Value::as_array)
            .ok_or(DataError)?
            .iter()
            .map(|name| name.as_str().map(str::to_owned).ok_or(DataError))
            .collect::<Result<_, _>>()?;
        if names.is_empty() {
            return Err(DataError);
        }
        Ok(Self {
            names,
            list_date: field("list_date")?,
            provenance: field("provenance")?,
        })
    }

    /// A list made of the given names, for a test or a project that keeps its own.
    #[must_use]
    pub fn of(names: &[&str]) -> Self {
        Self {
            names: names.iter().map(|name| (*name).to_owned()).collect(),
            list_date: "none".to_owned(),
            provenance: "given by the caller".to_owned(),
        }
    }

    /// The names.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// When the list was made.
    #[must_use]
    pub fn list_date(&self) -> &str {
        &self.list_date
    }

    /// Where the list came from.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_list_is_valid_and_says_where_it_came_from() {
        let list = PopularNames::bundled().expect("the bundled list");
        assert!(list.names().len() >= 200);
        assert_eq!(list.list_date(), "2026-10-28");
        assert!(list.provenance().contains("NOT fetched"));
        for name in ["serde", "reqwest", "tokio", "rand", "libc"] {
            assert!(list.names().iter().any(|n| n == name), "{name}");
        }
        let mut sorted = list.names().to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), list.names().len(), "no name appears twice");
    }

    #[test]
    fn a_list_without_a_date_or_names_is_refused() {
        assert!(PopularNames::from_json("{}").is_err());
        assert!(
            PopularNames::from_json(r#"{"list_date":"d","provenance":"p","names":[]}"#).is_err()
        );
        assert!(
            PopularNames::from_json(r#"{"list_date":"d","provenance":"","names":["a"]}"#).is_err()
        );
        assert!(
            PopularNames::from_json(r#"{"list_date":"d","provenance":"p","names":[1]}"#).is_err()
        );
    }
}
