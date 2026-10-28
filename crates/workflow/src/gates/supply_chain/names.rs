//! The list of popular package names that a new name is compared with.
//!
//! The list is **data**: `data/popular-crates.v1.json`, with the date it was made and where it
//! came from. It is compared by `DependencyPolicy::decide` (one edit away from a name on the
//! list means a security approver) and by the integrity checks (a transitive package one edit
//! away from a name on the list is a warning). It never approves anything.

use serde_json::Value;

use super::model::normalize;

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
    /// The same names, as cargo compares them.
    normalized: Vec<String>,
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
            normalized: names.iter().map(|name| normalize(name)).collect(),
            names,
            list_date: field("list_date")?,
            provenance: field("provenance")?,
        })
    }

    /// A list made of the given names, for a test or a project that keeps its own.
    #[must_use]
    pub fn of(names: &[&str]) -> Self {
        Self {
            normalized: names.iter().map(|name| normalize(name)).collect(),
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

    /// The popular name that `wanted` looks like without being it, if any. `wanted` is compared as
    /// cargo compares names. A name on the list is never a look-alike of another name on it
    /// (`serde_json` is not an imitation of `serde`).
    ///
    /// A name looks like a popular one when it is one edit away (a letter changed, added, dropped,
    /// or two neighbours swapped), or when it is the popular name with a decoration that a
    /// squatter adds and a reader skips over: `reqwest-rs`, `clap-derive-macros`, `rust-serde`.
    #[must_use]
    pub fn lookalike(&self, wanted: &str) -> Option<&String> {
        let wanted = normalize(wanted);
        if self.normalized.iter().any(|popular| *popular == wanted) {
            return None;
        }
        self.normalized
            .iter()
            .position(|popular| near_miss(popular, &wanted) || decorated(popular, &wanted))
            .and_then(|index| self.names.get(index))
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

/// Words a squatter puts before or after a popular name. A word that is a package of its own
/// (`derive`, `core`, `sys`) is on the list too, because `clap-derive-macros` is not `clap_derive`.
const DECORATIONS: [&str; 22] = [
    "rs", "rust", "ext", "extra", "plus", "fork", "patched", "fix", "new", "lib", "util", "utils",
    "derive", "macros", "macro", "core", "sys", "api", "sdk", "client", "cli", "the",
];

/// True when `wanted` is `popular` with one or two decorations in front of it or behind it,
/// separated as cargo separates words.
fn decorated(popular: &str, wanted: &str) -> bool {
    let all = |text: &str| {
        !text.is_empty()
            && text.split('_').count() <= 2
            && text.split('_').all(|word| DECORATIONS.contains(&word))
    };
    wanted
        .strip_prefix(popular)
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(all)
        || wanted
            .strip_suffix(popular)
            .and_then(|rest| rest.strip_suffix('_'))
            .is_some_and(all)
}

/// True when `a` and `b` differ and are one edit apart: one letter changed, added, dropped, or
/// two neighbouring letters swapped. This is the rule of `DependencyPolicy`.
fn near_miss(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let (ra, rb) = (
        a.get(common..).unwrap_or_default(),
        b.get(common..).unwrap_or_default(),
    );
    match ra.len().cmp(&rb.len()) {
        std::cmp::Ordering::Equal => {
            ra.get(1..) == rb.get(1..)
                || (ra.len() >= 2
                    && ra.first() == rb.get(1)
                    && ra.get(1) == rb.first()
                    && ra.get(2..) == rb.get(2..))
        }
        std::cmp::Ordering::Less => ra == rb.get(1..).unwrap_or_default(),
        std::cmp::Ordering::Greater => ra.get(1..).unwrap_or_default() == rb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_a_lookalike_when_it_is_one_edit_away_or_decorated() {
        let list = PopularNames::of(&["serde", "reqwest", "clap", "anyhow", "serde_json", "rand"]);
        for (wanted, popular) in [
            ("serdee", "serde"),
            ("reqwset", "reqwest"),
            ("reqwest-rs", "reqwest"),
            ("Reqwest_RS", "reqwest"),
            ("clap-derive-macros", "clap"),
            ("anyhow-ext", "anyhow"),
            ("rust-serde", "serde"),
            ("the_rand", "rand"),
        ] {
            assert_eq!(
                list.lookalike(wanted).map(String::as_str),
                Some(popular),
                "{wanted}"
            );
        }
        for fine in [
            "serde",
            "serde_json",
            "serde-json",
            "tokio",
            "reqwest-middleware",
            "serde-yaml-ng",
            "rand-chacha-fast",
        ] {
            assert_eq!(list.lookalike(fine), None, "{fine}");
        }
    }

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
