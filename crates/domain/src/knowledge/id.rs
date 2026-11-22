//! The kinds of entry and their identifiers.

use std::fmt;
use std::sync::OnceLock;

use regex::Regex;

use crate::error::ValueError;
use crate::macros::string_enum;

string_enum! {
    /// The kind of an entry. The first six are written by people, the last three by the factory
    /// (ADR 0029).
    pub enum EntryKind("knowledge entry kind") {
        /// Something the product does for its users.
        Feature = "feature",
        /// How something moves through the product, step by step.
        Flow = "flow",
        /// A rule the product must keep.
        BusinessRule = "business-rule",
        /// A word with the meaning the project gives it.
        Term = "term",
        /// An outside system the project talks to.
        Integration = "integration",
        /// A legal, regulatory or technical limit.
        Constraint = "constraint",
        /// The definition of a process number.
        Metric = "metric",
        /// A dated snapshot of the process numbers.
        Measurement = "measurement",
        /// What was tried to improve the process and what it changed.
        Improvement = "improvement",
    }
}

impl EntryKind {
    /// The prefix of its identifiers: `BR` for a business rule.
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Feature => "F",
            Self::Flow => "FL",
            Self::BusinessRule => "BR",
            Self::Term => "T",
            Self::Integration => "I",
            Self::Constraint => "C",
            Self::Metric => "MT",
            Self::Measurement => "M",
            Self::Improvement => "IM",
        }
    }

    /// The directory of its files under `docs/knowledge/`.
    pub const fn directory(self) -> &'static str {
        match self {
            Self::Feature => "features",
            Self::Flow => "flows",
            Self::BusinessRule => "business-rules",
            Self::Term => "terms",
            Self::Integration => "integrations",
            Self::Constraint => "constraints",
            Self::Metric => "metrics",
            Self::Measurement => "measurements",
            Self::Improvement => "improvements",
        }
    }

    /// The heading of its section in the index.
    pub const fn heading(self) -> &'static str {
        match self {
            Self::Feature => "Features",
            Self::Flow => "Flows",
            Self::BusinessRule => "Business rules",
            Self::Term => "Terms",
            Self::Integration => "Integrations",
            Self::Constraint => "Constraints",
            Self::Metric => "Metrics",
            Self::Measurement => "Measurements",
            Self::Improvement => "Improvements",
        }
    }

    /// Whether people write entries of this kind. The factory writes the others.
    pub const fn written_by_people(self) -> bool {
        !matches!(self, Self::Metric | Self::Measurement | Self::Improvement)
    }

    /// The kind whose identifiers start with `prefix`.
    fn of_prefix(prefix: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.prefix() == prefix)
    }
}

/// The identifier of an entry: its kind's prefix, a hyphen, and four digits from `0001`
/// (`BR-0007`). A measurement is named by its window instead: `M-2026-W47` or
/// `M-2026-11-16-to-2026-12-16`. An identifier is never reused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryId {
    text: String,
    kind: EntryKind,
}

fn measurement_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^(?:[0-9]{4}-W(?:0[1-9]|[1-4][0-9]|5[0-3])|[0-9]{4}-[0-9]{2}-[0-9]{2}-to-[0-9]{4}-[0-9]{2}-[0-9]{2})$")
            .expect("the pattern compiles")
    })
}

impl EntryId {
    /// Reads an identifier. The prefix says the kind.
    ///
    /// # Errors
    /// A [`ValueError`] naming the rule: an unknown prefix, or a number that is not four digits
    /// from `0001`, or a measurement name that is not a week or a range of dates.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let what = "knowledge entry identifier";
        let (prefix, rest) = text.split_once('-').ok_or_else(|| {
            ValueError::new(
                what,
                text,
                "write the prefix of its kind, a hyphen and its number, such as BR-0007",
            )
        })?;
        let kind = EntryKind::of_prefix(prefix).ok_or_else(|| {
            ValueError::new(
                what,
                text,
                "the prefix must be one of F, FL, BR, T, I, C, MT, M, IM",
            )
        })?;
        let valid = match kind {
            EntryKind::Measurement => measurement_pattern().is_match(rest),
            _ => rest.len() == 4 && rest.bytes().all(|b| b.is_ascii_digit()) && rest != "0000",
        };
        if !valid {
            let rule = match kind {
                EntryKind::Measurement => {
                    "a measurement is named by its week (M-2026-W47) or its dates (M-2026-11-16-to-2026-12-16)"
                }
                _ => "the number is four digits from 0001, such as BR-0007",
            };
            return Err(ValueError::new(what, text, rule));
        }
        Ok(Self {
            text: text.to_owned(),
            kind,
        })
    }

    /// The identifier as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The kind its prefix says.
    pub const fn kind(&self) -> EntryKind {
        self.kind
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl serde::Serialize for EntryId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

impl<'de> serde::Deserialize<'de> for EntryId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_its_own_prefix_and_directory() {
        let prefixes: std::collections::BTreeSet<_> =
            EntryKind::ALL.iter().map(|k| k.prefix()).collect();
        let directories: std::collections::BTreeSet<_> =
            EntryKind::ALL.iter().map(|k| k.directory()).collect();
        assert_eq!(prefixes.len(), EntryKind::ALL.len());
        assert_eq!(directories.len(), EntryKind::ALL.len());
        assert_eq!(
            EntryKind::ALL
                .iter()
                .filter(|k| k.written_by_people())
                .count(),
            6
        );
    }

    #[test]
    fn an_identifier_names_its_kind() {
        let cases = [
            ("F-0001", EntryKind::Feature),
            ("FL-0003", EntryKind::Flow),
            ("BR-0007", EntryKind::BusinessRule),
            ("T-0012", EntryKind::Term),
            ("I-0002", EntryKind::Integration),
            ("C-9999", EntryKind::Constraint),
            ("MT-0021", EntryKind::Metric),
            ("IM-0001", EntryKind::Improvement),
            ("M-2026-W47", EntryKind::Measurement),
            ("M-2026-W01", EntryKind::Measurement),
            ("M-2026-W53", EntryKind::Measurement),
            ("M-2026-11-16-to-2026-12-16", EntryKind::Measurement),
        ];
        for (text, kind) in cases {
            let id = EntryId::parse(text).expect(text);
            assert_eq!((id.as_str(), id.kind()), (text, kind));
        }
    }

    #[test]
    fn a_malformed_identifier_is_refused() {
        for text in [
            "",
            "BR",
            "BR-",
            "BR-7",
            "BR-007",
            "BR-00007",
            "BR-0000",
            "br-0007",
            "XX-0001",
            "BR-000a",
            " BR-0007",
            "BR-0007 ",
            "M-0001",
            "M-2026-W00",
            "M-2026-W54",
            "M-2026-W5",
            "M-2026-11-16",
            "M-2026-11-16-2026-12-16",
            "MT-2026-W47",
            "IM-2026-W47",
            "BR-+007",
        ] {
            assert!(EntryId::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn identifiers_sort_by_their_text() {
        let mut ids: Vec<EntryId> = ["BR-0010", "BR-0002", "F-0001"]
            .iter()
            .map(|t| EntryId::parse(t).expect("valid"))
            .collect();
        ids.sort();
        let texts: Vec<&str> = ids.iter().map(EntryId::as_str).collect();
        assert_eq!(texts, ["BR-0002", "BR-0010", "F-0001"]);
    }
}
