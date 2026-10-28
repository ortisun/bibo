//! The rule catalog: `fixtures/readability/rules.json`, embedded at compile time.
//!
//! The file is the one source of truth for what a rule is called, whether it blocks or warns,
//! which artifacts it applies to, what the author should do about it, and every word list. The
//! code does not copy any of that. It keeps one function for each deterministic rule, and
//! [`Catalog::parse`] checks that the two agree: a deterministic rule in the file that no
//! function implements, a function with no rule in the file, a reviewer rule that blocks, or a
//! language the detector cannot recognise all make the catalog fail to load. A gate whose catalog
//! failed to load reports `BLOCKED`, never `PASSED` (policy section 9.3).
//!
//! `include_str!` makes the embedded copy the file itself, and Cargo rebuilds this crate when the
//! file changes, so the two cannot drift. The tests in `tests/readability/catalog.rs` check that
//! this module embeds that file and not a copy.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use serde_json::Value;

use super::artifact::ArtifactKind;

/// The text of `fixtures/readability/rules.json`, as it was when this crate was built.
pub const RULES_JSON: &str = include_str!("../../../../../fixtures/readability/rules.json");

/// Whether a finding of a rule stops the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// The finding is reported next to the others and does not change the outcome.
    Warn,
    /// The finding makes the gate outcome `FAILED`.
    Block,
}

impl Severity {
    /// The spelling in the catalog.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

macro_rules! rule_ids {
    ($($variant:ident = $id:literal),+ $(,)?) => {
        /// The deterministic rules this gate implements. The identifier is also the `check_id`
        /// of a failure or warning in the gate report.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum RuleId {
            $(
                #[doc = concat!("`", $id, "`")]
                $variant,
            )+
        }

        impl RuleId {
            /// Every deterministic rule, in the order of the catalog.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The identifier as written in the catalog and in the gate report.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $id,)+
                }
            }

            /// The rule with this identifier, or `None` for a reviewer rule or an unknown one.
            #[must_use]
            pub fn parse(text: &str) -> Option<Self> {
                match text {
                    $($id => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

rule_ids! {
    TitleSchemaShape = "title-schema-shape",
    TitleOpaquePrefix = "title-opaque-prefix",
    TitleMachineLabel = "title-machine-label",
    TitleVague = "title-vague",
    TitleTypeTag = "title-type-tag",
    TitleNotSentenceCase = "title-not-sentence-case",
    TitleTooLong = "title-too-long",
    TitleTrailingPunctuation = "title-trailing-punctuation",
    TaskMissingSection = "task-missing-section",
    BodyMetadataPrefix = "body-metadata-prefix",
    BodyMetadataLines = "body-metadata-lines",
    PrMissingEvidenceLink = "pr-missing-evidence-link",
    DocGuideMissingPart = "doc-guide-missing-part",
    TextNotEnglish = "text-not-english",
    TextQuotationDominates = "text-quotation-dominates",
    TextAbbreviationUnexpanded = "text-abbreviation-unexpanded",
    TextRawInternalId = "text-raw-internal-id",
    TextFillerPhrase = "text-filler-phrase",
    TextLongSentence = "text-long-sentence",
}

/// A language the detector can recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Language {
    /// Portuguese, the only language the master prompt names.
    Portuguese,
}

/// What the catalog says about one deterministic rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSpec {
    /// Whether a finding blocks or warns.
    pub severity: Severity,
    /// The kinds of artifact the rule applies to.
    pub applies_to: Vec<ArtifactKind>,
    /// Advice for the author, taken from the catalog.
    pub suggested_fix: String,
}

/// A rule that a model judges. The gate does not run it and only names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewerRule {
    /// The identifier.
    pub id: String,
}

/// The word lists of the catalog. Lists that are searched are sets. Lists that are only walked
/// keep the order of the file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lists {
    /// Abbreviations that need no explanation, upper case.
    pub acronym_allowlist: BTreeSet<String>,
    /// Upper-case words that are not abbreviations, upper case.
    pub not_abbreviation_words: BTreeSet<String>,
    /// Generic verbs, nouns and articles, lower case, in one set: a title made only of these
    /// names no outcome.
    pub generic_words: BTreeSet<String>,
    /// Nouns that make a placeholder when a letter or number follows ("part 3"), lower case.
    pub placeholder_nouns: BTreeSet<String>,
    /// Subjects of a status report ("agent task complete"), lower case.
    pub status_subjects: BTreeSet<String>,
    /// Phrases that report a status, lower case.
    pub status_phrases: BTreeSet<String>,
    /// Conventional-commit types, lower case.
    pub conventional_commit_types: Vec<String>,
    /// Prefixes of a role stamp, upper case.
    pub role_stamp_prefixes: Vec<String>,
    /// Keys of internal bookkeeping lines, lower case.
    pub metadata_line_keys: Vec<String>,
    /// Chatbot filler and marketing phrases, lower case, with a straight apostrophe.
    pub filler_phrases: Vec<String>,
    /// The four sections of a task, in template order.
    pub required_task_sections: Vec<String>,
    /// Phrases for a prerequisites heading, lower case.
    pub guide_prerequisites: Vec<String>,
    /// Phrases for an expected-result heading, lower case.
    pub guide_expected_result: Vec<String>,
    /// Phrases for a troubleshooting heading, lower case.
    pub guide_troubleshooting: Vec<String>,
    /// The languages that must be detected without a model.
    pub languages: Vec<Language>,
}

/// Why the catalog could not be used. The gate that holds this error reports `BLOCKED`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    /// The text is not JSON.
    #[error("the rule catalog is not valid JSON")]
    NotJson,
    /// A field is missing or has the wrong type.
    #[error("the rule catalog has no usable `{0}`")]
    Field(&'static str),
    /// A deterministic rule has no function in this gate.
    #[error("the rule catalog names a deterministic rule that this gate does not implement")]
    UnknownRule,
    /// A function of this gate has no rule in the catalog.
    #[error("the rule catalog lacks the deterministic rule `{0}`")]
    MissingRule(&'static str),
    /// A rule has a severity, mode or kind the gate does not know.
    #[error("a rule in the catalog has a severity, mode or kind the gate does not know")]
    BadRule,
    /// A reviewer rule is marked as blocking, but a model judgement never blocks by itself.
    #[error("a reviewer rule in the catalog is marked as blocking")]
    ReviewerCannotBlock,
    /// The catalog asks for a language the detector cannot recognise.
    #[error("the rule catalog asks for deterministic detection of a language the gate lacks")]
    UnsupportedLanguage,
}

/// The loaded catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    rules: BTreeMap<RuleId, RuleSpec>,
    reviewer_rules: Vec<ReviewerRule>,
    lists: Lists,
}

impl Catalog {
    /// Reads a catalog from the text of `rules.json`.
    ///
    /// # Errors
    /// A [`CatalogError`] when the text is not JSON, a field is missing, or the rules and the
    /// functions of this gate do not match.
    pub fn parse(json: &str) -> Result<Self, CatalogError> {
        let root: Value = serde_json::from_str(json).map_err(|_| CatalogError::NotJson)?;
        let mut rules = BTreeMap::new();
        let mut reviewer_rules = Vec::new();
        let entries = root
            .get("rules")
            .and_then(Value::as_array)
            .ok_or(CatalogError::Field("rules"))?;
        for entry in entries {
            let id = text_field(entry, "id")?;
            let severity = match text_field(entry, "severity")? {
                "block" => Severity::Block,
                "warn" => Severity::Warn,
                _ => return Err(CatalogError::BadRule),
            };
            match text_field(entry, "mode")? {
                "reviewer" => {
                    if severity == Severity::Block {
                        return Err(CatalogError::ReviewerCannotBlock);
                    }
                    reviewer_rules.push(ReviewerRule { id: id.to_owned() });
                }
                "deterministic" => {
                    let rule = RuleId::parse(id).ok_or(CatalogError::UnknownRule)?;
                    let applies_to = entry
                        .get("applies_to")
                        .and_then(Value::as_array)
                        .ok_or(CatalogError::Field("applies_to"))?
                        .iter()
                        .map(|kind| {
                            kind.as_str()
                                .and_then(ArtifactKind::parse)
                                .ok_or(CatalogError::BadRule)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let spec = RuleSpec {
                        severity,
                        applies_to,
                        suggested_fix: text_field(entry, "suggested_fix")?.to_owned(),
                    };
                    if rules.insert(rule, spec).is_some() {
                        return Err(CatalogError::BadRule);
                    }
                }
                _ => return Err(CatalogError::BadRule),
            }
        }
        for rule in RuleId::ALL {
            if !rules.contains_key(rule) {
                return Err(CatalogError::MissingRule(rule.as_str()));
            }
        }
        let lists = Lists::parse(root.get("lists").ok_or(CatalogError::Field("lists"))?)?;
        Ok(Self {
            rules,
            reviewer_rules,
            lists,
        })
    }

    /// The embedded catalog, parsed once. Every caller shares the one copy.
    ///
    /// # Errors
    /// The [`CatalogError`] of the embedded file, if it does not load.
    pub fn embedded() -> Result<Arc<Self>, CatalogError> {
        static EMBEDDED: OnceLock<Result<Arc<Catalog>, CatalogError>> = OnceLock::new();
        EMBEDDED
            .get_or_init(|| Self::parse(RULES_JSON).map(Arc::new))
            .clone()
    }

    /// What the catalog says about a deterministic rule. Every rule has an entry, so this never
    /// fails for a catalog that loaded.
    #[must_use]
    pub fn rule(&self, id: RuleId) -> Option<&RuleSpec> {
        self.rules.get(&id)
    }

    /// The severity of a rule. A rule the catalog somehow lacks counts as blocking, so a gap
    /// can never turn into a pass.
    #[must_use]
    pub fn severity(&self, id: RuleId) -> Severity {
        self.rule(id).map_or(Severity::Block, |spec| spec.severity)
    }

    /// The rules a model judges. This gate does not run them.
    #[must_use]
    pub fn reviewer_rules(&self) -> &[ReviewerRule] {
        &self.reviewer_rules
    }

    /// The word lists.
    #[must_use]
    pub const fn lists(&self) -> &Lists {
        &self.lists
    }
}

fn text_field<'a>(entry: &'a Value, name: &'static str) -> Result<&'a str, CatalogError> {
    entry
        .get(name)
        .and_then(Value::as_str)
        .ok_or(CatalogError::Field(name))
}

fn strings(lists: &Value, name: &'static str) -> Result<Vec<String>, CatalogError> {
    lists
        .get(name)
        .and_then(Value::as_array)
        .ok_or(CatalogError::Field(name))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(CatalogError::Field(name))
        })
        .collect()
}

fn lower(items: Vec<String>) -> Vec<String> {
    items.into_iter().map(|s| s.to_lowercase()).collect()
}

fn upper(items: Vec<String>) -> BTreeSet<String> {
    items.into_iter().map(|s| s.to_uppercase()).collect()
}

fn lower_set(items: Vec<String>) -> BTreeSet<String> {
    items.into_iter().map(|s| s.to_lowercase()).collect()
}

impl Lists {
    fn parse(lists: &Value) -> Result<Self, CatalogError> {
        let mut generic_words = BTreeSet::new();
        for name in ["generic_verbs", "generic_nouns", "generic_articles"] {
            generic_words.extend(lower_set(strings(lists, name)?));
        }
        let headings = lists
            .get("guide_headings")
            .ok_or(CatalogError::Field("guide_headings"))?;
        let languages = strings(lists, "deterministic_language_detection")?
            .iter()
            .map(|code| match code.as_str() {
                "pt" => Ok(Language::Portuguese),
                _ => Err(CatalogError::UnsupportedLanguage),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            acronym_allowlist: upper(strings(lists, "acronym_allowlist")?),
            not_abbreviation_words: upper(strings(lists, "not_abbreviation_words")?),
            generic_words,
            placeholder_nouns: lower_set(strings(lists, "placeholder_nouns")?),
            status_subjects: lower_set(strings(lists, "status_subjects")?),
            status_phrases: lower_set(strings(lists, "status_phrases")?),
            conventional_commit_types: lower(strings(lists, "conventional_commit_types")?),
            role_stamp_prefixes: strings(lists, "role_stamp_prefixes")?
                .into_iter()
                .map(|s| s.to_uppercase())
                .collect(),
            metadata_line_keys: lower(strings(lists, "metadata_line_keys")?),
            filler_phrases: lower(strings(lists, "filler_phrases")?)
                .into_iter()
                .map(|phrase| phrase.replace('\u{2019}', "'"))
                .collect(),
            required_task_sections: strings(lists, "required_task_sections")?,
            guide_prerequisites: lower(strings(headings, "prerequisites")?),
            guide_expected_result: lower(strings(headings, "expected_result")?),
            guide_troubleshooting: lower(strings(headings, "troubleshooting")?),
            languages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_catalog_loads_and_has_every_deterministic_rule() {
        let catalog = Catalog::embedded().expect("the embedded catalog loads");
        for rule in RuleId::ALL {
            assert!(catalog.rule(*rule).is_some(), "{}", rule.as_str());
        }
        assert_eq!(catalog.reviewer_rules().len(), 6);
        assert_eq!(catalog.severity(RuleId::TitleVague), Severity::Block);
        assert_eq!(catalog.severity(RuleId::TitleTypeTag), Severity::Warn);
    }

    #[test]
    fn a_catalog_that_does_not_match_the_functions_does_not_load() {
        assert_eq!(Catalog::parse("not json"), Err(CatalogError::NotJson));
        assert_eq!(Catalog::parse("{}"), Err(CatalogError::Field("rules")));
        // A deterministic rule that no function implements.
        let unknown =
            RULES_JSON.replacen("\"id\": \"title-vague\"", "\"id\": \"title-unheard\"", 1);
        assert_eq!(Catalog::parse(&unknown), Err(CatalogError::UnknownRule));
        // A language the detector lacks.
        let language = RULES_JSON.replace(
            "\"deterministic_language_detection\": [\"pt\"]",
            "\"deterministic_language_detection\": [\"fr\"]",
        );
        assert_eq!(
            Catalog::parse(&language),
            Err(CatalogError::UnsupportedLanguage)
        );
    }

    #[test]
    fn a_reviewer_rule_cannot_block() {
        let blocking = RULES_JSON.replacen(
            "\"id\": \"title-lacks-concrete-outcome\",\n      \"family\": \"title\",\n      \"severity\": \"warn\"",
            "\"id\": \"title-lacks-concrete-outcome\",\n      \"family\": \"title\",\n      \"severity\": \"block\"",
            1,
        );
        assert_ne!(blocking, RULES_JSON, "the replacement found the rule");
        assert_eq!(
            Catalog::parse(&blocking),
            Err(CatalogError::ReviewerCannotBlock)
        );
    }
}
