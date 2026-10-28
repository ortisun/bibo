//! What a repository may switch off.
//!
//! ADR 0009 item 19: a repository may list `title-type-tag` in
//! `documentation.disabled_readability_rules` of its project manifest, and no other rule. The
//! manifest type already refuses every other name. This module keeps the same limit on its own,
//! so the gate does not rely on the caller having read the manifest correctly.

use std::collections::BTreeSet;

use factory_domain::contracts::ProjectManifest;
use factory_domain::contracts::project_manifest::ReadabilityRule;

use super::catalog::{Catalog, RuleId, Severity};

/// A name in the list of disabled rules that may not be switched off.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OptionsError {
    /// Only a rule that warns and that the manifest schema lists can be switched off.
    #[error("only the rule title-type-tag can be switched off, and no rule that blocks")]
    NotSwitchable,
}

/// The settings of one gate run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    disabled: BTreeSet<RuleId>,
}

/// The rule a manifest name stands for. The match has no wildcard, so a rule added to the
/// manifest schema cannot be left out here.
const fn rule_for(rule: ReadabilityRule) -> RuleId {
    match rule {
        ReadabilityRule::TitleTypeTag => RuleId::TitleTypeTag,
    }
}

impl Options {
    /// Every rule on.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The rules a project manifest switches off.
    #[must_use]
    pub fn from_manifest(manifest: &ProjectManifest) -> Self {
        let listed = manifest.documentation.disabled_readability_rules.as_ref();
        Self::from_disabled(listed.map(|list| list.as_slice()).unwrap_or_default())
    }

    /// The rules in this list switched off.
    #[must_use]
    pub fn from_disabled(rules: &[ReadabilityRule]) -> Self {
        Self {
            disabled: rules.iter().copied().map(rule_for).collect(),
        }
    }

    /// The rules named by identifier, for a caller that has the names as text.
    ///
    /// # Errors
    /// [`OptionsError::NotSwitchable`] for any name the manifest schema does not list, which
    /// includes every rule that blocks.
    pub fn from_rule_ids<'a>(ids: impl IntoIterator<Item = &'a str>) -> Result<Self, OptionsError> {
        let mut disabled = BTreeSet::new();
        for id in ids {
            let rule = ReadabilityRule::parse(id).map_err(|_| OptionsError::NotSwitchable)?;
            disabled.insert(rule_for(rule));
        }
        Ok(Self { disabled })
    }

    /// True when a repository switched `rule` off and the catalog lets it. A rule that blocks
    /// is never off, whatever was asked.
    #[must_use]
    pub fn is_disabled(&self, catalog: &Catalog, rule: RuleId) -> bool {
        self.disabled.contains(&rule) && catalog.severity(rule) == Severity::Warn
    }
}
