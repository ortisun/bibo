//! How far a reviewer's model was from the model whose work it reviewed, as the reviewing stages
//! record it next to their verdict.
//!
//! The router says it in its decision (`RoutingDecision::independence`), from the models of the
//! routing policy. The reviewing stages write it into their record (`review-record`,
//! `documentation-review-record`) under the key `independence`, and the delivery stage reads it
//! back and lists a review by another model of the same family among the limitations of the
//! evidence: it is a weaker check than a review by another family (ADR 0020, amendment of
//! 2026-11-13). The names in it are the policy's model names, a closed set, never a model's text.

use factory_ports::agent::{IndependenceKind, RoutingDecision};
use serde_json::{Value, json};

/// The key of the record that holds it.
pub const KEY: &str = "independence";

/// The value to store under [`KEY`]: the author's model, the reviewer's model and how far apart
/// they are. `null` when the stage was routed with no known author.
#[must_use]
pub fn record(decision: &RoutingDecision) -> Value {
    decision
        .independence
        .as_ref()
        .map_or(Value::Null, |independence| {
            json!({
                "author_model": independence.author.model.as_str(),
                "reviewer_model": decision.model.model.as_str(),
                "kind": independence.kind.as_str(),
            })
        })
}

/// A review made by another model of the same family as the author, read from a stored record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SameFamilyReview {
    /// The model that made the work.
    pub author_model: String,
    /// The model that reviewed it.
    pub reviewer_model: String,
}

/// Reads a stored record and returns the review when it was by another model of the same family
/// as the author. `None` for any other record, or one that does not say.
#[must_use]
pub fn same_family_review(bytes: &[u8]) -> Option<SameFamilyReview> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let found = value.get(KEY)?;
    if found.get("kind")?.as_str()? != IndependenceKind::SameFamilyOtherModel.as_str() {
        return None;
    }
    Some(SameFamilyReview {
        author_model: found.get("author_model")?.as_str()?.to_owned(),
        reviewer_model: found.get("reviewer_model")?.as_str()?.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::values::NonEmptyString;
    use factory_ports::agent::{FlagSet, ModelSelection, ReviewIndependence, RuntimeId};

    fn selection(model: &str) -> ModelSelection {
        ModelSelection {
            runtime: RuntimeId::new("claude-code-cli").expect("a runtime"),
            model: NonEmptyString::parse(model).expect("a model"),
        }
    }

    fn decision(kind: Option<IndependenceKind>) -> RoutingDecision {
        RoutingDecision {
            model: selection("claude-opus-5-5"),
            flag_set: FlagSet::Standard,
            independence: kind.map(|kind| ReviewIndependence {
                author: selection("claude-sonnet-5-5"),
                kind,
            }),
        }
    }

    #[test]
    fn a_review_by_the_same_family_is_recorded_and_read_back() {
        let stored =
            json!({ (KEY): record(&decision(Some(IndependenceKind::SameFamilyOtherModel))) });
        let bytes = serde_json::to_vec(&stored).expect("json");
        assert_eq!(
            same_family_review(&bytes),
            Some(SameFamilyReview {
                author_model: "claude-sonnet-5-5".to_owned(),
                reviewer_model: "claude-opus-5-5".to_owned(),
            })
        );
    }

    #[test]
    fn a_review_by_another_family_or_with_no_known_author_is_not_one() {
        for kind in [
            Some(IndependenceKind::OtherFamily),
            Some(IndependenceKind::OtherProvider),
            None,
        ] {
            let stored = json!({ (KEY): record(&decision(kind)) });
            let bytes = serde_json::to_vec(&stored).expect("json");
            assert_eq!(same_family_review(&bytes), None, "{kind:?}");
        }
        assert_eq!(same_family_review(b"not json"), None);
    }
}
