//! Turning the rules that apply to a branch into a protection report.
//!
//! The preflight reads `GET /repos/{owner}/{repo}/rules/branches/{branch}`, which needs the
//! Metadata permission only. It never reads classic branch protection (`.../protection`), which
//! needs Administration, a permission the App must not hold. A repository that has only classic
//! protection therefore reads as "no ruleset rules" and runs at level L0 with that named reason.
//!
//! The answer is a list of active rules from every ruleset that applies to the branch. Each rule
//! has a `type` and, for most, `parameters`. The types used here are `pull_request`
//! (`dismiss_stale_reviews_on_push`, `require_code_owner_review`), `required_status_checks`
//! (`required_status_checks`: a list of `context` and `integration_id`), `non_fast_forward` and
//! `deletion`. Rules of other types are ignored. When several rules speak to the same setting the
//! strictest wins, as on GitHub.
//!
//! UNVERIFIED against the real GitHub: the exact type names and parameter names. The fixtures in
//! `tests/fixtures/` are written from the documented shape, not recorded, and say so. Before the
//! preflight is trusted, a person must record one real response from the protected fixture
//! repository and add it as a fixture (`ports-v1.1`, section 13).

use factory_ports::githost::{GitHostError, ProtectionReport, ProtectionSource, RequiredCheck};
use factory_ports::paths::BranchName;
use serde_json::Value;

/// Builds the report from the body of the rules answer.
///
/// # Errors
/// `Unavailable` when the body is not a list of rules.
pub fn protection_from_rules(
    default_branch: BranchName,
    rules: &Value,
) -> Result<ProtectionReport, GitHostError> {
    let list = rules.as_array().ok_or(GitHostError::Unavailable)?;
    let mut report = ProtectionReport {
        default_branch,
        source: if list.is_empty() {
            ProtectionSource::NoRulesetRules
        } else {
            ProtectionSource::Rulesets
        },
        requires_pull_request: false,
        requires_code_owner_review: false,
        dismisses_stale_approvals: false,
        blocks_force_push: false,
        blocks_deletion: false,
        required_checks: Vec::new(),
    };
    for rule in list {
        let parameters = &rule["parameters"];
        match rule["type"].as_str() {
            Some("pull_request") => {
                report.requires_pull_request = true;
                report.requires_code_owner_review |=
                    parameters["require_code_owner_review"].as_bool() == Some(true);
                report.dismisses_stale_approvals |=
                    parameters["dismiss_stale_reviews_on_push"].as_bool() == Some(true);
            }
            Some("required_status_checks") => {
                for check in parameters["required_status_checks"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    if let Some(context) = check["context"].as_str() {
                        report.required_checks.push(RequiredCheck {
                            context: context.to_owned(),
                            integration_id: check["integration_id"].as_u64(),
                        });
                    }
                }
            }
            Some("non_fast_forward") => report.blocks_force_push = true,
            Some("deletion") => report.blocks_deletion = true,
            _ => {}
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn branch() -> BranchName {
        BranchName::new("main").unwrap()
    }

    #[test]
    fn no_rules_means_no_ruleset_rules_and_every_setting_off() {
        let report = protection_from_rules(branch(), &json!([])).unwrap();
        assert_eq!(report.source, ProtectionSource::NoRulesetRules);
        assert!(!report.requires_pull_request && !report.blocks_deletion);
        assert!(report.required_checks.is_empty());
    }

    #[test]
    fn each_rule_type_sets_its_own_setting() {
        let rules = json!([
            {"type": "pull_request", "parameters": {"dismiss_stale_reviews_on_push": true, "require_code_owner_review": true}},
            {"type": "required_status_checks", "parameters": {"required_status_checks": [
                {"context": "factory-validation", "integration_id": 4242}, {"context": "lint"}]}},
            {"type": "non_fast_forward"},
            {"type": "deletion"},
            {"type": "creation"}
        ]);
        let report = protection_from_rules(branch(), &rules).unwrap();
        assert_eq!(report.source, ProtectionSource::Rulesets);
        assert!(report.requires_pull_request && report.requires_code_owner_review);
        assert!(
            report.dismisses_stale_approvals && report.blocks_force_push && report.blocks_deletion
        );
        assert_eq!(
            report.required_checks,
            vec![
                RequiredCheck {
                    context: "factory-validation".to_owned(),
                    integration_id: Some(4242)
                },
                RequiredCheck {
                    context: "lint".to_owned(),
                    integration_id: None
                },
            ]
        );
    }

    #[test]
    fn a_pull_request_rule_without_the_stricter_parameters_leaves_them_off() {
        let rules = json!([{"type": "pull_request", "parameters": {"dismiss_stale_reviews_on_push": false}}]);
        let report = protection_from_rules(branch(), &rules).unwrap();
        assert!(report.requires_pull_request);
        assert!(!report.requires_code_owner_review && !report.dismisses_stale_approvals);
    }

    #[test]
    fn the_strictest_of_several_rules_wins() {
        let rules = json!([
            {"type": "pull_request", "parameters": {"require_code_owner_review": false}},
            {"type": "pull_request", "parameters": {"require_code_owner_review": true}}
        ]);
        assert!(
            protection_from_rules(branch(), &rules)
                .unwrap()
                .requires_code_owner_review
        );
    }

    #[test]
    fn an_answer_that_is_not_a_list_is_an_error() {
        for bad in [json!({"message": "Not Found"}), json!(null), json!("x")] {
            assert_eq!(
                protection_from_rules(branch(), &bad),
                Err(GitHostError::Unavailable)
            );
        }
    }
}
