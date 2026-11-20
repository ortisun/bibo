//! The engine builds from the real policies, and does not build from a policy it cannot honour.

use factory_domain::policy::{BuildError, PolicyEngine};

use crate::support::{
    approval, approval_from, approval_json, security, security_from, security_json,
};

#[test]
fn the_engine_builds_from_the_real_policies() {
    if let Err(e) = PolicyEngine::new(&security(), &approval()) {
        panic!("{e}");
    }
}

/// A named change to one key of a policy document.
type Case = (&'static str, fn(&mut serde_json::Value));

fn builds_with_security(
    change: impl FnOnce(&mut serde_json::Value),
) -> Result<PolicyEngine, BuildError> {
    let mut json = security_json();
    change(&mut json);
    PolicyEngine::new(&security_from(json), &approval())
}

fn builds_with_approval(
    change: impl FnOnce(&mut serde_json::Value),
) -> Result<PolicyEngine, BuildError> {
    let mut json = approval_json();
    change(&mut json);
    PolicyEngine::new(&security(), &approval_from(json))
}

#[test]
fn a_policy_that_switches_off_a_protection_the_engine_always_applies_does_not_build() {
    let off: [Case; 5] = [
        ("agents may self-grant", |j| {
            j["tools"]["agents_may_self_grant"] = true.into()
        }),
        ("wildcard egress", |j| {
            j["egress"]["allow_wildcards"] = true.into()
        }),
        ("dotdot allowed", |j| {
            j["matching"]["reject_dotdot"] = false.into()
        }),
        ("new dependency without a human", |j| {
            j["supply_chain"]["new_direct_dependency"]["approval"] = "heuristic".into();
        }),
        ("deny does not win", |j| {
            j["agent_stage_profiles"]["profiles"][1]["skills"]["deny_wins_over_allow"] =
                false.into();
        }),
    ];
    for (name, change) in off {
        assert!(
            builds_with_security(change).is_err(),
            "{name} must not build"
        );
    }
    let off: [Case; 6] = [
        ("github permission grants authority", |j| {
            j["authority"]["github_permission"]["can_grant_authority"] = true.into();
        }),
        ("bots may be listed", |j| {
            j["authority"]["bots_may_be_listed"] = true.into()
        }),
        ("self grant allowed", |j| {
            j["authority"]["allowlist_changes"]["self_grant_allowed"] = true.into();
        }),
        ("the app may approve", |j| {
            j["separation_of_duties"]["factory_app_may_approve"] = true.into();
        }),
        ("an agent may lower its tier", |j| {
            j["risk_classification"]["agent_may_lower_tier"] = true.into();
        }),
        ("a label alone authorizes", |j| {
            j["intake"]["label_presence_alone_is_authorization"] = true.into();
        }),
    ];
    for (name, change) in off {
        assert!(
            builds_with_approval(change).is_err(),
            "{name} must not build"
        );
    }
}

#[test]
fn an_action_row_that_contradicts_always_human_does_not_build() {
    // `add_new_direct_dependency` is on always_human. A row that lets it happen with no human is a
    // contradiction, found when the engine is built and not when a dependency is requested.
    let result = builds_with_approval(|j| {
        let rows = j["actions"].as_array_mut().expect("actions");
        for row in rows {
            if row["id"] == "add_new_direct_dependency" {
                row["requires"] = "none".into();
            }
        }
    });
    assert!(
        matches!(result, Err(BuildError::Contradiction(_))),
        "{result:?}"
    );
}

#[test]
fn a_policy_that_allows_an_override_of_an_unresolved_dependency_review_does_not_build() {
    // The protection is not only in the shipped file: a policy that drops the pair
    // (`dependency-review`, `policy_unresolvable`) from the blocks nobody may override, or names
    // a code that is not a block code, is found when the engine is built.
    let drop_it = builds_with_security(|j| {
        j["gate_integrity"]["non_overridable_blocks"] = serde_json::json!([]);
    });
    assert!(
        matches!(drop_it, Err(BuildError::ProtectionDisabled { .. })),
        "{drop_it:?}"
    );
    let renamed = builds_with_security(|j| {
        j["gate_integrity"]["non_overridable_blocks"][0]["code"] = "policy-unresolvable".into();
    });
    assert!(
        matches!(renamed, Err(BuildError::UnknownValue { .. })),
        "{renamed:?}"
    );
    // The control: another pair, added, builds, and is then not overridable either.
    let more = builds_with_security(|j| {
        j["gate_integrity"]["non_overridable_blocks"]
            .as_array_mut()
            .expect("the list")
            .push(serde_json::json!({
                "id": "advisories-unavailable",
                "gate": "dependency-advisories",
                "code": "dependency_unavailable",
                "reason": "a test"
            }));
    })
    .expect("a longer list builds");
    assert!(
        !more
            .authority
            .block_may_be_overridden("dependency-advisories", "dependency_unavailable")
    );
}

#[test]
fn a_policy_that_lets_anyone_but_a_security_approver_approve_build_code_does_not_build() {
    // The rules about build code rely on one human decision by one designation. A row that is
    // missing, that lets the action happen with no human, or that adds a designation is found
    // when the engine is built.
    type Change = fn(&mut serde_json::Value);
    fn row(json: &mut serde_json::Value) -> &mut serde_json::Value {
        json["actions"]
            .as_array_mut()
            .expect("actions")
            .iter_mut()
            .find(|row| row["id"] == "approve_build_code")
            .expect("the real policy has the row")
    }
    let cases: [(&str, Change); 5] = [
        ("an ordinary approver may approve it", |j| {
            row(j)["approver_roles"] = serde_json::json!(["approver", "security_approver"]);
        }),
        ("only an ordinary approver may approve it", |j| {
            row(j)["approver_roles"] = serde_json::json!(["approver"]);
        }),
        ("an organization administrator may approve it", |j| {
            row(j)["approver_roles"] = serde_json::json!(["security_approver", "org_admin"]);
        }),
        ("no human is needed", |j| {
            row(j)["requires"] = "none".into();
        }),
        ("there is no row", |j| {
            j["actions"]
                .as_array_mut()
                .expect("actions")
                .retain(|row| row["id"] != "approve_build_code");
        }),
    ];
    for (name, change) in cases {
        assert!(
            matches!(
                builds_with_approval(change),
                Err(BuildError::Contradiction(_))
            ),
            "{name} must not build"
        );
    }
}

#[test]
fn a_rework_or_repair_cap_above_two_does_not_build() {
    for set in [
        (|j: &mut serde_json::Value| {
            j["budgets"]["hard_ceilings"]["per_job"]["max_rework_iterations"] = 3.into();
        }) as fn(&mut serde_json::Value),
        |j| {
            j["budgets"]["hard_ceilings"]["per_job"]["max_documentation_rework_iterations"] =
                3.into()
        },
        |j| {
            j["budgets"]["hard_ceilings"]["per_job"]["max_specification_rework_iterations"] =
                3.into()
        },
        |j| j["budgets"]["hard_ceilings"]["per_job"]["max_design_rework_iterations"] = 3.into(),
        |j| {
            j["budgets"]["hard_ceilings"]["per_job"]["max_design_rework_iterations"] =
                u32::MAX.into()
        },
        |j| j["budgets"]["rework"]["default_rounds"] = 3.into(),
        |j| j["untrusted_content"]["structured_output"]["bounded_repair_attempts"] = 3.into(),
    ] {
        assert!(
            matches!(builds_with_security(set), Err(BuildError::Contradiction(_))),
            "a cap of three must not build"
        );
    }
}

#[test]
fn a_policy_without_a_rework_count_of_its_own_does_not_load() {
    // Fail closed: a file written before ADR 0023 has no specification or design count, and it
    // is refused rather than read as some default.
    for key in [
        "max_specification_rework_iterations",
        "max_design_rework_iterations",
    ] {
        let mut json = security_json();
        json["budgets"]["hard_ceilings"]["per_job"]
            .as_object_mut()
            .expect("per_job is a map")
            .remove(key);
        assert!(
            serde_json::from_value::<factory_domain::policy::SecurityPolicy>(json).is_err(),
            "a policy without {key} must not load"
        );
    }
}

#[test]
fn each_rework_count_takes_its_own_policy_value() {
    use factory_domain::machines::limits::ReworkTrack;
    for (key, track) in [
        (
            "max_specification_rework_iterations",
            ReworkTrack::Specification,
        ),
        ("max_design_rework_iterations", ReworkTrack::Design),
        ("max_rework_iterations", ReworkTrack::Code),
        (
            "max_documentation_rework_iterations",
            ReworkTrack::Documentation,
        ),
    ] {
        for configured in [0_u32, 1, 2] {
            let engine = builds_with_security(|j| {
                j["budgets"]["hard_ceilings"]["per_job"][key] = configured.into();
            })
            .expect("a cap of two or less builds");
            let limits = engine.budget.rework_limits();
            assert_eq!(u32::from(limits.cap(track).get()), configured, "{key}");
            for other in ReworkTrack::ALL.iter().filter(|t| **t != track) {
                assert_eq!(limits.cap(*other).get(), 2, "{key} moved {other}");
            }
        }
    }
}
