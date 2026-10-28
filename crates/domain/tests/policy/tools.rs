//! Tool grants, never-grantable tools, self-grant and per-stage skill profiles.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use factory_domain::policy::SandboxProfileKind::{self, Agent, FetchDeps, Verify};
use factory_domain::policy::security::HumanGate;
use factory_domain::policy::tools::{
    GrantRequest, Requester, SkillDenial, SkillVerdict, ToolDenial, ToolPolicy, ToolVerdict,
};
use factory_domain::vocabulary::StageKind;
use proptest::prelude::*;

use crate::support::{security, security_from, security_json};

fn policy() -> &'static ToolPolicy {
    static POLICY: LazyLock<ToolPolicy> =
        LazyLock::new(|| ToolPolicy::from_policy(&security()).expect("the real policy builds"));
    &POLICY
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

const ALL_TOOLS: [&str; 15] = [
    "fs.read",
    "fs.list",
    "fs.search",
    "fs.write",
    "fs.delete",
    "exec.run",
    "exec.shell",
    "vcs.read",
    "vcs.commit",
    "deps.request",
    "net.fetch",
    "spec.read",
    "report.submit",
    "github.write",
    "vcs.push",
];

fn grant(
    manifest: &[&str],
    needs: &[&str],
    role: &str,
    profile: Option<SandboxProfileKind>,
) -> factory_domain::policy::tools::GrantSet {
    policy().grant(&GrantRequest {
        manifest_allowed: &strings(manifest),
        stage_needs: &strings(needs),
        role,
        profile,
    })
}

#[test]
fn a_builder_gets_the_intersection_of_manifest_policy_and_stage_need() {
    let set = grant(
        &[
            "fs.read",
            "fs.write",
            "exec.run",
            "vcs.commit",
            "deps.request",
        ],
        &["fs.read", "fs.write", "exec.run", "fs.delete"],
        "builder",
        Some(Agent),
    );
    let held: Vec<&str> = set.granted().keys().map(String::as_str).collect();
    assert_eq!(held, ["exec.run", "fs.read", "fs.write"]);
    // `fs.delete` is needed and policy would allow it to a builder, but the manifest does not.
    assert!(
        set.denied()
            .contains(&("fs.delete".to_owned(), ToolDenial::NotInManifest))
    );
    // A tool in the manifest that the stage does not need is not granted.
    assert!(!set.holds("vcs.commit") && !set.holds("deps.request"));
}

#[test]
fn a_tool_is_held_only_by_a_role_and_a_profile_the_entry_names() {
    let table = [
        // (tool, role, profile, outcome)
        ("fs.write", "builder", Some(Agent), None),
        (
            "fs.write",
            "qa",
            Some(Agent),
            Some(ToolDenial::RoleNotAllowed),
        ),
        (
            "fs.write",
            "builder",
            Some(Verify),
            Some(ToolDenial::ProfileNotAllowed),
        ),
        (
            "fs.write",
            "builder",
            None,
            Some(ToolDenial::ProfileNotAllowed),
        ),
        ("exec.run", "builder", Some(FetchDeps), None),
        (
            "exec.run",
            "code_reviewer",
            Some(Agent),
            Some(ToolDenial::RoleNotAllowed),
        ),
        ("net.fetch", "research", None, None),
        ("net.fetch", "intake", None, None),
        (
            "net.fetch",
            "research",
            Some(Agent),
            Some(ToolDenial::ProfileNotAllowed),
        ),
        (
            "net.fetch",
            "builder",
            None,
            Some(ToolDenial::RoleNotAllowed),
        ),
        ("report.submit", "any-role-at-all", Some(Agent), None),
        (
            "exec.shell",
            "builder",
            Some(Agent),
            Some(ToolDenial::Disabled),
        ),
        ("exec.shell", "builder", None, Some(ToolDenial::Disabled)),
    ];
    for (tool, role, profile, expected) in table {
        let set = grant(&[tool], &[tool], role, profile);
        match expected {
            None => assert!(set.holds(tool), "{tool} for {role} in {profile:?}"),
            Some(reason) => {
                assert!(!set.holds(tool), "{tool} for {role} in {profile:?}");
                assert_eq!(
                    set.denied(),
                    [(tool.to_owned(), reason)],
                    "{tool} {role} {profile:?}"
                );
            }
        }
    }
}

#[test]
fn negative_nt_tool_03_unknown_never_grantable_and_self_granted_tools_are_refused() {
    // Even when the manifest lists them and the stage asks for them.
    for tool in [
        "github.write",
        "vcs.push",
        "merge",
        "approval.grant",
        "policy.write",
        "tool.grant",
        "secrets.read",
        "docker.any",
        "audit.write",
    ] {
        let set = grant(&[tool], &[tool], "builder", Some(Agent));
        assert!(!set.holds(tool), "{tool}");
        assert_eq!(
            set.denied(),
            [(tool.to_owned(), ToolDenial::NeverGrantable)],
            "{tool}"
        );
        let verdict = policy().check_call(&set, tool, 0);
        assert!(
            matches!(
                verdict,
                ToolVerdict::Denied {
                    reason: ToolDenial::NeverGrantable,
                    ..
                }
            ),
            "{tool}: {verdict:?}"
        );
        let asked = policy().request_grant(Requester::PolicyEngine, tool);
        assert!(matches!(
            asked,
            ToolVerdict::Denied {
                reason: ToolDenial::NeverGrantable,
                ..
            }
        ));
    }
    // An unregistered tool (`shell.exec` is not `exec.shell`) is unknown, never granted by default.
    let set = grant(&["shell.exec"], &["shell.exec"], "builder", Some(Agent));
    assert_eq!(
        set.denied(),
        [("shell.exec".to_owned(), ToolDenial::UnknownTool)]
    );
    assert!(matches!(
        policy().check_call(&set, "shell.exec", 0),
        ToolVerdict::Denied {
            reason: ToolDenial::UnknownTool,
            ..
        }
    ));
    // An agent that asks for any grant, by call, by output text or by editing its manifest, is
    // refused, for a tool it could legitimately hold as well.
    for tool in ["fs.read", "exec.run", "tool.grant", "anything"] {
        let verdict = policy().request_grant(Requester::Agent, tool);
        assert!(
            matches!(
                verdict,
                ToolVerdict::Denied {
                    reason: ToolDenial::SelfGrant,
                    ..
                }
            ),
            "{tool}"
        );
    }
    // A call of a tool the stage does not hold is refused, whether registered or not.
    let none = grant(&[], &[], "builder", Some(Agent));
    assert!(matches!(
        policy().check_call(&none, "fs.read", 0),
        ToolVerdict::Denied {
            reason: ToolDenial::NotGranted,
            ..
        }
    ));
}

#[test]
fn negative_nt_pol_04_a_tool_allowed_in_a_profile_but_never_grantable_is_denied() {
    // Put `fs.read` on the never-grantable list as well as in the entries: deny wins.
    let mut json = security_json();
    json["tools"]["never_grantable"]
        .as_array_mut()
        .expect("list")
        .push("fs.read".into());
    let strict = ToolPolicy::from_policy(&security_from(json)).expect("builds");
    let set = strict.grant(&GrantRequest {
        manifest_allowed: &strings(&["fs.read"]),
        stage_needs: &strings(&["fs.read"]),
        role: "builder",
        profile: Some(Agent),
    });
    assert!(!set.holds("fs.read"));
    assert_eq!(
        set.denied(),
        [("fs.read".to_owned(), ToolDenial::NeverGrantable)]
    );
}

#[test]
fn negative_nt_tool_08_calls_stop_at_the_cap_and_a_per_call_gate_is_reported() {
    let set = grant(
        &["fs.read", "deps.request"],
        &["fs.read", "deps.request"],
        "builder",
        Some(Agent),
    );
    let cap = set.granted()["fs.read"]
        .caps
        .expect("caps")
        .max_calls_per_task;
    assert_eq!(cap, 3000);
    assert!(matches!(
        policy().check_call(&set, "fs.read", cap - 1),
        ToolVerdict::Allowed {
            human_gate: HumanGate::None
        }
    ));
    assert!(matches!(
        policy().check_call(&set, "fs.read", cap),
        ToolVerdict::Denied {
            reason: ToolDenial::CapReached,
            ..
        }
    ));
    // A new dependency request is always a per-call human decision.
    assert!(matches!(
        policy().check_call(&set, "deps.request", 0),
        ToolVerdict::Allowed {
            human_gate: HumanGate::PerCall
        }
    ));
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 500, ..ProptestConfig::default() })]

    #[test]
    fn grants_never_exceed_the_manifest(
        manifest in proptest::collection::vec(prop::sample::select(ALL_TOOLS.to_vec()).prop_map(String::from), 0..16),
        needs in proptest::collection::vec(prop_oneof![prop::sample::select(ALL_TOOLS.to_vec()).prop_map(String::from), "[a-z.]{1,12}"], 0..24),
        role in prop::sample::select(vec!["builder", "qa", "research", "intake", "planner", "code_reviewer", "unknown_role", "*"]),
        profile in prop::sample::select(vec![None, Some(Agent), Some(Verify), Some(FetchDeps)]),
    ) {
        let set = policy().grant(&GrantRequest {
            manifest_allowed: &manifest,
            stage_needs: &needs,
            role,
            profile,
        });
        let allowed: BTreeSet<&String> = manifest.iter().collect();
        let wanted: BTreeSet<&String> = needs.iter().collect();
        let never: BTreeSet<&str> = ["github.write","vcs.push","merge","approval.grant","policy.write","tool.grant","secrets.read","docker.any","audit.write"].into();
        let known: BTreeSet<&str> = ALL_TOOLS.into();
        for tool in set.granted().keys() {
            prop_assert!(allowed.contains(tool), "{tool} is not in the manifest");
            prop_assert!(wanted.contains(tool), "{tool} is not needed by the stage");
            prop_assert!(!never.contains(tool.as_str()), "{tool} is never grantable");
            prop_assert!(known.contains(tool.as_str()), "{tool} is not a registered tool");
            prop_assert_ne!(tool.as_str(), "exec.shell");
        }
        // Everything asked for is accounted for exactly once.
        let asked: BTreeSet<&String> = wanted;
        let answered: BTreeSet<&String> = set.granted().keys().chain(set.denied().iter().map(|(t, _)| t)).collect();
        prop_assert_eq!(answered, asked);
    }
}

#[test]
fn negative_nt_pol_08_the_specification_stage_may_run_four_skills_in_any_spelling_and_no_others() {
    let allowed = [
        "speckit.constitution",
        "speckit.specify",
        "speckit.clarify",
        "speckit.checklist",
    ];
    let denied = [
        "plan",
        "tasks",
        "analyze",
        "implement",
        "converge",
        "taskstoissues",
    ];
    for id in allowed {
        let name = id.trim_start_matches("speckit.");
        for spelling in [
            format!("/speckit-{name}"),
            format!("$speckit-{name}"),
            format!("speckit.{name}"),
            format!("/speckit.{name}"),
            format!("/SpecKit-{name}"),
        ] {
            assert!(
                matches!(
                    policy().check_skill(StageKind::Specification, &spelling),
                    SkillVerdict::Allowed { .. }
                ),
                "{spelling}"
            );
        }
    }
    let SkillVerdict::Allowed {
        writes,
        protected_path_exception_required,
        ..
    } = policy().check_skill(StageKind::Specification, "/speckit-constitution")
    else {
        panic!("allowed");
    };
    assert_eq!(writes, [".specify/memory/constitution.md"]);
    assert!(protected_path_exception_required);
    for name in denied {
        for spelling in [
            format!("/speckit-{name}"),
            format!("$speckit-{name}"),
            format!("speckit.{name}"),
            format!("/speckit.{name}"),
            format!("/SPECKIT_{name}"),
            format!(" speckit:{name} "),
        ] {
            assert!(
                matches!(
                    policy().check_skill(StageKind::Specification, &spelling),
                    SkillVerdict::Denied {
                        reason: SkillDenial::Denied,
                        ..
                    }
                ),
                "{spelling}"
            );
        }
    }
    for other in [
        "",
        "frobnicate",
        "/review",
        "speckit",
        "speckit.",
        "x".repeat(300).as_str(),
    ] {
        assert!(
            matches!(
                policy().check_skill(StageKind::Specification, other),
                SkillVerdict::Denied { .. }
            ),
            "{other:?}"
        );
    }
    // Every other stage kind has skills and slash commands off, even for the four.
    for kind in StageKind::ALL {
        if *kind == StageKind::Specification {
            continue;
        }
        for skill in ["/speckit-specify", "speckit.plan", "/anything"] {
            assert!(
                matches!(
                    policy().check_skill(*kind, skill),
                    SkillVerdict::Denied {
                        reason: SkillDenial::SkillsDisabled,
                        ..
                    }
                ),
                "{kind:?} {skill}"
            );
        }
    }
}

#[test]
fn a_skill_on_both_lists_is_denied() {
    let mut json = security_json();
    json["agent_stage_profiles"]["profiles"][1]["skills"]["denied"]
        .as_array_mut()
        .expect("list")
        .push("speckit.specify".into());
    let strict = ToolPolicy::from_policy(&security_from(json)).expect("builds");
    assert!(matches!(
        strict.check_skill(StageKind::Specification, "/speckit-specify"),
        SkillVerdict::Denied {
            reason: SkillDenial::Denied,
            ..
        }
    ));
}
