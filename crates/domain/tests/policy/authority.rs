//! Authority: the allowlist, admission, the autonomy ladder, action authorization, separation of
//! duties, allowlist changes and overrides.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use factory_domain::ids::TenantId;
use factory_domain::policy::authority::{
    ActionContext, ActionDenialReason, ActionVerdict, Actor, ActorKind, Admission, AdmissionInput,
    AllowlistChange, AllowlistChangeDenial, AuthorityDenial, AuthorityPolicy, AutonomyLevel,
    ChangeFacts, GithubPermission, OverrideContext, OverrideDenial,
};
use factory_domain::policy::authority::{Allowlist, AllowlistEntry};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::policy::paths::{ChangeEvidence, Operation, PathPolicy, PathVerdict};
use factory_domain::policy::{PolicyEngine, RepoKind};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::RiskTier;

use crate::support::{approval, approval_from, approval_json, security};

const REPO: &str = "acme/widgets";

fn engine() -> &'static PolicyEngine {
    static ENGINE: LazyLock<PolicyEngine> =
        LazyLock::new(|| PolicyEngine::new(&security(), &approval()).expect("builds"));
    &ENGINE
}

fn authority() -> &'static AuthorityPolicy {
    &engine().authority
}

fn tenant() -> TenantId {
    TenantId::parse("018f3a00-0000-7000-8000-00000000c001").expect("tenant")
}

fn other_tenant() -> TenantId {
    TenantId::parse("018f3a00-0000-7000-8000-00000000c002").expect("tenant")
}

fn now() -> Timestamp {
    Timestamp::parse("2026-10-27T12:00:00Z").expect("time")
}

fn uid(n: u64) -> GithubUserId {
    GithubUserId::new(n).expect("a GitHub id")
}

// The people of the fixtures. Every login is the same word on purpose where a test needs it.
const REQUESTER: u64 = 1001;
const OPERATOR: u64 = 1002;
const APPROVER: u64 = 1003;
const APPROVER_TWO: u64 = 1004;
const SECURITY: u64 = 1005;
const ORG_ONE: u64 = 1006;
const ORG_TWO: u64 = 1007;
const REPO_ADMIN: u64 = 1008;
const EXPIRED: u64 = 1009;
const OTHER_REPO_ONLY: u64 = 1010;
const SECURITY_TWO: u64 = 1011;

fn entry(id: u64, login: &str, designations: &[Designation]) -> AllowlistEntry {
    AllowlistEntry {
        tenant: tenant(),
        github_user_id: uid(id),
        login: login.to_owned(),
        designations: designations.iter().copied().collect(),
        repositories: None,
        expires_at: None,
    }
}

fn allowlist() -> Allowlist {
    use Designation::{Approver, Operator, OrgAdmin, RepoAdmin, Requester, SecurityApprover};
    let mut expired = entry(EXPIRED, "temp", &[Approver]);
    expired.expires_at = Some(Timestamp::parse("2026-10-27T11:59:59Z").expect("time"));
    let mut narrow = entry(OTHER_REPO_ONLY, "narrow", &[Approver]);
    narrow.repositories = Some(BTreeSet::from(["acme/other".to_owned()]));
    let mut future = entry(SECURITY_TWO, "sec2", &[SecurityApprover]);
    future.expires_at = Some(Timestamp::parse("2027-01-01T00:00:00Z").expect("time"));
    Allowlist::new(
        "sha256:allowlist-v1",
        vec![
            // Same person is a requester and an approver: the single-maintainer case.
            entry(REQUESTER, "alice", &[Requester, Approver]),
            entry(OPERATOR, "olga", &[Operator]),
            entry(APPROVER, "mallory", &[Approver]),
            entry(APPROVER_TWO, "bob", &[Approver]),
            entry(SECURITY, "sam", &[SecurityApprover]),
            entry(ORG_ONE, "gina", &[OrgAdmin]),
            entry(ORG_TWO, "gus", &[OrgAdmin]),
            entry(REPO_ADMIN, "rita", &[RepoAdmin]),
            expired,
            narrow,
            future,
            // A person of another tenant with every designation.
            AllowlistEntry {
                tenant: other_tenant(),
                ..entry(3000, "carol", &Designation::ALL)
            },
        ],
    )
    .expect("no duplicates")
}

fn human(id: u64, login: &str) -> Actor<'_> {
    Actor {
        github_user_id: uid(id),
        login,
        kind: ActorKind::User,
        github_permission: None,
        author_association: None,
    }
}

const LOW: ChangeFacts = ChangeFacts {
    risk_tier: RiskTier::Low,
    protected_path_change: false,
    sensitive_file_change: false,
    new_dependency: false,
};

fn decide(
    list: &Allowlist,
    actor: &Actor<'_>,
    action: &str,
    level: AutonomyLevel,
    requester: Option<u64>,
    change: ChangeFacts,
) -> ActionVerdict {
    decide_with(
        authority(),
        list,
        actor,
        action,
        level,
        requester,
        change,
        None,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_with(
    policy: &AuthorityPolicy,
    list: &Allowlist,
    actor: &Actor<'_>,
    action: &str,
    level: AutonomyLevel,
    requester: Option<u64>,
    change: ChangeFacts,
    require_designation: Option<Designation>,
    step_up_done: bool,
) -> ActionVerdict {
    let tenant = tenant();
    let now = now();
    policy.authorize_action(&ActionContext {
        action,
        level,
        tenant: &tenant,
        repository: REPO,
        actor,
        allowlist: list,
        now: &now,
        requester: requester.map(uid),
        change,
        require_designation,
        step_up_done,
    })
}

fn reason(verdict: &ActionVerdict) -> Option<ActionDenialReason> {
    match verdict {
        ActionVerdict::Denied(d) => Some(d.reason.clone()),
        _ => None,
    }
}

fn authorized(verdict: ActionVerdict) -> AuthorizedApproval {
    match verdict {
        ActionVerdict::Authorized(a) => a,
        other => panic!("expected an authorization, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Who holds a designation: the allowlist, by numeric id
// ---------------------------------------------------------------------------------------------

#[test]
fn negative_nt_authz_01_only_the_numeric_id_on_the_allowlist_grants_a_designation() {
    let list = allowlist();
    let (tenant, now) = (tenant(), now());
    let held = |actor: &Actor<'_>| authority().designations(&list, &tenant, REPO, actor, &now);

    assert_eq!(
        held(&human(REQUESTER, "alice")).expect("listed"),
        BTreeSet::from([Designation::Requester, Designation::Approver])
    );
    // A login that matches a listed entry, with another id: nothing. The login `mallory` was the
    // listed person's login; the account that holds it now is somebody else.
    assert_eq!(
        held(&human(2000, "mallory")),
        Err(AuthorityDenial::NotOnAllowlist)
    );
    // The listed id under another login still holds what the entry gives.
    assert!(held(&human(APPROVER, "renamed-since")).is_ok());
    // An organization owner and repository admin on GitHub who is not on the list.
    let owner = Actor {
        github_permission: Some(GithubPermission::Admin),
        author_association: Some("OWNER"),
        ..human(2001, "boss")
    };
    assert_eq!(held(&owner), Err(AuthorityDenial::NotOnAllowlist));
    // A person on the list for another tenant only.
    assert_eq!(
        held(&human(3000, "carol")),
        Err(AuthorityDenial::NotOnAllowlist)
    );
    // Bots and apps hold nothing, even with a listed id.
    for kind in [ActorKind::Bot, ActorKind::App] {
        let bot = Actor {
            kind,
            ..human(APPROVER, "dependabot[bot]")
        };
        assert_eq!(held(&bot), Err(AuthorityDenial::NotHuman));
    }
    // Expiry and narrowing to other repositories.
    assert_eq!(
        held(&human(EXPIRED, "temp")),
        Err(AuthorityDenial::EntryExpired)
    );
    assert_eq!(
        held(&human(OTHER_REPO_ONLY, "narrow")),
        Err(AuthorityDenial::RepositoryNotListed)
    );
    // GitHub ids start at 1.
    assert!(GithubUserId::new(0).is_none());
}

#[test]
fn negative_nt_authz_04_removing_the_entry_removes_the_authority_at_the_next_decision() {
    let before = allowlist();
    let after = Allowlist::new(
        "sha256:allowlist-v2",
        vec![entry(REQUESTER, "alice", &[Designation::Requester])],
    )
    .expect("list");
    let actor = human(APPROVER, "mallory");
    let ask = |list: &Allowlist| {
        decide(
            list,
            &actor,
            "approve_pr",
            AutonomyLevel::L1,
            Some(REQUESTER),
            LOW,
        )
    };
    let approval = authorized(ask(&before));
    assert_eq!(approval.allowlist_version(), "sha256:allowlist-v1");
    // The same person, the same GitHub permission, the next decision: denied, and nothing cached.
    assert_eq!(
        reason(&ask(&after)),
        Some(ActionDenialReason::Authority(
            AuthorityDenial::NotOnAllowlist
        ))
    );
}

#[test]
fn a_github_permission_condition_can_only_deny() {
    let mut json = approval_json();
    json["authority"]["github_permission"]["additional_condition"]["enabled"] = true.into();
    let policy = AuthorityPolicy::from_policies(&approval_from(json), &security()).expect("builds");
    let list = allowlist();
    let ask = |actor: &Actor<'_>| {
        decide_with(
            &policy,
            &list,
            actor,
            "approve_pr",
            AutonomyLevel::L1,
            Some(REQUESTER),
            LOW,
            None,
            true,
        )
    };
    let low = Actor {
        github_permission: Some(GithubPermission::Read),
        ..human(APPROVER, "mallory")
    };
    let none = human(APPROVER, "mallory");
    let high = Actor {
        github_permission: Some(GithubPermission::Maintain),
        ..human(APPROVER, "mallory")
    };
    let expect_denied = Some(ActionDenialReason::Authority(
        AuthorityDenial::GithubPermissionBelowCondition,
    ));
    assert_eq!(reason(&ask(&low)), expect_denied);
    assert_eq!(
        reason(&ask(&none)),
        expect_denied,
        "an unknown permission is not enough"
    );
    assert!(matches!(ask(&high), ActionVerdict::Authorized(_)));
    // Admin on GitHub without an entry is still nothing.
    let admin = Actor {
        github_permission: Some(GithubPermission::Admin),
        ..human(2002, "root")
    };
    assert_eq!(
        reason(&ask(&admin)),
        Some(ActionDenialReason::Authority(
            AuthorityDenial::NotOnAllowlist
        ))
    );
}

// ---------------------------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------------------------

fn admit(
    actor: &Actor<'_>,
    quota: bool,
    registered: bool,
    class: bool,
    preflight: bool,
) -> Admission {
    let (tenant, now, list) = (tenant(), now(), allowlist());
    authority().admit(&AdmissionInput {
        tenant: &tenant,
        repository: REPO,
        actor,
        allowlist: &list,
        now: &now,
        tenant_within_job_quota: quota,
        repository_registered_and_enabled: registered,
        policy_allows_request_class: class,
        protection_preflight_passed: preflight,
    })
}

#[test]
fn admission_needs_the_requester_designation_and_four_other_facts() {
    let alice = human(REQUESTER, "alice");
    assert_eq!(
        admit(&alice, true, true, true, true),
        Admission::Admitted {
            max_level: AutonomyLevel::L1
        }
    );
    // A failed preflight admits the job at L0 only.
    assert_eq!(
        admit(&alice, true, true, true, false),
        Admission::Admitted {
            max_level: AutonomyLevel::L0
        }
    );
    for (quota, registered, class) in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        assert!(matches!(
            admit(&alice, quota, registered, class, true),
            Admission::Denied { .. }
        ));
    }
    // Holding approver, operator or any other designation is not the requester designation.
    for (id, login) in [
        (OPERATOR, "olga"),
        (APPROVER, "mallory"),
        (ORG_ONE, "gina"),
        (SECURITY, "sam"),
    ] {
        let actor = human(id, login);
        assert!(
            matches!(
                admit(&actor, true, true, true, true),
                Admission::Denied { .. }
            ),
            "{login}"
        );
    }
    // The label sender who is only an issue author, an owner or an admin on GitHub.
    let owner = Actor {
        github_permission: Some(GithubPermission::Admin),
        author_association: Some("OWNER"),
        ..human(4000, "alice")
    };
    assert!(matches!(
        admit(&owner, true, true, true, true),
        Admission::Denied { .. }
    ));
    let bot = Actor {
        kind: ActorKind::Bot,
        ..human(REQUESTER, "alice")
    };
    assert!(matches!(
        admit(&bot, true, true, true, true),
        Admission::Denied { .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// The autonomy ladder
// ---------------------------------------------------------------------------------------------

#[test]
fn the_autonomy_ladder_caps_at_l0_without_a_preflight_and_never_reaches_a_disabled_level() {
    let a = authority();
    assert_eq!(a.default_level(), AutonomyLevel::L1);
    assert!(a.level_enabled(AutonomyLevel::L2) && !a.level_enabled(AutonomyLevel::L3));
    for configured in AutonomyLevel::ALL {
        assert_eq!(a.effective_level(configured, false), AutonomyLevel::L0);
        assert!(a.level_enabled(a.effective_level(configured, true)));
        assert!(a.effective_level(configured, true) <= configured);
    }
    assert_eq!(
        a.effective_level(AutonomyLevel::L3, true),
        AutonomyLevel::L2
    );
    assert_eq!(
        a.effective_level(AutonomyLevel::L1, true),
        AutonomyLevel::L1
    );
}

#[test]
fn raising_autonomy_needs_an_org_admin_and_lowering_a_repo_admin() {
    let list = allowlist();
    let (tenant, now) = (tenant(), now());
    let change = |actor: &Actor<'_>, from, to| {
        authority().authorize_autonomy_change(
            &ActionContext {
                action: "raise_autonomy_level",
                level: from,
                tenant: &tenant,
                repository: REPO,
                actor,
                allowlist: &list,
                now: &now,
                requester: Some(uid(REQUESTER)),
                change: LOW,
                require_designation: None,
                step_up_done: true,
            },
            from,
            to,
        )
    };
    use AutonomyLevel::{L1, L2, L3};
    assert!(matches!(
        change(&human(ORG_ONE, "gina"), L1, L2),
        ActionVerdict::Authorized(_)
    ));
    for (id, login) in [
        (REPO_ADMIN, "rita"),
        (APPROVER, "mallory"),
        (SECURITY, "sam"),
    ] {
        assert!(
            matches!(
                reason(&change(&human(id, login), L1, L2)),
                Some(ActionDenialReason::MissingDesignation { .. })
            ),
            "{login} may not raise"
        );
    }
    // L3 is off: not even an org admin can reach it.
    assert_eq!(
        reason(&change(&human(ORG_ONE, "gina"), L2, L3)),
        Some(ActionDenialReason::LevelDisabled)
    );
    // Lowering.
    assert!(matches!(
        change(&human(REPO_ADMIN, "rita"), L2, L1),
        ActionVerdict::Authorized(_)
    ));
    assert!(matches!(
        reason(&change(&human(APPROVER, "mallory"), L2, L1)),
        Some(ActionDenialReason::MissingDesignation { .. })
    ));
    // No change, no decision.
    assert!(matches!(
        change(&human(APPROVER, "mallory"), L1, L1),
        ActionVerdict::NoHumanNeeded { .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------------------------

#[test]
fn an_action_needs_the_level_the_requirement_and_a_designation_the_row_names() {
    let list = allowlist();
    let approver = human(APPROVER, "mallory");
    use AutonomyLevel::{L0, L1, L2, L3};
    // merge_pr: a human at L1 and L2, impossible at L0 (below min_level) and at L3 (off).
    assert!(matches!(
        decide(&list, &approver, "merge_pr", L1, Some(REQUESTER), LOW),
        ActionVerdict::Authorized(_)
    ));
    assert!(matches!(
        decide(&list, &approver, "merge_pr", L2, Some(REQUESTER), LOW),
        ActionVerdict::Authorized(_)
    ));
    assert_eq!(
        reason(&decide(
            &list,
            &approver,
            "merge_pr",
            L0,
            Some(REQUESTER),
            LOW
        )),
        Some(ActionDenialReason::BelowMinLevel)
    );
    assert_eq!(
        reason(&decide(
            &list,
            &approver,
            "merge_pr",
            L3,
            Some(REQUESTER),
            LOW
        )),
        Some(ActionDenialReason::LevelDisabled)
    );
    // mark_pr_ready: forbidden at L0, a human at L1, the policy alone at L2.
    assert_eq!(
        reason(&decide(
            &list,
            &approver,
            "mark_pr_ready",
            L0,
            Some(REQUESTER),
            LOW
        )),
        Some(ActionDenialReason::BelowMinLevel)
    );
    assert!(matches!(
        decide(&list, &approver, "mark_pr_ready", L1, Some(REQUESTER), LOW),
        ActionVerdict::Authorized(_)
    ));
    assert!(matches!(
        decide(&list, &approver, "mark_pr_ready", L2, Some(REQUESTER), LOW),
        ActionVerdict::NoHumanNeeded { .. }
    ));
    // An action that needs nobody.
    assert!(matches!(
        decide(&list, &approver, "post_comment", L0, None, LOW),
        ActionVerdict::NoHumanNeeded { .. }
    ));
    // Roles: an operator pauses and cannot approve; an approver approves and cannot pause.
    let operator = human(OPERATOR, "olga");
    assert!(matches!(
        decide(
            &list,
            &operator,
            "pause_or_resume_job",
            L1,
            Some(REQUESTER),
            LOW
        ),
        ActionVerdict::Authorized(_)
    ));
    for (actor, action) in [
        (&operator, "approve_pr"),
        (&approver, "pause_or_resume_job"),
        (&approver, "change_authority_allowlist"),
        (&approver, "raise_budget_ceiling"),
    ] {
        assert!(
            matches!(
                reason(&decide(&list, actor, action, L1, Some(REQUESTER), LOW)),
                Some(ActionDenialReason::MissingDesignation { .. })
            ),
            "{action}"
        );
    }
    // Designations do not imply each other: an org admin is not an approver.
    let admin = human(ORG_ONE, "gina");
    assert!(matches!(
        reason(&decide(
            &list,
            &admin,
            "approve_pr",
            L1,
            Some(REQUESTER),
            LOW
        )),
        Some(ActionDenialReason::MissingDesignation { .. })
    ));
    assert!(matches!(
        decide(&list, &admin, "raise_budget_ceiling", L1, None, LOW),
        ActionVerdict::Authorized(_)
    ));
}

#[test]
fn approving_build_code_is_a_security_approvers_decision_and_nobody_elses() {
    // B-2, SC-10. A build script or a procedural macro of a package that is new to the build
    // runs on the machines that build the project. The decision is a human's at every level,
    // the designation is the security approver's alone, and the requester cannot make it.
    use AutonomyLevel::{L0, L1, L2, L3};
    let list = allowlist();
    let change = ChangeFacts {
        new_dependency: true,
        ..LOW
    };
    let security = human(SECURITY, "sam");
    for level in [L1, L2] {
        let proof = authorized(decide(
            &list,
            &security,
            "approve_build_code",
            level,
            Some(REQUESTER),
            change,
        ));
        assert_eq!(proof.action(), "approve_build_code");
        assert_eq!(proof.designation(), Designation::SecurityApprover);
        assert_eq!(proof.approver(), uid(SECURITY));
    }
    // Nobody without the designation, whatever else they hold: the approver of a dependency,
    // the operator, an organization administrator, a repository administrator, the requester.
    for (id, login) in [
        (APPROVER, "mallory"),
        (APPROVER_TWO, "bob"),
        (OPERATOR, "olga"),
        (ORG_ONE, "gina"),
        (REPO_ADMIN, "rita"),
        (REQUESTER, "alice"),
    ] {
        let verdict = decide(
            &list,
            &human(id, login),
            "approve_build_code",
            L1,
            Some(SECURITY),
            change,
        );
        assert!(
            matches!(
                reason(&verdict),
                Some(ActionDenialReason::MissingDesignation { .. })
            ),
            "{login}: {verdict:?}"
        );
    }
    // A security approver who asked for the job does not approve the build code of its change.
    assert_eq!(
        reason(&decide(
            &list,
            &security,
            "approve_build_code",
            L1,
            Some(SECURITY),
            change
        )),
        Some(ActionDenialReason::SelfApproval)
    );
    // The action does not exist below L1, and the level that is off stays off.
    assert_eq!(
        reason(&decide(
            &list,
            &security,
            "approve_build_code",
            L0,
            Some(REQUESTER),
            change
        )),
        Some(ActionDenialReason::BelowMinLevel)
    );
    assert_eq!(
        reason(&decide(
            &list,
            &security,
            "approve_build_code",
            L3,
            Some(REQUESTER),
            change
        )),
        Some(ActionDenialReason::LevelDisabled)
    );
    // The engine knows the designations of the row, so a gate can ask it instead of naming one.
    assert_eq!(
        authority().approver_designations("approve_build_code"),
        [Designation::SecurityApprover]
    );
    assert!(
        authority()
            .approver_designations("no_such_action")
            .is_empty()
    );
}

#[test]
fn an_action_with_no_row_needs_an_org_admin_and_a_forbidden_one_is_never_allowed() {
    let list = allowlist();
    use AutonomyLevel::L1;
    let unknown = "delete_everything";
    assert!(matches!(
        reason(&decide(&list, &human(APPROVER, "mallory"), unknown, L1, None, LOW)),
        Some(ActionDenialReason::MissingDesignation { needed }) if needed == [Designation::OrgAdmin]
    ));
    assert!(matches!(
        decide(&list, &human(ORG_ONE, "gina"), unknown, L1, None, LOW),
        ActionVerdict::Authorized(_)
    ));
    for name in [
        "force_push_to_default_branch",
        "bypass_branch_protection",
        "disable_audit_logging",
        "read_secret_values_into_agent_context",
        "run_agent_with_unsandboxed_host_execution",
    ] {
        assert!(authority().is_never_allowed(name));
        assert_eq!(
            reason(&decide(&list, &human(ORG_ONE, "gina"), name, L1, None, LOW)),
            Some(ActionDenialReason::NeverAllowed),
            "{name} even for an org admin"
        );
    }
}

#[test]
fn separation_of_duties_follows_the_change_and_the_designation() {
    let list = allowlist();
    use AutonomyLevel::L1;
    let alice = human(REQUESTER, "alice"); // requester and approver at once
    let high = ChangeFacts {
        risk_tier: RiskTier::High,
        ..LOW
    };
    let flags = [
        ChangeFacts {
            protected_path_change: true,
            ..LOW
        },
        ChangeFacts {
            sensitive_file_change: true,
            ..LOW
        },
        ChangeFacts {
            new_dependency: true,
            ..LOW
        },
        high,
    ];
    // A low-risk change in a single-maintainer repository: the requester may approve.
    assert!(matches!(
        decide(&list, &alice, "approve_pr", L1, Some(REQUESTER), LOW),
        ActionVerdict::Authorized(_)
    ));
    // Any of the four triggers: not the requester.
    for change in flags {
        assert_eq!(
            reason(&decide(
                &list,
                &alice,
                "approve_pr",
                L1,
                Some(REQUESTER),
                change
            )),
            Some(ActionDenialReason::SelfApproval),
            "{change:?}"
        );
        // Another approver is fine, and an unknown requester fails closed.
        assert!(matches!(
            decide(
                &list,
                &human(APPROVER, "mallory"),
                "approve_pr",
                L1,
                Some(REQUESTER),
                change
            ),
            ActionVerdict::Authorized(_)
        ));
        assert_eq!(
            reason(&decide(
                &list,
                &human(APPROVER, "mallory"),
                "approve_pr",
                L1,
                None,
                change
            )),
            Some(ActionDenialReason::RequesterUnknown)
        );
    }
    // A security approver is never the requester, whatever the risk.
    let mut with_security = vec![entry(
        SECURITY,
        "sam",
        &[Designation::SecurityApprover, Designation::Requester],
    )];
    with_security.push(entry(REQUESTER, "alice", &[Designation::Requester]));
    let list2 = Allowlist::new("sha256:v3", with_security).expect("list");
    assert_eq!(
        reason(&decide(
            &list2,
            &human(SECURITY, "sam"),
            "waive_failed_gate",
            L1,
            Some(SECURITY),
            LOW
        )),
        Some(ActionDenialReason::SelfApproval)
    );
}

#[test]
fn a_critical_change_needs_two_distinct_security_approvers() {
    let list = allowlist();
    use AutonomyLevel::L1;
    let critical = ChangeFacts {
        risk_tier: RiskTier::Critical,
        protected_path_change: true,
        ..LOW
    };
    // An ordinary approver does not satisfy a critical tier.
    assert!(matches!(
        reason(&decide(&list, &human(APPROVER, "mallory"), "approve_pr", L1, Some(REQUESTER), critical)),
        Some(ActionDenialReason::MissingDesignation { needed }) if needed == [Designation::SecurityApprover]
    ));
    let first = authorized(decide(
        &list,
        &human(SECURITY, "sam"),
        "approve_pr",
        L1,
        Some(REQUESTER),
        critical,
    ));
    let second = authorized(decide(
        &list,
        &human(SECURITY_TWO, "sec2"),
        "approve_pr",
        L1,
        Some(REQUESTER),
        critical,
    ));
    assert_eq!(first.designation(), Designation::SecurityApprover);
    let a = authority();
    assert_eq!(a.required_approvals(RiskTier::Critical), 2);
    assert_eq!(a.required_approvals(RiskTier::Low), 1);
    assert!(!a.quorum_met(
        RiskTier::Critical,
        "approve_pr",
        std::slice::from_ref(&first)
    ));
    assert!(
        !a.quorum_met(
            RiskTier::Critical,
            "approve_pr",
            &[first.clone(), first.clone()]
        ),
        "one person twice is one approval"
    );
    assert!(a.quorum_met(
        RiskTier::Critical,
        "approve_pr",
        &[first.clone(), second.clone()]
    ));
    assert!(
        !a.quorum_met(RiskTier::Critical, "merge_pr", &[first, second]),
        "approvals for another action do not count"
    );
}

#[test]
fn step_up_authentication_is_required_where_the_policy_says() {
    let list = allowlist();
    use AutonomyLevel::L1;
    let sam = human(SECURITY, "sam");
    let protected = ChangeFacts {
        risk_tier: RiskTier::Critical,
        protected_path_change: true,
        ..LOW
    };
    let ask = |step_up| {
        decide_with(
            authority(),
            &list,
            &sam,
            "change_protected_path",
            L1,
            Some(REQUESTER),
            protected,
            None,
            step_up,
        )
    };
    assert_eq!(
        reason(&ask(false)),
        Some(ActionDenialReason::StepUpRequired)
    );
    assert!(matches!(ask(true), ActionVerdict::Authorized(_)));
    // Where it is not asked for, the flag changes nothing.
    assert!(matches!(
        decide_with(
            authority(),
            &list,
            &human(APPROVER, "mallory"),
            "approve_pr",
            L1,
            Some(REQUESTER),
            LOW,
            None,
            false
        ),
        ActionVerdict::Authorized(_)
    ));
}

// ---------------------------------------------------------------------------------------------
// NT-POL-04: the exception flow works only through a recorded human decision
// ---------------------------------------------------------------------------------------------

fn paths() -> &'static PathPolicy {
    &engine().paths
}

#[test]
fn negative_nt_pol_04_a_protected_change_is_accepted_only_with_all_three_elements() {
    let list = allowlist();
    use AutonomyLevel::L1;
    let protected = ChangeFacts {
        risk_tier: RiskTier::Critical,
        protected_path_change: true,
        ..LOW
    };
    let human_decision = authorized(decide(
        &list,
        &human(SECURITY, "sam"),
        "change_protected_path",
        L1,
        Some(REQUESTER),
        protected,
    ));
    assert_eq!(human_decision.action(), "change_protected_path");
    let write = Operation::Modify {
        gained_lines_only: false,
    };
    let check = |evidence: &ChangeEvidence<'_>| {
        paths().check(
            RepoKind::Target,
            ".github/workflows/ci.yml",
            write,
            None,
            evidence,
        )
    };

    let full = ChangeEvidence {
        spec_authorization: true,
        independent_policy_review: true,
        human_approval: Some(&human_decision),
    };
    let PathVerdict::Allowed(allowance) = check(&full) else {
        panic!("all three elements lift the refusal");
    };
    assert_eq!(
        allowance
            .exception_for
            .iter()
            .map(|r| r.id())
            .collect::<Vec<_>>(),
        ["ci_workflows"]
    );

    // Each element removed in turn: refused, naming exactly the missing one.
    let remove_spec = ChangeEvidence {
        spec_authorization: false,
        ..full
    };
    let remove_review = ChangeEvidence {
        independent_policy_review: false,
        ..full
    };
    let remove_human = ChangeEvidence {
        human_approval: None,
        ..full
    };
    for (evidence, missing) in [
        (remove_spec, "spec_authorization"),
        (remove_review, "independent_policy_review"),
        (remove_human, "human_approval"),
    ] {
        let PathVerdict::Denied(denial) = check(&evidence) else {
            panic!("{missing} removed must be refused");
        };
        assert_eq!(
            denial
                .missing
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>(),
            [missing]
        );
    }
    // A decision for another action does not stand in for the protected-path decision.
    let merge = authorized(decide(
        &list,
        &human(APPROVER, "mallory"),
        "merge_pr",
        L1,
        Some(REQUESTER),
        LOW,
    ));
    let wrong_action = ChangeEvidence {
        human_approval: Some(&merge),
        ..full
    };
    assert!(!check(&wrong_action).is_allowed());
    // And it cannot lift a hidden path, with every element present.
    assert!(
        !paths()
            .check(RepoKind::Target, ".env", Operation::Read, None, &full)
            .is_allowed()
    );
    // A person who is not an authorized security approver cannot produce the decision at all.
    assert!(matches!(
        decide(
            &list,
            &human(APPROVER, "mallory"),
            "change_protected_path",
            L1,
            Some(REQUESTER),
            protected
        ),
        ActionVerdict::Denied(_)
    ));
    // Nor can one who is the requester of the change.
    assert_eq!(
        reason(&decide(
            &list,
            &human(SECURITY, "sam"),
            "change_protected_path",
            L1,
            Some(SECURITY),
            protected
        )),
        Some(ActionDenialReason::SelfApproval)
    );
}

// ---------------------------------------------------------------------------------------------
// Changes to the allowlist
// ---------------------------------------------------------------------------------------------

#[test]
fn a_change_that_adds_a_high_designation_needs_two_distinct_org_admins_and_never_the_beneficiary() {
    let list = allowlist();
    use AutonomyLevel::L1;
    let by = |id: u64, login: &str| {
        authorized(decide(
            &list,
            &human(id, login),
            "change_authority_allowlist",
            L1,
            None,
            LOW,
        ))
    };
    let (one, two) = (by(ORG_ONE, "gina"), by(ORG_TWO, "gus"));
    let widening = AllowlistChange {
        beneficiary: uid(APPROVER),
        adds_or_widens_high_designation: true,
    };
    let ordinary = AllowlistChange {
        adds_or_widens_high_designation: false,
        ..widening
    };
    let a = authority();
    assert_eq!(
        a.check_allowlist_change(&widening, std::slice::from_ref(&one)),
        Err(AllowlistChangeDenial::TooFewApprovers)
    );
    assert_eq!(
        a.check_allowlist_change(&widening, &[one.clone(), one.clone()]),
        Err(AllowlistChangeDenial::TooFewApprovers)
    );
    assert_eq!(
        a.check_allowlist_change(&widening, &[one.clone(), two.clone()]),
        Ok(())
    );
    assert_eq!(
        a.check_allowlist_change(&ordinary, std::slice::from_ref(&one)),
        Ok(())
    );
    // The person gaining authority cannot be one of the approvers.
    let self_grant = AllowlistChange {
        beneficiary: uid(ORG_ONE),
        ..widening
    };
    assert_eq!(
        a.check_allowlist_change(&self_grant, &[one.clone(), two]),
        Err(AllowlistChangeDenial::SelfGrant)
    );
    // An approval for another action is not an approval of this one.
    let other = authorized(decide(
        &list,
        &human(ORG_TWO, "gus"),
        "raise_budget_ceiling",
        L1,
        None,
        LOW,
    ));
    assert_eq!(
        a.check_allowlist_change(&widening, &[one, other]),
        Err(AllowlistChangeDenial::WrongAction)
    );
}

// ---------------------------------------------------------------------------------------------
// INV-07 and overrides
// ---------------------------------------------------------------------------------------------

fn override_with(
    actor: &Actor<'_>,
    request: &OverrideContext<'_>,
    list: &Allowlist,
) -> Result<bool, OverrideDenial> {
    let (tenant, now) = (tenant(), now());
    let ctx = ActionContext {
        action: "waive_failed_gate",
        level: AutonomyLevel::L1,
        tenant: &tenant,
        repository: REPO,
        actor,
        allowlist: list,
        now: &now,
        requester: Some(uid(REQUESTER)),
        change: LOW,
        require_designation: None,
        step_up_done: true,
    };
    authority().authorize_override(&ctx, request).map(|g| {
        assert!(g.residual_risk_accepted);
        g.creates_assurance_claim
    })
}

#[test]
fn nobody_overrides_a_dependency_review_that_waits_for_a_recorded_decision() {
    // The review of the supply chain gates, "How a person is asked", point 4. A new direct
    // dependency with no recorded decision makes
    // `dependency-review` BLOCKED with the code `policy_unresolvable`. An override would pass the
    // stage without a decision bound to a package, a version and a checksum, so the policy says
    // there is none: a person records the decision, and the stage is run again.
    let list = allowlist();
    let expiry = Timestamp::parse("2026-11-27T00:00:00Z").expect("time");
    let waiver = OverrideContext {
        gate: "dependency-review",
        block_code: "policy_unresolvable",
        block_is_security_class: true,
        gate_is_mandatory_of_active_profile: false,
        justification: "the package is fine, we looked at it together",
        owner: Some(uid(SECURITY)),
        expires_at: Some(&expiry),
    };
    // Nobody: not the security approver who can waive other gates, not the org admin.
    for actor in [
        human(SECURITY, "sam"),
        human(ORG_ONE, "gina"),
        human(APPROVER, "mallory"),
    ] {
        assert_eq!(
            override_with(&actor, &waiver, &list),
            Err(OverrideDenial::NoOverrideForBlock),
            "{}",
            actor.login
        );
    }
    assert!(!authority().block_may_be_overridden("dependency-review", "policy_unresolvable"));
    // The same gate with another code, and the same code on another gate, are not on the list:
    // the rule is the pair, and it is the only one the policy names.
    let tool_missing = OverrideContext {
        block_code: "tool_unavailable",
        ..waiver
    };
    assert_eq!(
        override_with(&human(SECURITY, "sam"), &tool_missing, &list),
        Ok(false)
    );
    let other_gate = OverrideContext {
        gate: "dependency-advisories",
        ..waiver
    };
    assert_eq!(
        override_with(&human(SECURITY, "sam"), &other_gate, &list),
        Ok(false)
    );
}

#[test]
fn override_and_dependency_rules_an_override_is_refused_for_the_gates_the_policy_protects() {
    let list = allowlist();
    let sam = human(SECURITY, "sam");
    let expiry = Timestamp::parse("2026-11-27T00:00:00Z").expect("time");
    let ok = OverrideContext {
        gate: "lint_gate",
        block_code: "tool_unavailable",
        block_is_security_class: true,
        gate_is_mandatory_of_active_profile: false,
        justification: "known false positive, tracked in the risk register",
        owner: Some(uid(SECURITY)),
        expires_at: Some(&expiry),
    };
    // The allowed case: risk accepted, never an assurance claim.
    assert_eq!(override_with(&sam, &ok, &list), Ok(false));
    // INV-07: a mandatory gate of an active domain profile.
    let mandatory = OverrideContext {
        gate_is_mandatory_of_active_profile: true,
        ..ok
    };
    assert_eq!(
        override_with(&sam, &mandatory, &list),
        Err(OverrideDenial::MandatoryGateOfActiveProfile)
    );
    // The gates that can never be waived.
    for gate in [
        "protected_path_check",
        "secret_scan",
        "sandbox_posture",
        "evidence_binding",
        "test_regression_check",
        "signature_verification",
        "stage_profile_check",
    ] {
        let request = OverrideContext { gate, ..ok };
        assert_eq!(
            override_with(&sam, &request, &list),
            Err(OverrideDenial::NonWaivableGate),
            "{gate}"
        );
        assert!(authority().is_nonwaivable_gate(gate));
    }
    // Record-keeping.
    for request in [
        OverrideContext {
            justification: "   ",
            ..ok
        },
        OverrideContext { owner: None, ..ok },
        OverrideContext {
            expires_at: None,
            ..ok
        },
    ] {
        assert!(matches!(
            override_with(&sam, &request, &list),
            Err(OverrideDenial::NoJustification | OverrideDenial::NoOwnerOrExpiry)
        ));
    }
    let past = Timestamp::parse("2026-10-01T00:00:00Z").expect("time");
    assert_eq!(
        override_with(
            &sam,
            &OverrideContext {
                expires_at: Some(&past),
                ..ok
            },
            &list
        ),
        Err(OverrideDenial::NoOwnerOrExpiry)
    );
    // Roles: an approver or an org admin is not a security approver, and a GitHub admin who is not
    // on the list is nobody.
    for actor in [human(APPROVER, "mallory"), human(ORG_ONE, "gina")] {
        assert!(matches!(
            override_with(&actor, &ok, &list),
            Err(OverrideDenial::Action(_))
        ));
    }
    let github_admin = Actor {
        github_permission: Some(GithubPermission::Admin),
        author_association: Some("OWNER"),
        ..human(2003, "sam")
    };
    assert!(matches!(
        override_with(&github_admin, &ok, &list),
        Err(OverrideDenial::Action(d)) if d.reason == ActionDenialReason::Authority(AuthorityDenial::NotOnAllowlist)
    ));
}

// ---- API-1: the narrowing of an allowlist entry, as one question -------------------------------

#[test]
fn an_entry_covers_the_repositories_it_lists_and_no_others() {
    let plain = entry(APPROVER, "mallory", &[Designation::Approver]);
    for repository in ["acme/repo", "acme/other", "anything/at-all"] {
        assert!(plain.covers_repository(repository), "{repository}");
    }
    let mut narrow = entry(OTHER_REPO_ONLY, "narrow", &[Designation::Approver]);
    narrow.repositories = Some(BTreeSet::from(["Acme/Other".to_owned()]));
    assert!(
        narrow.covers_repository("acme/other"),
        "case is not compared"
    );
    assert!(narrow.covers_repository("ACME/OTHER"));
    for not_listed in [
        "acme/repo",
        "acme/othe",
        "acme/other2",
        "acme/other/",
        " acme/other",
        "acme/other\n",
        "",
    ] {
        assert!(!narrow.covers_repository(not_listed), "{not_listed:?}");
    }
    // An empty list is a narrowing to nothing, not to everything.
    narrow.repositories = Some(BTreeSet::new());
    assert!(!narrow.covers_repository("acme/other"));
}

#[test]
fn the_policy_and_the_entry_agree_on_which_repository_a_designation_reaches() {
    let mut narrow = entry(OTHER_REPO_ONLY, "narrow", &[Designation::Approver]);
    narrow.repositories = Some(BTreeSet::from(["acme/other".to_owned()]));
    let list = Allowlist::new("sha256:narrow", vec![narrow.clone()]).expect("list");
    let now = Timestamp::parse("2026-10-27T12:00:00Z").expect("time");
    for repository in ["acme/repo", "acme/other", "ACME/Other"] {
        let reached = authority()
            .designations(
                &list,
                &tenant(),
                repository,
                &human(OTHER_REPO_ONLY, "narrow"),
                &now,
            )
            .is_ok();
        assert_eq!(
            reached,
            narrow.covers_repository(repository),
            "{repository}"
        );
    }
}
