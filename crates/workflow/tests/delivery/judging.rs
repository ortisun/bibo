//! The rules of a decision, tried without an engine: the pure judgement against the real policy.

use std::collections::BTreeSet;

use factory_domain::ids::{CausationId, JobId, StageRunId, TenantId};
use factory_domain::policy::authority::{
    ActionDenialReason, ActorKind, Allowlist, AllowlistEntry, AuthorityDenial, AutonomyLevel,
};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::values::{GitSha, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::githost::{
    ActorLogin, Comment, CommentRef, CommentTarget, GithubActor, PullRequestRef,
};
use factory_ports::paths::RepoRef;
use factory_ports::store::ApprovalChannel;
use factory_workflow::stages::approval::request::VALID_HOURS;
use factory_workflow::stages::approval::{
    ApprovalCommand, ApprovalRequest, CommentEvidence, Context, Live, NotACommand, Refusal, Seen,
    Sender, Verb, judge,
};
use factory_workflow::stages::validation::Binding;

const SECURITY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");

pub const REQUESTER: u64 = 1001;
pub const APPROVER: u64 = 2001;
pub const SECOND_APPROVER: u64 = 2002;
pub const SECURITY_APPROVER: u64 = 2003;
pub const OPERATOR: u64 = 2004;
pub const REQUESTER_ONLY: u64 = 2005;
pub const OUTSIDER: u64 = 3001;

pub fn policy() -> PolicyEngine {
    let security: SecurityPolicy = serde_json::from_str(SECURITY).expect("security policy");
    let approval: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("approval policy");
    PolicyEngine::new(&security, &approval).expect("a policy engine")
}

pub fn sha(c: char) -> GitSha {
    GitSha::parse(&c.to_string().repeat(40)).expect("a sha")
}

pub fn allowlist(tenant: TenantId) -> Allowlist {
    let entry = |id: u64, designations: &[Designation]| AllowlistEntry {
        tenant,
        github_user_id: GithubUserId::new(id).expect("an id"),
        login: format!("user-{id}"),
        designations: designations.iter().copied().collect::<BTreeSet<_>>(),
        repositories: None,
        expires_at: None,
    };
    Allowlist::new(
        "allowlist-version-one",
        vec![
            entry(REQUESTER, &[Designation::Requester, Designation::Approver]),
            entry(APPROVER, &[Designation::Approver]),
            entry(SECOND_APPROVER, &[Designation::Approver]),
            entry(SECURITY_APPROVER, &[Designation::SecurityApprover]),
            entry(OPERATOR, &[Designation::Operator]),
            entry(REQUESTER_ONLY, &[Designation::Requester]),
        ],
    )
    .expect("an allowlist")
}

pub fn request(created: &str) -> ApprovalRequest {
    ApprovalRequest {
        repository: "example-org/word-count".to_owned(),
        pull_request: 7,
        head_branch: "factory/job-1".to_owned(),
        base_branch: "main".to_owned(),
        pr_head: sha('a'),
        tree: sha('b'),
        base: sha('c'),
        manifest: Sha256Digest::of(b"manifest"),
        spec_version: 1,
        gates_clear: true,
        open_translation_warnings: 0,
        tier: RiskTier::Low,
        protected_path_change: false,
        sensitive_file_change: false,
        new_dependency: false,
        requester: REQUESTER,
        evidence_binding: Binding {
            implementation_result: Sha256Digest::of(b"result"),
            base_commit: sha('c'),
            head_commit: sha('a'),
            policy_hash: Sha256Digest::of(b"policy"),
            image_digest: Sha256Digest::of(b"image"),
            definition_hash: Sha256Digest::of(b"definitions"),
        },
        created_at: Timestamp::parse(created).expect("a time"),
    }
}

pub fn ledger_head() -> Sha256Digest {
    Sha256Digest::of(b"ledger head")
}

pub fn command(verb: Verb, sender: u64, request: &ApprovalRequest) -> ApprovalCommand {
    ApprovalCommand {
        id: CausationId::from_uuid(uuid::Uuid::from_u128(0xC0DE)),
        tenant: TenantId::from_uuid(uuid::Uuid::from_u128(1)),
        job: JobId::from_uuid(uuid::Uuid::from_u128(2)),
        stage_run: StageRunId::from_uuid(uuid::Uuid::from_u128(3)),
        verb,
        sender: Sender {
            id: sender,
            login: ActorLogin::new("someone").expect("a login"),
            kind: ActorKind::User,
        },
        channel: ApprovalChannel::Dashboard,
        reason: "The change does what the specification says.".to_owned(),
        seen: Some(request.seen_with(ledger_head())),
        warnings_decided: true,
        rework_target: Some(StageKind::Implementation),
        comment: None,
    }
}

/// Everything a judgement reads, owned so that a test can change one part.
pub struct Setup {
    pub policy: PolicyEngine,
    pub allowlist: Allowlist,
    pub tenant: TenantId,
    pub request: ApprovalRequest,
    pub now: Timestamp,
    pub open: bool,
    pub draft: bool,
    pub head: GitSha,
    pub pr_base: String,
    pub tree: GitSha,
    pub base: GitSha,
    pub ledger: Sha256Digest,
    pub drift: Vec<&'static str>,
    pub level: AutonomyLevel,
    pub comment: Option<Comment>,
}

impl Setup {
    pub fn new() -> Self {
        let request = request("2026-10-27T10:00:00Z");
        let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(1));
        Self {
            policy: policy(),
            allowlist: allowlist(tenant),
            tenant,
            head: request.pr_head.clone(),
            pr_base: request.base_branch.clone(),
            tree: request.tree.clone(),
            base: request.base.clone(),
            request,
            now: Timestamp::parse("2026-10-27T11:00:00Z").expect("a time"),
            open: true,
            draft: true,
            ledger: ledger_head(),
            drift: Vec::new(),
            level: AutonomyLevel::L1,
            comment: None,
        }
    }

    pub fn judge(&self, cmd: &ApprovalCommand) -> Result<(), Refusal> {
        judge(
            cmd,
            &Context {
                request: &self.request,
                live: Live {
                    now: self.now,
                    pr_open: self.open,
                    pr_draft: self.draft,
                    pr_head: &self.head,
                    pr_base: &self.pr_base,
                    tree: Some(&self.tree),
                    base_tip: &self.base,
                    ledger_head: &self.ledger,
                    drift: &self.drift,
                },
                policy: &self.policy,
                allowlist: &self.allowlist,
                level: self.level,
                tenant: &self.tenant,
                comment: self.comment.as_ref(),
            },
        )
        .map(|_| ())
    }
}

#[test]
fn an_authorized_approval_of_what_the_person_saw_is_accepted() {
    let setup = Setup::new();
    let cmd = command(Verb::Approve, APPROVER, &setup.request);
    assert_eq!(setup.judge(&cmd), Ok(()));
}

#[test]
fn negative_nt_authz_02_a_sender_who_may_not_decide_is_refused_without_a_reply() {
    // A reader and an outsider (never on the list), a person on the requester list who does not
    // hold the approver designation, and a user who is not on the list although they might be an
    // owner of the repository: the policy reads the list by numeric id and nothing else.
    for sender in [OUTSIDER, REQUESTER_ONLY, 0, u64::MAX] {
        let setup = Setup::new();
        let cmd = command(Verb::Approve, sender, &setup.request);
        let refusal = setup.judge(&cmd).expect_err("refused");
        assert!(
            matches!(refusal, Refusal::Unauthorized(_)),
            "{sender}: {refusal:?}"
        );
        assert!(!refusal.may_reply(), "{sender}: no oracle for outsiders");
    }
    // A person removed from the allowlist (the revoked case) loses the right at once.
    let mut setup = Setup::new();
    setup.allowlist = Allowlist::new("allowlist-version-two", Vec::new()).expect("empty");
    let refusal = setup
        .judge(&command(Verb::Approve, APPROVER, &setup.request))
        .expect_err("refused");
    assert_eq!(
        refusal,
        Refusal::Unauthorized(ActionDenialReason::Authority(
            AuthorityDenial::NotOnAllowlist
        ))
    );
    // The same login with another numeric id is another person.
    let setup = Setup::new();
    let mut cmd = command(Verb::Approve, OUTSIDER, &setup.request);
    cmd.sender.login = ActorLogin::new("user-2001").expect("a login");
    assert!(matches!(setup.judge(&cmd), Err(Refusal::Unauthorized(_))));
}

#[test]
fn negative_nt_mrg_06_a_bot_an_app_and_the_requester_on_a_risky_change_do_not_count() {
    for kind in [ActorKind::Bot, ActorKind::App] {
        let setup = Setup::new();
        // Even an id that the allowlist names as an approver is refused when the account is a bot.
        let mut cmd = command(Verb::Approve, APPROVER, &setup.request);
        cmd.sender.kind = kind;
        let refusal = setup.judge(&cmd).expect_err("refused");
        assert_eq!(refusal.code(), "ineligible_approver", "{kind:?}");
    }
    // The requester approves their own high-risk change.
    let mut setup = Setup::new();
    setup.request.tier = RiskTier::High;
    let cmd = command(Verb::Approve, REQUESTER, &setup.request);
    let refusal = setup.judge(&cmd).expect_err("refused");
    assert_eq!(
        refusal,
        Refusal::Unauthorized(ActionDenialReason::SelfApproval)
    );
    assert_eq!(refusal.code(), "ineligible_approver");
    // A protected path, a sensitive file and a new dependency each trigger separation too.
    for set in [
        (|r: &mut ApprovalRequest| r.protected_path_change = true) as fn(&mut ApprovalRequest),
        |r| r.sensitive_file_change = true,
        |r| r.new_dependency = true,
    ] {
        let mut setup = Setup::new();
        set(&mut setup.request);
        let cmd = command(Verb::Approve, REQUESTER, &setup.request);
        assert!(matches!(
            setup.judge(&cmd),
            Err(Refusal::Unauthorized(ActionDenialReason::SelfApproval))
        ));
    }
}

#[test]
fn a_low_risk_change_may_be_approved_by_the_requester_where_the_policy_allows_it() {
    // `approver_may_equal_requester_when_low_risk: true`. The engine refuses it anyway
    // (see the notes of the package): this test pins what the policy says.
    let setup = Setup::new();
    let cmd = command(Verb::Approve, REQUESTER, &setup.request);
    assert_eq!(setup.judge(&cmd), Ok(()));
}

#[test]
fn stale_digest_is_rejected() {
    // The person looked at the evidence when its ledger ended at one entry, and a gate result
    // arrived after that.
    let mut setup = Setup::new();
    setup.ledger = Sha256Digest::of(b"a later entry");
    let cmd = command(Verb::Approve, APPROVER, &setup.request);
    assert_eq!(setup.judge(&cmd), Err(Refusal::EvidenceMoved));
}

#[test]
fn an_approval_that_names_nothing_the_person_saw_is_refused() {
    let setup = Setup::new();
    let mut cmd = command(Verb::Approve, APPROVER, &setup.request);
    cmd.seen = None;
    assert_eq!(setup.judge(&cmd), Err(Refusal::NotBound));
}

#[test]
fn each_part_of_the_binding_must_be_the_one_in_the_request() {
    type Change = fn(&mut Seen);
    let parts: [(&str, Change); 5] = [
        ("pr_head", |s| s.pr_head = sha('1')),
        ("tree", |s| s.tree = sha('2')),
        ("base", |s| s.base = sha('3')),
        ("manifest", |s| s.manifest = Sha256Digest::of(b"another")),
        ("spec_version", |s| s.spec_version = 2),
    ];
    for (part, change) in parts {
        let setup = Setup::new();
        let mut cmd = command(Verb::Approve, APPROVER, &setup.request);
        change(cmd.seen.as_mut().expect("seen"));
        assert_eq!(
            setup.judge(&cmd),
            Err(Refusal::StaleBinding(part)),
            "{part}"
        );
    }
}

#[test]
fn the_world_moving_after_the_person_looked_refuses_the_approval() {
    let mut setup = Setup::new();
    let cmd = command(Verb::Approve, APPROVER, &setup.request);
    setup.head = sha('9');
    assert_eq!(setup.judge(&cmd), Err(Refusal::HeadMoved));
    let mut setup = Setup::new();
    setup.base = sha('9');
    assert_eq!(setup.judge(&cmd), Err(Refusal::BaseMoved));
    let mut setup = Setup::new();
    setup.pr_base = "release".to_owned();
    assert_eq!(setup.judge(&cmd), Err(Refusal::BaseRetargeted));
    let mut setup = Setup::new();
    setup.tree = sha('9');
    assert_eq!(setup.judge(&cmd), Err(Refusal::TreeChanged));
    let mut setup = Setup::new();
    setup.drift = vec!["policy_hash"];
    assert_eq!(
        setup.judge(&cmd),
        Err(Refusal::EvidenceDrift(vec!["policy_hash"]))
    );
}

#[test]
fn an_approval_expires_after_seventy_two_hours() {
    let cmd_for = |setup: &Setup| command(Verb::Approve, APPROVER, &setup.request);
    assert_eq!(VALID_HOURS, 72);
    let mut setup = Setup::new();
    // One second before the end.
    setup.now = Timestamp::parse("2026-10-30T09:59:59Z").expect("a time");
    assert_eq!(setup.judge(&cmd_for(&setup)), Ok(()));
    // At the end, and after it.
    for at in ["2026-10-30T10:00:00Z", "2026-11-05T10:00:00Z"] {
        setup.now = Timestamp::parse(at).expect("a time");
        assert_eq!(setup.judge(&cmd_for(&setup)), Err(Refusal::Expired), "{at}");
    }
}

#[test]
fn the_pull_request_must_be_an_open_draft() {
    let mut setup = Setup::new();
    setup.open = false;
    assert_eq!(
        setup.judge(&command(Verb::Approve, APPROVER, &setup.request)),
        Err(Refusal::NotOpen)
    );
    let mut setup = Setup::new();
    setup.draft = false;
    assert_eq!(
        setup.judge(&command(Verb::Approve, APPROVER, &setup.request)),
        Err(Refusal::NotDraft)
    );
}

#[test]
fn negative_nt_mrg_01_a_gate_that_is_not_clear_refuses_the_approval() {
    let mut setup = Setup::new();
    setup.request.gates_clear = false;
    assert_eq!(
        setup.judge(&command(Verb::Approve, APPROVER, &setup.request)),
        Err(Refusal::GatesNotClear)
    );
}

#[test]
fn translation_warnings_need_a_decision() {
    let mut setup = Setup::new();
    setup.request.open_translation_warnings = 2;
    let mut cmd = command(Verb::Approve, APPROVER, &setup.request);
    cmd.warnings_decided = false;
    assert_eq!(
        setup.judge(&cmd),
        Err(Refusal::TranslationWarningsUndecided)
    );
    cmd.warnings_decided = true;
    assert_eq!(setup.judge(&cmd), Ok(()));
    // No warning: the flag does not matter.
    let setup = Setup::new();
    let mut cmd = command(Verb::Approve, APPROVER, &setup.request);
    cmd.warnings_decided = false;
    assert_eq!(setup.judge(&cmd), Ok(()));
}

fn comment(author: u64, body: &str, edited: bool) -> (Comment, CommentEvidence) {
    let reference = CommentRef {
        target: CommentTarget::PullRequest(PullRequestRef {
            repo: RepoRef::parse("example-org/word-count").expect("a repo"),
            number: 7,
        }),
        id: 55,
    };
    let at = Timestamp::parse("2026-10-27T10:30:00Z").expect("a time");
    (
        Comment {
            reference: reference.clone(),
            author: GithubActor {
                id: author,
                login: ActorLogin::new("someone").expect("a login"),
            },
            body: body.to_owned(),
            created_at: at,
            edited_at: edited.then_some(at),
        },
        CommentEvidence {
            comment: reference,
            body_sha256: Sha256Digest::of(body.as_bytes()),
        },
    )
}

#[test]
fn a_command_comment_must_be_the_one_the_parser_read() {
    let body = "/factory approve";
    let ok = |setup: &mut Setup, live: Comment, evidence: CommentEvidence| {
        setup.comment = Some(live);
        let mut cmd = command(Verb::Approve, APPROVER, &setup.request);
        cmd.channel = ApprovalChannel::GithubComment;
        cmd.comment = Some(evidence);
        setup.judge(&cmd)
    };
    let mut setup = Setup::new();
    let (live, evidence) = comment(APPROVER, body, false);
    assert_eq!(ok(&mut setup, live, evidence), Ok(()));

    // Edited after the command was read.
    let (live, evidence) = comment(APPROVER, body, true);
    assert_eq!(
        ok(&mut setup, live, evidence),
        Err(Refusal::NotACommand(NotACommand::CommentEdited))
    );
    // The body changed (the parser read another text).
    let (mut live, evidence) = comment(APPROVER, body, false);
    live.body = "/factory approve now".to_owned();
    assert_eq!(
        ok(&mut setup, live, evidence),
        Err(Refusal::NotACommand(NotACommand::CommentChanged))
    );
    // Someone else wrote it.
    let (live, evidence) = comment(OUTSIDER, body, false);
    assert_eq!(
        ok(&mut setup, live, evidence),
        Err(Refusal::NotACommand(NotACommand::CommentAuthor))
    );
    // Another comment.
    let (mut live, evidence) = comment(APPROVER, body, false);
    live.reference.id = 56;
    assert_eq!(
        ok(&mut setup, live, evidence),
        Err(Refusal::NotACommand(NotACommand::CommentOther))
    );
    // No comment at all.
    setup.comment = None;
    let mut cmd = command(Verb::Approve, APPROVER, &setup.request);
    cmd.channel = ApprovalChannel::GithubComment;
    assert_eq!(
        setup.judge(&cmd),
        Err(Refusal::NotACommand(NotACommand::CommentMissing))
    );
    assert!(!Refusal::NotACommand(NotACommand::CommentEdited).may_reply());
}

#[test]
fn the_other_verbs_need_their_own_authority_and_inputs() {
    let setup = Setup::new();
    // An operator may pause, resume and cancel and may not approve or reject.
    for verb in [Verb::Pause, Verb::Resume, Verb::Cancel] {
        assert_eq!(
            setup.judge(&command(verb, OPERATOR, &setup.request)),
            Ok(()),
            "{verb:?}"
        );
        assert!(matches!(
            setup.judge(&command(verb, OUTSIDER, &setup.request)),
            Err(Refusal::Unauthorized(_))
        ));
    }
    for verb in [Verb::Approve, Verb::Reject, Verb::Rework] {
        assert!(matches!(
            setup.judge(&command(verb, OPERATOR, &setup.request)),
            Err(Refusal::Unauthorized(
                ActionDenialReason::MissingDesignation { .. }
            ))
        ));
    }
    // Reject needs a reason and rework needs a target.
    let mut cmd = command(Verb::Reject, APPROVER, &setup.request);
    cmd.reason = "  ".to_owned();
    assert_eq!(setup.judge(&cmd), Err(Refusal::MissingReason));
    let mut cmd = command(Verb::Rework, APPROVER, &setup.request);
    cmd.rework_target = None;
    assert_eq!(setup.judge(&cmd), Err(Refusal::MissingTarget));
    // A reject and a rework do not need the binding.
    let mut cmd = command(Verb::Reject, APPROVER, &setup.request);
    cmd.seen = None;
    assert_eq!(setup.judge(&cmd), Ok(()));
}

#[test]
fn a_level_that_forbids_the_action_refuses_it() {
    // At L0 the factory only observes: a human decision on a pull request is not an input.
    let mut setup = Setup::new();
    setup.level = AutonomyLevel::L0;
    assert!(matches!(
        setup.judge(&command(Verb::Approve, APPROVER, &setup.request)),
        Err(Refusal::Unauthorized(_))
    ));
}

#[test]
fn negative_nt_mrg_05_there_is_no_verb_for_merge_deploy_or_ready() {
    use factory_workflow::stages::approval::{VerbParse, parse_verb};
    for word in [
        "merge",
        "deploy",
        "ready",
        "undraft",
        "release",
        "auto-merge",
    ] {
        assert_eq!(parse_verb(word), VerbParse::Unknown, "{word}");
    }
    let policy = policy();
    // Level L3 is off, so auto-merge cannot be reached by any setting.
    assert!(!policy.authority.level_enabled(AutonomyLevel::L3));
    assert_eq!(
        policy.authority.effective_level(AutonomyLevel::L3, true),
        AutonomyLevel::L2
    );
    // Merging and marking ready always need a human at L1 and L2, and L0 forbids them.
    let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(1));
    let list = allowlist(tenant);
    let now = Timestamp::parse("2026-10-27T11:00:00Z").expect("a time");
    for action in ["merge_pr", "mark_pr_ready"] {
        for level in [AutonomyLevel::L0, AutonomyLevel::L3] {
            let actor = factory_domain::policy::authority::Actor {
                github_user_id: GithubUserId::new(APPROVER).expect("an id"),
                login: "user",
                kind: ActorKind::User,
                github_permission: None,
                author_association: None,
            };
            let verdict = policy.authority.authorize_action(
                &factory_domain::policy::authority::ActionContext {
                    action,
                    level,
                    tenant: &tenant,
                    repository: "example-org/word-count",
                    actor: &actor,
                    allowlist: &list,
                    now: &now,
                    requester: GithubUserId::new(REQUESTER),
                    change: factory_domain::policy::authority::ChangeFacts {
                        risk_tier: RiskTier::Low,
                        protected_path_change: false,
                        sensitive_file_change: false,
                        new_dependency: false,
                    },
                    require_designation: None,
                    step_up_done: false,
                },
            );
            assert!(
                matches!(
                    verdict,
                    factory_domain::policy::authority::ActionVerdict::Denied(_)
                ),
                "{action} at {level:?}: {verdict:?}"
            );
        }
    }
}
