//! The permissions a token carries, and the audit of the App's own permissions.
//!
//! `docs/security/secrets-and-credentials.md` section 3.3: the intake stage gets `issues` read-only
//! (LB-03), because it reads one issue and its events; an analysis stage gets `contents`, `issues`
//! and `pull_requests` read-only. The delivery stage gets `contents`,
//! `pull_requests` and `issues` write and `checks` write. The approval stage reads, and writes
//! `issues` only, so that it can post the one comment that acknowledges a decision (AUT-9). A token
//! for a stage never carries more than that stage needs. Every set also names `metadata: read`, which every GitHub App has.
//!
//! Section 3.1 and `policies/security.yaml` `credentials.github_app`: the App must hold the
//! required permissions and none of the forbidden ones, checked at onboarding and on every job
//! start ([`audit_app`]).

use std::collections::BTreeMap;

use factory_domain::policy::security::GithubApp;
use factory_domain::vocabulary::StageKind;

/// How much a permission allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Read.
    Read,
    /// Read and write.
    Write,
}

impl Level {
    /// The name GitHub uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Level::Read => "read",
            Level::Write => "write",
        }
    }

    /// Reads a level GitHub reports. `admin` is above `write` and is not a level this adapter ever
    /// asks for, so it reads as `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "read" => Some(Level::Read),
            "write" => Some(Level::Write),
            _ => None,
        }
    }
}

/// The permissions asked for in one token, by GitHub's repository permission names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSet(BTreeMap<&'static str, Level>);

impl PermissionSet {
    fn of(entries: &[(&'static str, Level)]) -> Self {
        Self(entries.iter().copied().collect())
    }

    /// The intake stage (LB-03): it reads one issue and the events of that issue, so it asks for
    /// `issues: read` and the `metadata: read` that every installation token carries, and for
    /// nothing else. It has no use for the contents of the repository or for pull requests. It is
    /// a class of its own, narrower than [`read_stage`](Self::read_stage), so that a change to
    /// the analysis stages cannot widen it.
    #[must_use]
    pub fn issue_reader() -> Self {
        Self::of(&[("metadata", Level::Read), ("issues", Level::Read)])
    }

    /// An analysis stage that reads the repository: read only.
    #[must_use]
    pub fn read_stage() -> Self {
        Self::of(&[
            ("metadata", Level::Read),
            ("contents", Level::Read),
            ("issues", Level::Read),
            ("pull_requests", Level::Read),
        ])
    }

    /// The delivery stage: it pushes a factory branch, opens a draft pull request, comments and
    /// publishes check runs.
    #[must_use]
    pub fn delivery_stage() -> Self {
        Self::of(&[
            ("metadata", Level::Read),
            ("contents", Level::Write),
            ("pull_requests", Level::Write),
            ("issues", Level::Write),
            ("checks", Level::Write),
        ])
    }

    /// The approval stage: it reads the pull request and the branches, and posts one comment that
    /// acknowledges a decision. A comment on a pull request is an issue comment, so the only write
    /// level it holds is `issues`. It cannot push, open a pull request or publish a check.
    #[must_use]
    pub fn approval_stage() -> Self {
        Self::of(&[
            ("metadata", Level::Read),
            ("contents", Level::Read),
            ("issues", Level::Write),
            ("pull_requests", Level::Read),
        ])
    }

    /// The credential handed to a comment: the right to write issues (a comment on a pull request
    /// is an issue comment) and the metadata, nothing else (SF-14). A stage that holds a wider set
    /// gives this one up for its comments. A stage that does not hold `issues: write` is not given
    /// it: it keeps its own permissions for the call, and the code host refuses the comment.
    #[must_use]
    pub fn comment() -> Self {
        Self::of(&[("metadata", Level::Read), ("issues", Level::Write)])
    }

    /// The credential of the status writer (ports v1.2, ADR 0017): `issues: write` and the
    /// `metadata: read` that every installation token carries, for one repository, and nothing
    /// else. It is minted for this purpose and independent of any stage: an intake or analysis
    /// token stays at `issues: read`, and the delivery token is not borrowed. Equal in content to
    /// [`comment`](Self::comment) today; a separate name, so that the purpose is stated and a
    /// change to one cannot widen the other.
    #[must_use]
    pub fn issue_status() -> Self {
        Self::of(&[("metadata", Level::Read), ("issues", Level::Write)])
    }

    /// True when the set holds the permission `name` at the level `level` or above.
    #[must_use]
    pub fn holds(&self, name: &str, level: Level) -> bool {
        self.0.get(name).is_some_and(|held| *held >= level)
    }

    /// The permissions of the token for a stage.
    #[must_use]
    pub fn for_stage(stage: StageKind) -> Self {
        match stage {
            StageKind::Intake => Self::issue_reader(),
            StageKind::Delivery => Self::delivery_stage(),
            StageKind::Approval => Self::approval_stage(),
            _ => Self::read_stage(),
        }
    }

    /// The credential handed to a fetch: contents read, nothing else.
    #[must_use]
    pub fn fetch() -> Self {
        Self::of(&[("metadata", Level::Read), ("contents", Level::Read)])
    }

    /// The credential handed to a push: contents write, nothing else.
    #[must_use]
    pub fn push() -> Self {
        Self::of(&[("metadata", Level::Read), ("contents", Level::Write)])
    }

    /// The `permissions` object of the token request.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.0
                .iter()
                .map(|(name, level)| {
                    (
                        (*name).to_owned(),
                        serde_json::Value::String(level.as_str().to_owned()),
                    )
                })
                .collect(),
        )
    }

    /// True when `granted` (the `permissions` object of the answer) holds nothing that this set
    /// did not ask for, and no level above the one asked for. A token that fails this is wider
    /// than the request and must not be used.
    #[must_use]
    pub fn contains_all_of(&self, granted: &BTreeMap<String, String>) -> bool {
        granted.iter().all(|(name, level)| {
            Level::parse(level)
                .zip(self.0.get(name.as_str()))
                .is_some_and(|(got, asked)| got <= *asked)
        })
    }

    /// The names and levels, for tests and for the audit trail.
    #[must_use]
    pub fn entries(&self) -> Vec<(&'static str, Level)> {
        self.0.iter().map(|(n, l)| (*n, *l)).collect()
    }
}

/// True when a stage may write to the repository: push a branch, open a pull request, publish a
/// check. Only the delivery stage may. The approval stage holds `issues: write` for its comment and
/// nothing else, so it is not a writer in this sense.
#[must_use]
pub const fn may_write(stage: StageKind) -> bool {
    matches!(stage, StageKind::Delivery)
}

/// What the policy says the App must and must not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPolicy {
    required: BTreeMap<String, Level>,
    forbidden: Vec<String>,
}

impl AppPolicy {
    /// From explicit lists.
    #[must_use]
    pub fn new(required: &[(&str, Level)], forbidden: &[&str]) -> Self {
        Self {
            required: required
                .iter()
                .map(|(n, l)| ((*n).to_owned(), *l))
                .collect(),
            forbidden: forbidden.iter().map(|n| (*n).to_owned()).collect(),
        }
    }

    /// From the typed `credentials.github_app` section of `policies/security.yaml`. A required
    /// permission with a level this adapter does not know is read as `write`, the stricter one.
    #[must_use]
    pub fn from_github_app(app: &GithubApp) -> Self {
        Self {
            required: app
                .permissions_required
                .iter()
                .map(|(name, level)| (name.clone(), Level::parse(level).unwrap_or(Level::Write)))
                .collect(),
            forbidden: app.permissions_forbidden.clone(),
        }
    }
}

/// The result of checking the App's permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppAudit {
    /// The App holds every required permission and none of the forbidden ones.
    Pass,
    /// The App holds a forbidden permission. Onboarding is refused and no token is minted.
    Refuse {
        /// The forbidden names the App holds.
        forbidden_held: Vec<String>,
    },
    /// The App lacks a required permission, or holds it at a lower level. The repository runs at
    /// level L0.
    CapAtL0 {
        /// The required names that are missing or too weak.
        missing: Vec<String>,
    },
}

/// Compares the permissions the App reports (`GET /app`, `permissions`) with the policy. A
/// forbidden permission outranks a missing one: it is the more serious finding.
#[must_use]
pub fn audit_app(policy: &AppPolicy, held: &BTreeMap<String, String>) -> AppAudit {
    let forbidden_held: Vec<String> = policy
        .forbidden
        .iter()
        .filter(|name| held.contains_key(name.as_str()))
        .cloned()
        .collect();
    if !forbidden_held.is_empty() {
        return AppAudit::Refuse { forbidden_held };
    }
    let missing: Vec<String> = policy
        .required
        .iter()
        .filter(|(name, need)| {
            // An unknown level (such as `admin`) is above `write`, so it satisfies any need.
            held.get(name.as_str())
                .is_none_or(|have| Level::parse(have).is_some_and(|got| got < **need))
        })
        .map(|(name, _)| name.clone())
        .collect();
    if missing.is_empty() {
        AppAudit::Pass
    } else {
        AppAudit::CapAtL0 { missing }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(n, l)| ((*n).to_owned(), (*l).to_owned()))
            .collect()
    }

    fn policy() -> AppPolicy {
        AppPolicy::new(
            &[
                ("metadata", Level::Read),
                ("contents", Level::Write),
                ("checks", Level::Write),
            ],
            &["administration", "workflows"],
        )
    }

    #[test]
    fn the_approval_stage_may_comment_and_do_nothing_else_that_writes() {
        let set = PermissionSet::approval_stage();
        let writes: Vec<&str> = set
            .entries()
            .into_iter()
            .filter(|(_, level)| *level == Level::Write)
            .map(|(name, _)| name)
            .collect();
        assert_eq!(writes, ["issues"]);
        assert!(!may_write(StageKind::Approval));
        assert_eq!(PermissionSet::for_stage(StageKind::Approval), set);
        // It reads what it needs to judge a decision, and has no check or contents write.
        assert!(set.entries().contains(&("pull_requests", Level::Read)));
        assert!(!set.entries().iter().any(|(name, _)| *name == "checks"));
    }

    #[test]
    fn a_comment_holds_the_right_to_write_issues_and_the_metadata_and_nothing_else() {
        let set = PermissionSet::comment();
        assert_eq!(
            set.entries(),
            [("issues", Level::Write), ("metadata", Level::Read)]
        );
        // It is narrower than what either stage that comments holds, and is held by both.
        for stage in [StageKind::Approval, StageKind::Delivery] {
            let own = PermissionSet::for_stage(stage);
            assert!(own.holds("issues", Level::Write), "{stage:?}");
            assert!(
                set.entries()
                    .iter()
                    .all(|(name, level)| own.holds(name, *level)),
                "{stage:?}"
            );
        }
        // A stage that does not hold the right does not get it for a comment.
        assert!(!PermissionSet::read_stage().holds("issues", Level::Write));
    }

    #[test]
    fn the_intake_stage_asks_for_issues_read_and_metadata_read_and_nothing_else() {
        // LB-03: intake reads one issue and its events. It gets no contents and no pull requests.
        let set = PermissionSet::for_stage(StageKind::Intake);
        assert_eq!(
            set.entries(),
            [("issues", Level::Read), ("metadata", Level::Read)]
        );
        assert_eq!(set, PermissionSet::issue_reader());
        assert!(!set.holds("contents", Level::Read));
        assert!(!set.holds("pull_requests", Level::Read));
        assert!(!set.holds("issues", Level::Write));
    }

    #[test]
    fn the_narrow_class_is_for_intake_alone_and_the_other_stages_keep_theirs() {
        // Every stage that reads more than issues keeps the class it had.
        for stage in StageKind::ALL.iter().copied() {
            let expected = match stage {
                StageKind::Intake => PermissionSet::issue_reader(),
                StageKind::Delivery => PermissionSet::delivery_stage(),
                StageKind::Approval => PermissionSet::approval_stage(),
                _ => PermissionSet::read_stage(),
            };
            assert_eq!(PermissionSet::for_stage(stage), expected, "{stage:?}");
        }
        // The narrow class is inside the wider read class, never the reverse.
        let narrow = PermissionSet::issue_reader();
        let wide = PermissionSet::read_stage();
        assert!(
            narrow
                .entries()
                .iter()
                .all(|(name, level)| wide.holds(name, *level))
        );
        assert!(narrow.entries().len() < wide.entries().len());
    }

    #[test]
    fn a_grant_wider_than_the_narrow_class_is_not_accepted_as_that_class() {
        // A server that answers with a wider token than the request asked for is refused, so a
        // caller cannot widen the class by naming a permission in the answer.
        let asked = PermissionSet::issue_reader();
        assert!(asked.contains_all_of(&map(&[("issues", "read"), ("metadata", "read")])));
        assert!(!asked.contains_all_of(&map(&[("issues", "write")])));
        assert!(!asked.contains_all_of(&map(&[("contents", "read")])));
        assert!(!asked.contains_all_of(&map(&[("pull_requests", "read")])));
    }

    #[test]
    fn only_the_delivery_stage_can_write() {
        for stage in [
            StageKind::RepositoryIntelligence,
            StageKind::Specification,
            StageKind::Implementation,
            StageKind::Validation,
            StageKind::Review,
            StageKind::Merge,
        ] {
            assert!(!may_write(stage), "{stage:?}");
            assert_eq!(PermissionSet::for_stage(stage), PermissionSet::read_stage());
        }
        assert!(may_write(StageKind::Delivery));
        assert_eq!(
            PermissionSet::for_stage(StageKind::Delivery),
            PermissionSet::delivery_stage()
        );
    }

    #[test]
    fn a_read_stage_set_has_no_write_level_and_no_checks() {
        let set = PermissionSet::read_stage();
        assert!(set.entries().iter().all(|(_, level)| *level == Level::Read));
        assert!(!set.entries().iter().any(|(name, _)| *name == "checks"));
    }

    #[test]
    fn no_set_asks_for_a_forbidden_permission_or_for_statuses() {
        for set in [
            PermissionSet::issue_reader(),
            PermissionSet::read_stage(),
            PermissionSet::delivery_stage(),
            PermissionSet::approval_stage(),
            PermissionSet::comment(),
            PermissionSet::fetch(),
            PermissionSet::push(),
        ] {
            for (name, _) in set.entries() {
                assert!(
                    ![
                        "administration",
                        "workflows",
                        "statuses",
                        "secrets",
                        "members"
                    ]
                    .contains(&name),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_grant_is_checked_name_by_name_and_level_by_level() {
        let asked = PermissionSet::read_stage();
        assert!(asked.contains_all_of(&map(&[("contents", "read"), ("metadata", "read")])));
        assert!(asked.contains_all_of(&map(&[])));
        assert!(
            !asked.contains_all_of(&map(&[("contents", "write")])),
            "a higher level"
        );
        assert!(
            !asked.contains_all_of(&map(&[("checks", "read")])),
            "a name not asked for"
        );
        assert!(
            !asked.contains_all_of(&map(&[("contents", "admin")])),
            "an unknown level"
        );
    }

    #[test]
    fn the_audit_refuses_a_forbidden_permission_at_any_level() {
        let held = map(&[
            ("metadata", "read"),
            ("contents", "write"),
            ("checks", "write"),
            ("workflows", "read"),
        ]);
        assert_eq!(
            audit_app(&policy(), &held),
            AppAudit::Refuse {
                forbidden_held: vec!["workflows".to_owned()]
            }
        );
    }

    #[test]
    fn the_audit_caps_an_app_that_lacks_or_weakens_a_required_permission() {
        let held = map(&[("metadata", "read"), ("contents", "read")]);
        assert_eq!(
            audit_app(&policy(), &held),
            AppAudit::CapAtL0 {
                missing: vec!["checks".to_owned(), "contents".to_owned()]
            }
        );
    }

    #[test]
    fn a_forbidden_permission_outranks_a_missing_one() {
        let held = map(&[("administration", "write")]);
        assert!(matches!(
            audit_app(&policy(), &held),
            AppAudit::Refuse { .. }
        ));
    }

    #[test]
    fn an_app_with_exactly_the_required_permissions_passes() {
        let held = map(&[
            ("metadata", "read"),
            ("contents", "write"),
            ("checks", "write"),
        ]);
        assert_eq!(audit_app(&policy(), &held), AppAudit::Pass);
    }
}
