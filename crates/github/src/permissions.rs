//! The permissions a token carries, and the audit of the App's own permissions.
//!
//! `docs/security/secrets-and-credentials.md` section 3.3: an intake or analysis stage gets
//! `contents`, `issues` and `pull_requests` read-only. The delivery stage gets `contents`,
//! `pull_requests` and `issues` write and `checks` write. A token for a stage never carries more
//! than that stage needs. Every set also names `metadata: read`, which every GitHub App has.
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

    /// An intake or analysis stage: read only.
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

    /// The permissions of the token for a stage.
    #[must_use]
    pub fn for_stage(stage: StageKind) -> Self {
        if may_write(stage) {
            Self::delivery_stage()
        } else {
            Self::read_stage()
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

/// True when a stage may write to the repository. Only the delivery stage may.
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
    fn only_the_delivery_stage_can_write() {
        for stage in [
            StageKind::Intake,
            StageKind::RepositoryIntelligence,
            StageKind::Specification,
            StageKind::Implementation,
            StageKind::Validation,
            StageKind::Review,
            StageKind::Approval,
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
            PermissionSet::read_stage(),
            PermissionSet::delivery_stage(),
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
