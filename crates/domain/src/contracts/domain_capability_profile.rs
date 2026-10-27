//! `schemas/domain-capability-profile.schema.json`: what a kind of software needs.
//!
//! A profile states requirements. It does not claim that any tool exists. Every declared tool
//! has to be probed before the profile can be active, and a mandatory gate whose tool is missing
//! blocks promotion instead of becoming a warning. New domains are added by adding profile files.

use serde::{Deserialize, Serialize};

use super::common::SchemaVersion;
use super::{Violations, contract};
use crate::macros::string_enum;
use crate::values::{
    HumanText, HumanTitle, Integer, NonEmptyString, NonEmptyVec, PositiveInt, Slug, Timestamp,
    UniqueVec,
};

string_enum! {
    /// Where a profile stands. Only an active profile may drive a production job.
    pub enum ProfileStatus("profile status") {
        /// Being written. The default when the field is missing.
        Draft = "draft",
        /// Reviewed, tools not yet probed.
        Reviewed = "reviewed",
        /// Reviewed and probed. May drive a production job.
        Active = "active",
    }
}

/// A command that proves a tool is present.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolProbe {
    /// A name from `required_tools`.
    pub tool: Slug,
    /// The executable and its arguments, for example the tool and `--version`.
    pub argv: NonEmptyVec<String>,
    /// The exit code that means present. 0 when missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_exit_code: Option<Integer>,
    /// A pattern the version output must match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_regex: Option<NonEmptyString>,
}

/// Who reviewed the profile and when. Profiles are reviewed and tested like production code.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileReview {
    /// The reviewer.
    pub reviewed_by: Slug,
    /// When.
    pub reviewed_at: Timestamp,
}

contract! {
    "domain-capability-profile";
    /// A versioned description of what a kind of software needs.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
    pub struct DomainCapabilityProfile {
        /// Optional. A missing value means 1.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub schema_version: Option<SchemaVersion>,
        /// The profile.
        pub id: Slug,
        /// Its version.
        pub version: PositiveInt,
        /// A plain-English title.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub title: Option<HumanTitle>,
        /// What the profile is for.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<HumanText>,
        /// A missing value means draft.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub status: Option<ProfileStatus>,
        /// Domain tags this profile applies to. A job may match several profiles.
        pub matches: UniqueVec<Slug, 1>,
        /// Skills the work needs.
        pub required_skills: UniqueVec<Slug>,
        /// Skills that help.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub optional_skills: Option<UniqueVec<Slug>>,
        /// Tools the work needs.
        pub required_tools: UniqueVec<Slug>,
        /// Evidence the work must leave behind.
        pub required_evidence: UniqueVec<Slug>,
        /// Gates that must pass. If one cannot run, promotion is blocked.
        pub mandatory_gates: UniqueVec<Slug, 1>,
        /// Gates that run when they apply.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub conditional_gates: Option<UniqueVec<Slug>>,
        /// Actions that always need a human, such as placing live orders. May be empty.
        pub forbidden_autonomous_actions: UniqueVec<Slug>,
        /// The approval policy, by name.
        pub approval_policy: Slug,
        /// How each tool is probed. Required for an active profile.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tool_probes: Option<Vec<ToolProbe>>,
        /// The review. Required for an active profile.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub review: Option<ProfileReview>,
    }
}

impl DomainCapabilityProfile {
    /// The status, with a missing value read as draft.
    #[must_use]
    pub fn effective_status(&self) -> ProfileStatus {
        self.status.unwrap_or(ProfileStatus::Draft)
    }

    fn check(&self, found: &mut Violations) {
        if self.status == Some(ProfileStatus::Active) {
            found.require(
                self.review.is_some(),
                "review",
                "an active profile must record who reviewed it and when",
            );
            found.require(
                self.tool_probes.is_some(),
                "tool_probes",
                "an active profile must say how each of its tools is probed",
            );
        }
    }
}
