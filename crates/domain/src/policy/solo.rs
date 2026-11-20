//! The solo mode (ADR 0022): when the person who asked for a job may approve it alone.
//!
//! "Nobody approves their own request" holds everywhere except where one person is the only one
//! who can approve. The exception is a fact, the **solo fact**, and [`AuthorityPolicy::solo_fact`]
//! is the one function that computes it, from conditions 1 and 2 below. Conditions 3 and 4 are
//! applied by [`AuthorityPolicy::authorize_action`], which grants the exception only to the
//! requester and only for the designation the action needs:
//!
//! 1. the repository is marked `single_maintainer`;
//! 2. exactly one active person of the tenant holds an approving designation (`approver` or
//!    `security_approver`) in the repository's scope;
//! 3. the approver is the requester of the job;
//! 4. that person holds the designation the action needs (a `security_approver` at the critical
//!    tier, for build code and for a package younger than the minimum age).
//!
//! The policy switch `solo_mode.enabled` gates the whole: with it off the fact never holds.
//!
//! The exception covers the approval actions of [`SOLO_ACTIONS`] only. `reject`, `rework`,
//! `pause`, `resume`, `cancel` and the waiver of a gate keep the rule they always had.
//!
//! # Wait and phrase
//!
//! For the riskier decisions the solo approver must wait a minimum time after the stage run asked
//! and must type a confirmation phrase naming what they approve. The waits are whole minutes in
//! the policy, from [`MIN_WAIT_MINUTES`] to [`MAX_WAIT_MINUTES`]; a wait passes when the time from
//! the milestone to the request is at least the wait, so a request exactly one wait after the
//! milestone passes. A missing milestone refuses: the wait cannot be shown to have passed.
//!
//! The phrase is compared as a [`ConfirmationWord`], 16 hex digits of the SHA-256 of the phrase
//! after an ASCII-only normalization, so that the signed request carries one word and never the
//! text.

use std::fmt;
use std::time::Duration;

use super::approval::SoloMode;
use super::authority::AuthorityPolicy;
use crate::ids::JobId;
use crate::values::{Sha256Digest, Timestamp};
use crate::vocabulary::RiskTier;

/// The shortest minimum wait the policy may set, in minutes.
pub const MIN_WAIT_MINUTES: u32 = 1;
/// The longest minimum wait the policy may set, in minutes: one day.
pub const MAX_WAIT_MINUTES: u32 = 1440;
/// The words every confirmation phrase starts with.
pub const TEMPLATE_PREFIX: &str = "I confirm the solo approval of ";
/// The one placeholder of the template.
pub const TARGET: &str = "{target}";
/// The longest template, in bytes.
pub const TEMPLATE_MAX_BYTES: usize = 120;
/// The template a policy with the solo mode off is read with.
const DEFAULT_TEMPLATE: &str = "I confirm the solo approval of {target}";
/// The number of hex digits a confirmation word keeps.
const WORD_DIGITS: usize = 16;
/// Seconds in a minute, for turning a policy wait into a duration.
const SECONDS_PER_MINUTE: u64 = 60;

/// The approval actions the solo exception applies to: the approval of a pull request, the
/// freezing of a specification, and the decisions on a new dependency, on build code and on a
/// translation warning. No other action, and in particular not the waiver of a gate, has it.
pub const SOLO_ACTIONS: [&str; 5] = [
    "approve_pr",
    "freeze_specification",
    "add_new_direct_dependency",
    "approve_build_code",
    "acknowledge_documentation_warning",
];

/// Whether the solo exception may apply to a decision: the policy switch is on, the repository
/// is marked `single_maintainer` and exactly one active person may approve on it. Only
/// [`AuthorityPolicy::solo_fact`] makes one that holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoloFact(bool);

impl SoloFact {
    /// The fact that does not hold: outside the solo mode.
    pub const NONE: Self = Self(false);

    /// True when the solo exception may apply.
    #[must_use]
    pub const fn holds(self) -> bool {
        self.0
    }
}

/// The waits of the solo mode, by the decision they apply to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoloWait {
    /// The approval of a pull request at the high tier.
    PullRequestHigh,
    /// The approval of a pull request at the critical tier.
    PullRequestCritical,
    /// A decision on a new direct dependency.
    Dependency,
    /// A decision on a translation warning.
    TranslationWarning,
    /// A decision on build code.
    BuildCode,
}

impl SoloWait {
    /// The wait of the approval of a pull request at `tier`, or `None` where it has none: the low
    /// and medium tiers need no wait and no phrase.
    #[must_use]
    pub const fn for_pull_request(tier: RiskTier) -> Option<Self> {
        match tier {
            RiskTier::High => Some(Self::PullRequestHigh),
            RiskTier::Critical => Some(Self::PullRequestCritical),
            RiskTier::Low | RiskTier::Medium => None,
        }
    }
}

/// What a confirmation phrase names. The text is made of typed fields only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoloTarget<'a> {
    /// A pull request at its risk tier.
    PullRequest {
        /// The number of the pull request.
        number: u64,
        /// Its risk tier.
        tier: RiskTier,
    },
    /// A new direct dependency.
    Dependency {
        /// The package name.
        name: &'a str,
        /// The version.
        version: &'a str,
    },
    /// The build code of a package.
    BuildCode {
        /// The package name.
        name: &'a str,
        /// The version.
        version: &'a str,
    },
    /// The build code of the project, a file.
    ProjectBuildCode {
        /// The path of the file.
        path: &'a str,
    },
    /// One translation warning of a job.
    TranslationWarning {
        /// The number of the warning, from 1.
        number: u32,
        /// The job.
        job: JobId,
    },
}

impl fmt::Display for SoloTarget<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PullRequest { number, tier } => {
                write!(f, "PR {number} at level {}", tier.as_str())
            }
            Self::Dependency { name, version } => write!(f, "dependency {name} {version}"),
            Self::BuildCode { name, version } => write!(f, "build code {name} {version}"),
            Self::ProjectBuildCode { path } => write!(f, "build code {path}"),
            Self::TranslationWarning { number, job } => {
                let text = job.as_text();
                write!(
                    f,
                    "translation warning {number} of job {}",
                    text.get(..8).unwrap_or(&text)
                )
            }
        }
    }
}

/// The phrase the template asks for, with `target` in place of its one `{target}`.
#[must_use]
pub fn expected_confirmation(template: &str, target: &str) -> String {
    template.replacen(TARGET, target, 1)
}

/// A confirmation phrase as the signed request carries it: the first 16 lowercase hex digits of
/// the SHA-256 of the phrase after normalization. The normalization is ASCII only: runs of ASCII
/// white space become one space, the ends are trimmed and ASCII letters are lowered. A non-ASCII
/// space or a letter that only Unicode folding would lower (the Kelvin sign) is kept as it is, so
/// it does not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationWord(String);

impl ConfirmationWord {
    /// The word of a phrase.
    #[must_use]
    pub fn of(text: &str) -> Self {
        let normal = text
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        let digest = Sha256Digest::of(normal.as_bytes());
        Self(digest.hex().chars().take(WORD_DIGITS).collect())
    }

    /// Reads a word back: exactly 16 lowercase hex digits, or `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == WORD_DIGITS
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| Self(text.to_owned()))
    }

    /// The 16 hex digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The rules of the solo mode that the deciders read: the switch, the waits and the template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoloRules {
    enabled: bool,
    pull_request_high: Duration,
    pull_request_critical: Duration,
    dependency: Duration,
    translation_warning: Duration,
    build_code: Duration,
    template: String,
}

fn minutes(value: u32) -> Duration {
    // At most 1440 minutes once checked, 86 400 seconds; saturating all the same.
    Duration::from_secs(u64::from(value).saturating_mul(SECONDS_PER_MINUTE))
}

impl SoloRules {
    /// The rules with the switch off: the solo fact never holds, so the waits are never read.
    #[must_use]
    pub fn disabled() -> Self {
        let none = Duration::ZERO;
        Self {
            enabled: false,
            pull_request_high: none,
            pull_request_critical: none,
            dependency: none,
            translation_warning: none,
            build_code: none,
            template: DEFAULT_TEMPLATE.to_owned(),
        }
    }

    /// The rules of a checked block.
    ///
    /// # Errors
    /// The first [`SoloProblem`] of [`check_solo_mode`].
    pub fn from_block(block: &SoloMode) -> Result<Self, SoloProblem> {
        if let Some(problem) = check_solo_mode(block).into_iter().next() {
            return Err(problem);
        }
        let waits = &block.minimum_wait_minutes;
        Ok(Self {
            enabled: block.enabled,
            pull_request_high: minutes(waits.pull_request_high),
            pull_request_critical: minutes(waits.pull_request_critical),
            dependency: minutes(waits.dependency),
            translation_warning: minutes(waits.translation_warning),
            build_code: minutes(waits.build_code),
            template: block.confirmation_template.clone(),
        })
    }

    /// Whether the switch is on.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The solo fact: the switch is on, the repository is marked `single_maintainer` and exactly
    /// one active person may approve on it. [`AuthorityPolicy::solo_fact`] and the engine's check
    /// at commit both answer from here, so the rule is written once.
    #[must_use]
    pub fn fact(&self, single_maintainer: bool, approver_count: u32) -> SoloFact {
        SoloFact(self.enabled && single_maintainer && approver_count == 1)
    }

    /// The minimum wait of a decision.
    #[must_use]
    pub fn wait(&self, which: SoloWait) -> Duration {
        match which {
            SoloWait::PullRequestHigh => self.pull_request_high,
            SoloWait::PullRequestCritical => self.pull_request_critical,
            SoloWait::Dependency => self.dependency,
            SoloWait::TranslationWarning => self.translation_warning,
            SoloWait::BuildCode => self.build_code,
        }
    }

    /// True when a decision asked for at `requested_at` comes at least the wait after the
    /// `milestone`. A missing milestone, or a request before it, does not pass.
    #[must_use]
    pub fn wait_passed(
        &self,
        which: SoloWait,
        milestone: Option<&Timestamp>,
        requested_at: &Timestamp,
    ) -> bool {
        milestone
            .and_then(|start| requested_at.duration_since(start))
            .is_some_and(|waited| waited >= self.wait(which))
    }

    /// The phrase that confirms a decision on `target`.
    #[must_use]
    pub fn expected(&self, target: &SoloTarget<'_>) -> String {
        expected_confirmation(&self.template, &target.to_string())
    }

    /// The word of the phrase that confirms a decision on `target`.
    #[must_use]
    pub fn expected_word(&self, target: &SoloTarget<'_>) -> ConfirmationWord {
        ConfirmationWord::of(&self.expected(target))
    }
}

/// A value of the `solo_mode` block the engine will not run with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoloProblem {
    /// The key, such as `solo_mode.minimum_wait_minutes.dependency`.
    pub key: &'static str,
    /// What is wrong.
    pub message: String,
}

/// Every problem of a `solo_mode` block: a wait outside 1 to 1440 minutes, or a template that
/// does not start with [`TEMPLATE_PREFIX`], does not hold exactly one `{target}`, is longer than
/// 120 bytes or has a character outside printable ASCII. Empty when the block is good. The
/// policy loader and the engine's build both ask here, so there is one rule.
#[must_use]
pub fn check_solo_mode(block: &SoloMode) -> Vec<SoloProblem> {
    let mut found = Vec::new();
    let waits = &block.minimum_wait_minutes;
    for (key, value) in [
        (
            "solo_mode.minimum_wait_minutes.pull_request_high",
            waits.pull_request_high,
        ),
        (
            "solo_mode.minimum_wait_minutes.pull_request_critical",
            waits.pull_request_critical,
        ),
        (
            "solo_mode.minimum_wait_minutes.dependency",
            waits.dependency,
        ),
        (
            "solo_mode.minimum_wait_minutes.translation_warning",
            waits.translation_warning,
        ),
        (
            "solo_mode.minimum_wait_minutes.build_code",
            waits.build_code,
        ),
    ] {
        if !(MIN_WAIT_MINUTES..=MAX_WAIT_MINUTES).contains(&value) {
            found.push(SoloProblem {
                key,
                message: format!(
                    "a minimum wait is from {MIN_WAIT_MINUTES} to {MAX_WAIT_MINUTES} minutes; this is {value}"
                ),
            });
        }
    }
    let template = &block.confirmation_template;
    let key = "solo_mode.confirmation_template";
    if !template.starts_with(TEMPLATE_PREFIX) {
        found.push(SoloProblem {
            key,
            message: format!("the template must start with `{TEMPLATE_PREFIX}`"),
        });
    }
    if template.matches(TARGET).count() != 1 {
        found.push(SoloProblem {
            key,
            message: format!("the template must hold exactly one `{TARGET}`"),
        });
    }
    if template.len() > TEMPLATE_MAX_BYTES {
        found.push(SoloProblem {
            key,
            message: format!("the template is longer than {TEMPLATE_MAX_BYTES} bytes"),
        });
    }
    if !template.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        found.push(SoloProblem {
            key,
            message: "the template has a character outside printable ASCII".to_owned(),
        });
    }
    found
}

impl AuthorityPolicy {
    /// The solo fact of a decision: it holds when the policy's switch is on, the repository is
    /// marked `single_maintainer` and exactly one active person may approve on it. This is the
    /// one place the fact is computed; the API, the engine, the approval stage and the quorum all
    /// ask here.
    #[must_use]
    pub fn solo_fact(&self, single_maintainer: bool, approver_count: u32) -> SoloFact {
        self.solo.fact(single_maintainer, approver_count)
    }

    /// The rules of the solo mode, for the deciders that check the wait and the phrase.
    #[must_use]
    pub fn solo_rules(&self) -> SoloRules {
        self.solo.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::approval::MinimumWaitMinutes;

    fn block(wait: u32, template: &str) -> SoloMode {
        SoloMode {
            enabled: true,
            minimum_wait_minutes: MinimumWaitMinutes {
                pull_request_high: wait,
                pull_request_critical: wait,
                dependency: wait,
                translation_warning: wait,
                build_code: wait,
            },
            confirmation_template: template.to_owned(),
        }
    }

    #[test]
    fn extra_spaces_and_capitals_give_the_same_word() {
        assert_eq!(
            ConfirmationWord::of("I confirm the solo approval of PR 7 at level high"),
            ConfirmationWord::of("  i  CONFIRM the\tsolo approval of pr 7 AT level HIGH \n"),
        );
    }

    #[test]
    fn a_non_ascii_space_or_the_kelvin_sign_gives_another_word() {
        let plain = ConfirmationWord::of("I confirm the solo approval of PR 7 at level high");
        let nbsp = ConfirmationWord::of("I confirm\u{a0}the solo approval of PR 7 at level high");
        let kelvin = ConfirmationWord::of("I confirm the solo approval of \u{212a}");
        let k = ConfirmationWord::of("I confirm the solo approval of k");
        assert_ne!(plain, nbsp);
        assert_ne!(kelvin, k);
    }

    #[test]
    fn a_word_is_sixteen_lowercase_hex_digits() {
        let word = ConfirmationWord::of("anything");
        assert_eq!(word.as_str().len(), 16);
        assert_eq!(ConfirmationWord::parse(word.as_str()), Some(word));
        assert_eq!(ConfirmationWord::parse("0123456789abcdeF"), None);
        assert_eq!(ConfirmationWord::parse("0123456789abcde"), None);
        assert_eq!(ConfirmationWord::parse("0123456789abcdef0"), None);
        assert_eq!(ConfirmationWord::parse("0123456789abcdeg"), None);
    }

    #[test]
    fn the_targets_are_made_of_typed_fields() {
        let rules = SoloRules::from_block(&block(10, DEFAULT_TEMPLATE)).expect("a good block");
        assert_eq!(
            rules.expected(&SoloTarget::PullRequest {
                number: 42,
                tier: RiskTier::High
            }),
            "I confirm the solo approval of PR 42 at level high"
        );
        assert_eq!(
            rules.expected(&SoloTarget::Dependency {
                name: "serde",
                version: "1.0.0"
            }),
            "I confirm the solo approval of dependency serde 1.0.0"
        );
        assert_eq!(
            rules.expected(&SoloTarget::ProjectBuildCode { path: "build.rs" }),
            "I confirm the solo approval of build code build.rs"
        );
        let job = JobId::parse("0a1b2c3d-0000-4000-8000-000000000000").expect("a job id");
        assert_eq!(
            rules.expected(&SoloTarget::TranslationWarning { number: 2, job }),
            "I confirm the solo approval of translation warning 2 of job 0a1b2c3d"
        );
    }

    #[test]
    fn a_wait_passes_at_the_minute_and_not_a_nanosecond_before() {
        let rules = SoloRules::from_block(&block(10, DEFAULT_TEMPLATE)).expect("a good block");
        let at = |text: &str| Timestamp::parse(text).expect("a time");
        let start = at("2026-11-20T10:00:00Z");
        let which = SoloWait::Dependency;
        assert!(!rules.wait_passed(which, Some(&start), &at("2026-11-20T10:09:59.999999999Z")));
        assert!(rules.wait_passed(which, Some(&start), &at("2026-11-20T10:10:00Z")));
        assert!(rules.wait_passed(which, Some(&start), &at("2026-11-20T11:00:00Z")));
        // Before the milestone, and with no milestone, it never passes.
        assert!(!rules.wait_passed(which, Some(&start), &at("2026-11-20T09:00:00Z")));
        assert!(!rules.wait_passed(which, None, &at("2026-11-20T11:00:00Z")));
    }

    #[test]
    fn a_wait_out_of_range_or_a_bad_template_is_refused() {
        assert!(check_solo_mode(&block(1, DEFAULT_TEMPLATE)).is_empty());
        assert!(check_solo_mode(&block(1440, DEFAULT_TEMPLATE)).is_empty());
        assert_eq!(check_solo_mode(&block(0, DEFAULT_TEMPLATE)).len(), 5);
        assert_eq!(check_solo_mode(&block(1441, DEFAULT_TEMPLATE)).len(), 5);
        assert_eq!(check_solo_mode(&block(u32::MAX, DEFAULT_TEMPLATE)).len(), 5);
        for bad in [
            "I confirm the solo approval of",
            "I confirm the solo approval of {target} {target}",
            "Approve {target}",
            "I confirm the solo approval of {target} \u{e9}",
        ] {
            assert!(
                !check_solo_mode(&block(10, bad)).is_empty(),
                "{bad} was accepted"
            );
        }
        let long = format!("{DEFAULT_TEMPLATE}{}", " x".repeat(60));
        assert!(!check_solo_mode(&block(10, &long)).is_empty());
        assert!(SoloRules::from_block(&block(0, DEFAULT_TEMPLATE)).is_err());
    }

    #[test]
    fn the_longest_wait_has_no_overflow() {
        let rules = SoloRules::from_block(&block(MAX_WAIT_MINUTES, DEFAULT_TEMPLATE))
            .expect("a good block");
        assert_eq!(rules.wait(SoloWait::BuildCode), Duration::from_secs(86_400));
        assert_eq!(
            rules.wait(SoloWait::Dependency),
            Duration::from_secs(86_400)
        );
    }
}
