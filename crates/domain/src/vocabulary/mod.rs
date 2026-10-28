//! Closed sets of names that many contracts share: execution mode, fidelity, risk tier, gate
//! outcome, review verdict and the pipeline names.
//!
//! Each value is spelled on the wire exactly as the schemas spell it. A name outside the set is an
//! error that lists the allowed names, so a typo cannot become a new state.

mod pipeline;

use crate::macros::string_enum;

pub use pipeline::{AssuranceLevel, ReleaseState, StageKind};

string_enum! {
    /// Whether a job may use fakes. Test mode allows fake adapters. Production mode does not.
    pub enum ExecutionMode("execution mode") {
        /// Real adapters only.
        Production = "production",
        /// Fake adapters are allowed, and labelled as fake in every record.
        Test = "test",
    }
}

string_enum! {
    /// Whether an adapter talked to the real system or to a stand-in.
    pub enum Fidelity("fidelity") {
        /// The real system.
        Real = "real",
        /// A labelled fake from the test kit.
        Fake = "fake",
    }
}

impl ExecutionMode {
    /// True when an adapter of this fidelity may take part in a job of this mode. A fake is
    /// accepted only in test mode (invariant INV-08).
    #[must_use]
    pub const fn permits(self, fidelity: Fidelity) -> bool {
        matches!(
            (self, fidelity),
            (ExecutionMode::Test, _) | (_, Fidelity::Real)
        )
    }
}

string_enum! {
    /// The fidelity of the component that wrote a ledger entry. A ledger entry may also come from
    /// a simulation, which an adapter report never does.
    pub enum RecorderFidelity("recorder fidelity") {
        /// A real component.
        Real = "real",
        /// A simulation of the real system.
        Simulated = "simulated",
        /// A labelled fake.
        Fake = "fake",
    }
}

impl From<Fidelity> for RecorderFidelity {
    fn from(fidelity: Fidelity) -> Self {
        match fidelity {
            Fidelity::Real => RecorderFidelity::Real,
            Fidelity::Fake => RecorderFidelity::Fake,
        }
    }
}

string_enum! {
    /// The role of a human who records a decision or stands behind a judgment. Matches the actors
    /// in `state-machine.json` and the roles in `policies/approval.yaml`.
    pub enum HumanRole("human role") {
        /// The person who submitted the request.
        Requester = "requester",
        /// A person with operational rights on the tenant.
        Operator = "operator",
        /// A person with the approval role.
        Approver = "approver",
        /// A person on the security approver list.
        SecurityApprover = "security_approver",
        /// An organization administrator.
        OrgAdmin = "org_admin",
    }
}

string_enum! {
    /// How much could go wrong if the work is wrong.
    pub enum RiskTier("risk tier") {
        /// Low.
        Low = "low",
        /// Medium.
        Medium = "medium",
        /// High.
        High = "high",
        /// Critical.
        Critical = "critical",
    }
}

string_enum! {
    /// How sure the author of a claim or a contract is.
    pub enum ConfidenceLevel("confidence level") {
        /// Low.
        Low = "low",
        /// Medium.
        Medium = "medium",
        /// High.
        High = "high",
    }
}

string_enum! {
    /// The result of one deterministic gate. A gate that did not run is `BLOCKED`, never `PASSED`.
    pub enum GateOutcome("gate outcome") {
        /// Every command ran and exited with code 0.
        Passed = "PASSED",
        /// The gate ran and found failures.
        Failed = "FAILED",
        /// The gate could not run: a tool or dependency was missing.
        Blocked = "BLOCKED",
        /// A rule, a profile or a policy says the gate does not apply here.
        NotApplicable = "NOT_APPLICABLE",
    }
}

string_enum! {
    /// The result of one independent review.
    pub enum Verdict("review verdict") {
        /// The work may go on.
        Pass = "PASS",
        /// The builder must change something.
        ChangesRequired = "CHANGES_REQUIRED",
        /// The work must stop.
        Block = "BLOCK",
        /// A human must answer one question first.
        NeedsHuman = "NEEDS_HUMAN",
    }
}

string_enum! {
    /// What an independent reviewer looks at.
    pub enum ReviewerRole("reviewer role") {
        /// Code quality and correctness.
        CodeReviewer = "code_reviewer",
        /// Security.
        SecurityReviewer = "security_reviewer",
        /// Reliability.
        ReliabilityReviewer = "reliability_reviewer",
        /// User experience.
        UxReviewer = "ux_reviewer",
        /// Tries to break the work.
        AdversarialReviewer = "adversarial_reviewer",
        /// Documentation.
        DocumentationReviewer = "documentation_reviewer",
        /// The specification.
        SpecificationReviewer = "specification_reviewer",
        /// The architecture.
        ArchitectureCritic = "architecture_critic",
    }
}

string_enum! {
    /// How much the factory may do on its own in a repository. `L0` is the lowest.
    pub enum AutonomyLevel("autonomy level") {
        /// The lowest level.
        L0 = "L0",
        /// The next level.
        L1 = "L1",
        /// The level after that.
        L2 = "L2",
        /// The highest level.
        L3 = "L3",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_autonomy_levels_read_back_and_a_fifth_is_refused() {
        for (text, level) in [
            ("L0", AutonomyLevel::L0),
            ("L1", AutonomyLevel::L1),
            ("L2", AutonomyLevel::L2),
            ("L3", AutonomyLevel::L3),
        ] {
            assert_eq!(AutonomyLevel::parse(text).unwrap(), level);
            assert_eq!(level.as_str(), text);
        }
        let message = AutonomyLevel::parse("L4").unwrap_err().to_string();
        assert!(message.contains("L0, L1, L2, L3"), "{message}");
    }

    #[test]
    fn a_fake_is_permitted_only_in_test_mode() {
        assert!(ExecutionMode::Test.permits(Fidelity::Fake));
        assert!(ExecutionMode::Test.permits(Fidelity::Real));
        assert!(ExecutionMode::Production.permits(Fidelity::Real));
        assert!(!ExecutionMode::Production.permits(Fidelity::Fake));
    }

    #[test]
    fn unknown_names_list_the_allowed_ones() {
        let message = ExecutionMode::parse("staging").unwrap_err().to_string();
        assert!(message.contains("production, test"), "{message}");
        assert!(message.contains("execution mode"), "{message}");
    }
}
