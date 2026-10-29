//! Profiles: which kind of run this process is, and which adapters it may use in it.
//!
//! A profile is chosen once, by name, in the configuration (there is no default: a configuration
//! that does not name one is refused). It answers two questions. The first is the
//! [`ExecutionMode`] that the engine records in every ledger entry: the production profile is
//! `production`, the other two are `test`. The second is finer: for each port, may a stand-in
//! (fidelity `fake`) stand in for the real adapter?
//!
//! | Profile | Fakes allowed for |
//! |---|---|
//! | `production` | nothing |
//! | `local` | the model and GitHub side only: the agent runtime, the router, the broker, the GitHub ports, the capability probes of the runtimes, the registry and the advisory database that the dependency gates ask, and the statement about the bypass list. Everything that holds state or runs code (store, artifacts, sandbox, workspaces, specification provider, registry, clock, ids, process runner, ticker, authority) is real. |
//! | `test` | every port |
//!
//! `local` exists for a developer who has a database and Docker on a machine and no credentials.
//! It labels what it records as test mode, so no record of it can pass for production evidence
//! (invariant INV-08), and it still refuses an in-memory store that would lose the job on exit.
//!
//! # The list of ports is closed
//!
//! [`PortName`], [`PortName::ALL`] and [`PortName::label`] come from one macro call, so a name
//! cannot be in one and missing from another. The registry ([`crate::registry`]) builds its report
//! from the same names, and a test enumerates the trait of every seam and the input of a security
//! decision and fails for one that reports no fidelity.

use factory_domain::vocabulary::{ExecutionMode, Fidelity};
use factory_ports::{FakeRefused, require_permitted};

/// A kind of run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Real adapters only.
    Production,
    /// Real state and execution, stand-ins for the model and GitHub.
    Local,
    /// Any stand-in.
    Test,
}

impl Profile {
    /// The mode the engine records.
    #[must_use]
    pub const fn execution_mode(self) -> ExecutionMode {
        match self {
            Self::Production => ExecutionMode::Production,
            Self::Local | Self::Test => ExecutionMode::Test,
        }
    }

    /// The name used in the configuration and in logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Local => "local",
            Self::Test => "test",
        }
    }

    /// True when this profile accepts a stand-in for `port`.
    #[must_use]
    pub const fn permits_fake(self, port: PortName) -> bool {
        match self {
            Self::Production => false,
            Self::Local => port.is_credentialed(),
            Self::Test => true,
        }
    }

    /// Refuses a stand-in for `port` unless this profile accepts one.
    ///
    /// Both rules apply: the engine's mode rule (`require_permitted`, invariant INV-08) and the
    /// profile's own list.
    ///
    /// # Errors
    /// [`FakeRefused`] naming the port.
    pub fn admit(self, port: PortName, fidelity: Fidelity) -> Result<(), FakeRefused> {
        require_permitted(self.execution_mode(), port.label(), fidelity)?;
        if fidelity == Fidelity::Fake && !self.permits_fake(port) {
            return Err(FakeRefused {
                component: port.label().to_owned(),
            });
        }
        Ok(())
    }
}

/// Declares [`PortName`] with its list and its labels in one place.
macro_rules! port_names {
    ($( $(#[$doc:meta])* $variant:ident => $label:literal, )*) => {
        /// Every port of the composition, by the name used in refusals.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum PortName {
            $( $(#[$doc])* $variant, )*
        }

        impl PortName {
            /// Every port, in a fixed order. The first 17 are the ports of the engine; the others
            /// are the seams of the stages and the inputs of the security decisions, each of which
            /// reports a fidelity, so a stand-in among them is refused like any other.
            pub const ALL: [PortName; PortName::COUNT] = [ $( Self::$variant, )* ];

            const COUNT: usize = [ $( stringify!($variant), )* ].len();

            /// The name in a refusal and in the health report.
            #[must_use]
            pub const fn label(self) -> &'static str {
                match self {
                    $( Self::$variant => $label, )*
                }
            }
        }
    };
}

port_names! {
    /// `Store`.
    Store => "store",
    /// `Clock`.
    Clock => "clock",
    /// `IdGenerator`.
    Ids => "id generator",
    /// `ArtifactStore`.
    Artifacts => "artifact store",
    /// `SandboxProvider`.
    Sandbox => "sandbox provider",
    /// `WorkspaceProvider`.
    Workspaces => "workspace provider",
    /// `AgentRuntime`.
    Runtime => "agent runtime",
    /// `ModelRouter`.
    Router => "model router",
    /// `AgentRegistry`.
    Agents => "agent registry",
    /// `ModelBroker`.
    Broker => "model broker",
    /// `SpecificationProvider`.
    Specification => "specification provider",
    /// `IssueSource`.
    Issues => "issue source",
    /// `ChangeHost`.
    Changes => "change host",
    /// `WebhookVerifier`.
    Webhooks => "webhook verifier",
    /// `ProcessRunner`.
    Process => "process runner",
    /// The engine's `Ticker`.
    Ticker => "ticker",
    /// The engine's `Authority`.
    Authority => "authority",
    /// `AgentOutputCheck`, a seam of the stages.
    OutputCheck => "agent output check",
    /// `AllowlistSource`, a seam of the stages.
    Allowlist => "allowlist source",
    /// `RequestSource`, a seam of the stages.
    Requests => "request source",
    /// `TaskLedger`, a seam of the implementation stage.
    TaskLedger => "task ledger",
    /// `SpecApprovals`, a seam of the specification stage.
    SpecApprovals => "specification approvals",
    /// `SpecDrafts`, a seam of the specification stage.
    SpecDrafts => "specification drafts",
    /// `DeliverySources`, a seam of the delivery stage.
    Delivery => "delivery sources",
    /// `ApprovalSources`, a seam of the approval stage.
    Approvals => "approval sources",
    /// `ProjectManifestParser`, a seam of the repository stage (RR-6).
    Manifests => "project manifest parser",
    /// `JobRepository`, a seam of the repository stage (RR-6).
    Repositories => "job repository",
    /// `CapabilityProbes`, a seam of the intake stage (RR-6).
    Probes => "capability probes",
    /// `ReworkSource`, a seam of the implementation stage (RR-6).
    Rework => "rework source",
    /// `RoundSource`, a seam of the architecture stage (RR-6).
    Rounds => "round source",
    /// `RiskSource`, a seam of the architecture stage (RR-6).
    Risk => "risk source",
    /// `EvidenceDrift`, a seam of the delivery stage (RR-6).
    Drift => "evidence drift",
    /// `SpecHistory`, a seam of the specification stage (RR-6).
    SpecHistory => "specification history",
    /// `RegistryMetadata`: what the package registry says about a package (RR-7).
    PackageMetadata => "package metadata source",
    /// `AdvisoryDatabase`: the date of the database the audit reads (RR-7).
    AdvisoryDatabase => "advisory database date",
    /// `RecordedApprovals`: the decisions people recorded about new dependencies (RR-7).
    RecordedApprovals => "recorded dependency decisions",
    /// `BypassAttestations`: the administrator's statement about the bypass list (RR-7).
    Attestations => "bypass attestation",
}

impl PortName {
    /// True for the ports that need a credential or a paid service the `local` profile may lack.
    #[must_use]
    pub const fn is_credentialed(self) -> bool {
        matches!(
            self,
            Self::Runtime
                | Self::Router
                | Self::Broker
                | Self::Issues
                | Self::Changes
                | Self::Webhooks
                // What the runtimes report they can do comes from running them.
                | Self::Probes
                // The package registry and the audit image's database are outside services, and
                // the statement about the bypass list is about GitHub.
                | Self::PackageMetadata
                | Self::AdvisoryDatabase
                | Self::Attestations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_admits_no_fake_at_all() {
        for port in PortName::ALL {
            assert!(Profile::Production.admit(port, Fidelity::Fake).is_err());
            assert!(Profile::Production.admit(port, Fidelity::Real).is_ok());
        }
    }

    #[test]
    fn local_admits_a_fake_only_for_the_credentialed_ports() {
        for port in PortName::ALL {
            let result = Profile::Local.admit(port, Fidelity::Fake);
            assert_eq!(result.is_ok(), port.is_credentialed(), "{port:?}");
        }
    }

    #[test]
    fn test_admits_everything() {
        for port in PortName::ALL {
            assert!(Profile::Test.admit(port, Fidelity::Fake).is_ok());
        }
    }

    #[test]
    fn only_production_runs_in_production_mode() {
        assert_eq!(
            Profile::Production.execution_mode(),
            ExecutionMode::Production
        );
        assert_eq!(Profile::Local.execution_mode(), ExecutionMode::Test);
        assert_eq!(Profile::Test.execution_mode(), ExecutionMode::Test);
    }

    #[test]
    fn the_list_has_every_name_once_and_every_label_once() {
        let mut labels: Vec<&str> = PortName::ALL.iter().map(|port| port.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), PortName::ALL.len(), "a label is used twice");
        let mut names = PortName::ALL.to_vec();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), PortName::ALL.len(), "a name is listed twice");
        assert_eq!(PortName::ALL.len(), 37);
    }
}
