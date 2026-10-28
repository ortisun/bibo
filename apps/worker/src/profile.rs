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
//! | `local` | the model and GitHub side only: the agent runtime, the router, the broker, the GitHub ports. Everything that holds state or runs code (store, artifacts, sandbox, workspaces, specification provider, registry, clock, ids, process runner, ticker, authority) is real. |
//! | `test` | every port |
//!
//! `local` exists for a developer who has a database and Docker on a machine and no credentials.
//! It labels what it records as test mode, so no record of it can pass for production evidence
//! (invariant INV-08), and it still refuses an in-memory store that would lose the job on exit.

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

/// Every port of the composition, by the name used in refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PortName {
    /// `Store`.
    Store,
    /// `Clock`.
    Clock,
    /// `IdGenerator`.
    Ids,
    /// `ArtifactStore`.
    Artifacts,
    /// `SandboxProvider`.
    Sandbox,
    /// `WorkspaceProvider`.
    Workspaces,
    /// `AgentRuntime`.
    Runtime,
    /// `ModelRouter`.
    Router,
    /// `AgentRegistry`.
    Agents,
    /// `ModelBroker`.
    Broker,
    /// `SpecificationProvider`.
    Specification,
    /// `IssueSource`.
    Issues,
    /// `ChangeHost`.
    Changes,
    /// `WebhookVerifier`.
    Webhooks,
    /// `ProcessRunner`.
    Process,
    /// The engine's `Ticker`.
    Ticker,
    /// The engine's `Authority`.
    Authority,
}

impl PortName {
    /// Every port, in a fixed order.
    pub const ALL: [PortName; 17] = [
        Self::Store,
        Self::Clock,
        Self::Ids,
        Self::Artifacts,
        Self::Sandbox,
        Self::Workspaces,
        Self::Runtime,
        Self::Router,
        Self::Agents,
        Self::Broker,
        Self::Specification,
        Self::Issues,
        Self::Changes,
        Self::Webhooks,
        Self::Process,
        Self::Ticker,
        Self::Authority,
    ];

    /// The name in a refusal and in the health report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Clock => "clock",
            Self::Ids => "id generator",
            Self::Artifacts => "artifact store",
            Self::Sandbox => "sandbox provider",
            Self::Workspaces => "workspace provider",
            Self::Runtime => "agent runtime",
            Self::Router => "model router",
            Self::Agents => "agent registry",
            Self::Broker => "model broker",
            Self::Specification => "specification provider",
            Self::Issues => "issue source",
            Self::Changes => "change host",
            Self::Webhooks => "webhook verifier",
            Self::Process => "process runner",
            Self::Ticker => "ticker",
            Self::Authority => "authority",
        }
    }

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
}
