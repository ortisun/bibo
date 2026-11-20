//! The registry of ports: every adapter the composition holds, in one value, with the check that a
//! profile accepts each of them.
//!
//! The registry is the single answer to "what is this process made of". A binary builds it once
//! (the production assembly in [`crate::assemble`], or a test with fakes), calls
//! [`PortRegistry::check`], and only then builds the engine. The check runs
//! [`Profile::admit`](crate::profile::Profile::admit) for **every** port, collects every refusal
//! and does not stop at the first, so an operator sees the whole list.
//!
//! The list of ports is closed by [`PortName::ALL`]: [`PortRegistry::fidelities`] returns one
//! entry per name, and a test fails if a name is missing. Adding a port means adding a name, a
//! field and an entry, and the compiler and that test say where.
//!
//! The seams of the stages are part of the registry, and so are the four inputs of the security
//! decisions of the dependency gates and the preflight (what the registry says about a package,
//! the date of the advisory database, the decisions people recorded, the statement about the
//! bypass list). [`Seams`] exists only when every one was supplied, and every one reports a
//! fidelity that is checked like any port. The macro that declares them calls `fidelity()` on each,
//! so a seam whose trait has none does not compile, and none can be left out of the report
//! (RR-6, RR-7).
//!
//! `OutputValidator` reports no fidelity (it is a pure port, and the port crate gives it no
//! stand-in label), so the registry cannot refuse a fake validator. That is a gap in the port
//! crate, listed in the README.

use std::sync::Arc;

use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{AgentRuntime, ModelBroker, ModelRouter};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{ChangeHost, IssueSource, WebhookVerifier};
use factory_ports::process::ProcessRunner;
use factory_ports::registry::{AgentRegistry, OutputValidator};
use factory_ports::sandbox::SandboxProvider;
use factory_ports::spec::SpecificationProvider;
use factory_ports::store::Store;
use factory_ports::workspace::WorkspaceProvider;
use factory_workflow::commands::Authority;
use factory_workflow::gates::supply_chain::approval::RecordedApprovals;
use factory_workflow::gates::supply_chain::facts::{AdvisoryDatabase, RegistryMetadata};
use factory_workflow::scheduler::Ticker;
use factory_workflow::stages::approval::ApprovalSources;
use factory_workflow::stages::architecture::seams::{RiskSource, RoundSource};
use factory_workflow::stages::delivery::{DeliverySources, EvidenceDrift};
use factory_workflow::stages::implementation::seams::{ReworkSource, TaskLedger};
use factory_workflow::stages::intake::seams::{
    AgentOutputCheck, AllowlistSource, CapabilityProbes, RequestSource,
};
use factory_workflow::stages::repo_intel::seams::{JobRepository, ProjectManifestParser};
use factory_workflow::stages::specification::seams::{SpecApprovals, SpecDrafts, SpecHistory};

use crate::preflight::BypassAttestations;
use crate::profile::{PortName, Profile};

/// Every adapter a binary may hold. `webhooks` is `None` in the worker, which does not verify
/// webhooks, and `Some` in the API.
#[derive(Clone)]
pub struct PortRegistry {
    /// Transactional state.
    pub store: Arc<dyn Store>,
    /// Time.
    pub clock: Arc<dyn Clock>,
    /// Identifiers.
    pub ids: Arc<dyn IdGenerator>,
    /// Immutable blobs.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// Sandboxes.
    pub sandbox: Arc<dyn SandboxProvider>,
    /// Job workspaces.
    pub workspaces: Arc<dyn WorkspaceProvider>,
    /// Agent tool runner.
    pub runtime: Arc<dyn AgentRuntime>,
    /// Model routing.
    pub router: Arc<dyn ModelRouter>,
    /// Agent manifests and prompts.
    pub agents: Arc<dyn AgentRegistry>,
    /// Schema validation of documents.
    pub validator: Arc<dyn OutputValidator>,
    /// Job tokens and metering.
    pub broker: Arc<dyn ModelBroker>,
    /// The specification provider.
    pub specification: Arc<dyn SpecificationProvider>,
    /// Issues.
    pub issues: Arc<dyn IssueSource>,
    /// Branches and pull requests.
    pub changes: Arc<dyn ChangeHost>,
    /// Webhook verification (API only).
    pub webhooks: Option<Arc<dyn WebhookVerifier>>,
    /// The one place that starts processes.
    pub process: Arc<dyn ProcessRunner>,
    /// The engine's waits.
    pub ticker: Arc<dyn Ticker>,
    /// Who may do what.
    pub authority: Arc<dyn Authority>,
    /// The seams of the stages. Complete by construction (see [`Seams`]).
    pub seams: Seams,
}

impl std::fmt::Debug for PortRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortRegistry")
            .field("ports", &self.fidelities())
            .finish()
    }
}

/// One or more ports that the profile does not accept.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the {profile} profile refuses {} port(s): {}", refused.len(), names(refused))]
pub struct RegistryRefused {
    /// The profile.
    pub profile: &'static str,
    /// Each refused port.
    pub refused: Vec<PortName>,
}

fn names(ports: &[PortName]) -> String {
    ports
        .iter()
        .map(|port| port.label())
        .collect::<Vec<_>>()
        .join(", ")
}

impl PortRegistry {
    /// The fidelity each port reports, one entry per name that is present.
    #[must_use]
    pub fn fidelities(&self) -> Vec<(PortName, Fidelity)> {
        let mut found = vec![
            (PortName::Store, self.store.fidelity()),
            (PortName::Clock, self.clock.fidelity()),
            (PortName::Ids, self.ids.fidelity()),
            (PortName::Artifacts, self.artifacts.fidelity()),
            (PortName::Sandbox, self.sandbox.fidelity()),
            (PortName::Workspaces, self.workspaces.fidelity()),
            (PortName::Runtime, self.runtime.fidelity()),
            (PortName::Router, self.router.fidelity()),
            (PortName::Agents, self.agents.fidelity()),
            (PortName::Broker, self.broker.fidelity()),
            (PortName::Specification, self.specification.fidelity()),
            (PortName::Issues, self.issues.fidelity()),
            (PortName::Changes, self.changes.fidelity()),
            (PortName::Process, self.process.fidelity()),
            (PortName::Ticker, self.ticker.fidelity()),
            (PortName::Authority, self.authority.fidelity()),
        ];
        if let Some(webhooks) = &self.webhooks {
            found.push((PortName::Webhooks, webhooks.fidelity()));
        }
        found.extend(self.seams.fidelities());
        found
    }

    /// Runs `require_permitted` for every port against the profile.
    ///
    /// # Errors
    /// [`RegistryRefused`] with every port the profile does not accept.
    pub fn check(&self, profile: Profile) -> Result<(), RegistryRefused> {
        check_fidelities(profile, &self.fidelities())
    }

    /// The lowest fidelity among the ports: the fidelity of whatever this process records.
    #[must_use]
    pub fn lowest_fidelity(&self) -> Fidelity {
        if self
            .fidelities()
            .iter()
            .any(|(_, fidelity)| *fidelity == Fidelity::Fake)
        {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }
}

/// The check on a list of reported fidelities. Separate so that a test can feed it a list in which
/// exactly one port is a fake.
///
/// # Errors
/// [`RegistryRefused`] with every refused port.
pub fn check_fidelities(
    profile: Profile,
    reported: &[(PortName, Fidelity)],
) -> Result<(), RegistryRefused> {
    let refused: Vec<PortName> = reported
        .iter()
        .filter(|(port, fidelity)| profile.admit(*port, *fidelity).is_err())
        .map(|(port, _)| *port)
        .collect();
    if refused.is_empty() {
        Ok(())
    } else {
        Err(RegistryRefused {
            profile: profile.name(),
            refused,
        })
    }
}

// ------------------------------------------------------------------------------------------
// The seams of the stages
// ------------------------------------------------------------------------------------------

/// Names a seam that the wiring left out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the wiring forgot {} seam(s): {}", missing.len(), missing.join(", "))]
pub struct SeamsIncomplete {
    /// The label of each seam that was not supplied, in the order of the registry.
    pub missing: Vec<&'static str>,
}

/// Declares every seam once: its field, its trait, its label and the name under which the profile
/// refuses a stand-in for it. The report of fidelities is written by the macro from the same list,
/// by calling `fidelity()` on each seam, so a seam whose trait has no such method does not compile
/// and a seam cannot be left out of the report (RR-6, RR-7).
macro_rules! seams {
    ($( $field:ident : $ty:ty = $label:literal => $port:ident, )*) => {
        /// Every seam the stage handlers and the engine declare, in one value.
        ///
        /// A value of this type exists only if every seam was supplied: [`SeamsBuilder::build`]
        /// refuses an incomplete set and names each seam that is missing. So a seam forgotten at
        /// wiring stops the process at start-up, in the same place and with the same report as
        /// a refused stand-in, and not on the first job that reaches the stage that needs it.
        #[derive(Clone)]
        pub struct Seams {
            $(
                #[doc = $label]
                pub $field: Arc<$ty>,
            )*
        }

        /// Collects the seams. Nothing is optional at the end: see [`Seams`].
        #[derive(Default)]
        pub struct SeamsBuilder {
            $( $field: Option<Arc<$ty>>, )*
        }

        impl SeamsBuilder {
            $(
                #[doc = $label]
                #[must_use]
                pub fn $field(mut self, seam: Arc<$ty>) -> Self {
                    self.$field = Some(seam);
                    self
                }
            )*

            /// The set, when every seam was supplied.
            ///
            /// # Errors
            /// [`SeamsIncomplete`] naming every seam that is missing.
            pub fn build(self) -> Result<Seams, SeamsIncomplete> {
                let mut missing = Vec::new();
                $( if self.$field.is_none() { missing.push($label); } )*
                if !missing.is_empty() {
                    return Err(SeamsIncomplete { missing });
                }
                Ok(Seams {
                    $( $field: self.$field.expect("checked above"), )*
                })
            }
        }

        impl Seams {
            /// The fidelity of every seam, under its port name. All of them: a seam that reports
            /// none does not compile (RR-6, RR-7).
            #[must_use]
            pub fn fidelities(&self) -> Vec<(PortName, Fidelity)> {
                vec![ $( (PortName::$port, self.$field.fidelity()), )* ]
            }

            /// The port name of each seam, in the order of the declaration. A test compares it with
            /// [`PortName::ALL`].
            #[must_use]
            pub const fn port_names() -> &'static [PortName] {
                &[ $( PortName::$port, )* ]
            }
        }
    };
}

seams! {
    output_check: dyn AgentOutputCheck = "agent output check" => OutputCheck,
    manifests: dyn ProjectManifestParser = "project manifest parser" => Manifests,
    allowlist: dyn AllowlistSource = "allowlist source" => Allowlist,
    requests: dyn RequestSource = "request source" => Requests,
    repositories: dyn JobRepository = "job repository" => Repositories,
    probes: dyn CapabilityProbes = "capability probes" => Probes,
    ledger: dyn TaskLedger = "task ledger" => TaskLedger,
    rework: dyn ReworkSource = "rework source" => Rework,
    rounds: dyn RoundSource = "round source" => Rounds,
    risk: dyn RiskSource = "risk source" => Risk,
    drift: dyn EvidenceDrift = "evidence drift" => Drift,
    spec_approvals: dyn SpecApprovals = "specification approvals" => SpecApprovals,
    spec_drafts: dyn SpecDrafts = "specification drafts" => SpecDrafts,
    spec_history: dyn SpecHistory = "specification history" => SpecHistory,
    delivery: dyn DeliverySources = "delivery sources" => Delivery,
    approvals: dyn ApprovalSources = "approval sources" => Approvals,
    package_metadata: dyn RegistryMetadata = "package metadata source" => PackageMetadata,
    advisory_database: dyn AdvisoryDatabase = "advisory database date" => AdvisoryDatabase,
    recorded_approvals: dyn RecordedApprovals = "recorded dependency decisions" => RecordedApprovals,
    attestations: dyn BypassAttestations = "bypass attestation" => Attestations,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ports of the engine, which `PortRegistry` holds as fields. Every other name belongs to a
    /// seam, and [`Seams::port_names`] lists those from the one macro call.
    const ENGINE_PORTS: [PortName; 17] = [
        PortName::Store,
        PortName::Clock,
        PortName::Ids,
        PortName::Artifacts,
        PortName::Sandbox,
        PortName::Workspaces,
        PortName::Runtime,
        PortName::Router,
        PortName::Agents,
        PortName::Broker,
        PortName::Specification,
        PortName::Issues,
        PortName::Changes,
        PortName::Webhooks,
        PortName::Process,
        PortName::Ticker,
        PortName::Authority,
    ];

    #[test]
    fn every_name_of_the_list_is_a_port_of_the_engine_or_a_seam_and_none_is_both() {
        let mut named: Vec<PortName> = ENGINE_PORTS.to_vec();
        named.extend(Seams::port_names());
        named.sort();
        let mut all = PortName::ALL.to_vec();
        all.sort();
        assert_eq!(
            named, all,
            "a name of the list belongs to no port or to two, or a seam reports under another name"
        );
        assert_eq!(Seams::port_names().len(), 20);
    }

    #[test]
    fn one_fake_among_real_ports_is_named_and_refused_in_production() {
        for odd in PortName::ALL {
            let reported: Vec<(PortName, Fidelity)> = PortName::ALL
                .iter()
                .map(|port| {
                    let fidelity = if *port == odd {
                        Fidelity::Fake
                    } else {
                        Fidelity::Real
                    };
                    (*port, fidelity)
                })
                .collect();
            let refusal = check_fidelities(Profile::Production, &reported)
                .expect_err("production must refuse a fake");
            assert_eq!(refusal.refused, vec![odd]);
        }
    }

    #[test]
    fn every_fake_is_listed_not_only_the_first() {
        let reported = [
            (PortName::Store, Fidelity::Fake),
            (PortName::Sandbox, Fidelity::Fake),
            (PortName::Clock, Fidelity::Real),
        ];
        let refusal = check_fidelities(Profile::Production, &reported).expect_err("refused");
        assert_eq!(refusal.refused, vec![PortName::Store, PortName::Sandbox]);
        assert!(refusal.to_string().contains("store, sandbox provider"));
    }

    #[test]
    fn an_all_real_list_passes_every_profile() {
        let reported: Vec<_> = PortName::ALL
            .iter()
            .map(|port| (*port, Fidelity::Real))
            .collect();
        for profile in [Profile::Production, Profile::Local, Profile::Test] {
            assert_eq!(check_fidelities(profile, &reported), Ok(()));
        }
    }
}
