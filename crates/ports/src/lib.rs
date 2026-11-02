//! The outbound traits, and their closed error types, that the inner code needs from the outside:
//! the store, the sandbox, the agent runtime, the change host, the clock and others. Ring 1: it
//! depends on `factory-domain` only and makes no I/O call (rule DEP-05).
//!
//! This is **version 1.2** of the ports (ADR 0014 and `docs/architecture/ports-v1.1.md` for v1.1, ADR 0017 and
//! `docs/architecture/ports-v1.2.md` for the status writer added in v1.2). Every
//! adapter is built against it, and every adapter must pass the same shared contract suite as its
//! in-memory fake (`factory-testkit`, module `contracts`). A port changes only by a reviewed pull
//! request that updates the trait, the fake and the contract suite together.
//!
//! # Map
//!
//! | Module | Ports |
//! |---|---|
//! | [`clock`] | `Clock`, `IdGenerator`, `CancelSignal` |
//! | [`store`] | `Store`, the read-only `SystemTx`, `Tx` and its parts: `JobOps`, `RequestOps`, `DeliveryOps`, `RepositoryOps`, `StageRunOps`, `AttemptOps`, `TaskNodeOps`, `StageArtifactOps`, `ApprovalOps`, `LedgerOps`, `OutboxOps`, `AuditOps`, `ArtifactIndexOps`, `PrincipalOps` |
//! | [`artifact`] | `ArtifactStore` |
//! | [`sandbox`] | `SandboxProvider`, `SandboxSession`, and the pure `SandboxSpec::validate` and `PostureReport::differences` |
//! | [`workspace`] | `WorkspaceProvider`, `JobRepo`, `Workspace` |
//! | [`agent`] | `AgentRuntime`, `ModelRouter`, `ModelBroker`, the metering seam `MeteringOps`, and the broker's record of a job's turns, `TurnAttestation` |
//! | [`registry`] | `AgentRegistry`, `OutputValidator` |
//! | [`spec`] | `SpecificationProvider` |
//! | [`githost`] | `IssueSource`, `ChangeHost`, `WebhookVerifier` |
//! | [`issue_status`] | `IssueStatusWriter`: one `factory: <state>` label and one status comment on the issue a job came from (v1.2) |
//! | [`process`] | `ProcessRunner` |
//! | [`paths`] | Checked names shared by the ports: `RepoPath`, `RepoGlob`, `BranchName`, `RepoRef`, and the policy's `PathRules` |
//!
//! # Async strategy
//!
//! Ports that do I/O are `async` traits declared with `#[async_trait]` (the `async-trait` crate,
//! which the dependency rules allow for this crate). The reason is dyn compatibility. The engine
//! holds `Box<dyn Tx>` and `Box<dyn SandboxSession>` and passes `&dyn CancelSignal` and
//! `&mut dyn SandboxSession`, so a trait with `async fn` must work behind a pointer. Native
//! `async fn` in a trait (stable since Rust 1.75) cannot be used as `dyn Trait`, because each
//! method returns its own anonymous future type. `#[async_trait]` boxes that future. The cost is
//! one allocation per call, which is small next to a database round trip or a container start.
//!
//! The alternative, generics all the way up, would put a type parameter for every adapter on the
//! engine and every stage handler. ADR 0002 keeps adapter choice in the composition root, and
//! the slice plan sketches every port with `#[async_trait]`, so this crate follows the plan.
//! This crate depends on no executor: the traits name no runtime, and a caller may use any.
//!
//! Pure ports (`ModelRouter`, `AgentRegistry`, `OutputValidator`, and the clock and id
//! generator) are plain synchronous traits.
//!
//! # Rules every port follows
//!
//! * **Closed errors.** Each port has one error enum with a fixed set of variants. A variant
//!   carries plain data and never a boxed error, a library error type or a secret. An adapter
//!   maps every failure of its library onto the enum.
//! * **Fidelity.** Every port that has a stand-in reports [`Fidelity`](factory_domain::vocabulary::Fidelity)
//!   through `fidelity()`. A fake reports `fake`, and a production run refuses it: see
//!   [`require_permitted`].
//! * **A documented contract.** Each public trait states its preconditions, postconditions,
//!   closed error set, idempotency, and cancellation and timeouts in its documentation. A test
//!   (`trait_docs_state_the_contract`) fails if one is missing.
//! * **No merge, no ready.** `ChangeHost` has no method whose name starts with `merge`, `ready` or
//!   `undraft`.
//! * **No secret in `Debug`.** `FetchCredential`, `PushCredential`, `JobTokenSecret`, `RawOutput`,
//!   `TokenHash` and `EnvValue::Secret` show a placeholder.
//! * **Identifiers and time come in.** Nothing here reads the clock or makes an identifier. The
//!   `Clock` and `IdGenerator` ports do.

pub mod agent;
pub mod artifact;
pub mod clock;
pub mod githost;
pub mod issue_status;
pub mod paths;
pub mod process;
pub mod registry;
pub mod sandbox;
pub mod spec;
pub mod store;
pub mod workspace;

use factory_domain::vocabulary::{ExecutionMode, Fidelity};

/// A fake adapter was offered to a run that does not allow fakes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{component} is a fake and cannot take part in a production run")]
pub struct FakeRefused {
    /// The name of the component that was refused.
    pub component: String,
}

/// The gate that keeps a fake out of a production run (invariant INV-08).
///
/// The composition root calls this for every adapter it wires, with the adapter's name and the
/// fidelity it reports. In test mode every fidelity is allowed. In production mode only `real` is.
///
/// # Errors
/// Returns [`FakeRefused`] naming the component when a fake is offered in production mode.
pub fn require_permitted(
    mode: ExecutionMode,
    component: &str,
    fidelity: Fidelity,
) -> Result<(), FakeRefused> {
    if mode.permits(fidelity) {
        Ok(())
    } else {
        Err(FakeRefused {
            component: component.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fake_is_refused_in_production_and_allowed_in_test_mode() {
        let refused = require_permitted(ExecutionMode::Production, "store", Fidelity::Fake)
            .expect_err("production mode must refuse a fake");
        assert_eq!(refused.component, "store");
        assert!(refused.to_string().contains("store is a fake"));
        assert_eq!(
            require_permitted(ExecutionMode::Test, "store", Fidelity::Fake),
            Ok(())
        );
        assert_eq!(
            require_permitted(ExecutionMode::Production, "store", Fidelity::Real),
            Ok(())
        );
        assert_eq!(
            require_permitted(ExecutionMode::Test, "store", Fidelity::Real),
            Ok(())
        );
    }
}
