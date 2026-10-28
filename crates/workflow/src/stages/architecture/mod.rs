//! The `ARCHITECTURE` stage: a design for the frozen specification, checked by rules and not by
//! the word of the agent that made it.
//!
//! Work package `s1-stage-architecture-and-planning`. The stage gives the `architect` agent the
//! frozen specification and the repository map, in a read-only sandbox, and takes back a typed
//! design: the parts, the decisions with the alternatives weighed, the risks and the open
//! questions. It then does three things the agent cannot do for itself. It checks the design
//! against the specification by rule. It computes the risk tier from facts. And for work whose
//! tier the policy says needs one, it asks an independent critic, or records that there is none.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `design` | The architect's answer read into a typed design, strictly |
//! | `checks` | The traceability and completeness checks, and what counts as a trivial change |
//! | `risk` | The risk tier, from the job's facts and the facts the design shows |
//! | `critic` | The independent critic: what it receives, what it returns, and what is recorded |
//! | `adr` | The draft decision records |
//! | `seams` | The small traits the stage needs and no port offers |
//! | `shared` | What this stage and the planning stage do the same way |
//! | `handler` | `ArchitectureHandler`, its configuration, its contract and its deliverable names |
//! | `run` | `execute` |
//! | `gates` | `evaluate` |
//!
//! # Rules this stage keeps
//!
//! * **Every requirement is mapped, and nothing is added for its own sake.** A requirement or
//!   success criterion with no design element fails the traceability gate. So does a design element
//!   that names no requirement that exists, which is how a part added "for novelty" is caught.
//! * **A change that is not trivial shows its alternatives.** At least the configured number of
//!   alternatives over all decisions, and at least one named way the design can fail. A trivial
//!   change needs one design, and the record states why, from facts.
//! * **The risk tier is computed.** The policy engine reads facts of the job and facts the design
//!   shows. The architect's claim can raise the tier and never lowers it. A design that matches no
//!   criterion is high risk.
//! * **High-risk work is reviewed by someone else.** A critic must be a different agent, with a
//!   critic role and tools that only read, and it never sees the architect's summary. If the
//!   registry has none, the gate reports that it could not run and a person decides. The stage
//!   writes no verdict in a critic's name.
//! * **The agent's answer is never repaired.** It is checked against its schema and then read
//!   strictly. A design that fails a check is stored all the same so the gate can say what is wrong.
//! * **An answer with a secret in it is stored nowhere.** The agent reads the repository with its
//!   own tools, so a secret in a file it could read can come out in what it wrote. Every answer
//!   of an agent, the planner's and the critic's included, is checked with the redactor before
//!   anything is stored, and a stage that finds one fails with a policy denial.
//!
//! # Decisions that the specification leaves open
//!
//! * **`architecture-design` v1 has no field for assumptions, failure modes or a rollback.** The
//!   stage enforces what the schema carries: `risks` stand for the failure modes, and the decisions
//!   carry the alternatives and the consequences. Assumptions and a rollback note need a new schema
//!   version, which belongs to the agent definitions.
//! * **The architect's prompt has no input for the domain profile.** The profile is recorded as an
//!   input of the stage contract, and the architect does not receive it.
//! * **A critic's disagreement fails the gate.** The engine routes a failed gate to another run of
//!   the architect. The finer routing of a verdict by defect class (a specification or policy
//!   defect goes to a person) needs a `ReviewVerdict`, whose contract names a diff and gate reports
//!   that a design review does not have. A critic that asks for a person goes to the human gate.

pub mod adr;
pub mod checks;
pub mod critic;
pub mod design;
mod gates;
pub mod handler;
pub mod risk;
mod run;
pub mod seams;
pub mod shared;

pub use handler::{
    ADRS, ArchitectureConfig, ArchitectureDeps, ArchitectureHandler, COMPLETENESS_GATE,
    CRITIC_GATE, DESIGN, DOMAIN_PROFILE, GRANTED_TOOLS, RECORD, TRACEABILITY_GATE,
};
pub use seams::{
    AgentOutputCheck, CapabilityProbes, JobRisk, PreviousRound, RiskSource, RoundSource, SeamError,
    WorkspaceAgentSpecs,
};
pub use shared::AgentSettings;
