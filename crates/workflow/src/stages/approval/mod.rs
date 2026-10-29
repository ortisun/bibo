//! The approval stage: a person decides, bound to what they saw.
//!
//! The stage is a human gate. The handler stores an **approval request** (the pull request and the
//! binding the person is shown) and hands the engine a gate report that says a person is needed.
//! The decision itself comes as an [`ApprovalCommand`] from any of three channels, and
//! [`ApprovalService`] applies it: it judges the command with [`judge`], records it with
//! `ApprovalOps::record_approval`, and asks the engine to move the stage run.
//!
//! # What an approval is bound to
//!
//! The head of the pull request, its git tree, the base commit, the evidence manifest, the version
//! of the specification and the last entry of the evidence ledger, all as the person saw them. The
//! approval is refused when any of them differs now, when a value the gate reports are bound to
//! changed, when a gate is not clear, when a translation warning has no decision, or when more
//! than 72 hours passed. An approval that is recorded stops counting when the head or the base
//! moves.
//!
//! # Who may decide
//!
//! The policy engine decides from the allowlist by **numeric id**: the designation the action
//! names, the autonomy level, and separation of duties (the requester does not approve a change
//! that policy marks as risky, and a bot or an App never approves). The engine checks the role
//! again from its own source. A refusal of authority gets no reply and is audited.
//!
//! # What this never does
//!
//! It never merges, never marks a pull request ready and never deploys. There is no verb for it:
//! [`parse_verb`] gives `Unknown` for `merge`, `deploy`, `ready` and `undraft`, and the code host
//! port has no such call. After an approval the stage run passes and the job reaches the approved
//! state; the person merges on the code host.
//!
//! # The parsers
//!
//! The dashboard, the command line and the comment parser belong to the composition packages.
//! Each builds an [`ApprovalCommand`]; the type says what it must provide.

pub mod command;
pub mod contract;
pub mod handler;
pub mod judge;
pub mod request;
pub mod seams;
pub mod service;
pub mod warnings;

pub use command::{ApprovalCommand, CommentEvidence, Seen, Sender, Verb, VerbParse, parse_verb};
pub use contract::{GATE, REQUEST};
pub use handler::{ApprovalConfig, ApprovalHandler, ApprovalHandlerDeps};
pub use judge::{Accepted, Context, Live, NotACommand, Refusal, judge};
pub use request::{ApprovalRequest, TRANSLATION_WARNING, VALID_HOURS};
pub use seams::ApprovalSources;
pub use service::{ApprovalDeps, ApprovalService, Outcome, ServiceError};
