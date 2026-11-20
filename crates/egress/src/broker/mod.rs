//! The model broker, without its network side: tokens, caps, metering and the per-job ledger.
//!
//! [`BrokerCore`] implements the `ModelBroker` and `MeteringOps` ports. The HTTP listener
//! ([`crate::http`]) calls the same core, so what the contract suite proves about the ports is
//! what the listener enforces.

pub mod audit;
pub mod caps;
pub mod core;
pub mod pricing;
pub mod provider;
pub mod shape;
pub mod token;

pub use audit::{AuditEvent, AuditKind, AuditSink, JsonLinesAudit, MemoryAudit, NullAudit};
pub use caps::{CapPolicy, PerRequestCaps, Refusal, RevokeReason};
pub use core::{
    BrokerCore, BrokerParts, JobLedger, LedgerEntry, LedgerKind, Outcome, Permit, RequestFacts,
    TokenView,
};
pub use pricing::{ModelPrice, PriceList, PriceTable, TokenCounts};
pub use provider::Provider;
pub use token::{
    EntropyError, SystemEntropy, TOKEN_PREFIX, TokenEntropy, TokenHash, has_token_shape,
    mint_secret,
};
