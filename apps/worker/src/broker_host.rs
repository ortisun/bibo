//! The model broker, hosted in the worker's process.
//!
//! The code is `factory_composition::broker_host`: the troubleshooter (ADR 0021) hosts the same
//! broker in its own process, so the module moved to the shared composition library (ADR 0015).
//! This module keeps the worker's paths (`factory_worker::broker_host::start`) for its callers.

pub use factory_composition::broker_host::{
    CredentialSetting, HostedBroker, read_subscription_token, start,
};
