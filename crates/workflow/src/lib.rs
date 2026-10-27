//! The durable workflow engine and every stage handler: admission, scheduling, leases, retries,
//! gate evaluation and rework routing. An application crate: it depends on `factory-domain` and
//! `factory-ports` and never on an adapter.
