//! The real policies, read from the fixtures that `factory-contracts` keeps equal to
//! `policies/security.yaml` and `policies/approval.yaml`.

use factory_domain::policy::{ApprovalPolicy, SecurityPolicy};

const SECURITY: &str = include_str!("../fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../fixtures/policy/approval.json");

pub fn security() -> SecurityPolicy {
    serde_json::from_str(SECURITY).expect("the security fixture is a valid SecurityPolicy")
}

pub fn approval() -> ApprovalPolicy {
    serde_json::from_str(APPROVAL).expect("the approval fixture is a valid ApprovalPolicy")
}

/// The security policy as a JSON value, for tests that change one key.
pub fn security_json() -> serde_json::Value {
    serde_json::from_str(SECURITY).expect("the security fixture is JSON")
}

/// The approval policy as a JSON value, for tests that change one key.
pub fn approval_json() -> serde_json::Value {
    serde_json::from_str(APPROVAL).expect("the approval fixture is JSON")
}

/// Builds a security policy from JSON, failing the test with the reason when it is not valid.
pub fn security_from(value: serde_json::Value) -> SecurityPolicy {
    serde_json::from_value(value).expect("the changed security policy is still well formed")
}

/// Builds an approval policy from JSON.
pub fn approval_from(value: serde_json::Value) -> ApprovalPolicy {
    serde_json::from_value(value).expect("the changed approval policy is still well formed")
}
