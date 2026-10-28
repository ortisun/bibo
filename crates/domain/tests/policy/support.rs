//! The real policies, read from the fixtures that `factory-contracts` keeps equal to
//! `policies/security.yaml` and `policies/approval.yaml`.

use factory_domain::policy::SecurityPolicy;

const SECURITY: &str = include_str!("../fixtures/policy/security.json");

pub fn security() -> SecurityPolicy {
    serde_json::from_str(SECURITY).expect("the security fixture is a valid SecurityPolicy")
}

/// The security policy as a JSON value, for tests that change one key.
pub fn security_json() -> serde_json::Value {
    serde_json::from_str(SECURITY).expect("the security fixture is JSON")
}

/// Builds a security policy from JSON, failing the test with the reason when it is not valid.
pub fn security_from(value: serde_json::Value) -> SecurityPolicy {
    serde_json::from_value(value).expect("the changed security policy is still well formed")
}
