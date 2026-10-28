//! Liveness and readiness.
//!
//! * `/healthz` says the process is up and answering. It never reads the database, so a database
//!   outage does not make an orchestrator kill a process that would recover.
//! * `/readyz` is the composition library's health report (`factory_composition::health`): the
//!   schema is not behind the code, the policy is loaded and every port is acceptable to the
//!   profile. It answers 503 when any check does not pass, and a check that could not run is not a
//!   pass. The body names each check and its status and nothing else: the detail sentences of the
//!   report (counts of migrations, for one) stay out of an unauthenticated answer.

use axum::http::StatusCode;
use factory_composition::health::CheckStatus;
use serde_json::json;

use crate::answers::{Answer, Reply};
use crate::state::ApiState;

/// `GET /healthz`.
pub fn live() -> Answer {
    Ok(Reply::ok(json!({"status": "live"})))
}

/// `GET /readyz`.
pub async fn ready(state: &ApiState) -> Answer {
    let report = state.readiness().await;
    let checks: Vec<_> = report
        .checks
        .iter()
        .map(|check| {
            json!({
                "name": check.name,
                "status": match check.status {
                    CheckStatus::Pass => "pass",
                    CheckStatus::Fail => "fail",
                    CheckStatus::Blocked => "blocked",
                },
            })
        })
        .collect();
    let status = if report.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    Ok(Reply::new(
        status,
        json!({"ready": report.ready, "checks": checks}),
    ))
}
