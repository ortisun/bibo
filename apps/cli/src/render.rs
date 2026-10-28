//! Plain English for what the API answered. Nothing here prints a token, a header or the raw body of
//! an answer the command did not understand.

use serde_json::Value;

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("unknown")
}

/// A line for an answer with an error code.
#[must_use]
pub fn refusal(status: u16, body: &Value) -> String {
    let code = body
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("no_reason_given");
    let field = body.get("field").and_then(Value::as_str);
    let meaning = match code {
        "unauthorized" => {
            "the token was not accepted (missing, expired, revoked or for another audience)"
        }
        "forbidden" => "you are not permitted to do this",
        "not_found" => "there is no such job, stage run or route for you",
        "bad_request" => "the request is not valid",
        "conflict" => {
            "this conflicts with a request already recorded; use another key or the same request"
        }
        "payload_too_large" => "the request is too large",
        "unsupported_media_type" => "the request was not sent as JSON",
        "request_timeout" => "the request was too slow",
        "rate_limited" => "too many requests; try again in a minute",
        "unavailable" => "the service cannot answer now; try again later",
        _ => "the API refused the request",
    };
    match field {
        Some(field) => format!("The API answered {status}: {meaning} (field: {field})."),
        None => format!("The API answered {status}: {meaning}."),
    }
}

/// The status of a job.
#[must_use]
pub fn job(body: &Value) -> String {
    let mut out = format!(
        "Job {} is {}.\nRepository: {}\nRequested by: {}\nAutonomy level {}, {} mode.\nCreated: {}\n",
        text(body, "job_id"),
        text(body, "status"),
        text(body, "repository_id"),
        text(body, "requester_id"),
        text(body, "autonomy_level"),
        text(body, "execution_mode"),
        text(body, "created_at"),
    );
    if let Some(done) = body.get("terminal_at").and_then(Value::as_str) {
        out.push_str(&format!("Finished: {done}\n"));
    }
    let stages = body
        .get("stages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if stages.is_empty() {
        out.push_str("No stage has started.\n");
    } else {
        out.push_str("Stages:\n");
        for stage in stages {
            out.push_str(&format!(
                "  {} run {}: {} (stage run {})\n",
                text(&stage, "kind"),
                stage.get("run_number").and_then(Value::as_u64).unwrap_or(0),
                text(&stage, "status"),
                text(&stage, "stage_run_id"),
            ));
        }
    }
    out
}

/// The timeline of a job.
#[must_use]
pub fn timeline(body: &Value) -> String {
    let entries = body
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = format!("Timeline of job {}:\n", text(body, "job_id"));
    if entries.is_empty() {
        out.push_str("  nothing has happened yet.\n");
    }
    for entry in entries {
        let line = match text(&entry, "kind") {
            "transition" => format!(
                "moved: {} ({}){}",
                text(&entry, "event"),
                text(&entry, "transition"),
                entry
                    .get("reason")
                    .and_then(Value::as_str)
                    .map_or_else(String::new, |reason| format!(", reason {reason}")),
            ),
            _ => format!(
                "recorded: {} ({})",
                text(&entry, "action"),
                text(&entry, "decision")
            ),
        };
        out.push_str(&format!("  {}  {line}\n", text(&entry, "at")));
    }
    if body.get("truncated").and_then(Value::as_bool) == Some(true) {
        out.push_str("  (the list is cut short)\n");
    }
    out
}

/// What a submission did.
#[must_use]
pub fn submitted(body: &Value, key: &str) -> String {
    let created = body
        .get("created")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    format!(
        "{} job {} ({}).\nIdempotency key: {key} (repeat the command with --key {key} to retry safely).\n",
        if created {
            "Created"
        } else {
            "Found the existing"
        },
        text(body, "job_id"),
        text(body, "status"),
    )
}

/// What a decision did.
#[must_use]
pub fn decided(body: &Value, key: &str) -> String {
    let applied = body
        .get("applied")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    format!(
        "Decision {} is recorded{}.\nIdempotency key: {key}\n",
        text(body, "decision_id"),
        if applied {
            " and applied"
        } else {
            "; the engine has not applied it yet"
        },
    )
}

/// The readiness report.
#[must_use]
pub fn readiness(body: &Value) -> String {
    let ready = body.get("ready").and_then(Value::as_bool) == Some(true);
    let mut out = format!(
        "The API is {}.\n",
        if ready { "ready" } else { "not ready" }
    );
    for check in body
        .get("checks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        out.push_str(&format!(
            "  {}: {}\n",
            text(&check, "name"),
            text(&check, "status")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_refusal_says_what_it_means_and_names_the_field() {
        let line = refusal(400, &json!({"error": "bad_request", "field": "text"}));
        assert!(line.contains("400") && line.contains("field: text"));
        assert!(refusal(401, &json!({"error": "unauthorized"})).contains("token was not accepted"));
        assert!(refusal(418, &Value::Null).contains("refused"));
    }

    #[test]
    fn a_job_is_described_in_sentences() {
        let text = job(&json!({"job_id": "j", "status": "ACTIVE", "stages": [
            {"kind": "INTAKE", "run_number": 1, "status": "PASSED", "stage_run_id": "s"}]}));
        assert!(text.starts_with("Job j is ACTIVE."));
        assert!(text.contains("INTAKE run 1: PASSED"));
    }

    #[test]
    fn a_decision_that_is_not_applied_says_so() {
        let line = decided(&json!({"decision_id": "d", "applied": false}), "k");
        assert!(line.contains("has not applied it yet"));
    }
}
