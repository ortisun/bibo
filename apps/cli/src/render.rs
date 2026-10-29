//! Plain English for what the API answered. Nothing here prints a token, a header or the raw body of
//! an answer the command did not understand.

use std::borrow::Cow;

use factory_ports::paths::hides_text;
use serde_json::Value;

/// True for a character that a terminal acts on or that changes how the text around it reads: every
/// control (the C0 range, DEL and the C1 range, which holds the single-character CSI 0x9B, the
/// operating system command 0x9D and the device control string 0x90), and every character that
/// hides, reorders or splits text. The second part is the rule that names in a repository are held
/// to, [`hides_text`]: the whole Unicode category Cf (zero-width marks, bidirectional controls and
/// isolates, the soft hyphen, the Arabic letter mark, the deprecated format characters U+206A to
/// U+206F, the byte order mark), the line and paragraph separators, the tag characters, and the
/// fillers that render as nothing. One function decides it for both, so a character that cannot be in
/// a path cannot be in a line the CLI prints (RR-9).
fn is_unsafe(c: char) -> bool {
    c.is_control() || hides_text(c)
}

/// Text that came from the server, made safe to print on one line: every character that
/// [`is_unsafe`] becomes U+FFFD. The real API sends only values typed on its side, so nothing a
/// tenant writes reaches a terminal; a server that is wrong, replaced or compromised can send a
/// clear-screen, a new window title or a carriage return that rewrites a line already printed, and
/// the CLI must not carry it to the person's terminal (API-10).
#[must_use]
pub fn printable(value: &str) -> Cow<'_, str> {
    if value.chars().any(is_unsafe) {
        Cow::Owned(
            value
                .chars()
                .map(|c| if is_unsafe(c) { '\u{fffd}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(value)
    }
}

/// A finished block of lines, made safe: line feeds and tabs stay (the block is ours), every other
/// unsafe character goes. The last line of defence at the output, behind [`printable`] on each field.
#[must_use]
pub fn printable_block(block: &str) -> Cow<'_, str> {
    let bad = |c: char| is_unsafe(c) && !matches!(c, '\n' | '\t');
    if block.chars().any(bad) {
        Cow::Owned(
            block
                .chars()
                .map(|c| if bad(c) { '\u{fffd}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(block)
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Cow<'a, str> {
    printable(value.get(key).and_then(Value::as_str).unwrap_or("unknown"))
}

/// A line for an answer with an error code.
#[must_use]
pub fn refusal(status: u16, body: &Value) -> String {
    let code = body
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("no_reason_given");
    let field = body.get("field").and_then(Value::as_str).map(printable);
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
        out.push_str(&format!("Finished: {}\n", printable(done)));
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

/// The gate reports of a job, one line each.
#[must_use]
pub fn gate_reports(body: &Value) -> String {
    let reports = body
        .get("reports")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if reports.is_empty() {
        return "No gate has reported yet.\n".to_owned();
    }
    let mut out = format!("Gate reports ({}):\n", reports.len());
    for report in &reports {
        let hash = text(report, "report_sha256");
        if report.get("readable").and_then(Value::as_bool) == Some(false) {
            out.push_str(&format!(
                "  {}: a report that could not be read, {hash}\n",
                text(report, "stage"),
            ));
            continue;
        }
        let code = report
            .get("code")
            .and_then(Value::as_str)
            .map(|code| format!(" ({})", printable(code)))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {} {}: {}{code}, {hash}\n",
            text(report, "stage"),
            text(report, "gate"),
            text(report, "outcome"),
        ));
    }
    if body.get("truncated").and_then(Value::as_bool) == Some(true) {
        out.push_str("There are more reports than this list holds.\n");
    }
    out.push_str(
        "Read one with: factory-cli artifact --api URL --token-file FILE JOB <the hash without sha256:>\n",
    );
    out
}

/// The specification draft a person is asked to approve, with the values an approval needs.
#[must_use]
pub fn draft(body: &Value) -> String {
    let mut out = format!(
        "Specification stage run {} of job {} is {}.\n",
        text(body, "stage_run_id"),
        text(body, "job_id"),
        text(body, "status"),
    );
    match body.get("draft").filter(|draft| !draft.is_null()) {
        None => out.push_str("The stage run has kept no draft yet.\n"),
        Some(draft) => out.push_str(&format!(
            "Draft {} saved at {}.\nCommit that holds it: {}\nFeature directory: {}\nDraft document: {}\n",
            draft.get("number").and_then(Value::as_u64).unwrap_or(0),
            text(draft, "saved_at"),
            text(draft, "commit"),
            text(draft, "feature_directory"),
            text(draft, "artifact_sha256"),
        )),
    }
    match body.get("ledger_head").filter(|head| !head.is_null()) {
        None => out.push_str("The ledger of the job is empty.\n"),
        Some(head) => out.push_str(&format!(
            "Ledger head: entry {}, {}\n",
            head.get("sequence").and_then(Value::as_u64).unwrap_or(0),
            text(head, "hash"),
        )),
    }
    let approval = body.get("approval").cloned().unwrap_or(Value::Null);
    let hours = approval
        .get("window_hours")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if approval.get("approvable").and_then(Value::as_bool) == Some(true) {
        out.push_str(&format!(
            "To approve what you read: head={} evidence={}\nA decision stays good for {hours} hours.\n",
            text(&approval, "head"),
            text(&approval, "evidence"),
        ));
    } else {
        out.push_str("It cannot be approved now: the stage run does not wait for a person or holds no draft.\n");
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
        let line = match text(&entry, "kind").as_ref() {
            "transition" => format!(
                "moved: {} ({}){}",
                text(&entry, "event"),
                text(&entry, "transition"),
                entry.get("reason").and_then(Value::as_str).map_or_else(
                    String::new,
                    |reason| format!(", reason {}", printable(reason))
                ),
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
            "; the worker has not applied it yet, and the timeline shows the outcome"
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
    fn nothing_the_server_sends_reaches_the_terminal_as_a_control_character() {
        let nasty = "\u{1b}[2J\u{1b}]0;owned\u{7}\u{1b}[31mRED\r\nfake line\u{9b}1A\u{202e}rtl\u{200b}x\u{7f}";
        let clean = printable(nasty);
        assert!(
            !clean.chars().any(is_unsafe),
            "{clean:?} still holds an unsafe character"
        );
        assert!(
            clean.contains("RED") && clean.contains("fake line"),
            "the words stay"
        );
        // Ordinary text, including accents and symbols, is not touched, and is not copied.
        assert!(matches!(
            printable("Zürich ✓ 日本"),
            Cow::Borrowed("Zürich ✓ 日本")
        ));
    }

    #[test]
    fn every_field_of_every_answer_is_cleaned() {
        let evil = "\u{1b}[31mX";
        let everything = json!({
            "job_id": evil, "status": evil, "repository_id": evil, "requester_id": evil,
            "autonomy_level": evil, "execution_mode": evil, "created_at": evil, "terminal_at": evil,
            "stages": [{"kind": evil, "status": evil, "stage_run_id": evil, "run_number": 1}],
            "entries": [
                {"kind": "transition", "at": evil, "event": evil, "transition": evil, "reason": evil},
                {"kind": "audit", "at": evil, "action": evil, "decision": evil}
            ],
            "decision_id": evil, "error": "bad_request", "field": evil, "created": true,
            "checks": [{"name": evil, "status": evil}], "ready": true,
        });
        for (name, rendered) in [
            ("job", job(&everything)),
            ("timeline", timeline(&everything)),
            ("submitted", submitted(&everything, "key")),
            ("decided", decided(&everything, "key")),
            ("readiness", readiness(&everything)),
            ("refusal", refusal(400, &everything)),
        ] {
            assert!(
                !rendered.contains('\u{1b}'),
                "{name} carried an escape: {rendered:?}"
            );
        }
    }

    #[test]
    fn a_block_keeps_its_line_feeds_and_loses_the_rest() {
        assert_eq!(printable_block("a\nb\tc"), "a\nb\tc");
        assert_eq!(
            printable_block("a\u{1b}[2Jb\r\n"),
            "a\u{fffd}[2Jb\u{fffd}\n"
        );
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
        assert!(line.contains("the timeline shows the outcome"));
    }
}
