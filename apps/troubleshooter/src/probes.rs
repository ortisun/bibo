//! The deterministic probes (ADR 0021, Decision 2): what each kind calls, how its answer is read,
//! and how the value is compared with the threshold.
//!
//! | Kind | Source | Call | Value |
//! |---|---|---|---|
//! | `promql_threshold` | VictoriaMetrics | gateway `vm_query` (`{"query": ...}`) on the control-plane path | the sample of a scalar, or of each series of a vector (the last sample of a matrix); trips when any series trips |
//! | `sql_check` | the factory database | gateway `pg_factory_health` (`{"window_hours": ...}`) | a count read from the named check's section |
//! | `datadog_monitors_alerting` | Datadog | gateway `datadog_search_monitors` (`{"query": ...}`) | the number of monitors returned |
//! | `http_health` | the factory API | a direct GET of `api_health_url` + route, with a timeout | the HTTP status, `0` when nothing answered |
//!
//! A gateway probe whose call does not end `ok`, or whose answer cannot be read, is
//! `source_unavailable`: the troubleshooter raises that as a finding without the model. An answer
//! with no sample is `no_data`, which the policy has no setting for, so it never trips and is
//! recorded as such. An HTTP health probe is not a source: an API that does not answer is exactly
//! what it watches, so no answer is status `0` and is compared like any other status.
//!
//! The answer formats of the upstreams were read from their documentation and not called against
//! a real server (ADR 0021, "What was checked"); the readers accept the documented envelopes and
//! call anything else unreadable.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::policy::troubleshooting::{Probe, ProbeKind, Upstream};
use factory_domain::troubleshooting::GatewayCallId;
use factory_domain::values::Timestamp;
use factory_mcp_gateway::{Gateway, Outcome};
use factory_storage::pg::troubleshooting::ProbeOutcome;
use serde_json::{Map, Value, json};

use crate::exact::{Exact, trips};

/// What one probe found.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeObservation {
    /// The probe, as the policy names it.
    pub probe: Probe,
    /// What it found.
    pub outcome: ProbeOutcome,
    /// The observed value, exact.
    pub value: Option<Exact>,
    /// The gateway call it ran under, when it ran through the gateway and the gateway recorded it.
    pub call_id: Option<GatewayCallId>,
    /// The source, for a probe that runs through the gateway.
    pub upstream: Option<Upstream>,
    /// Why the source was unavailable: the call's outcome or `unreadable`.
    pub reason: Option<String>,
    /// When it ran.
    pub observed_at: Timestamp,
}

/// Reads the HTTP status of a URL. A seam so that tests run without the network.
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// The status of a GET of `url`, or `None` when nothing answered within `timeout`.
    async fn status(&self, url: &str, timeout: Duration) -> Option<u16>;
}

/// The real health check: a blocking GET with rustls, no redirect and no proxy, on a blocking
/// thread.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpHealth;

#[async_trait]
impl HealthCheck for HttpHealth {
    async fn status(&self, url: &str, timeout: Duration) -> Option<u16> {
        let url = url.to_owned();
        tokio::task::spawn_blocking(move || {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .https_only(!url.starts_with("http://"))
                .max_redirects(0)
                .proxy(None)
                .timeout_global(Some(timeout))
                .build()
                .into();
            agent
                .get(&url)
                .call()
                .ok()
                .map(|response| response.status().as_u16())
        })
        .await
        .ok()
        .flatten()
    }
}

/// What the probes may reach.
pub struct ProbeSources {
    /// The gateway, with the run of this pass open.
    pub gateway: Gateway,
    /// The HTTP health check.
    pub health: Arc<dyn HealthCheck>,
    /// The base URL of the factory API, such as `http://127.0.0.1:8080`.
    pub api_base_url: String,
    /// How long the health GET waits.
    pub health_timeout: Duration,
    /// VictoriaMetrics is configured.
    pub victoriametrics: bool,
    /// Datadog is configured.
    pub datadog: bool,
}

/// The gateway tool a probe kind calls.
#[must_use]
pub const fn gateway_tool(kind: ProbeKind) -> Option<(&'static str, Upstream)> {
    match kind {
        ProbeKind::PromqlThreshold => Some(("vm_query", Upstream::Victoriametrics)),
        ProbeKind::SqlCheck => Some(("pg_factory_health", Upstream::Postgres)),
        ProbeKind::DatadogMonitorsAlerting => Some(("datadog_search_monitors", Upstream::Datadog)),
        ProbeKind::HttpHealth => None,
    }
}

fn observation(probe: &Probe, now: &Timestamp, outcome: ProbeOutcome) -> ProbeObservation {
    ProbeObservation {
        probe: probe.clone(),
        outcome,
        value: None,
        call_id: None,
        upstream: gateway_tool(probe.kind).map(|(_, upstream)| upstream),
        reason: None,
        observed_at: *now,
    }
}

/// Runs one probe in the gateway run `run_id`.
pub async fn run_probe(
    sources: &ProbeSources,
    run_id: &str,
    probe: &Probe,
    now: &Timestamp,
) -> ProbeObservation {
    let mut found = observation(probe, now, ProbeOutcome::Ok);
    let enabled = match probe.kind {
        ProbeKind::PromqlThreshold => sources.victoriametrics,
        ProbeKind::DatadogMonitorsAlerting => sources.datadog,
        ProbeKind::SqlCheck | ProbeKind::HttpHealth => true,
    };
    if !enabled {
        found.outcome = ProbeOutcome::Disabled;
        return found;
    }
    if probe.kind == ProbeKind::HttpHealth {
        let url = format!(
            "{}/{}",
            sources.api_base_url.trim_end_matches('/'),
            probe.query.trim_start_matches('/')
        );
        let status = sources
            .health
            .status(&url, sources.health_timeout)
            .await
            .unwrap_or(0);
        let value = Exact::parse(&status.to_string()).unwrap_or(Exact::NaN);
        found.outcome = if trips(probe.comparator, &value, probe.threshold) {
            ProbeOutcome::Tripped
        } else {
            ProbeOutcome::Ok
        };
        found.value = Some(value);
        return found;
    }
    let Some((tool, _)) = gateway_tool(probe.kind) else {
        return found;
    };
    let arguments = arguments_of(probe);
    let result = match sources
        .gateway
        .call_for_run(run_id, tool, Some(arguments))
        .await
    {
        Ok(result) => result,
        Err(error) => {
            found.outcome = ProbeOutcome::SourceUnavailable;
            found.reason = Some(format!("the gateway refused the call: {error}"));
            return found;
        }
    };
    found.call_id = GatewayCallId::parse(&result.call_id.to_string()).ok();
    if result.outcome != Outcome::Ok {
        found.outcome = ProbeOutcome::SourceUnavailable;
        found.reason = Some(result.outcome.to_string());
        return found;
    }
    let values = match probe.kind {
        ProbeKind::PromqlThreshold => promql_values(&result.text),
        ProbeKind::SqlCheck => sql_check_count(&result.text, &probe.query).map(|v| vec![v]),
        ProbeKind::DatadogMonitorsAlerting => monitor_count(&result.text).map(|v| vec![v]),
        ProbeKind::HttpHealth => None,
    };
    let Some(values) = values else {
        found.outcome = ProbeOutcome::SourceUnavailable;
        found.reason = Some("unreadable".to_owned());
        return found;
    };
    if values.is_empty() {
        found.outcome = ProbeOutcome::NoData;
        return found;
    }
    let tripping = values
        .iter()
        .find(|value| trips(probe.comparator, value, probe.threshold));
    match tripping {
        Some(value) => {
            found.outcome = ProbeOutcome::Tripped;
            found.value = Some(value.clone());
        }
        None => {
            found.value = values.into_iter().next();
        }
    }
    found
}

fn arguments_of(probe: &Probe) -> Map<String, Value> {
    let value = match probe.kind {
        ProbeKind::SqlCheck => {
            let hours = probe.window_s.div_ceil(3600).clamp(1, 720);
            json!({ "window_hours": hours })
        }
        _ => json!({ "query": probe.query }),
    };
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// The JSON of a result text, or of its first line that parses (a result can carry a truncation
/// marker after the document, which then makes it unreadable on purpose: a cut answer is not a
/// value).
fn document(text: &str) -> Option<Value> {
    serde_json::from_str(text.trim()).ok()
}

/// A sample `[<time>, "<value>"]` as an exact number.
fn sample(value: &Value) -> Option<Exact> {
    let pair = value.as_array()?;
    let text = pair.get(1)?;
    match text {
        Value::String(text) => Exact::parse(text),
        Value::Number(number) => Exact::parse(&number.to_string()),
        _ => None,
    }
}

/// The values of a PromQL answer: the Prometheus envelope (`{"status":"success","data":{...}}`)
/// or its `data` object alone. `Some(vec![])` for an empty result (no data); `None` for anything
/// that is not one of the four result types.
#[must_use]
pub fn promql_values(text: &str) -> Option<Vec<Exact>> {
    let root = document(text)?;
    if root.get("status").and_then(Value::as_str) == Some("error") {
        return None;
    }
    let data = root.get("data").unwrap_or(&root);
    let result = data.get("result")?;
    match data.get("resultType").and_then(Value::as_str)? {
        "scalar" | "string" => Some(vec![sample(result)?]),
        "vector" => result
            .as_array()?
            .iter()
            .map(|series| sample(series.get("value")?))
            .collect(),
        "matrix" => result
            .as_array()?
            .iter()
            .filter_map(|series| series.get("values")?.as_array()?.last().cloned())
            .map(|last| sample(&last))
            .collect(),
        _ => None,
    }
}

fn rows_of<'a>(root: &'a Value, section: &str) -> Option<(&'a Vec<Value>, u64)> {
    let section = root.get(section)?;
    let rows = section.get("rows")?.as_array()?;
    let omitted = section
        .get("truncated")
        .and_then(|cut| cut.get("omitted_rows"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Some((rows, omitted))
}

fn sum_of(rows: &[Value], column: &str) -> Option<u64> {
    rows.iter().try_fold(0_u64, |total, row| {
        let value = row.get(column)?;
        let count = value
            .as_u64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))?;
        Some(total.saturating_add(count))
    })
}

/// The count of a `sql_check` probe, read from the answer of `pg_factory_health`. The policy's
/// check ids map onto the sections the tool returns:
///
/// | Check | Section | Count |
/// |---|---|---|
/// | `leases_past_expiry` | `leases_past_expiry` | rows |
/// | `stage_runs_past_deadline` | `attempts_past_deadline` | rows |
/// | `human_waits_past_expiry` | `waiting_for_a_person` | rows whose `has_expired_approval` is true |
/// | `jobs_by_state` | `jobs_by_status` | the sum of `jobs` |
/// | `failures_by_reason` | `failures_in_window` | the sum of `failures` |
///
/// A row count includes the rows the byte cap cut (`truncated.omitted_rows`); past the row cap it
/// is a lower bound, which is enough for a probe that trips over a small threshold.
#[must_use]
pub fn sql_check_count(text: &str, check: &str) -> Option<Exact> {
    let root = document(text)?;
    let count = match check {
        "leases_past_expiry" => {
            let (rows, omitted) = rows_of(&root, "leases_past_expiry")?;
            (rows.len() as u64).saturating_add(omitted)
        }
        "stage_runs_past_deadline" => {
            let (rows, omitted) = rows_of(&root, "attempts_past_deadline")?;
            (rows.len() as u64).saturating_add(omitted)
        }
        "human_waits_past_expiry" => {
            let (rows, _) = rows_of(&root, "waiting_for_a_person")?;
            rows.iter()
                .filter(|row| {
                    row.get("has_expired_approval")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .count() as u64
        }
        "jobs_by_state" => sum_of(rows_of(&root, "jobs_by_status")?.0, "jobs")?,
        "failures_by_reason" => sum_of(rows_of(&root, "failures_in_window")?.0, "failures")?,
        _ => return None,
    };
    Exact::parse(&count.to_string())
}

/// The number of monitors in a Datadog answer: a list, an object with a `monitors` list, or an
/// object with a whole `total` or `count`. Not checked against the real Datadog server.
#[must_use]
pub fn monitor_count(text: &str) -> Option<Exact> {
    let root = document(text)?;
    let count = match &root {
        Value::Array(items) => items.len() as u64,
        Value::Object(map) => match map.get("monitors") {
            Some(Value::Array(items)) => items.len() as u64,
            _ => map
                .get("total")
                .or_else(|| map.get("count"))
                .and_then(Value::as_u64)?,
        },
        _ => return None,
    };
    Exact::parse(&count.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promql_answers_of_every_shape_are_read_exactly() {
        let vector = r#"{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1763630000,"0.30000000000000004"]}]}}"#;
        assert_eq!(
            promql_values(vector),
            Some(vec![Exact::parse("0.30000000000000004").expect("a number")])
        );
        let scalar = r#"{"resultType":"scalar","result":[1763630000,"12"]}"#;
        assert_eq!(
            promql_values(scalar),
            Some(vec![Exact::parse("12").expect("n")])
        );
        let empty = r#"{"status":"success","data":{"resultType":"vector","result":[]}}"#;
        assert_eq!(promql_values(empty), Some(vec![]), "no data, not an error");
        let matrix =
            r#"{"resultType":"matrix","result":[{"metric":{},"values":[[1,"1"],[2,"7"]]}]}"#;
        assert_eq!(
            promql_values(matrix),
            Some(vec![Exact::parse("7").expect("n")])
        );
        assert_eq!(
            promql_values(r#"{"status":"error","error":"bad query"}"#),
            None
        );
        assert_eq!(promql_values("not json"), None);
        assert_eq!(
            promql_values(r#"{"resultType":"vector","result":[{"value":[1,"x"]}]}"#),
            None
        );
    }

    #[test]
    fn sql_checks_count_their_own_section() {
        let text = r#"{"jobs_by_status":{"rows":[{"status":"ACTIVE","jobs":3},{"status":"DONE","jobs":"2"}],"returned_rows":2,"more_rows_than_limit":false},
            "attempts_past_deadline":{"rows":[{}],"returned_rows":1,"more_rows_than_limit":false},
            "leases_past_expiry":{"rows":[{},{}],"returned_rows":2,"more_rows_than_limit":false,"truncated":{"omitted_rows":3}},
            "waiting_for_a_person":{"rows":[{"has_expired_approval":true},{"has_expired_approval":false}],"returned_rows":2,"more_rows_than_limit":false},
            "failures_in_window":{"rows":[{"failures":4},{"failures":1}],"returned_rows":2,"more_rows_than_limit":false},
            "outbox_backlog":{"rows":[],"returned_rows":0,"more_rows_than_limit":false}}"#;
        let count = |check| sql_check_count(text, check).map(|v| v.canonical());
        assert_eq!(count("jobs_by_state").as_deref(), Some("5"));
        assert_eq!(count("stage_runs_past_deadline").as_deref(), Some("1"));
        assert_eq!(count("leases_past_expiry").as_deref(), Some("5"));
        assert_eq!(count("human_waits_past_expiry").as_deref(), Some("1"));
        assert_eq!(count("failures_by_reason").as_deref(), Some("5"));
        assert_eq!(count("unknown_check"), None);
    }

    #[test]
    fn monitors_are_counted_from_the_documented_shapes() {
        assert_eq!(
            monitor_count("[{},{}]").map(|v| v.canonical()).as_deref(),
            Some("2")
        );
        assert_eq!(
            monitor_count(r#"{"monitors":[{}]}"#)
                .map(|v| v.canonical())
                .as_deref(),
            Some("1")
        );
        assert_eq!(
            monitor_count(r#"{"total":0}"#)
                .map(|v| v.canonical())
                .as_deref(),
            Some("0")
        );
        assert_eq!(monitor_count("no monitors"), None);
    }
}
