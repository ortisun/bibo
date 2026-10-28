//! The metrics of the conventions page exist, follow its naming rules, and are the ones the engine
//! emits (package `s1-observability-instrumentation`).
//!
//! Three kinds of check:
//!
//! * **The registry.** The metrics table of the page names queue depth, duration, gate failures,
//!   retries and spend, and every row follows the naming rules of section 2: prefix, `_total` on
//!   counters only, the unit in the name, labels that are single words and not attribute keys.
//! * **What is emitted.** The engine runs a job through a pass, a failed gate, a retry and an agent
//!   that spends, and a recording `Subscriber` reads the metric events back. Each must name a
//!   metric of the table, with the instrument kind the table gives, and only the labels the table
//!   lists.
//! * **What is not emitted yet.** A metric on the page that the engine never records is written as a
//!   test marked as a confirmed gap and ignored, so the build stays green while the gap stays
//!   visible. Run them with `cargo nextest run -p factory-workflow --test metric_names
//!   --run-ignored only`.

mod support;
mod telemetry_support;

use std::collections::BTreeMap;

use factory_domain::vocabulary::StageKind;
use factory_workflow::handlers::StageError;
use support::{Eval, Step, World};
use telemetry_support::{EventRecord, Recorder, names_in, table};

// ---- The registry ------------------------------------------------------------------------

struct Row {
    name: String,
    kind: String,
    unit: String,
    labels: Vec<String>,
}

fn metrics() -> Vec<Row> {
    table("metrics")
        .into_iter()
        .map(|row| Row {
            name: row[0].clone(),
            kind: row[1].clone(),
            unit: row[2].clone(),
            labels: names_in(&row[3]),
        })
        .collect()
}

fn row(name: &str) -> Row {
    metrics()
        .into_iter()
        .find(|m| m.name == name)
        .unwrap_or_else(|| panic!("the conventions page has no metric {name}"))
}

#[test]
fn the_registry_has_queue_depth_duration_gate_failures_retries_and_spend() {
    for (question, name) in [
        ("queue depth", "factory_queue_depth"),
        ("duration", "factory_stage_duration_seconds"),
        ("gate failures", "factory_gate_failures_total"),
        ("retries", "factory_retries_total"),
        ("spend", "factory_spend_usd_total"),
        ("error rate", "factory_stage_runs_total"),
    ] {
        assert!(
            metrics().iter().any(|m| m.name == name),
            "the metrics table has no metric for {question}: {name}"
        );
    }
    assert_eq!(
        metrics().len(),
        6,
        "a metric was added: say what this file does about it"
    );
}

#[test]
fn every_metric_follows_the_naming_rules() {
    for metric in metrics() {
        let name = &metric.name;
        assert!(
            name.starts_with("factory_"),
            "{name} lacks the factory_ prefix"
        );
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{name} is not lower case with underscores"
        );
        match metric.kind.as_str() {
            "counter" => assert!(
                name.ends_with("_total"),
                "counter {name} must end in _total"
            ),
            "gauge" | "histogram" => {
                assert!(
                    !name.ends_with("_total"),
                    "{} {name} must not end in _total",
                    metric.kind
                );
            }
            other => panic!("{name} has the unknown type {other}"),
        }
        if metric.unit == "s" {
            assert!(
                name.ends_with("_seconds"),
                "{name} has the unit s and must say seconds"
            );
        }
        if metric.unit.contains("USD") {
            assert!(
                name.ends_with("_usd_total"),
                "{name} counts dollars and must say so"
            );
        }
        assert!(!metric.unit.is_empty(), "{name} has no unit");
    }
}

#[test]
fn labels_are_single_lower_case_words_and_never_attribute_keys() {
    let label_rows = table("labels");
    let known: Vec<&str> = label_rows.iter().map(|r| r[0].as_str()).collect();
    let attribute_keys: Vec<String> = table("attributes")
        .into_iter()
        .map(|r| r[0].clone())
        .collect();
    for label in &known {
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase()),
            "label {label} is not one lower case word"
        );
        assert!(
            !attribute_keys.iter().any(|key| key == label),
            "label {label} repeats an attribute key"
        );
    }
    for metric in metrics() {
        for label in &metric.labels {
            assert!(
                known.contains(&label.as_str()),
                "{} uses the unknown label {label}",
                metric.name
            );
        }
    }
}

// ---- What the engine emits ---------------------------------------------------------------

#[derive(Debug, Clone)]
struct Metric {
    kind: &'static str,
    name: String,
    labels: BTreeMap<String, String>,
}

/// The metric events among the recorded events: a field named `monotonic_counter.<name>`,
/// `histogram.<name>` or `gauge.<name>`, with every other field a label.
fn metric_events(events: &[EventRecord]) -> Vec<Metric> {
    let mut found = Vec::new();
    for event in events {
        for key in event.fields.keys() {
            let (kind, name) = if let Some(name) = key.strip_prefix("monotonic_counter.") {
                ("counter", name)
            } else if let Some(name) = key.strip_prefix("histogram.") {
                ("histogram", name)
            } else if let Some(name) = key.strip_prefix("gauge.") {
                ("gauge", name)
            } else {
                continue;
            };
            let labels = event
                .fields
                .iter()
                .filter(|(other, _)| *other != key && *other != "message")
                .map(|(label, value)| (label.clone(), value.text()))
                .collect();
            found.push(Metric {
                kind,
                name: name.to_owned(),
                labels,
            });
        }
    }
    found
}

/// Runs the first stage of a fresh job, after `prepare` changed the world, and returns the metrics
/// it emitted.
async fn first_stage_metrics(prepare: impl FnOnce(&World)) -> Vec<Metric> {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    prepare(&world);
    world.admitted_job().await;
    world.advance(400);
    let claimed = world.claim_one("worker-1").await;
    world
        .engine
        .run_attempt(&claimed)
        .await
        .expect("the attempt runs");
    metric_events(&recorder.events())
}

fn emitted(metrics: &[Metric], name: &str) -> Vec<Metric> {
    metrics.iter().filter(|m| m.name == name).cloned().collect()
}

#[tokio::test]
async fn every_metric_the_engine_emits_is_on_the_page_with_its_kind_and_labels() {
    let mut all = Vec::new();
    all.extend(first_stage_metrics(|_| {}).await);
    all.extend(
        first_stage_metrics(|w| {
            w.script(StageKind::Intake)
                .evals_otherwise(Eval::Fail("check"))
        })
        .await,
    );
    all.extend(
        first_stage_metrics(|w| {
            w.script(StageKind::Intake)
                .queue([Step::Fail(StageError::Tool)])
        })
        .await,
    );
    all.extend(
        first_stage_metrics(|w| w.script(StageKind::Intake).agent_spending(1_500_000)).await,
    );
    assert!(
        !all.is_empty(),
        "the scenarios emitted no metric; the reader is broken"
    );

    for metric in &all {
        let spec = row(&metric.name);
        assert_eq!(
            spec.kind, metric.kind,
            "{} is recorded as a {} and the page says {}",
            metric.name, metric.kind, spec.kind
        );
        for label in metric.labels.keys() {
            assert!(
                spec.labels.contains(label),
                "{} carries the label {label}, which the page does not list for it",
                metric.name
            );
        }
        for label in &spec.labels {
            assert!(
                metric.labels.contains_key(label),
                "{} lacks the label {label} that the page lists",
                metric.name
            );
        }
    }
}

#[tokio::test]
async fn a_passed_stage_run_is_counted_with_its_stage_and_outcome() {
    let metrics = first_stage_metrics(|_| {}).await;
    let counted = emitted(&metrics, "factory_stage_runs_total");
    assert_eq!(counted.len(), 1, "{metrics:?}");
    assert_eq!(counted[0].labels["stage"], "INTAKE");
    assert_eq!(counted[0].labels["outcome"], "passed");
}

#[tokio::test]
async fn a_failed_gate_is_counted_by_gate_and_outcome() {
    let metrics = first_stage_metrics(|w| {
        w.script(StageKind::Intake)
            .evals_otherwise(Eval::Fail("check"));
    })
    .await;
    let counted = emitted(&metrics, "factory_gate_failures_total");
    assert_eq!(counted.len(), 1, "{metrics:?}");
    assert_eq!(counted[0].labels["outcome"], "failed");
    assert!(!counted[0].labels["gate"].is_empty());
}

#[tokio::test]
async fn a_retryable_failure_is_counted_as_a_retry_of_its_stage() {
    let metrics = first_stage_metrics(|w| {
        w.script(StageKind::Intake)
            .queue([Step::Fail(StageError::Tool)]);
    })
    .await;
    let counted = emitted(&metrics, "factory_retries_total");
    assert_eq!(counted.len(), 1, "{metrics:?}");
    assert_eq!(counted[0].labels["stage"], "INTAKE");
}

// ---- Confirmed gaps ----------------------------------------------------------------------

/// Confirmed gap OBS-5. `factory_queue_depth` is on the page and nothing records it, so the queue
/// of ready stage runs cannot be graphed and a stuck queue cannot be alerted on.
///
/// Owner: `crates/workflow`, `src/scheduler/claim.rs`. Smallest change: after a claim (and after a
/// sweep), `tracing::info!(gauge.factory_queue_depth = ready as i64, queue = "ready_stage_runs")`,
/// where `ready` is the count the claim query already knows or one `count_ready` store read. The
/// worker loop in `apps/worker` can record it instead if the engine should not read the count.
#[tokio::test]
#[ignore = "confirmed gap OBS-5: nothing records factory_queue_depth"]
async fn the_queue_depth_gauge_is_recorded_when_work_is_claimed() {
    let metrics = first_stage_metrics(|_| {}).await;
    let gauges = emitted(&metrics, "factory_queue_depth");
    assert!(
        !gauges.is_empty(),
        "no factory_queue_depth was recorded: {metrics:?}"
    );
    assert_eq!(gauges[0].kind, "gauge");
    assert_eq!(gauges[0].labels["queue"], "ready_stage_runs");
}

/// Confirmed gap OBS-6. `factory_stage_duration_seconds` is on the page and nothing records it,
/// so there is no stage latency, no p95, and nothing to alert on for a stage over its deadline.
///
/// Owner: `crates/workflow`, `src/engine/gate.rs` (where `factory_stage_runs_total` is recorded)
/// and `src/engine/failure.rs`. Smallest change: when a stage run ends, record
/// `tracing::info!(histogram.factory_stage_duration_seconds = seconds, stage, outcome)` with the
/// seconds between the stage run's start and the engine clock.
#[tokio::test]
#[ignore = "confirmed gap OBS-6: nothing records factory_stage_duration_seconds"]
async fn the_stage_duration_histogram_is_recorded_when_a_stage_run_ends() {
    let metrics = first_stage_metrics(|_| {}).await;
    let histograms = emitted(&metrics, "factory_stage_duration_seconds");
    assert!(
        !histograms.is_empty(),
        "no factory_stage_duration_seconds was recorded: {metrics:?}"
    );
    assert_eq!(histograms[0].kind, "histogram");
}

/// Confirmed gap OBS-7. `factory_spend_usd_total` is on the page and nothing records it. The
/// engine reads what the broker metered (`token_cost` in `src/engine/attempt.rs`) and writes it
/// into the events of the attempt, so the number is known where the metric should be recorded, but
/// the metric is not, and no alert on spend can be written.
///
/// Owner: `crates/workflow`, `src/engine/attempt.rs`, right after `notes.set_cost(...)`. Smallest
/// change: `tracing::info!(monotonic_counter.factory_spend_usd_total = dollars, provider, stage)`,
/// with `dollars` the cost converted from micro-dollars and `provider` the runtime the router chose
/// for the stage. The counter takes a float; the recording type must stay `f64`.
#[tokio::test]
#[ignore = "confirmed gap OBS-7: nothing records factory_spend_usd_total"]
async fn the_spend_counter_is_recorded_when_an_agent_spends() {
    let metrics =
        first_stage_metrics(|w| w.script(StageKind::Intake).agent_spending(1_500_000)).await;
    let spend = emitted(&metrics, "factory_spend_usd_total");
    assert!(
        !spend.is_empty(),
        "no factory_spend_usd_total was recorded: {metrics:?}"
    );
    assert_eq!(spend[0].labels["stage"], "INTAKE");
}

/// Confirmed gap OBS-8. The page says `factory_stage_runs_total` counts stage runs that ended, by
/// outcome, and gives the error rate as the share with outcome `failed`. The engine records it only
/// for `passed` (`src/engine/gate.rs`, the `match metric_outcome`). A failed or blocked stage run is
/// counted in `factory_gate_failures_total` and nowhere in `factory_stage_runs_total`, so the
/// documented error-rate query returns zero whatever the failures.
///
/// Owner: `crates/workflow`, `src/engine/gate.rs`. Smallest change: record
/// `factory_stage_runs_total` with the `metric_outcome` for every outcome, not only `passed`, and do
/// the same where a stage run ends by exhausted attempts (`src/engine/failure.rs`).
#[tokio::test]
#[ignore = "confirmed gap OBS-8: failed stage runs are not counted in factory_stage_runs_total"]
async fn a_failed_stage_run_is_counted_in_the_stage_run_total() {
    let metrics = first_stage_metrics(|w| {
        w.script(StageKind::Intake)
            .evals_otherwise(Eval::Fail("check"));
    })
    .await;
    let counted = emitted(&metrics, "factory_stage_runs_total");
    assert!(
        counted
            .iter()
            .any(|m| m.labels.get("outcome").map(String::as_str) == Some("failed")),
        "no failed stage run was counted: {metrics:?}"
    );
}
