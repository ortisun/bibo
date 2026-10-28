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
use telemetry_support::{EventRecord, Recorder, Value, names_in, table};

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
    /// The number the event added or set, in the type it was recorded in.
    value: Value,
}

impl Metric {
    /// The number as a float, whatever type it was recorded in.
    fn number(&self) -> f64 {
        match &self.value {
            Value::F64(n) => *n,
            Value::I64(n) => *n as f64,
            Value::U64(n) => *n as f64,
            other => panic!(
                "{} carries a value that is not a number: {other:?}",
                self.name
            ),
        }
    }
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
                value: event.fields[key].clone(),
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

/// Gap OBS-6, closed. `factory_stage_duration_seconds` is recorded when a stage run ends, with the
/// stage kind and the outcome the run ended in (`src/engine/ended.rs`, called from `gate.rs` and
/// `failure.rs`).
#[tokio::test]
async fn the_stage_duration_histogram_is_recorded_when_a_stage_run_ends() {
    let metrics = first_stage_metrics(|_| {}).await;
    let histograms = emitted(&metrics, "factory_stage_duration_seconds");
    assert_eq!(histograms.len(), 1, "{metrics:?}");
    assert_eq!(histograms[0].kind, "histogram");
    assert_eq!(histograms[0].labels["stage"], "INTAKE");
    assert_eq!(histograms[0].labels["outcome"], "passed");
}

#[tokio::test]
async fn the_duration_runs_from_the_first_start_of_the_stage_run_across_its_attempts() {
    // The first attempt fails and is retried. The clock moves 120 seconds between the two
    // claims, so the stage run took 120 seconds from its first start to its end, and not the
    // zero seconds the second attempt alone took.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world
        .script(StageKind::Intake)
        .queue([Step::Fail(StageError::Tool)]);
    world.admitted_job().await;
    world.advance(400);
    let first = world.claim_one("worker-1").await;
    world
        .engine
        .run_attempt(&first)
        .await
        .expect("the first attempt runs");
    world.advance(120);
    let second = world.claim_one("worker-1").await;
    world
        .engine
        .run_attempt(&second)
        .await
        .expect("the second attempt runs");

    let metrics = metric_events(&recorder.events());
    let histograms = emitted(&metrics, "factory_stage_duration_seconds");
    assert_eq!(histograms.len(), 1, "{metrics:?}");
    assert!(
        (histograms[0].number() - 120.0).abs() < 1e-6,
        "the stage run took 120 seconds: {histograms:?}"
    );
    assert_eq!(emitted(&metrics, "factory_stage_runs_total").len(), 1);
}

/// Gap OBS-7, closed. `factory_spend_usd_total` is recorded in dollars from what the broker
/// metered for the attempt's token (`token_cost` in `src/engine/attempt.rs`). The `provider` label
/// is the name of the runtime the router chose, since the broker reports no provider.
#[tokio::test]
async fn the_spend_counter_is_recorded_when_an_agent_spends() {
    let metrics =
        first_stage_metrics(|w| w.script(StageKind::Intake).agent_spending(1_500_000)).await;
    let spend = emitted(&metrics, "factory_spend_usd_total");
    assert_eq!(spend.len(), 1, "{metrics:?}");
    assert_eq!(spend[0].kind, "counter");
    assert_eq!(spend[0].labels["stage"], "INTAKE");
    assert_eq!(spend[0].labels["provider"], "fake");
    // A double: an integer would be read as a count of whole dollars.
    assert_eq!(spend[0].value, Value::F64(1.5), "{:?}", spend[0]);
}

#[tokio::test]
async fn an_attempt_that_failed_after_spending_is_still_counted() {
    // The money is gone whatever happened to the attempt.
    let metrics = first_stage_metrics(|w| {
        w.script(StageKind::Intake)
            .queue([Step::Fail(StageError::Tool)]);
        w.script(StageKind::Intake).agent_spending(2_000_000);
    })
    .await;
    let spend = emitted(&metrics, "factory_spend_usd_total");
    assert_eq!(spend.len(), 1, "{metrics:?}");
    assert_eq!(spend[0].value, Value::F64(2.0));
}

#[tokio::test]
async fn a_stage_that_spent_nothing_and_a_stage_with_no_agent_record_no_spend() {
    let none = first_stage_metrics(|_| {}).await;
    let zero = first_stage_metrics(|w| w.script(StageKind::Intake).agent_spending(0)).await;
    for metrics in [none, zero] {
        assert!(
            emitted(&metrics, "factory_spend_usd_total").is_empty(),
            "{metrics:?}"
        );
    }
}

/// Gap OBS-8, closed. The page says `factory_stage_runs_total` counts stage runs that ended, by
/// outcome, and gives the error rate as the share with outcome `failed`. The engine used to record
/// it only for `passed`, so that query returned zero whatever the failures. It now records the
/// outcome the stage run ended in, whichever it is.
#[tokio::test]
async fn a_failed_stage_run_is_counted_in_the_stage_run_total() {
    // The intake gate has no rework route, so a failing gate ends the stage run as failed.
    let metrics = first_stage_metrics(|w| {
        w.script(StageKind::Intake)
            .evals_otherwise(Eval::Fail("check"));
    })
    .await;
    let counted = emitted(&metrics, "factory_stage_runs_total");
    assert_eq!(counted.len(), 1, "{metrics:?}");
    assert_eq!(counted[0].labels["stage"], "INTAKE");
    assert_eq!(counted[0].labels["outcome"], "failed");
    assert_eq!(counted[0].value, Value::U64(1));
}

/// The outcome and the count of the stage runs that the first stage of a fresh job ended.
async fn first_stage_end(prepare: impl FnOnce(&World)) -> Vec<(String, f64)> {
    let metrics = first_stage_metrics(prepare).await;
    emitted(&metrics, "factory_stage_runs_total")
        .iter()
        .map(|m| (m.labels["outcome"].clone(), m.number()))
        .collect()
}

#[tokio::test]
async fn a_blocked_gate_ends_the_stage_run_as_blocked() {
    let ended = first_stage_end(|w| {
        w.script(StageKind::Intake).evals_otherwise(Eval::Blocked);
    })
    .await;
    assert_eq!(ended, [("blocked".to_owned(), 1.0)]);
}

#[tokio::test]
async fn a_failure_that_retrying_cannot_fix_ends_the_stage_run_as_failed() {
    // Policy denial is not on the retry list of the scripted contract.
    let ended = first_stage_end(|w| {
        w.script(StageKind::Intake)
            .queue([Step::Fail(StageError::PolicyDenied)]);
    })
    .await;
    assert_eq!(ended, [("failed".to_owned(), 1.0)]);
}

#[tokio::test]
async fn a_missing_environment_ends_the_stage_run_as_blocked() {
    use factory_domain::machines::guards::EnvironmentCause;
    let ended = first_stage_end(|w| {
        w.script(StageKind::Intake)
            .queue([Step::Fail(StageError::Environment(
                EnvironmentCause::ToolMissing,
            ))]);
    })
    .await;
    assert_eq!(ended, [("blocked".to_owned(), 1.0)]);
}

#[tokio::test]
async fn a_gate_that_sends_the_work_back_ends_the_stage_run_as_rework_requested() {
    // Validation has a rework route (the code track), so a failing gate there is not final.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world
        .script(StageKind::Validation)
        .queue_evals([Eval::Fail("tests-pass")]);
    world.admitted_job().await;
    let before = world
        .config
        .scope
        .iter()
        .position(|kind| *kind == StageKind::Validation)
        .expect("validation is in the scope");
    world.run_stages(before).await;
    recorder.clear();
    world.advance(400);
    world.run_next("worker-1").await;

    let metrics = metric_events(&recorder.events());
    let counted = emitted(&metrics, "factory_stage_runs_total");
    assert_eq!(counted.len(), 1, "{metrics:?}");
    assert_eq!(counted[0].labels["stage"], "VALIDATION");
    assert_eq!(counted[0].labels["outcome"], "rework_requested");
    assert_eq!(
        emitted(&metrics, "factory_stage_duration_seconds")[0].labels["outcome"],
        "rework_requested"
    );
}

#[tokio::test]
async fn a_stage_run_that_only_pauses_is_not_counted_as_ended() {
    // A retry waits for its back-off, and a question to a person waits for the answer. Neither is
    // the end of the stage run, and counting them would put the same run in the total twice.
    let retried = first_stage_metrics(|w| {
        w.script(StageKind::Intake)
            .queue([Step::Fail(StageError::Tool)]);
    })
    .await;
    let asked_by_the_agent = first_stage_metrics(|w| {
        w.script(StageKind::Intake).queue([Step::NeedsHuman]);
    })
    .await;
    let asked_by_the_gate = first_stage_metrics(|w| {
        w.script(StageKind::Intake).evals_otherwise(Eval::HumanGate);
    })
    .await;
    for (what, metrics) in [
        ("a retry", retried),
        ("a question from the agent", asked_by_the_agent),
        ("a question from the gate", asked_by_the_gate),
    ] {
        assert!(
            emitted(&metrics, "factory_stage_runs_total").is_empty(),
            "{what} was counted as the end of the stage run: {metrics:?}"
        );
        assert!(
            emitted(&metrics, "factory_stage_duration_seconds").is_empty(),
            "{what} was timed as the end of the stage run: {metrics:?}"
        );
    }
}

#[tokio::test]
async fn a_worker_that_lost_its_lease_counts_nothing() {
    // Worker A hangs, loses its lease and finishes after worker B took over. A's result is
    // refused, so the stage run ended once, in B's attempt, and the total says one.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    world
        .script(StageKind::Intake)
        .queue([Step::Hang(release.clone())]);
    let claimed = world.claim_one("worker-a").await;
    let stale = async { world.engine.run_attempt(&claimed).await };
    let takeover = async {
        world.advance_time(61).await;
        world.engine.sweep().await.expect("sweep");
        world.advance_time(5).await;
        let second = world.claim_one("worker-b").await;
        release.notify_one();
        second
    };
    let (_, second) = tokio::join!(stale, takeover);
    world
        .engine
        .run_attempt(&second)
        .await
        .expect("the second attempt runs");

    let metrics = metric_events(&recorder.events());
    let counted = emitted(&metrics, "factory_stage_runs_total");
    assert_eq!(counted.len(), 1, "{counted:?}");
    assert_eq!(counted[0].labels["outcome"], "passed");
}
