//! How an operator learns that the redactor replaced something (runbook
//! `docs/observability/runbook-first-run-signals.md`, signal 5).

use factory_observability::metrics::METRICS;

/// Confirmed gap OBS-10. The attribute guard counts the values it redacted, truncated and dropped
/// (`GuardStats`, read with `Pipeline::stats`), and the log writer replaces a line when the redactor
/// fails. The counts stay in the process: no metric carries them, so a redaction hit cannot be
/// graphed or alerted on, and an operator can only search the text of logs and spans for the
/// `[REDACTED:` marker.
///
/// Owner: `crates/observability` and its conventions page. Smallest change: add a counter
/// `factory_redactions_total` with the unit `{redaction}` and a label `sink` (`span`, `log`) to the
/// metrics table, `METRICS` and `LABELS`; raise the count in `guard.rs` where `redacted_values` is
/// raised and in `logging.rs` where a line is cleaned. The table change needs the software
/// architect's review, because it adds a metric to the contract and changes its series budget, so
/// it is reported here and not made.
///
/// Run it with `cargo nextest run -p factory-observability --run-ignored only
/// a_redaction_is_counted_in_a_metric`.
#[test]
#[ignore = "confirmed gap OBS-10: no metric counts redactions"]
fn a_redaction_is_counted_in_a_metric() {
    assert!(
        METRICS
            .iter()
            .any(|metric| metric.name == "factory_redactions_total"),
        "the metrics table has no counter for redactions"
    );
}
