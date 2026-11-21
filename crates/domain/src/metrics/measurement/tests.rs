use super::*;

fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("valid timestamp")
}

fn window(from: &str, to: &str) -> Window {
    Window::new(at(from), at(to)).expect("ordered window")
}

fn ms(value: u64) -> Milliseconds {
    Milliseconds::new(value).expect("valid duration")
}

fn value(reading: Reading, samples: u64) -> Cell {
    Cell::Measured(Measured::Value {
        value: reading,
        samples,
    })
}

fn too_few(samples: u64) -> Cell {
    Cell::Measured(Measured::TooFewSamples {
        samples,
        minimum: 20,
    })
}

fn rate(numerator: u64, denominator: u64) -> Reading {
    Reading::Rate(Proportion::new(numerator, denominator).expect("valid rate"))
}

#[test]
fn a_window_needs_its_end_after_its_start() {
    let instant = at("2026-11-16T00:00:00Z");
    assert_eq!(
        Window::new(instant, instant),
        Err(MetricError::WindowOutOfOrder)
    );
    assert_eq!(
        Window::new(at("2026-11-16T00:00:01Z"), instant),
        Err(MetricError::WindowOutOfOrder)
    );
    let shortest = window("2026-11-16T00:00:00Z", "2026-11-16T00:00:00.000000001Z");
    assert_eq!(shortest.from(), instant);
}

#[test]
fn a_week_from_monday_midnight_is_named_by_its_iso_week() {
    let week = window("2026-11-16T00:00:00Z", "2026-11-23T00:00:00Z");
    assert_eq!(week.iso_week(), Some((2026, 47)));
    assert_eq!(week.identifier(), "M-2026-W47");
    assert_eq!(week.title(), "Process numbers, week 47 of 2026");
    // Single-digit weeks are padded in the identifier, so that names sort.
    assert_eq!(
        window("2026-01-05T00:00:00Z", "2026-01-12T00:00:00Z").identifier(),
        "M-2026-W02"
    );
}

#[test]
fn the_week_belongs_to_the_year_of_its_thursday() {
    // Monday 2025-12-29 starts week 1 of 2026: its Thursday is 2026-01-01.
    assert_eq!(
        window("2025-12-29T00:00:00Z", "2026-01-05T00:00:00Z").identifier(),
        "M-2026-W01"
    );
    // Monday 2026-12-28 starts week 53 of 2026: its Thursday is 2026-12-31.
    assert_eq!(
        window("2026-12-28T00:00:00Z", "2027-01-04T00:00:00Z").identifier(),
        "M-2026-W53"
    );
    // Monday 2024-12-30 starts week 1 of 2025.
    assert_eq!(
        window("2024-12-30T00:00:00Z", "2025-01-06T00:00:00Z").identifier(),
        "M-2025-W01"
    );
}

#[test]
fn any_other_window_is_named_by_its_dates() {
    let cases = [
        ("2026-11-17T00:00:00Z", "2026-11-24T00:00:00Z"), // seven days from a Tuesday
        ("2026-11-16T00:00:00Z", "2026-11-22T00:00:00Z"), // six days
        ("2026-11-16T00:00:00Z", "2026-11-23T00:00:01Z"), // a second too long
        ("2026-11-16T00:00:01Z", "2026-11-23T00:00:01Z"), // not from midnight
        ("2026-11-16T00:00:00Z", "2026-11-23T00:00:00.5Z"), // half a second too long
    ];
    for (from, to) in cases {
        assert_eq!(window(from, to).iso_week(), None, "{from} to {to}");
    }
    let month = window("2026-11-16T00:00:00Z", "2026-12-16T00:00:00Z");
    assert_eq!(month.identifier(), "M-2026-11-16-to-2026-12-16");
    assert_eq!(month.title(), "Process numbers, 2026-11-16 to 2026-12-16");
}

#[test]
fn a_duration_is_shown_in_the_unit_a_person_reads() {
    assert_eq!(duration_text(ms(0)), "0 ms");
    assert_eq!(duration_text(ms(1)), "1 ms");
    assert_eq!(duration_text(ms(999)), "999 ms");
    assert_eq!(duration_text(ms(1_000)), "1.000 s");
    assert_eq!(duration_text(ms(12_345)), "12.345 s");
    assert_eq!(duration_text(ms(59_999)), "59.999 s");
    assert_eq!(duration_text(ms(60_000)), "1 min 0 s");
    assert_eq!(duration_text(ms(2_472_000)), "41 min 12 s");
    assert_eq!(duration_text(ms(60_500)), "1 min 0 s"); // 60.5 s, tie, even
    assert_eq!(duration_text(ms(61_500)), "1 min 2 s"); // 61.5 s, tie, even
    assert_eq!(duration_text(ms(3_599_499)), "59 min 59 s");
    assert_eq!(duration_text(ms(3_599_500)), "1 h 0 min 0 s"); // rounds into the next hour
    assert_eq!(duration_text(ms(7_205_000)), "2 h 0 min 5 s");
    assert_eq!(duration_text(Milliseconds::MAX), "2501999792 h 59 min 1 s");
}

#[test]
fn a_row_must_fit_its_metric() {
    let duration = value(Reading::Duration(ms(5)), 20);
    let refused = |metric, statistic, current, previous| {
        assert!(
            matches!(
                Row::new(metric, statistic, current, previous),
                Err(MetricError::RowDoesNotFit { .. })
            ),
            "{metric:?} {statistic:?} {current:?} {previous:?}"
        );
    };
    // A statistic the catalogue does not show for the metric.
    refused(
        Metric::LeadTimeToPullRequest,
        Statistic::Rate,
        duration,
        Cell::NotAvailable,
    );
    refused(
        Metric::TimeToFirstFailingTest,
        Statistic::NinetiethPercentile,
        Cell::NotMeasuredYet,
        Cell::NotMeasuredYet,
    );
    // A value of another unit, now or before.
    refused(
        Metric::LeadTimeToPullRequest,
        Statistic::Median,
        value(Reading::Count(5), 20),
        Cell::NotAvailable,
    );
    refused(
        Metric::FirstPassGateSuccess,
        Statistic::Rate,
        value(rate(1, 2), 20),
        duration,
    );
    refused(
        Metric::CostPerAcceptedPullRequest,
        Statistic::AmountPerItem,
        value(Reading::Count(1), 20),
        Cell::NotAvailable,
    );
    // A metric without stored facts cannot carry a value, and a stored one is measured.
    refused(
        Metric::EscapedDefects,
        Statistic::Total,
        value(Reading::Count(0), 20),
        Cell::NotMeasuredYet,
    );
    refused(
        Metric::EscapedDefects,
        Statistic::Total,
        too_few(0),
        Cell::NotMeasuredYet,
    );
    refused(
        Metric::ReworkRounds,
        Statistic::Total,
        Cell::NotMeasuredYet,
        Cell::NotAvailable,
    );
    // The current window always exists.
    refused(
        Metric::ReworkRounds,
        Statistic::Total,
        Cell::NotAvailable,
        Cell::NotAvailable,
    );

    assert!(
        Row::new(
            Metric::ReworkRounds,
            Statistic::Total,
            value(Reading::Count(9), 20),
            too_few(3)
        )
        .is_ok()
    );
    assert!(
        Row::new(
            Metric::EscapedDefects,
            Statistic::Total,
            Cell::NotMeasuredYet,
            Cell::NotMeasuredYet
        )
        .is_ok()
    );
    assert!(
        Row::new(
            Metric::EscapedDefects,
            Statistic::Total,
            Cell::NotMeasuredYet,
            Cell::NotAvailable
        )
        .is_ok()
    );
}

fn example() -> Measurement {
    let row = |metric, statistic, current, previous| {
        Row::new(metric, statistic, current, previous).expect("fitting row")
    };
    Measurement {
        window: window("2026-11-16T00:00:00Z", "2026-11-23T00:00:00Z"),
        query_version: 3,
        computed_at_commit: GitSha::parse("3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d")
            .expect("valid"),
        rows: vec![
            row(
                Metric::LeadTimeToPullRequest,
                Statistic::Median,
                value(Reading::Duration(ms(2_472_000)), 23),
                value(Reading::Duration(ms(3_303_000)), 21),
            ),
            row(
                Metric::StageDuration,
                Statistic::NinetiethPercentile,
                value(Reading::Duration(ms(12_345)), 88),
                value(Reading::Duration(ms(15_020)), 90),
            ),
            row(
                Metric::FirstPassGateSuccess,
                Statistic::Rate,
                value(rate(14, 23), 23),
                value(rate(11, 21), 21),
            ),
            row(
                Metric::ReworkRounds,
                Statistic::Total,
                too_few(3),
                too_few(2),
            ),
            row(
                Metric::EscapedDefects,
                Statistic::Total,
                Cell::NotMeasuredYet,
                Cell::NotMeasuredYet,
            ),
        ],
        stands_out: vec![],
    }
}

/// The entry of the design document, row for row.
#[test]
fn the_entry_is_the_example_of_the_design_document() {
    let measurement = example();
    assert_eq!(measurement.entry_path(), "measurements/M-2026-W47.md");
    let entry = measurement.render_entry().expect("renders");
    assert_eq!(
        entry,
        "---\n\
         id: M-2026-W47\n\
         kind: measurement\n\
         title: Process numbers, week 47 of 2026\n\
         window: { from: \"2026-11-16T00:00:00Z\", to: \"2026-11-23T00:00:00Z\" }\n\
         query_version: 3\n\
         computed_at_commit: \"3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d\"\n\
         ---\n\
         \n\
         | Metric | Value | Samples | Previous |\n\
         |---|---|---|---|\n\
         | MT-0001 lead-time-to-pull-request, median | 41 min 12 s | 23 | 55 min 3 s |\n\
         | MT-0002 stage-duration, 90th percentile | 12.345 s | 88 | 15.020 s |\n\
         | MT-0006 first-pass-gate-success | 60.9 % (14 of 23) | 23 | 52.4 % (11 of 21) |\n\
         | MT-0007 rework-rounds | too few samples | 3 | too few samples |\n\
         | MT-0009 escaped-defects | not measured yet | | not measured yet |\n\
         \n\
         ## What stands out\n\
         \n\
         Nothing: no comparison of this window shows a clear change.\n"
    );
    // Every table row of the document's example is a row of the rendered entry.
    let design =
        include_str!("../../../../../docs/architecture/process-metrics-and-improvement.md");
    let documented: Vec<&str> = design
        .lines()
        .filter(|line| line.starts_with("| MT-") && line.contains("| "))
        .filter(|line| line.split('|').count() == 6)
        .collect();
    assert_eq!(documented.len(), 5);
    for line in documented {
        assert!(
            entry.contains(line),
            "the document's row is not rendered: {line}"
        );
    }
}

#[test]
fn what_stands_out_is_a_list_of_single_lines() {
    let mut measurement = example();
    measurement.stands_out = vec![" First-pass gate success shows no clear change. ".to_owned()];
    let entry = measurement.render_entry().expect("renders");
    assert!(
        entry.ends_with("## What stands out\n\n- First-pass gate success shows no clear change.\n")
    );

    for broken in ["two\nlines", "carriage\rreturn", "", "   "] {
        measurement.stands_out = vec![broken.to_owned()];
        assert_eq!(
            measurement.render_entry(),
            Err(MetricError::TextIsNotOneLine {
                what: "a line of \"What stands out\""
            })
        );
    }
}

#[test]
fn a_first_snapshot_has_no_previous_window() {
    let mut measurement = example();
    measurement.rows = vec![
        Row::new(
            Metric::ReworkRounds,
            Statistic::Total,
            value(Reading::Count(0), 20),
            Cell::NotAvailable,
        )
        .expect("fitting row"),
    ];
    let entry = measurement.render_entry().expect("renders");
    assert!(entry.contains("| MT-0007 rework-rounds | 0 | 20 | n/a |\n"));
}
