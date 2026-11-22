use super::*;
use crate::metrics::{Direction, Measured};
use crate::values::Timestamp;

fn ms(value: u64) -> Milliseconds {
    Milliseconds::new(value).expect("valid duration")
}

fn week() -> Window {
    Window::new(
        Timestamp::parse("2026-11-16T00:00:00Z").expect("valid"),
        Timestamp::parse("2026-11-23T00:00:00Z").expect("valid"),
    )
    .expect("ordered")
}

fn commit() -> GitSha {
    GitSha::parse("3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d").expect("valid")
}

fn durations(count: u64, first: u64) -> Samples {
    Samples::Durations(
        (0..count)
            .map(|index| ms(first + (index * 37) % 101))
            .collect(),
    )
}

/// Facts for every stored metric, in the shape its unit needs. `jobs` is the number of samples
/// of everything, and `shift` moves the durations.
fn facts(jobs: u64, shift: u64) -> WindowFacts {
    Metric::ALL
        .iter()
        .filter(|metric| metric.definition().facts == Facts::Stored)
        .map(|metric| {
            let definition = metric.definition();
            let samples = match (definition.unit, definition.shown_as[0]) {
                (Unit::Milliseconds, _) => durations(jobs, 1_000 + shift),
                (Unit::Count, Statistic::Total) => Samples::Total {
                    count: 7,
                    samples: jobs,
                },
                (Unit::Count, _) => Samples::Counts((0..jobs).map(|index| 5_000 + index).collect()),
                (Unit::Ratio, _) => Samples::Rate {
                    part: jobs / 2,
                    whole: jobs,
                },
                (Unit::MicroUsd, _) => Samples::Amount {
                    total: MicroUsd::new(16_000_000).expect("valid"),
                    items: jobs,
                },
            };
            (*metric, samples)
        })
        .collect()
}

fn build(
    current: &WindowFacts,
    previous: Option<&WindowFacts>,
) -> Result<Measurement, MetricError> {
    snapshot(
        week(),
        1,
        commit(),
        current,
        previous,
        ComparisonSettings::default(),
    )
}

fn row(measurement: &Measurement, metric: Metric, statistic: Statistic) -> Row {
    *measurement
        .rows
        .iter()
        .find(|row| row.metric() == metric && row.statistic() == statistic)
        .expect("the row exists")
}

#[test]
fn there_is_one_row_for_each_statistic_of_each_metric_in_catalogue_order() {
    let measurement = build(&facts(40, 0), None).expect("builds");
    let expected: Vec<(Metric, Statistic)> = Metric::ALL
        .iter()
        .flat_map(|metric| {
            metric
                .definition()
                .shown_as
                .iter()
                .map(|statistic| (*metric, *statistic))
        })
        .collect();
    let rows: Vec<(Metric, Statistic)> = measurement
        .rows
        .iter()
        .map(|row| (row.metric(), row.statistic()))
        .collect();
    assert_eq!(rows, expected);
    assert!(measurement.stands_out.is_empty());
    assert!(
        measurement
            .rows
            .iter()
            .all(|row| row.previous() == Cell::NotAvailable
                || row.metric().definition().facts != Facts::Stored)
    );
    assert!(measurement.render_entry().is_ok());
}

#[test]
fn the_statistics_are_the_ones_of_the_design() {
    let mut current = facts(40, 0);
    // 1 to 40 ms: the median by nearest rank is the 20th, the 90th percentile the 36th.
    current.insert(
        Metric::StageDuration,
        Samples::Durations((1..=40).rev().map(ms).collect()),
    );
    current.insert(
        Metric::FirstPassGateSuccess,
        Samples::Rate {
            part: 14,
            whole: 23,
        },
    );
    let measurement = build(&current, None).expect("builds");

    let value = |metric, statistic| match row(&measurement, metric, statistic).current() {
        Cell::Measured(Measured::Value { value, samples }) => (value, samples),
        other => panic!("{metric:?} has no value: {other:?}"),
    };
    assert_eq!(
        value(Metric::StageDuration, Statistic::Median),
        (Reading::Duration(ms(20)), 40)
    );
    assert_eq!(
        value(Metric::StageDuration, Statistic::NinetiethPercentile),
        (Reading::Duration(ms(36)), 40)
    );
    assert_eq!(
        value(Metric::FirstPassGateSuccess, Statistic::Rate),
        (Reading::Rate(Proportion::new(14, 23).expect("valid")), 23)
    );
    assert_eq!(
        value(Metric::ReworkRounds, Statistic::Total),
        (Reading::Count(7), 40)
    );
}

#[test]
fn nineteen_samples_are_too_few_and_zero_samples_never_divide() {
    let mut current = facts(19, 0);
    current.insert(
        Metric::FirstPassGateSuccess,
        Samples::Rate { part: 0, whole: 0 },
    );
    current.insert(Metric::HumanWaitTime, Samples::Durations(vec![]));
    let measurement = build(&current, None).expect("builds");
    for row in &measurement.rows {
        if row.metric().definition().facts == Facts::Stored {
            assert!(
                matches!(
                    row.current(),
                    Cell::Measured(Measured::TooFewSamples { minimum: 20, .. })
                ),
                "{row:?}"
            );
        } else {
            assert_eq!(row.current(), Cell::NotMeasuredYet);
        }
    }
    let empty = row(&measurement, Metric::HumanWaitTime, Statistic::Median);
    assert_eq!(
        empty.current(),
        Cell::Measured(Measured::TooFewSamples {
            samples: 0,
            minimum: 20
        })
    );

    // With exactly twenty samples every stored metric has a value.
    let measurement = build(&facts(20, 0), None).expect("builds");
    assert!(measurement.rows.iter().all(|row| {
        row.metric().definition().facts != Facts::Stored
            || matches!(
                row.current(),
                Cell::Measured(Measured::Value { samples: 20, .. })
            )
    }));
}

#[test]
fn facts_that_do_not_fit_the_catalogue_are_refused() {
    let refused = |facts: &WindowFacts| {
        assert!(matches!(
            build(facts, None),
            Err(MetricError::RowDoesNotFit { .. })
        ));
    };
    // A stored metric is missing.
    let mut missing = facts(40, 0);
    missing.remove(&Metric::ReworkRounds);
    refused(&missing);
    // A metric without stored facts is handed in.
    let mut extra = facts(40, 0);
    extra.insert(
        Metric::EscapedDefects,
        Samples::Total {
            count: 0,
            samples: 40,
        },
    );
    refused(&extra);
    // Facts of another shape.
    let mut shape = facts(40, 0);
    shape.insert(Metric::LeadTimeToPullRequest, Samples::Counts(vec![1; 40]));
    refused(&shape);
    let mut shape = facts(40, 0);
    shape.insert(Metric::ReworkRounds, Samples::Counts(vec![1; 40]));
    refused(&shape);
    // The same rules hold for the window before.
    assert!(build(&facts(40, 0), Some(&missing)).is_err());
    // A part above its whole is an error of the facts, not a rate.
    let mut impossible = facts(40, 0);
    impossible.insert(
        Metric::FirstPassGateSuccess,
        Samples::Rate {
            part: 41,
            whole: 40,
        },
    );
    assert_eq!(
        build(&impossible, None),
        Err(MetricError::PartExceedsWhole {
            numerator: 41,
            denominator: 40
        })
    );
}

#[test]
fn only_a_clear_change_stands_out() {
    let before = facts(40, 500);
    let mut after = facts(40, 0); // every duration is 500 ms shorter
    after.insert(
        Metric::FirstPassGateSuccess,
        Samples::Rate {
            part: 10,
            whole: 1_000,
        },
    );
    let mut before_rates = before.clone();
    before_rates.insert(
        Metric::FirstPassGateSuccess,
        Samples::Rate {
            part: 300,
            whole: 1_000,
        },
    );

    let measurement = build(&after, Some(&before_rates)).expect("builds");
    let lines = &measurement.stands_out;
    // The three stored durations improved, and the success rate got worse. Nothing else moved:
    // totals and amounts have no interval, and the other rates and counts are unchanged.
    assert_eq!(lines.len(), 4, "{lines:#?}");
    // The interval is the one `tests/oracle/median_bootstrap_oracle.py` gives for these samples.
    assert_eq!(
        lines[0],
        "MT-0001 lead-time-to-pull-request improved against the window before: the median \
         changed by -500 ms (95 percent interval -523 to -479 ms)."
    );
    assert!(lines[1].starts_with("MT-0002 stage-duration improved"));
    assert!(lines[2].starts_with("MT-0003 human-wait-time improved"));
    assert!(lines[3].starts_with(
        "MT-0006 first-pass-gate-success got worse against the window before: the rate changed \
         by -290000 millionths"
    ));
    assert_eq!(
        Metric::FirstPassGateSuccess.definition().better,
        Direction::HigherIsBetter
    );

    // Previous cells are filled from the window before.
    let lead = row(
        &measurement,
        Metric::LeadTimeToPullRequest,
        Statistic::Median,
    );
    assert!(matches!(
        lead.previous(),
        Cell::Measured(Measured::Value { samples: 40, .. })
    ));
    assert!(
        measurement
            .render_entry()
            .expect("renders")
            .contains("- MT-0001 lead-time-to-pull-request improved")
    );

    // The same window twice: nothing stands out.
    assert!(
        build(&after, Some(&after))
            .expect("builds")
            .stands_out
            .is_empty()
    );

    // Too few samples on either side: nothing stands out, even with a large shift.
    assert!(
        build(&facts(19, 0), Some(&facts(40, 500)))
            .expect("builds")
            .stands_out
            .is_empty()
    );
    assert!(
        build(&facts(40, 0), Some(&facts(19, 500)))
            .expect("builds")
            .stands_out
            .is_empty()
    );
}

#[test]
fn the_same_facts_and_seed_give_the_same_snapshot() {
    let (before, after) = (facts(40, 30), facts(40, 0));
    let first = build(&after, Some(&before)).expect("builds");
    let second = build(&after, Some(&before)).expect("builds");
    assert_eq!(first, second);
    assert_eq!(first.render_entry(), second.render_entry());
}

/// No metric with stored facts is an amount of money or a median of counts today, so these two
/// shapes are checked here, without the catalogue.
#[test]
fn the_shapes_no_stored_metric_uses_yet() {
    let amount = Samples::Amount {
        total: MicroUsd::new(16_000_000).expect("valid"),
        items: 19,
    };
    assert_eq!(amount.count(), 19);
    assert!(amount.fits(Statistic::AmountPerItem, Unit::MicroUsd));
    assert!(!amount.fits(Statistic::Rate, Unit::Ratio));
    // 16 000 000 / 19 = 842 105.26...
    assert_eq!(
        amount.reading(Statistic::AmountPerItem),
        Ok(Reading::Money(MicroUsd::new(842_105).expect("valid")))
    );
    let nothing = Samples::Amount {
        total: MicroUsd::new(5).expect("valid"),
        items: 0,
    };
    assert!(nothing.reading(Statistic::AmountPerItem).is_err());

    let counts = Samples::Counts((1..=21).collect());
    assert!(counts.fits(Statistic::Median, Unit::Count));
    assert_eq!(counts.reading(Statistic::Median), Ok(Reading::Count(11)));
    assert_eq!(
        counts.reading(Statistic::NinetiethPercentile),
        Ok(Reading::Count(19))
    );

    // The median of counts is compared by the bootstrap, like a duration.
    let before = Samples::Counts((0..40).map(|index| 1_500 + (index * 37) % 101).collect());
    let after = Samples::Counts((0..40).map(|index| 1_000 + (index * 37) % 101).collect());
    let interval = difference(
        Metric::TokensPerTask,
        &before,
        &after,
        ComparisonSettings::default(),
    )
    .expect("compares")
    .expect("enough samples");
    assert_eq!(
        (interval.lower(), interval.point(), interval.upper()),
        (-523, -500, -479)
    );
    assert_eq!(
        difference(
            Metric::TokensPerTask,
            &amount,
            &amount,
            ComparisonSettings::default()
        ),
        Ok(None)
    );
    let huge = Samples::Counts(vec![u64::MAX; 20]);
    assert!(
        difference(
            Metric::TokensPerTask,
            &huge,
            &huge,
            ComparisonSettings::default()
        )
        .is_err()
    );
}
