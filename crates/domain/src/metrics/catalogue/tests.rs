use super::*;
use std::collections::BTreeSet;

const DESIGN: &str =
    include_str!("../../../../../docs/architecture/process-metrics-and-improvement.md");

/// The rows of the identifier table of the design document, as their cells.
fn documented_rows() -> Vec<Vec<String>> {
    DESIGN
        .lines()
        .filter(|line| line.starts_with("| MT-"))
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_owned())
                .collect()
        })
        // The example of a measurement entry also has rows that start with an identifier;
        // there the first cell goes on with the name of the metric.
        .filter(|cells: &Vec<String>| cells[0].len() == "MT-0001".len())
        .collect()
}

#[test]
fn the_catalogue_is_the_table_of_the_design_document() {
    let rows = documented_rows();
    assert_eq!(
        rows.len(),
        Metric::ALL.len(),
        "one documented row for each metric"
    );
    for (row, metric) in rows.iter().zip(Metric::ALL) {
        let definition = metric.definition();
        let better = match definition.better {
            Direction::LowerIsBetter => "lower",
            Direction::HigherIsBetter => "higher",
        };
        let shown_as: Vec<&str> = definition.shown_as.iter().map(|s| s.as_str()).collect();
        let facts = match definition.facts {
            Facts::Stored => "stored".to_owned(),
            Facts::NotStored(missing) => {
                format!("not stored: {}", missing.trim_start_matches("is "))
            }
        };
        let expected = vec![
            definition.identifier(),
            definition.name.to_owned(),
            definition.unit.as_str().to_owned(),
            better.to_owned(),
            shown_as.join(", "),
            facts,
        ];
        assert_eq!(row, &expected);
    }
}

#[test]
fn identifiers_run_from_one_without_a_gap_and_names_are_unique_slugs() {
    let mut names = BTreeSet::new();
    for (index, metric) in Metric::ALL.iter().enumerate() {
        let definition = metric.definition();
        assert_eq!(usize::from(definition.number), index + 1);
        assert!(
            names.insert(definition.name),
            "{} is used twice",
            definition.name
        );
        assert!(
            crate::values::Slug::parse(definition.name).is_ok(),
            "{}",
            definition.name
        );
        assert_eq!(
            Metric::from_identifier(&definition.identifier()),
            Some(*metric)
        );
    }
    assert_eq!(Metric::from_identifier("MT-0000"), None);
    assert_eq!(Metric::from_identifier("MT-0022"), None);
    assert_eq!(Metric::from_identifier("mt-0001"), None);
}

#[test]
fn every_statistic_fits_the_unit_of_its_metric() {
    for metric in Metric::ALL {
        let definition = metric.definition();
        assert!(!definition.shown_as.is_empty());
        for statistic in definition.shown_as {
            assert!(
                statistic.fits(definition.unit),
                "{} as {statistic:?}",
                definition.name
            );
        }
        assert!(!definition.formula.is_empty() && definition.formula.ends_with('.'));
        assert_eq!(definition.minimum_sample.get(), 20);
    }
    assert!(!Statistic::Rate.fits(Unit::Milliseconds));
    assert!(!Statistic::Median.fits(Unit::Ratio));
    assert!(!Statistic::Total.fits(Unit::MicroUsd));
}

#[test]
fn the_entry_of_a_stored_metric() {
    let definition = Metric::FirstPassGateSuccess.definition();
    assert_eq!(
        definition.entry_path(),
        "metrics/MT-0006-first-pass-gate-success.md"
    );
    assert_eq!(
        definition.render_entry(),
        "---\n\
         id: MT-0006\n\
         kind: metric\n\
         title: First-pass gate success\n\
         status: active\n\
         group: quality\n\
         unit: ratio\n\
         better: higher\n\
         shown_as: [rate]\n\
         minimum_sample: 20\n\
         cut_by: [agent, pack, model]\n\
         ---\n\
         \n\
         ## What is counted\n\
         \n\
         The tasks whose first attempt passed every gate, out of all tasks.\n\
         \n\
         ## How it is computed\n\
         \n\
         The rate is kept as a numerator and a denominator. It is divided only for display, \
         as a percentage with one decimal place, rounded half to even. With fewer than 20 \
         samples the value is \"too few samples\", never a number.\n\
         \n\
         ## Where the facts come from\n\
         \n\
         The factory's database and evidence ledger. Every snapshot names the query version \
         and the window, so the number can be computed again.\n"
    );
}

#[test]
fn the_entry_of_a_metric_without_facts_says_so() {
    let entry = Metric::EscapedDefects.definition().render_entry();
    assert!(entry.ends_with("Not measured yet: it needs bugs linked to pull requests.\n"));
    let entry = Metric::DeploymentFrequency.definition().render_entry();
    assert!(entry.contains("better: higher\n"));
    assert!(entry.ends_with("Not measured yet: it is read from the project's pipeline.\n"));
}
