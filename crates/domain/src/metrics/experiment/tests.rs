use super::*;
use proptest::prelude::*;

fn slug(text: &str) -> Slug {
    Slug::parse(text).expect("valid slug")
}

fn job(text: &str) -> JobId {
    JobId::parse(text).expect("valid job id")
}

fn range<'a>(tiers: &'a [Slug], reviewers: &'a [Slug]) -> SafeRange<'a> {
    SafeRange {
        parallel_tasks_limit: 8,
        evaluated_tiers: tiers,
        reviewers,
    }
}

fn test_order(share: Share, windows: Windows) -> Experiment {
    Experiment::declare(
        slug("targeted-tests-first"),
        Setting::TestOrder(false),
        Setting::TestOrder(true),
        Metric::TimeToFirstFailingTest,
        share,
        windows,
        &range(&[], &[]),
    )
    .expect("valid experiment")
}

fn shows(metric: Metric, lower: i64, point: i64, upper: i64) -> Comparison {
    let interval = Interval::new(lower, point, upper).expect("ordered");
    Comparison {
        metric,
        difference: Measured::Value {
            value: interval,
            samples: 40,
        },
    }
}

fn too_few(metric: Metric) -> Comparison {
    Comparison {
        metric,
        difference: Measured::TooFewSamples {
            samples: 3,
            minimum: 20,
        },
    }
}

/// Guards of the test-order setting that show no clear change.
fn calm_guards() -> Vec<Comparison> {
    SettingKind::TestOrder
        .guards()
        .iter()
        .map(|metric| shows(*metric, -5, 0, 5))
        .collect()
}

const FASTER: (i64, i64, i64) = (-900, -500, -100);

fn target(bounds: (i64, i64, i64)) -> Comparison {
    shows(Metric::TimeToFirstFailingTest, bounds.0, bounds.1, bounds.2)
}

#[test]
fn only_a_declared_setting_is_tier_a() {
    for kind in SettingKind::ALL {
        assert_eq!(Change::Setting(*kind).tier(), Tier::A);
        assert!(!kind.guards().is_empty());
        assert!(kind.guards().contains(&Metric::HumanRejectionRate));
    }
    for change in [
        Change::Prompt,
        Change::Skill,
        Change::EvaluationCase,
        Change::DefaultModel,
    ] {
        assert_eq!(change.tier(), Tier::B);
    }
    for change in [
        Change::Policy,
        Change::Gate,
        Change::SecurityRule,
        Change::Approval,
    ] {
        assert_eq!(change.tier(), Tier::C);
    }
}

#[test]
fn the_ranges_of_share_and_windows() {
    assert!(Share::new(0).is_err());
    assert_eq!(Share::new(1).map(Share::hundredths), Ok(1));
    assert_eq!(Share::new(5_000).map(Share::hundredths), Ok(5_000));
    assert!(Share::new(5_001).is_err());
    assert_eq!(Share::DEFAULT.hundredths(), 1_000);
    assert!(Windows::new(0).is_err());
    assert_eq!(Windows::new(1).map(Windows::get), Ok(1));
    assert_eq!(Windows::new(12).map(Windows::get), Ok(12));
    assert!(Windows::new(13).is_err());
    assert_eq!(Windows::DEFAULT.get(), 4);
}

#[test]
fn a_value_outside_its_safe_range_is_refused() {
    let tiers = [slug("small"), slug("large")];
    let reviewers = [slug("code-reviewer"), slug("architecture-critic")];
    let range = range(&tiers, &reviewers);

    assert!(Setting::TestOrder(true).check(&range).is_ok());
    assert!(Setting::ParallelTasks(0).check(&range).is_err());
    assert!(Setting::ParallelTasks(1).check(&range).is_ok());
    assert!(Setting::ParallelTasks(8).check(&range).is_ok());
    assert!(Setting::ParallelTasks(9).check(&range).is_err());
    assert!(Setting::ParallelTasks(u32::MAX).check(&range).is_err());
    assert!(
        Setting::StartingModelTier(slug("large"))
            .check(&range)
            .is_ok()
    );
    assert!(
        Setting::StartingModelTier(slug("huge"))
            .check(&range)
            .is_err()
    );

    let order = |names: &[&str]| Setting::ReviewerOrder(names.iter().map(|n| slug(n)).collect());
    assert!(
        order(&["architecture-critic", "code-reviewer"])
            .check(&range)
            .is_ok()
    );
    assert!(order(&["code-reviewer"]).check(&range).is_err()); // one removed
    assert!(
        order(&["code-reviewer", "architecture-critic", "new-one"])
            .check(&range)
            .is_err()
    );
    assert!(
        order(&["code-reviewer", "code-reviewer"])
            .check(&range)
            .is_err()
    ); // one twice
    assert!(order(&[]).check(&range).is_err());
}

#[test]
fn a_malformed_experiment_is_refused() {
    let empty = range(&[], &[]);
    let declare = |baseline, variant, target| {
        Experiment::declare(
            slug("an-experiment"),
            baseline,
            variant,
            target,
            Share::DEFAULT,
            Windows::DEFAULT,
            &empty,
        )
    };
    let speed = Metric::LeadTimeToPullRequest;
    // Values of different settings.
    assert!(declare(Setting::TestOrder(false), Setting::ParallelTasks(2), speed).is_err());
    // The variant equals the baseline.
    assert!(declare(Setting::ParallelTasks(2), Setting::ParallelTasks(2), speed).is_err());
    // A value outside the safe range, on either side.
    assert!(declare(Setting::ParallelTasks(2), Setting::ParallelTasks(9), speed).is_err());
    assert!(declare(Setting::ParallelTasks(0), Setting::ParallelTasks(2), speed).is_err());
    // The target is a guard of the setting.
    assert!(
        declare(
            Setting::ParallelTasks(2),
            Setting::ParallelTasks(4),
            Metric::FirstPassGateSuccess
        )
        .is_err()
    );
    assert!(declare(Setting::ParallelTasks(2), Setting::ParallelTasks(4), speed).is_ok());
}

/// The remainders come from Python's `hashlib`: the SHA-256 of the documented text, its first
/// eight bytes as a big-endian integer, modulo 10 000.
#[test]
fn the_choice_of_jobs_is_the_documented_hash() {
    let first = job("018f3f2a-7b1c-7e2d-9a4b-0123456789ab");
    let second = job("018f3f2a-7b1c-7e2d-9a4b-0123456789ac");
    assert_eq!(draw(&slug("targeted-tests-first"), first), 5_011);
    assert_eq!(draw(&slug("targeted-tests-first"), second), 6_043);
    // Another experiment draws the same job differently.
    assert_eq!(draw(&slug("parallel-tasks-4"), first), 8_773);

    // The job gets the variant exactly when its remainder is below the share.
    let at = |share: u16| test_order(Share::new(share).expect("in range"), Windows::DEFAULT);
    assert_eq!(at(5_000).setting_for(first), &Setting::TestOrder(false)); // 5011 is not below 5000
    // The largest share is 5000, so this job never gets the variant of this experiment.
    let parallel = |share: u16| {
        Experiment::declare(
            slug("parallel-tasks-4"),
            Setting::ParallelTasks(2),
            Setting::ParallelTasks(4),
            Metric::LeadTimeToPullRequest,
            Share::new(share).expect("in range"),
            Windows::DEFAULT,
            &range(&[], &[]),
        )
        .expect("valid experiment")
    };
    assert_eq!(
        parallel(5_000).setting_for(first),
        &Setting::ParallelTasks(2)
    );
}

#[test]
fn the_share_of_jobs_with_the_variant_is_close_to_the_declared_share() {
    let experiment = test_order(Share::DEFAULT, Windows::DEFAULT);
    let with_variant = (0..20_000u32)
        .filter(|index| {
            let id = job(&format!("018f3f2a-7b1c-7e2d-9a4b-{index:012x}"));
            experiment.setting_for(id) == &Setting::TestOrder(true)
        })
        .count();
    // Binomial(20 000, 0.1): mean 2000, standard deviation 42. The identifiers are fixed.
    assert!((1_790..=2_210).contains(&with_variant), "{with_variant}");
}

#[test]
fn promotion_follows_the_table_of_the_design_document() {
    let experiment = test_order(Share::DEFAULT, Windows::DEFAULT);
    let decide = |target: &Comparison, guards: &[Comparison], windows_run| {
        experiment
            .decide_promotion(target, guards, windows_run)
            .expect("valid comparisons")
    };
    let mut guards = calm_guards();

    // The target improved and every guard is measured and not worse.
    assert_eq!(
        decide(&target(FASTER), &guards, 1),
        PromotionDecision::Promote
    );
    assert_eq!(
        decide(&target(FASTER), &guards, 4),
        PromotionDecision::Promote
    );

    // No clear change, or too few samples: keep running until the last window.
    let unclear = target((-900, -500, 0));
    assert_eq!(decide(&unclear, &guards, 3), PromotionDecision::KeepRunning);
    assert_eq!(
        decide(&unclear, &guards, 4),
        PromotionDecision::Discard(DiscardReason::NoClearImprovementInTime)
    );
    let few = too_few(Metric::TimeToFirstFailingTest);
    assert_eq!(decide(&few, &guards, 0), PromotionDecision::KeepRunning);
    assert_eq!(
        decide(&few, &guards, 5),
        PromotionDecision::Discard(DiscardReason::NoClearImprovementInTime)
    );

    // The target got worse.
    assert_eq!(
        decide(&target((100, 500, 900)), &guards, 1),
        PromotionDecision::Discard(DiscardReason::TargetWorsened)
    );

    // A guard with too few samples blocks the promotion.
    guards[0] = too_few(Metric::EscapedDefects);
    assert_eq!(
        decide(&target(FASTER), &guards, 1),
        PromotionDecision::KeepRunning
    );
    assert_eq!(
        decide(&target(FASTER), &guards, 4),
        PromotionDecision::Discard(DiscardReason::NoClearImprovementInTime)
    );

    // A guard that got worse discards, whatever the target shows. First-pass gate success is
    // better when higher, so a difference below zero is the worsening.
    guards[1] = shows(Metric::FirstPassGateSuccess, -90_000, -50_000, -10_000);
    assert_eq!(
        decide(&target(FASTER), &guards, 1),
        PromotionDecision::Discard(DiscardReason::GuardWorsened(Metric::FirstPassGateSuccess))
    );
    // The same difference on a metric that is better when lower is an improvement of the
    // guard, and does not discard.
    let mut guards = calm_guards();
    guards[2] = shows(Metric::HumanRejectionRate, -90_000, -50_000, -10_000);
    assert_eq!(
        decide(&target(FASTER), &guards, 1),
        PromotionDecision::Promote
    );
    guards[2] = shows(Metric::HumanRejectionRate, 10_000, 50_000, 90_000);
    assert_eq!(
        decide(&target(FASTER), &guards, 1),
        PromotionDecision::Discard(DiscardReason::GuardWorsened(Metric::HumanRejectionRate))
    );
}

#[test]
fn comparisons_that_do_not_belong_to_the_experiment_are_refused() {
    let experiment = test_order(Share::DEFAULT, Windows::DEFAULT);
    let guards = calm_guards();
    // Another target metric.
    let other = shows(Metric::LeadTimeToPullRequest, -9, -5, -1);
    assert!(experiment.decide_promotion(&other, &guards, 1).is_err());
    // A guard missing, a guard twice, a metric that is not a guard, and none at all.
    assert!(
        experiment
            .decide_promotion(&target(FASTER), &guards[..2], 1)
            .is_err()
    );
    let twice = [guards[0], guards[0], guards[1], guards[2]];
    assert!(
        experiment
            .decide_promotion(&target(FASTER), &twice, 1)
            .is_err()
    );
    let foreign = [
        guards[0],
        guards[1],
        shows(Metric::ReviewPrecision, -5, 0, 5),
    ];
    assert!(
        experiment
            .decide_promotion(&target(FASTER), &foreign, 1)
            .is_err()
    );
    assert!(
        experiment
            .decide_promotion(&target(FASTER), &[], 1)
            .is_err()
    );
    assert!(experiment.decide_rollback(&[]).is_err());
    assert!(experiment.decide_rollback(&guards[..2]).is_err());
}

#[test]
fn one_worse_guard_rolls_a_promotion_back() {
    let experiment = test_order(Share::DEFAULT, Windows::DEFAULT);
    let mut guards = calm_guards();
    assert_eq!(
        experiment.decide_rollback(&guards),
        Ok(RollbackDecision::Keep)
    );
    guards[0] = too_few(Metric::EscapedDefects);
    assert_eq!(
        experiment.decide_rollback(&guards),
        Ok(RollbackDecision::Keep)
    );
    guards[0] = shows(Metric::EscapedDefects, 1, 3, 6); // more defects
    assert_eq!(
        experiment.decide_rollback(&guards),
        Ok(RollbackDecision::RollBack(Metric::EscapedDefects))
    );
    guards[0] = shows(Metric::EscapedDefects, 0, 3, 6); // the interval touches zero
    assert_eq!(
        experiment.decide_rollback(&guards),
        Ok(RollbackDecision::Keep)
    );
}

#[test]
fn the_entry_of_a_promoted_improvement() {
    let experiment = test_order(Share::DEFAULT, Windows::DEFAULT);
    let mut guards = calm_guards();
    guards[0] = too_few(Metric::EscapedDefects);
    let improvement = Improvement {
        number: 1,
        experiment: &experiment,
        hypothesis: " Running the targeted tests first shows a failure sooner. ",
        target: target(FASTER),
        guards: &guards,
        outcome: Outcome::Promoted,
        decided_at: Timestamp::parse("2026-11-23T00:05:00Z").expect("valid"),
    };
    assert_eq!(
        improvement.entry_path(),
        "improvements/IM-0001-targeted-tests-first.md"
    );
    assert_eq!(
        improvement.render_entry().expect("renders"),
        "---\n\
         id: IM-0001\n\
         kind: improvement\n\
         title: Running the targeted tests first shows a failure sooner.\n\
         status: active\n\
         tier: A\n\
         experiment: targeted-tests-first\n\
         setting: test-order\n\
         from: the suite's own order\n\
         to: targeted tests first\n\
         share_of_jobs: 1000 hundredths of a percent\n\
         decision: promoted\n\
         decided_at: 2026-11-23T00:05:00Z\n\
         ---\n\
         \n\
         ## Hypothesis\n\
         \n\
         Running the targeted tests first shows a failure sooner.\n\
         \n\
         ## What was measured\n\
         \n\
         The difference is the variant minus the baseline, with its 95 percent interval.\n\
         \n\
         | Metric | Role | Difference | Interval | Samples | Shows |\n\
         |---|---|---|---|---|---|\n\
         | MT-0004 time-to-first-failing-test | target | -500 ms | -900 to -100 ms | 40 | improvement |\n\
         | MT-0009 escaped-defects | guard | too few samples | too few samples | 3 | nothing yet |\n\
         | MT-0006 first-pass-gate-success | guard | 0 millionths | -5 to 5 millionths | 40 | no clear change |\n\
         | MT-0011 human-rejection-rate | guard | 0 millionths | -5 to 5 millionths | 40 | no clear change |\n\
         \n\
         ## Decision\n\
         \n\
         The target metric improved and no guard metric got worse, so the variant is now the \
         setting of every job. It is rolled back automatically if a guard metric gets worse in \
         the next window.\n"
    );
}

#[test]
fn the_entry_names_the_reason_of_every_other_outcome() {
    let experiment = test_order(Share::DEFAULT, Windows::DEFAULT);
    let guards = calm_guards();
    let render = |outcome, hypothesis| {
        Improvement {
            number: 12,
            experiment: &experiment,
            hypothesis,
            target: target(FASTER),
            guards: &guards,
            outcome,
            decided_at: Timestamp::parse("2026-11-23T00:05:00Z").expect("valid"),
        }
        .render_entry()
    };
    let text = "A hypothesis.";
    let guard = render(
        Outcome::Discarded(DiscardReason::GuardWorsened(Metric::EscapedDefects)),
        text,
    )
    .expect("renders");
    assert!(guard.contains("id: IM-0012\n") && guard.contains("decision: discarded\n"));
    assert!(
        guard.ends_with("The guard metric escaped-defects got worse, so the baseline is kept.\n")
    );
    let worse = render(Outcome::Discarded(DiscardReason::TargetWorsened), text).expect("renders");
    assert!(worse.ends_with("The target metric got worse, so the baseline is kept.\n"));
    let late = render(
        Outcome::Discarded(DiscardReason::NoClearImprovementInTime),
        text,
    )
    .expect("renders");
    assert!(late.contains("After 4 windows the target metric showed no clear improvement"));
    let back = render(Outcome::RolledBack(Metric::HumanRejectionRate), text).expect("renders");
    assert!(back.contains("decision: rolled back\n"));
    assert!(back.ends_with(
        "the guard metric human-rejection-rate got worse, so the earlier value is back.\n"
    ));

    for broken in ["", "  ", "two\nlines", "a\rb"] {
        assert_eq!(
            render(Outcome::Promoted, broken),
            Err(MetricError::TextIsNotOneLine {
                what: "the hypothesis of an improvement"
            })
        );
    }
}

proptest! {
    /// The choice is a function of the experiment and the job only, and a larger share never
    /// takes the variant away from a job that had it.
    #[test]
    fn a_larger_share_keeps_every_job_of_a_smaller_one(
        bytes in any::<u128>(),
        small in 1u16..=5_000,
        large in 1u16..=5_000,
    ) {
        let (small, large) = (small.min(large), small.max(large));
        let id = JobId::from_uuid(uuid::Uuid::from_u128(bytes));
        let at = |share: u16| test_order(Share::new(share).expect("in range"), Windows::DEFAULT);
        let (in_small, in_large) = (
            at(small).setting_for(id) == &Setting::TestOrder(true),
            at(large).setting_for(id) == &Setting::TestOrder(true),
        );
        prop_assert_eq!(in_small, at(small).setting_for(id) == &Setting::TestOrder(true));
        prop_assert!(!in_small || in_large);
    }
}
