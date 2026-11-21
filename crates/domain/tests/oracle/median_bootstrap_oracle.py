#!/usr/bin/env python3
"""An independent implementation of the bootstrap of the difference of two medians.

It follows the section "Comparing a duration or a cost before and after" of
docs/architecture/process-metrics-and-improvement.md and shares no code with
crates/domain/src/metrics/bootstrap.rs. The unit test
`the_interval_matches_the_independent_script` of that file holds the three numbers this script
prints. Run it with `python3 crates/domain/tests/oracle/median_bootstrap_oracle.py`.
"""

MASK = (1 << 64) - 1


class SplitMix64:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK
        mixed = self.state
        mixed = ((mixed ^ (mixed >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        mixed = ((mixed ^ (mixed >> 27)) * 0x94D049BB133111EB) & MASK
        return mixed ^ (mixed >> 31)

    def below(self, bound):
        """Lemire's method: a number from 0 to bound - 1 without bias."""
        product = self.next() * bound
        if (product & MASK) < bound:
            threshold = ((1 << 64) - bound) % bound
            while (product & MASK) < threshold:
                product = self.next() * bound
        return product >> 64


def nearest_rank(values, hundredths):
    ordered = sorted(values)
    rank = -(-hundredths * len(ordered) // 10_000)  # rounded up, in integers
    return ordered[rank - 1]


def resampled_median(samples, generator):
    drawn = [samples[generator.below(len(samples))] for _ in samples]
    return nearest_rank(drawn, 5_000)


def median_difference(before, after, resamples, seed):
    point = nearest_rank(after, 5_000) - nearest_rank(before, 5_000)
    generator = SplitMix64(seed)
    differences = []
    for _ in range(resamples):
        before_median = resampled_median(before, generator)
        after_median = resampled_median(after, generator)
        differences.append(after_median - before_median)
    lower = nearest_rank(differences, 250)
    upper = nearest_rank(differences, 9_750)
    return min(lower, point), point, max(upper, point)


if __name__ == "__main__":
    before = [1_000 + (i * 37) % 101 for i in range(40)]
    after = [980 + (i * 53) % 89 for i in range(35)]
    print(*median_difference(before, after, 2_000, 29))
