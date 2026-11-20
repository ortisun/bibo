//! Size limits and the budget.
//!
//! Three kinds of limit keep the work and the prompt bounded:
//!
//! * **Read limits** say how much text the assembler will look at. An input over the limit is
//!   refused, not cut: the redactor must see all of a text, because a secret cut in two by a
//!   limit would leave half of it in the prompt.
//! * **Block limits** say how much of one input goes into the prompt. An input over the limit is
//!   cut at a character boundary and the block says so in its opening line (`truncated=yes
//!   omitted=<bytes>`). The context manifest records it as well.
//! * **The budget** says how big the whole prompt may be. It is the smaller of a byte limit and
//!   a share of the agent's `resource_limits.max_tokens`. When the blocks together would be over
//!   it, every input that is larger than a common level is cut to that level, and the small ones
//!   are untouched.
//!
//! The token figure is an estimate (`bytes_per_token`, 3 by default, pessimistic for English and
//! code). The model's own tokenizer is not available to a pure crate, and the run is metered by
//! the broker anyway (ADR 0005); the estimate only keeps the prompt from filling the run.

/// The limits of an assembler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes of one input the assembler will read. A larger input is refused.
    pub max_read_bytes_per_input: usize,
    /// The most bytes of all inputs together that the assembler will read.
    pub max_read_bytes_total: usize,
    /// The most bytes one block may take in the prompt, quote prefixes included. It follows the
    /// 256 KiB result limit of the file tools in the policy.
    pub max_block_bytes: usize,
    /// The most bytes the finished prompt may have.
    pub max_prompt_bytes: usize,
    /// The share of the agent's `max_tokens` that the prompt may use, in percent. The rest is
    /// for the work: the answers, the tool results and the turns that follow.
    pub prompt_share_of_run_tokens_percent: u8,
    /// The estimate of bytes in one token.
    pub bytes_per_token: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_read_bytes_per_input: 8 << 20,
            max_read_bytes_total: 32 << 20,
            max_block_bytes: 256 << 10,
            max_prompt_bytes: 1 << 20,
            prompt_share_of_run_tokens_percent: 25,
            bytes_per_token: 3,
        }
    }
}

impl Limits {
    /// The most bytes the prompt of an agent with `max_tokens` may have.
    #[must_use]
    pub fn prompt_budget_bytes(&self, max_tokens: u64) -> usize {
        let share = u64::from(self.prompt_share_of_run_tokens_percent.min(100));
        let tokens = max_tokens.saturating_mul(share) / 100;
        let from_tokens = usize::try_from(tokens)
            .unwrap_or(usize::MAX)
            .saturating_mul(self.bytes_per_token.max(1));
        self.max_prompt_bytes.min(from_tokens)
    }

    /// The estimated number of tokens in `bytes` bytes of prompt, rounded up.
    #[must_use]
    pub fn estimate_tokens(&self, bytes: usize) -> u64 {
        let per = self.bytes_per_token.max(1);
        u64::try_from(bytes.div_ceil(per)).unwrap_or(u64::MAX)
    }
}

/// How much of `available` bytes each input gets, when the inputs want `sizes` bytes.
///
/// When everything fits, each input gets what it wants. When it does not, the inputs are taken
/// from the smallest to the largest, and each gets the smaller of what it wants and an equal
/// share of what is left among the inputs not yet served. So an input below the common level is
/// kept whole, and every input above it is cut to that level, give or take one byte. Ties go by
/// position, so the answer is a function of the sizes only.
#[must_use]
pub(super) fn allowances(sizes: &[usize], available: usize) -> Vec<usize> {
    let wanted: usize = sizes
        .iter()
        .fold(0usize, |sum, size| sum.saturating_add(*size));
    if wanted <= available {
        return sizes.to_vec();
    }
    let mut order: Vec<usize> = (0..sizes.len()).collect();
    order.sort_by_key(|at| (sizes.get(*at).copied().unwrap_or(0), *at));
    let mut given = vec![0usize; sizes.len()];
    let mut remaining = available;
    let mut left = sizes.len();
    for at in order {
        let size = sizes.get(at).copied().unwrap_or(0);
        let share = remaining / left.max(1);
        let take = size.min(share);
        if let Some(slot) = given.get_mut(at) {
            *slot = take;
        }
        remaining -= take;
        left -= 1;
    }
    given
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn prompts_limits_everything_fits_so_everything_is_kept() {
        assert_eq!(allowances(&[10, 20, 30], 60), vec![10, 20, 30]);
        assert_eq!(allowances(&[], 0), Vec::<usize>::new());
    }

    #[test]
    fn prompts_limits_large_inputs_are_cut_to_a_common_level() {
        assert_eq!(allowances(&[5, 100, 100], 55), vec![5, 25, 25]);
        assert_eq!(allowances(&[100, 100, 100], 10), vec![3, 3, 4]);
        assert_eq!(allowances(&[100, 100], 0), vec![0, 0]);
    }

    #[test]
    fn prompts_limits_the_budget_is_a_share_of_the_run_tokens_and_a_byte_limit() {
        let limits = Limits::default();
        assert_eq!(limits.prompt_budget_bytes(10_000), 7_500);
        assert_eq!(limits.prompt_budget_bytes(400_000), 300_000);
        assert_eq!(limits.prompt_budget_bytes(4_000_000), 1 << 20);
        assert_eq!(limits.prompt_budget_bytes(0), 0);
        assert_eq!(limits.prompt_budget_bytes(u64::MAX), 1 << 20);
        assert_eq!(limits.estimate_tokens(0), 0);
        assert_eq!(limits.estimate_tokens(7), 3);
    }

    proptest! {
        #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn prompts_limits_allowances_never_exceed_the_budget_or_the_wish(
            sizes in proptest::collection::vec(0usize..1_000_000, 0..12),
            available in 0usize..2_000_000,
        ) {
            let given = allowances(&sizes, available);
            prop_assert_eq!(given.len(), sizes.len());
            let total: usize = given.iter().sum();
            let wanted: usize = sizes.iter().sum();
            prop_assert!(total <= available);
            for (g, s) in given.iter().zip(&sizes) {
                prop_assert!(g <= s);
            }
            if wanted <= available {
                prop_assert_eq!(&given, &sizes);
            } else {
                // The budget is used up, give or take what rounding leaves.
                prop_assert!(available - total < sizes.len().max(1));
                // Fair: two inputs that were both cut differ by at most one byte.
                let cut: Vec<usize> = given.iter().zip(&sizes).filter(|(g, s)| g < s).map(|(g, _)| *g).collect();
                if let (Some(lo), Some(hi)) = (cut.iter().min(), cut.iter().max()) {
                    prop_assert!(hi - lo <= 1);
                }
            }
        }
    }
}
