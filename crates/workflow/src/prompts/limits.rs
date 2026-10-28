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
