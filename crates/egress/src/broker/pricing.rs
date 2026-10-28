//! What a request costs: token counts times a price per model, in millionths of a dollar.
//!
//! The broker meters from the provider's own report of usage. The cost of a request comes from a
//! [`PriceList`] that the composition root supplies from configuration. This crate holds no price
//! of any real model: a price in code would go stale without anyone noticing, and a wrong price
//! is a wrong budget. A model with no price is refused, never guessed.

use std::collections::BTreeMap;

use factory_ports::agent::CostMicroUsd;

use super::provider::Provider;

/// What one answer used, split the way providers bill it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenCounts {
    /// Input tokens billed at the plain input price.
    pub input: u64,
    /// Input tokens written to the provider's prompt cache.
    pub cache_write: u64,
    /// Input tokens read from the provider's prompt cache.
    pub cache_read: u64,
    /// Output tokens, including reasoning tokens.
    pub output: u64,
}

impl TokenCounts {
    /// Every token sent to the model, whatever price it was billed at.
    #[must_use]
    pub fn total_input(&self) -> u64 {
        self.input
            .saturating_add(self.cache_write)
            .saturating_add(self.cache_read)
    }
}

/// The price of one model, in millionths of a dollar per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelPrice {
    /// Plain input.
    pub input: u64,
    /// Input written to the cache.
    pub cache_write: u64,
    /// Input read from the cache.
    pub cache_read: u64,
    /// Output.
    pub output: u64,
}

/// Turns token counts into a cost.
pub trait PriceList: Send + Sync {
    /// The cost of `counts` for `model`, rounded up to a whole micro-dollar, or `None` when the
    /// list has no price for that model at that provider.
    fn cost(&self, provider: Provider, model: &str, counts: &TokenCounts) -> Option<CostMicroUsd>;
}

/// A price list read from configuration.
#[derive(Debug, Clone, Default)]
pub struct PriceTable {
    entries: BTreeMap<(Provider, String), ModelPrice>,
}

impl PriceTable {
    /// An empty table: every model is refused.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the price of one model.
    #[must_use]
    pub fn with_model(mut self, provider: Provider, model: &str, price: ModelPrice) -> Self {
        self.entries.insert((provider, model.to_owned()), price);
        self
    }
}

impl PriceList for PriceTable {
    fn cost(&self, provider: Provider, model: &str, counts: &TokenCounts) -> Option<CostMicroUsd> {
        let price = self.entries.get(&(provider, model.to_owned()))?;
        let part = |tokens: u64, rate: u64| u128::from(tokens) * u128::from(rate);
        let total = part(counts.input, price.input)
            .saturating_add(part(counts.cache_write, price.cache_write))
            .saturating_add(part(counts.cache_read, price.cache_read))
            .saturating_add(part(counts.output, price.output));
        let micro = total.div_ceil(1_000_000);
        Some(CostMicroUsd(u64::try_from(micro).unwrap_or(u64::MAX)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> PriceTable {
        PriceTable::new().with_model(
            Provider::Anthropic,
            "test-model",
            ModelPrice {
                input: 3_000_000,
                cache_write: 3_750_000,
                cache_read: 300_000,
                output: 15_000_000,
            },
        )
    }

    #[test]
    fn the_cost_adds_each_kind_of_token_at_its_own_price() {
        let counts = TokenCounts {
            input: 1_000,
            cache_write: 2_000,
            cache_read: 10_000,
            output: 500,
        };
        // 3_000 + 7_500 + 3_000 + 7_500 micro-dollars.
        assert_eq!(
            table().cost(Provider::Anthropic, "test-model", &counts),
            Some(CostMicroUsd(21_000))
        );
    }

    #[test]
    fn a_fraction_of_a_micro_dollar_rounds_up_so_cost_is_never_undercounted() {
        let counts = TokenCounts {
            input: 1,
            ..TokenCounts::default()
        };
        let cheap = PriceTable::new().with_model(
            Provider::OpenAi,
            "m",
            ModelPrice {
                input: 1,
                cache_write: 1,
                cache_read: 1,
                output: 1,
            },
        );
        assert_eq!(
            cheap.cost(Provider::OpenAi, "m", &counts),
            Some(CostMicroUsd(1))
        );
        assert_eq!(
            cheap.cost(Provider::OpenAi, "m", &TokenCounts::default()),
            Some(CostMicroUsd(0))
        );
    }

    #[test]
    fn a_model_with_no_price_or_at_another_provider_has_no_cost() {
        let counts = TokenCounts::default();
        assert_eq!(table().cost(Provider::Anthropic, "other", &counts), None);
        assert_eq!(table().cost(Provider::OpenAi, "test-model", &counts), None);
    }

    #[test]
    fn huge_counts_saturate_instead_of_overflowing() {
        let counts = TokenCounts {
            input: u64::MAX,
            cache_write: u64::MAX,
            cache_read: u64::MAX,
            output: u64::MAX,
        };
        let cost = table().cost(Provider::Anthropic, "test-model", &counts);
        assert!(cost.is_some());
    }
}
