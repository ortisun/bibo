//! A small random source for fake secrets and fake identifiers.
//!
//! The values it makes protect nothing. They only have to look like the real thing and differ
//! from run to run, so the canaries cannot be hard-coded into a test, a fixture or a git
//! history. `FxRng::from_entropy` seeds from the operating system through the standard library's
//! hash randomisation plus the clock and the process id. `FxRng::from_seed` replays the same
//! sequence for a test that needs to be exactly reproducible.
//!
//! The generator is SplitMix64. It is not a cryptographic generator and must not be used as one.

use std::hash::{BuildHasher, Hasher, RandomState};
use std::time::{SystemTime, UNIX_EPOCH};

/// A deterministic generator that can also seed itself from the environment.
#[derive(Debug, Clone)]
pub struct FxRng {
    state: u64,
}

impl FxRng {
    /// A generator that makes the same sequence for the same seed.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// A generator seeded from the operating system, the clock and the process id.
    #[must_use]
    pub fn from_entropy() -> Self {
        let mut hasher = RandomState::new().build_hasher();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        hasher.write_u128(nanos);
        hasher.write_u32(std::process::id());
        let local = 0u8;
        hasher.write_usize(std::ptr::from_ref(&local) as usize);
        Self {
            state: hasher.finish(),
        }
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `0..bound`. `bound` must not be zero.
    ///
    /// # Panics
    /// Panics when `bound` is zero.
    pub fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "below(0) has no answer");
        (self.next_u64() % bound as u64) as usize
    }

    /// `length` characters, each picked from `alphabet`.
    pub fn string_from(&mut self, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| char::from(alphabet[self.below(alphabet.len())]))
            .collect()
    }
}

/// Letters and digits.
pub const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Letters, digits, `-` and `_`.
pub const URL_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/// The standard base64 alphabet.
pub const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Lowercase hexadecimal digits.
pub const HEX_LOWER: &[u8] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_sequence_and_another_seed_does_not() {
        let mut a = FxRng::from_seed(7);
        let mut b = FxRng::from_seed(7);
        let mut c = FxRng::from_seed(8);
        let (x, y, z) = (a.next_u64(), b.next_u64(), c.next_u64());
        assert_eq!(x, y);
        assert_ne!(x, z);
    }

    #[test]
    fn splitmix64_matches_its_published_first_output() {
        // Reference value for seed 0 from the SplitMix64 description by Sebastiano Vigna.
        assert_eq!(FxRng::from_seed(0).next_u64(), 0xE220_A839_7B1D_CDAF);
    }

    #[test]
    fn two_entropy_generators_differ() {
        assert_ne!(
            FxRng::from_entropy().next_u64(),
            FxRng::from_entropy().next_u64()
        );
    }

    #[test]
    fn strings_use_only_the_alphabet_and_have_the_length_asked_for() {
        let mut rng = FxRng::from_seed(1);
        let text = rng.string_from(HEX_LOWER, 64);
        assert_eq!(text.len(), 64);
        assert!(text.bytes().all(|b| HEX_LOWER.contains(&b)));
    }

    #[test]
    #[should_panic(expected = "below(0)")]
    fn a_zero_bound_is_refused() {
        FxRng::from_seed(1).below(0);
    }
}
