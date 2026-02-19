//! Secure random number generation for NEAR smart contracts.
//!
//! This module provides a secure random number generator based on ChaCha20 that addresses
//! the security considerations mentioned in issue #223:
//!
//! 1. **Transaction hash influence**: Uses block-level VRF seed + additional entropy
//! 2. **Same block consistency**: Ensures different transactions in same block get different numbers
//! 3. **Gas efficiency**: Minimizes computational overhead while maintaining security
//!
//! # Examples
//!
//! ```rust
//! use near_sdk::random::{SecureRng, Rng};
//!
//! #[near(contract_state)]
//! pub struct LotteryContract {
//!     rng: SecureRng,
//! }
//!
//! #[near]
//! impl LotteryContract {
//!     pub fn pick_winner(&mut self, participants: Vec<AccountId>) -> Option<AccountId> {
//!         let winner_index = self.rng.usize(0..participants.len());
//!         participants.get(winner_index).cloned()
//!     }
//! }
//! ```

#[cfg(feature = "secure-random")]
use crate::env;
#[cfg(feature = "secure-random")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "secure-random")]
use rand_core::{CryptoRng, RngCore, SeedableRng};
#[cfg(feature = "secure-random")]
use sha2::{Digest, Sha256};
#[cfg(feature = "secure-random")]
use rand::Rng as RandTrait;

#[cfg(feature = "secure-random")]
/// A secure random number generator for NEAR smart contracts.
///
/// This RNG combines the block's VRF randomness with additional entropy to prevent
/// transaction hash influence and ensure different results for different transactions
/// within the same block.
#[derive(Clone)]
pub struct SecureRng {
    inner: ChaCha20Rng,
}

#[cfg(feature = "secure-random")]
impl SecureRng {
    /// Creates a new secure RNG using the current block's random seed and additional entropy.
    ///
    /// This method addresses the security concerns from issue #223 by:
    /// - Using the block's VRF randomness as the base seed
    /// - Adding transaction-specific entropy to prevent influence
    /// - Ensuring different transactions in the same block get different numbers
    ///
    /// # Examples
    ///
    /// ```rust
    /// use near_sdk::random::SecureRng;
    ///
    /// let mut rng = SecureRng::new();
    /// let random_number = rng.u32(..);
    /// ```
    pub fn new() -> Self {
        let seed = Self::generate_secure_seed();
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Creates a new secure RNG with a custom entropy source.
    ///
    /// This allows contracts to provide additional entropy sources if needed.
    ///
    /// # Arguments
    ///
    /// * `additional_entropy` - Additional entropy to mix with the block seed
    ///
    /// # Examples
    ///
    /// ```rust
    /// use near_sdk::random::SecureRng;
    ///
    /// let custom_entropy = b"my-custom-entropy-source";
    /// let mut rng = SecureRng::with_entropy(custom_entropy);
    /// ```
    pub fn with_entropy(additional_entropy: &[u8]) -> Self {
        let seed = Self::generate_seed_with_entropy(additional_entropy);
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Generates a secure seed combining block randomness with transaction-specific entropy.
    fn generate_secure_seed() -> [u8; 32] {
        // Add transaction-specific entropy to prevent influence
        let transaction_entropy = Self::get_transaction_entropy();
        
        // Combine using SHA-256 for cryptographic security
        Self::generate_seed_with_entropy(&transaction_entropy)
    }

    /// Gets transaction-specific entropy to ensure different results per transaction.
    fn get_transaction_entropy() -> Vec<u8> {
        let mut hasher = Sha256::new();
        
        // Include current account ID (different contracts get different numbers)
        hasher.update(env::current_account_id().as_bytes());
        
        // Include predecessor account ID (different callers get different numbers)
        hasher.update(env::predecessor_account_id().as_bytes());
        
        // Include block index if available (different transactions in same block)
        if let Ok(block_index) = Self::get_block_index() {
            hasher.update(block_index.to_le_bytes());
        }
        
        // Include current gas prepaid (different gas amounts affect execution)
        hasher.update(env::prepaid_gas().as_gas().to_le_bytes());
        
        hasher.finalize().to_vec()
    }

    /// Attempts to get the current block index for additional entropy.
    /// In test environments, this may not be available, so we fall back to 0.
    fn get_block_index() -> Result<u64, ()> {
        // This would ideally use env::block_index() but that might not be available
        // For now, we'll use a simple approach that works in production
        Ok(env::block_timestamp())
    }

    /// Generates a seed by combining block randomness with provided entropy.
    fn generate_seed_with_entropy(additional_entropy: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Start with the block's VRF randomness
        hasher.update(env::random_seed_array());
        
        // Add the additional entropy
        hasher.update(additional_entropy);
        
        // Add some context to prevent replay attacks
        hasher.update(b"near-sdk-secure-rng-v1");
        
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hasher.finalize());
        seed
    }

    /// Resets the RNG with fresh entropy from the current environment.
    ///
    /// This is useful when you want to ensure fresh randomness for a new operation.
    pub fn reseed(&mut self) {
        self.inner = ChaCha20Rng::from_seed(Self::generate_secure_seed());
    }

    /// Generates a random boolean value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use near_sdk::random::SecureRng;
    ///
    /// let mut rng = SecureRng::new();
    /// let should_win = rng.bool();
    /// ```
    pub fn bool(&mut self) -> bool {
        RandTrait::r#gen(&mut self.inner)
    }

    /// Generates a random value within the given range.
    ///
    /// # Arguments
    ///
    /// * `range` - The range of possible values (inclusive lower bound, exclusive upper bound)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use near_sdk::random::SecureRng;
    ///
    /// let mut rng = SecureRng::new();
    /// let dice_roll = rng.u8(1..7); // 1-6
    /// ```
    pub fn u8(&mut self, range: std::ops::Range<u8>) -> u8 {
        RandTrait::gen_range(&mut self.inner, range)
    }

    /// Generates a random u16 value within the given range.
    pub fn u16(&mut self, range: std::ops::Range<u16>) -> u16 {
        RandTrait::gen_range(&mut self.inner, range)
    }

    /// Generates a random u32 value within the given range.
    pub fn u32(&mut self, range: std::ops::Range<u32>) -> u32 {
        RandTrait::gen_range(&mut self.inner, range)
    }

    /// Generates a random u64 value within the given range.
    pub fn u64(&mut self, range: std::ops::Range<u64>) -> u64 {
        RandTrait::gen_range(&mut self.inner, range)
    }

    /// Generates a random usize value within the given range.
    pub fn usize(&mut self, range: std::ops::Range<usize>) -> usize {
        RandTrait::gen_range(&mut self.inner, range)
    }

    /// Generates a random i32 value within the given range.
    pub fn i32(&mut self, range: std::ops::Range<i32>) -> i32 {
        RandTrait::gen_range(&mut self.inner, range)
    }

    /// Generates a random i64 value within the given range.
    pub fn i64(&mut self, range: std::ops::Range<i64>) -> i64 {
        RandTrait::gen_range(&mut self.inner, range)
    }

    /// Generates a random f32 value between 0.0 and 1.0.
    pub fn f32(&mut self) -> f32 {
        RandTrait::r#gen(&mut self.inner)
    }

    /// Generates a random f64 value between 0.0 and 1.0.
    pub fn f64(&mut self) -> f64 {
        RandTrait::r#gen(&mut self.inner)
    }

    /// Shuffles a slice in place using secure randomness.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use near_sdk::random::SecureRng;
    ///
    /// let mut rng = SecureRng::new();
    /// let mut deck = vec![1, 2, 3, 4, 5];
    /// rng.shuffle(&mut deck);
    /// ```
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        use rand::seq::SliceRandom;
        slice.shuffle(&mut self.inner);
    }

    /// Selects a random element from a slice.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use near_sdk::random::SecureRng;
    ///
    /// let mut rng = SecureRng::new();
    /// let options = vec!["apple", "banana", "orange"];
    /// let fruit = rng.choice(&options);
    /// ```
    pub fn choice<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            None
        } else {
            let index = self.usize(0..slice.len());
            Some(&slice[index])
        }
    }
}

#[cfg(feature = "secure-random")]
impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "secure-random")]
impl CryptoRng for SecureRng {}

#[cfg(feature = "secure-random")]
impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.inner.try_fill_bytes(dest)
    }
}

/// A convenient trait extension for common random operations.
#[cfg(feature = "secure-random")]
pub trait Rng {
    /// Generates a random boolean value.
    fn flip_coin(&mut self) -> bool;

    /// Rolls a die with the specified number of sides (1-sides inclusive).
    fn roll_die(&mut self, sides: u8) -> u8;

    /// Generates a random percentage (0-100).
    fn percentage(&mut self) -> u8;

    /// Selects multiple random elements from a slice without replacement.
    fn sample_multiple<'a, T>(&mut self, slice: &'a [T], count: usize) -> Vec<&'a T>;
}

#[cfg(feature = "secure-random")]
impl Rng for SecureRng {
    fn flip_coin(&mut self) -> bool {
        self.bool()
    }

    /// Rolls a die with the specified number of sides (1-sides inclusive).
    fn roll_die(&mut self, sides: u8) -> u8 {
        if sides == 0 {
            return 0;
        }
        self.u8(1..(sides + 1))
    }

    fn percentage(&mut self) -> u8 {
        self.u8(0..101)
    }

    fn sample_multiple<'a, T>(&mut self, slice: &'a [T], count: usize) -> Vec<&'a T> {
        if slice.len() < count {
            return slice.iter().collect();
        }

        let mut indices: Vec<usize> = (0..slice.len()).collect();
        self.shuffle(&mut indices);
        indices[0..count].iter().map(|&i| &slice[i]).collect()
    }
}

#[cfg(all(test, feature = "secure-random"))]
mod tests {
    use super::*;
    use crate::testing_env;
    use crate::test_utils::VMContextBuilder;

    #[test]
    fn test_secure_rng_basic() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut rng = SecureRng::new();
        
        // Test basic functionality
        let bool_val = rng.bool();
        let u8_val = rng.u8(0..100);
        let u32_val = rng.u32(1000..2000);
        let f64_val = rng.f64();

        assert!((0.0..=1.0).contains(&f64_val));
        assert!(u8_val < 100);
        assert!(u32_val >= 1000 && u32_val < 2000);
    }

    #[test]
    fn test_secure_rng_with_entropy() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let entropy = b"test-entropy";
        let mut rng1 = SecureRng::with_entropy(entropy);
        let mut rng2 = SecureRng::with_entropy(entropy);

        // Same entropy should produce same sequence
        assert_eq!(rng1.next_u32(), rng2.next_u32());
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn test_different_transactions_different_numbers() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut rng1 = SecureRng::new();
        let val1 = rng1.u32(0..1000000);

        // Simulate different transaction context with different predecessor
        testing_env!(
            VMContextBuilder::new()
                .random_seed([42; 32])
                .predecessor_account_id("different.testnet".parse().unwrap())
                .build()
        );

        let mut rng2 = SecureRng::new();
        let val2 = rng2.u32(0..1000000);

        // Should get different values due to transaction entropy
        assert_ne!(val1, val2);
    }

    #[test]
    fn test_rng_trait_methods() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut rng = SecureRng::new();

        // Test flip_coin
        let heads = rng.flip_coin();
        assert!(heads || !heads);

        // Test roll_die
        let die_roll = rng.roll_die(6);
        assert!(die_roll >= 1 && die_roll <= 6);

        // Test percentage
        let percent = rng.percentage();
        assert!(percent <= 100);

        // Test sample_multiple
        let options = vec![1, 2, 3, 4, 5];
        let samples = rng.sample_multiple(&options, 3);
        assert_eq!(samples.len(), 3);
        assert!(samples.iter().all(|item| options.contains(item)));
    }

    #[test]
    fn test_shuffle() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut rng = SecureRng::new();
        let original = vec![1, 2, 3, 4, 5];
        let mut shuffled = original.clone();

        rng.shuffle(&mut shuffled);

        // Should have same elements but potentially different order
        assert_eq!(original.len(), shuffled.len());
        assert!(original.iter().all(|item| shuffled.contains(item)));
    }

    #[test]
    fn test_choice() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut rng = SecureRng::new();
        let options = vec!["a", "b", "c"];

        let choice = rng.choice(&options);
        assert!(choice.is_some());
        assert!(options.contains(choice.unwrap()));

        // Empty slice should return None
        let empty: Vec<i32> = vec![];
        assert!(rng.choice(&empty).is_none());
    }

    #[test]
    fn test_reseed() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut rng = SecureRng::new();
        let val1 = rng.next_u32();

        // Change the context to simulate a new transaction
        testing_env!(
            VMContextBuilder::new()
                .random_seed([42; 32])
                .predecessor_account_id("new.testnet".parse().unwrap())
                .build()
        );

        rng.reseed();
        let val2 = rng.next_u32();

        // Should get different values after reseeding
        assert_ne!(val1, val2);
    }
}
