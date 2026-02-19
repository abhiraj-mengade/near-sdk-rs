use near_sdk::near;
use near_sdk::random::{SecureRng, Rng};

#[near(contract_state)]
#[derive(Default)]
pub struct LotteryContract {
    participants: Vec<String>,
    winner: Option<String>,
}

#[near]
impl LotteryContract {
    /// Initialize the lottery contract
    #[init]
    pub fn new() -> Self {
        Self {
            participants: Vec::new(),
            winner: None,
        }
    }

    /// Enter the lottery by adding your name to the participants list
    #[payable]
    pub fn enter_lottery(&mut self, name: String) {
        self.participants.push(name);
    }

    /// Pick a random winner from all participants
    pub fn pick_winner(&mut self) -> Option<String> {
        if self.participants.is_empty() {
            return None;
        }

        let mut rng = SecureRng::new();
        let winner_index = rng.usize(0..self.participants.len());
        self.winner = self.participants.get(winner_index).cloned();
        self.winner.clone()
    }

    /// Roll a dice (1-6)
    pub fn roll_dice(&mut self) -> u8 {
        let mut rng = SecureRng::new();
        rng.roll_die(6)
    }

    /// Flip a coin
    pub fn flip_coin(&mut self) -> bool {
        let mut rng = SecureRng::new();
        rng.flip_coin()
    }

    /// Get a random percentage (0-100)
    pub fn random_percentage(&mut self) -> u8 {
        let mut rng = SecureRng::new();
        rng.percentage()
    }

    /// Get current winner
    pub fn get_winner(&self) -> Option<String> {
        self.winner.clone()
    }

    /// Get number of participants
    pub fn get_participant_count(&self) -> u64 {
        self.participants.len() as u64
    }

    /// Reset the lottery for a new round
    pub fn reset_lottery(&mut self) {
        self.participants.clear();
        self.winner = None;
    }

    /// Draw multiple random winners without replacement
    pub fn draw_multiple_winners(&mut self, count: u8) -> Vec<String> {
        if self.participants.is_empty() {
            return Vec::new();
        }

        let mut rng = SecureRng::new();
        let participant_refs: Vec<&String> = self.participants.iter().collect();
        let winners = rng.sample_multiple(&participant_refs, count as usize);
        winners.iter().map(|&&s| s.clone()).collect()
    }

    /// Shuffle the participants list
    pub fn shuffle_participants(&mut self) {
        let mut rng = SecureRng::new();
        rng.shuffle(&mut self.participants);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::testing_env;
    use near_sdk::test_utils::VMContextBuilder;

    #[test]
    fn test_lottery_basic() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut contract = LotteryContract::new();
        
        // Add participants
        contract.enter_lottery("Alice".to_string());
        contract.enter_lottery("Bob".to_string());
        contract.enter_lottery("Charlie".to_string());

        assert_eq!(contract.get_participant_count(), 3);

        // Pick winner
        let winner = contract.pick_winner();
        assert!(winner.is_some());
        assert!(["Alice", "Bob", "Charlie"].contains(&winner.unwrap().as_str()));
    }

    #[test]
    fn test_dice_and_coin() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut contract = LotteryContract::new();

        // Test dice roll
        let dice_roll = contract.roll_dice();
        assert!(dice_roll >= 1 && dice_roll <= 6);

        // Test coin flip
        let coin_result = contract.flip_coin();
        // Should be either true or false
        assert!(coin_result || !coin_result);

        // Test percentage
        let percentage = contract.random_percentage();
        assert!(percentage <= 100);
    }

    #[test]
    fn test_empty_lottery() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut contract = LotteryContract::new();
        
        // No participants, should return None
        assert_eq!(contract.pick_winner(), None);
    }

    #[test]
    fn test_reset_lottery() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut contract = LotteryContract::new();
        
        // Add participants and pick winner
        contract.enter_lottery("Alice".to_string());
        contract.enter_lottery("Bob".to_string());
        let winner1 = contract.pick_winner();
        
        // Reset and pick again
        contract.reset_lottery();
        contract.enter_lottery("Alice".to_string());
        contract.enter_lottery("Bob".to_string());
        let winner2 = contract.pick_winner();
        
        // Should have participants again
        assert_eq!(contract.get_participant_count(), 2);
        assert!(winner1.is_some());
        assert!(winner2.is_some());
    }

    #[test]
    fn test_multiple_winners() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut contract = LotteryContract::new();
        
        // Add participants
        contract.enter_lottery("Alice".to_string());
        contract.enter_lottery("Bob".to_string());
        contract.enter_lottery("Charlie".to_string());
        contract.enter_lottery("David".to_string());
        contract.enter_lottery("Eve".to_string());

        // Draw 2 winners
        let winners = contract.draw_multiple_winners(2);
        assert_eq!(winners.len(), 2);
        
        // Winners should be unique
        let mut unique_winners: Vec<String> = winners.clone();
        unique_winners.sort();
        unique_winners.dedup();
        assert_eq!(unique_winners.len(), 2);
    }

    #[test]
    fn test_shuffle_participants() {
        testing_env!(VMContextBuilder::new().random_seed([42; 32]).build());

        let mut contract = LotteryContract::new();
        
        // Add participants in order
        contract.enter_lottery("Alice".to_string());
        contract.enter_lottery("Bob".to_string());
        contract.enter_lottery("Charlie".to_string());
        
        let original_order = contract.participants.clone();
        
        // Shuffle
        contract.shuffle_participants();
        
        // Should still have same participants
        assert_eq!(contract.get_participant_count(), 3);
        assert_eq!(contract.participants.len(), original_order.len());
        
        // All original participants should still be present
        for participant in &original_order {
            assert!(contract.participants.contains(participant));
        }
    }
}
