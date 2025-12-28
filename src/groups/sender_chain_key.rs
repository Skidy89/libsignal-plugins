use crate::crypto::calculate_mac;
use crate::groups::message_key::SenderMessageKey;

const MESSAGE_KEY_SEED: &[u8] = &[0x01];
const CHAIN_KEY_SEED: &[u8] = &[0x02];

pub struct SenderChainKey {
  iteration: u32,
  chain_key: Vec<u8>,
}

impl SenderChainKey {
  pub fn new(iteration: u32, chain_key: Vec<u8>) -> Self {
    SenderChainKey {
      iteration,
      chain_key,
    }
  }

  pub fn get_iteration(&self) -> u32 {
    self.iteration
  }

  pub fn get_sender_message_key(&self) -> Result<SenderMessageKey, String> {
    let derivative = self.get_derivative(MESSAGE_KEY_SEED)?;
    let seed: [u8; 32] = derivative
      .try_into()
      .map_err(|_| "Invalid derivative length for message key")?;
    Ok(SenderMessageKey::new(self.iteration, seed))
  }

  pub fn get_next(&self) -> Result<SenderChainKey, String> {
    let next_chain_key = self.get_derivative(CHAIN_KEY_SEED)?;
    Ok(SenderChainKey::new(self.iteration + 1, next_chain_key))
  }

  pub fn get_seed(&self) -> &[u8] {
    &self.chain_key
  }

  fn get_derivative(&self, seed: &[u8]) -> Result<Vec<u8>, String> {
    calculate_mac(&self.chain_key, seed).map_err(|e| format!("Failed to calculate MAC: {:?}", e))
  }
}
