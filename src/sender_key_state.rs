use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct SenderKeyState {
  pub iteration: u32,
  pub chain_key: [u8; 32],
}

impl SenderKeyState {
  pub fn next_message_key(&mut self) -> ([u8; 32], [u8; 16]) {
    let mut hasher = Sha256::new();
    hasher.update(&self.chain_key);
    hasher.update(self.iteration.to_be_bytes());

    let hash = hasher.finalize();

    let mut cipher_key = [0u8; 32];
    let mut iv = [0u8; 16];

    cipher_key.copy_from_slice(&hash[..32]);
    iv.copy_from_slice(&hash[32..48]);

    self.iteration += 1;
    self.chain_key.zeroize();

    (cipher_key, iv)
  }
}
