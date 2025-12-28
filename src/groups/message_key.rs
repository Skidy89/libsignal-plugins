use std::vec;

use crate::{groups::ciphertext::WHISPER_GROUP, utils::derive_secrets_int};

#[derive(Debug)]
pub struct SenderMessageKey {
  iteration: u32,
  iv: [u8; 16],
  cipher_key: [u8; 32],
  seed: [u8; 32],
}

impl SenderMessageKey {
  pub fn new(iteration: u32, seed: [u8; 32]) -> Self {
    let secrets = derive_secrets_int(seed.as_ref(), vec![0u8; 32].as_ref(), WHISPER_GROUP, 2);
    let f = &secrets[0];
    let s = &secrets[1];

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&f[0..16]);
    let mut cipher: [u8; 32] = [0u8; 32];
    cipher[0..16].copy_from_slice(&f[16..32]);
    cipher[16..32].copy_from_slice(&s[0..16]);
    SenderMessageKey {
      iteration,
      iv,
      cipher_key: cipher,
      seed: seed,
    }
  }
  pub fn get_iteration(&self) -> u32 {
    self.iteration
  }
  pub fn get_seed(&self) -> [u8; 32] {
    self.seed
  }
  pub fn get_iv(&self) -> [u8; 16] {
    self.iv
  }
  pub fn get_cipher_key(&self) -> [u8; 32] {
    self.cipher_key
  }
}
