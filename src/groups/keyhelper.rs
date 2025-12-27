use rand::rngs::OsRng;
use rand::{Rng, RngCore};

use crate::libsignal::constants::KeyPair;
use crate::utils::generate_key_pair_int;

pub fn generate_sender_key() -> [u8; 32] {
  let mut rng = OsRng;
  let mut sender_key = [0u8; 32];
  rng.fill_bytes(&mut sender_key);
  sender_key
}

pub fn generate_sender_key_id() -> u32 {
  OsRng.gen_range(0..2_147_483_647)
}

pub fn generate_sender_signing_key(pair_keys: Option<KeyPair>) -> KeyPair {
  if !pair_keys.is_none() {
    return pair_keys.unwrap();
  }
  let d = generate_key_pair_int();
  KeyPair {
    pub_key: d.0,
    priv_key: d.1,
  }
}
