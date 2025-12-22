use crate::utils::generate_key_pair_int;
use rand::{rngs::OsRng, RngCore};
#[derive(Clone)]
pub struct KeyPair {
  pub priv_key: [u8; 32],
  pub pub_key: [u8; 33],
}

pub struct PreKey {
  pub key_id: u32,
  pub key_pair: KeyPair,
}

pub fn generate_registration_id_int() -> u16 {
  let mut rng = OsRng;
  let registration_id = rng.next_u32() as u16;
  registration_id & 0x3fff // ox3fff to limit to 14 bits
}

pub fn generate_pre_key_int(pre_key_id: u32) -> PreKey {
  let key_pair = generate_key_pair_int();
  PreKey {
    key_id: pre_key_id,
    key_pair: KeyPair {
      priv_key: key_pair.1,
      pub_key: key_pair.0,
    },
  }
}
