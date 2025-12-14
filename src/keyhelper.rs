use crate::utils::{curve25519_sign_inner, generate_key_pair_int};
use rand::{rngs::OsRng, RngCore};
#[derive(Clone)]
pub struct KeyPair {
  pub priv_key: [u8; 32],
  pub pub_key: [u8; 33],
}

pub struct SignedPreKey {
  pub key_id: u32,
  pub key_pair: KeyPair,
  pub signature: [u8; 64],
}

pub struct PreKey {
  pub key_id: u32,
  pub key_pair: KeyPair,
}

pub fn generate_registration_id_int() -> u16 {
  let mut rng = OsRng;
  let registration_id: u16 = rng.next_u32() as u16;
  (registration_id & 0x3fff) as u16 // ox3fff to limit to 14 bits
}

pub fn generate_signed_pre_key_int(
  identity_key_pair: &KeyPair,
  signed_pre_key_id: u32,
) -> Result<SignedPreKey, Box<dyn std::error::Error>> {
  if identity_key_pair.priv_key.len() != 32 {
    return Err(Box::<dyn std::error::Error>::from(
      "Invalid identity private key length",
    ));
  }
  if identity_key_pair.pub_key.len() != 33 {
    return Err(Box::<dyn std::error::Error>::from(
      "Invalid identity public key length",
    ));
  }
  let key_pair = generate_key_pair_int();
  let signature = curve25519_sign_inner(
    &identity_key_pair.priv_key,
    &key_pair.0, // public key
  );
  Ok(SignedPreKey {
    key_id: signed_pre_key_id,
    key_pair: KeyPair {
      priv_key: key_pair.1, // private key
      pub_key: key_pair.0,  // public key
    },
    signature,
  })
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
