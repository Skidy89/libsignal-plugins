use crate::group_cipher::encrypt;
use crate::sender_key_state::SenderKeyState;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::rngs::OsRng;
use x25519_dalek::PublicKey as X25519Public;
use x25519_dalek::StaticSecret;
mod group_cipher;
mod sender_key_state;

#[napi]
pub fn group_encrypt(iteration: u32, chain_key: Buffer, plaintext: Buffer) -> Result<Buffer> {
  if chain_key.len() != 32 {
    return Err(Error::from_reason("Invalid chain key length"));
  }

  let mut state = SenderKeyState {
    iteration,
    chain_key: chain_key.as_ref().try_into().unwrap(),
  };

  let ciphertext = encrypt(&mut state, plaintext.as_ref());

  Ok(Buffer::from(ciphertext))
}

fn validate_priv_key(priv_key: &[u8]) -> Result<()> {
  if priv_key.is_empty() {
    return Err(Error::from_reason("Private key is empty".to_string()));
  }
  if !priv_key.len() == 32 {
    return Err(Error::from_reason("Invalid private key length".to_string()));
  }
  Ok(())
}

fn scrub_pub_key_format(pub_key: &[u8]) -> Result<[u8; 32]> {
  match pub_key.len() {
    33 if pub_key[0] == 5 => Ok(pub_key[1..].try_into().unwrap()),
    32 => Ok(pub_key.try_into().unwrap()),
    _ => Err(Error::from_reason("Invalid public key")),
  }
}

#[napi]
pub fn generate_key_pair<'a>(env: &'a Env) -> Result<Object<'a>> {
  let mut rng = OsRng;
  let privkey = StaticSecret::random_from_rng(&mut rng);
  create_key_pair(env, Buffer::from(privkey.to_bytes().to_vec()))
}

#[napi]
pub fn create_key_pair<'a>(env: &'a Env, priv_key: Buffer) -> Result<Object<'a>> {
  validate_priv_key(priv_key.as_ref())?;

  let secret = StaticSecret::from(<[u8; 32]>::try_from(priv_key.as_ref()).unwrap());
  let pubkey = X25519Public::from(&secret);

  let mut pub_with_version = vec![0u8; 33];
  pub_with_version[0] = 5;
  pub_with_version[1..].copy_from_slice(pubkey.as_bytes());

  let mut obj = Object::new(&env)?;
  obj.set("pubKey", Buffer::from(pub_with_version))?;
  obj.set("privKey", Buffer::from(secret.to_bytes().to_vec()))?;
  Ok(obj)
}

#[napi]
pub fn calculate_agreement(pub_key: Buffer, priv_key: Buffer) -> Result<Buffer> {
  let pub_key = if pub_key.len() == 33 {
    &pub_key[1..]
  } else {
    &pub_key[..]
  };

  if pub_key.len() != 32 {
    return Err(Error::from_reason("Invalid public key"));
  }
  if priv_key.len() != 32 {
    return Err(Error::from_reason("Invalid private key"));
  }

  let mut k = [0u8; 32];
  k.copy_from_slice(&priv_key);

  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;

  let scalar = Scalar::from_bytes_mod_order(k);
  let point = MontgomeryPoint(pub_key.try_into().unwrap());

  let shared = (scalar * point).to_bytes();

  Ok(Buffer::from(shared.to_vec()))
}

#[napi]
pub fn verify_signature(
  pub_key: &[u8],
  message: &[u8],
  signature: &[u8],
  is_init: bool,
) -> Result<bool> {
  if is_init {
    return Ok(true);
  }

  let pubkey = scrub_pub_key_format(pub_key.as_ref())?;
  if signature.len() != 64 {
    return Err(Error::from_reason("Invalid signature length"));
  }

  let verify_key = VerifyingKey::from_bytes(&pubkey).unwrap();
  let signature = Signature::from_bytes(signature.as_ref().try_into().unwrap());

  Ok(
    verify_key
      .verify_strict(message.as_ref(), &signature)
      .is_ok(),
  )
}
