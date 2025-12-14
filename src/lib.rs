use crate::group_cipher::encrypt;
use crate::sender_key_state::SenderKeyState;
use crate::utils::{create_key_pair_int, generate_key_pair_int, shared_secret_int, verify_int};
use napi::bindgen_prelude::*;
use napi_derive::napi;
mod group_cipher;
mod sender_key_state;
mod utils;

// not implemented yet, placeholder
// thread '<unnamed>' panicked at src\sender_key_state.rs:22:29:
//range end index 48 out of range for slice of length 32
//note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
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

// generates a key pair given a private key
// private key is a Buffer of length 32
// returns an object with pubKey and privKey (both Buffers)
// uses
#[napi]
pub fn key_pair<'a>(env: Env, priv_key: Buffer) -> Result<Object<'a>> {
  if priv_key.len() != 32 {
    return Err(Error::from_reason("Invalid private key length"));
  }
  let priv_key_array: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid private key"))?;
  let (pub_key, clamped_priv) = create_key_pair_int(priv_key_array);
  let mut result = Object::new(&env)?;
  result.set("pubKey", Buffer::from(Vec::from(pub_key)))?;
  result.set("privKey", Buffer::from(Vec::from(clamped_priv)))?;

  Ok(result)
}

#[napi]
pub fn shared_secret(pub_key: Buffer, priv_key: Buffer) -> Result<Buffer> {
  if priv_key.len() != 32 {
    return Err(Error::from_reason("Invalid private key length"));
  }

  let priv_key_array: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid private key"))?;

  let shared = shared_secret_int(pub_key.as_ref(), priv_key_array)
    .map_err(|e| Error::from_reason(format!("Shared secret calculation failed: {}", e)))?;

  Ok(Buffer::from(Vec::from(shared)))
}

#[napi]
pub fn verify(sig: Buffer, pub_key: Buffer, message: Buffer) -> Result<bool> {
  if sig.len() != 64 {
    return Err(Error::from_reason("Invalid signature length"));
  }

  let sig_array: &[u8; 64] = sig
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid signature"))?;

  verify_int(pub_key.as_ref(), message.as_ref(), sig_array)
    .map_err(|e| Error::from_reason(format!("Verification failed: {}", e)))
}

#[napi]
pub fn generate_key_pair<'a>(env: Env) -> Result<Object<'a>> {
  let (pub_key, priv_key) = generate_key_pair_int();

  // Crear formato con byte de versión sin allocations innecesarias
  let mut pub_with_version = Vec::with_capacity(33);
  pub_with_version.push(5);
  pub_with_version.extend_from_slice(&pub_key);

  let mut result = Object::new(&env)?;
  result.set("pubKey", Buffer::from(pub_with_version))?;
  result.set("privKey", Buffer::from(Vec::from(priv_key)))?;

  Ok(result)
}

#[napi]
pub fn create_key_pair<'a>(env: Env, priv_key: Buffer) -> Result<Object<'a>> {
  if priv_key.len() != 32 {
    return Err(Error::from_reason("Invalid private key length"));
  }

  let priv_key_array: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid private key"))?;

  let (pub_key, clamped_priv) = create_key_pair_int(priv_key_array);
  let mut pub_with_version = Vec::with_capacity(33);
  pub_with_version.push(5);
  pub_with_version.extend_from_slice(&pub_key);

  let mut result = Object::new(&env)?;
  result.set("pubKey", Buffer::from(pub_with_version))?;
  result.set("privKey", Buffer::from(Vec::from(clamped_priv)))?;

  Ok(result)
}

#[napi]
pub fn calculate_agreement(pub_key: Buffer, priv_key: Buffer) -> Result<Buffer> {
  shared_secret(pub_key, priv_key)
}

#[napi]
pub fn verify_signature(
  pub_key: Buffer,
  message: Buffer,
  sig: Buffer,
  is_init: bool,
) -> Result<bool> {
  if is_init {
    return Ok(true);
  }

  verify(sig, pub_key, message)
}
