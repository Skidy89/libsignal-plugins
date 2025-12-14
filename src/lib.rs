use crate::group_cipher::encrypt;
use crate::keyhelper::{generate_pre_key_int, generate_registration_id_int};
use crate::sender_key_state::SenderKeyState;
use crate::utils::{
  create_key_pair_int, curve25519_sign_inner, generate_key_pair_int, scrub_pub_key,
  shared_secret_int, verify_int,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;
mod group_cipher;
mod keyhelper;
mod sender_key_state;
mod utils;
mod binding;



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
  let pub_key = scrub_pub_key(&pub_key).map_err(|e| Error::from_reason(e))?;
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
  let pub_key_scrubbed = scrub_pub_key(&pub_key)
    .map_err(|e| Error::from_reason(format!("Failed to scrub public key: {}", e)))?;

  let sig_array: &[u8; 64] = sig
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid signature"))?;

  verify_int(pub_key_scrubbed.as_ref(), message.as_ref(), sig_array)
    .map_err(|e| Error::from_reason(format!("Verification failed: {}", e)))
}

#[napi]
pub fn generate_key_pair<'a>(env: Env) -> Result<Object<'a>> {
  let (pub_key, priv_key) = generate_key_pair_int();

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

#[napi]
pub fn curve25519_sign(privkey: Buffer, msg: Buffer) -> Result<Buffer> {

  if privkey.len() != 32 {
    return Err(Error::new(Status::InvalidArg, "privkey must be 32 bytes"));
  }

  let mut pk = [0u8; 32];
  pk.copy_from_slice(&privkey);

  let sig = curve25519_sign_inner(&pk, &msg);

  Ok(Buffer::from(sig.to_vec()))
}

#[napi]
pub fn generate_registration_id() -> Result<u16> {
  Ok(generate_registration_id_int())
}

#[napi]
pub fn generate_signed_pre_key<'a>(
  env: Env,
  identity_priv_key: Buffer,
  identity_pub_key: Buffer,
  signed_pre_key_id: u32,
) -> Result<Object<'a>> {
  if identity_priv_key.len() != 32 {
    return Err(Error::from_reason("Invalid identity private key length"));
  }
  if identity_pub_key.len() != 33 {
    return Err(Error::from_reason("Invalid identity public key length"));
  }

  let identity_priv_array: [u8; 32] = identity_priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid identity private key"))?;
  let identity_pub_array: [u8; 33] = identity_pub_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid identity public key"))?;

  let identity_key_pair = keyhelper::KeyPair {
    priv_key: identity_priv_array,
    pub_key: identity_pub_array,
  };

  let signed_pre_key =
    keyhelper::generate_signed_pre_key_int(&identity_key_pair, signed_pre_key_id)
      .map_err(|e| Error::from_reason(format!("Failed to generate Signed Pre Key: {}", e)))?;

  let mut result = Object::new(&env)?;
  result.set("keyId", signed_pre_key.key_id)?;
  result.set(
    "privKey",
    Buffer::from(Vec::from(signed_pre_key.key_pair.priv_key)),
  )?;
  result.set(
    "pubKey",
    Buffer::from(Vec::from(signed_pre_key.key_pair.pub_key)),
  )?;
  result.set(
    "signature",
    Buffer::from(Vec::from(signed_pre_key.signature)),
  )?;

  Ok(result)
}

#[napi]
pub fn generate_pre_key<'a>(env: Env, key_id: u32) -> Result<Object<'a>> {
  let pre_key = generate_pre_key_int(key_id);

  let mut result = Object::new(&env)?;
  result.set("keyId", pre_key.key_id)?;
  result.set("privKey", Buffer::from(pre_key.key_pair.priv_key.to_vec()))?;
  result.set("pubKey", Buffer::from(pre_key.key_pair.pub_key.to_vec()))?;

  Ok(result)
}
