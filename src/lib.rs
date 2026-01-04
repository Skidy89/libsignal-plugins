use crate::binding::{CreateKeyPair, GeneratePreKey, JsKeyPair};
use crate::keyhelper::{generate_pre_key_int, generate_registration_id_int};
use crate::utils::{
  create_key_pair_int, curve25519_sign_inner, derive_secrets_int, generate_key_pair_int,
  scrub_pub_key, shared_secret_int, verify_int,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;
mod binding;
mod crypto;
mod libsignal;

mod keyhelper;
mod utils;

// generates a key pair given a private key
// private key is a Buffer of length 32
// returns an object with pubKey and privKey (both Buffers)
// uses
#[napi]
pub fn key_pair<'a>(priv_key: Buffer) -> Result<JsKeyPair> {
  if priv_key.len() != 32 {
    return Err(Error::from_reason("Invalid private key length"));
  }
  let priv_key_array: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid private key"))?;
  let keys = create_key_pair_int(priv_key_array);
  Ok(JsKeyPair {
    pub_key: Buffer::from(keys.0.as_ref()),
    priv_key: Buffer::from(keys.1.as_ref()),
  })
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

  Ok(Buffer::from(shared.as_ref()))
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
pub fn generate_key_pair() -> Result<CreateKeyPair> {
  let (pub_key, priv_key) = generate_key_pair_int();

  let result = CreateKeyPair {
    pub_key: Buffer::from(pub_key.as_ref()),
    priv_key: Buffer::from(priv_key.as_ref()),
  };
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

  let pk: [u8; 32] = privkey
    .as_ref()
    .try_into()
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid private key"))?;

  let sig = curve25519_sign_inner(&pk, &msg);

  Ok(Buffer::from(sig.as_ref()))
}

#[napi]
pub fn generate_registration_id() -> Result<u16> {
  Ok(generate_registration_id_int())
}

#[napi]
pub fn generate_pre_key(key_id: u32) -> Result<GeneratePreKey> {
  let pre_key = generate_pre_key_int(key_id);

  let result = GeneratePreKey {
    pub_key: Buffer::from(pre_key.key_pair.pub_key.as_ref()),
    priv_key: Buffer::from(pre_key.key_pair.priv_key.as_ref()),
    key_id: pre_key.key_id,
  };

  Ok(result)
}

#[napi]
pub fn derive_secrets(
  input: Buffer,
  salt: Buffer,
  info: Buffer,
  chunks: u32,
) -> Result<Vec<Buffer>> {
  let secrets = derive_secrets_int(
    input.as_ref(),
    salt.as_ref(),
    info.as_ref(),
    chunks as usize,
  );
  let buffers: Vec<Buffer> = secrets
    .into_iter()
    .map(|arr| Buffer::from(arr.as_ref()))
    .collect();
  Ok(buffers)
}

#[napi]
pub fn encrypt_data(key: Buffer, data: Buffer, iv: Buffer) -> Result<Buffer> {
  if key.len() != 32 {
    return Err(Error::from_reason("Invalid key length"));
  }
  if iv.len() != 16 {
    return Err(Error::from_reason("Invalid IV length"));
  }

  let encrypted = crypto::encrypt_int(key.as_ref(), data.as_ref(), iv.as_ref())
    .map_err(|e| Error::from_reason(format!("Encryption failed: {:?}", e)))?;

  Ok(Buffer::from(encrypted))
}

#[napi]
pub fn decrypt_data(key: Buffer, data: Buffer, iv: Buffer) -> Result<Buffer> {
  if key.len() != 32 {
    return Err(Error::from_reason("Invalid key length"));
  }
  if iv.len() != 16 {
    return Err(Error::from_reason("Invalid IV length"));
  }
  let decrypted = crypto::decrypt_int(key.as_ref(), data.as_ref(), iv.as_ref())
    .map_err(|e| Error::from_reason(format!("Decryption failed: {:?}", e)))?;
  Ok(Buffer::from(decrypted))
}

#[napi]
pub fn verify_mac(key: Buffer, data: Buffer, expected_mac: Buffer, length: u32) -> Result<()> {
  crypto::verify_mac_int(
    key.as_ref(),
    data.as_ref(),
    expected_mac.as_ref(),
    length as usize,
  )
  .map_err(|e| Error::from_reason(format!("MAC verification failed: {:?}", e)))
}

#[napi]
pub fn calculate_mac(key: Buffer, data: Buffer) -> Result<Buffer> {
  let mac = crypto::calculate_mac(key.as_ref(), data.as_ref())
    .map_err(|e| Error::from_reason(format!("MAC calculation failed: {:?}", e)))?;
  Ok(Buffer::from(mac))
}
#[napi]
pub fn hash(data: Buffer) -> Result<Buffer> {
  let hash = crypto::hash_int(data.as_ref());
  Ok(Buffer::from(hash))
}


#[napi(object)]
pub struct DeviceBundleObject {
  pub identity_key: Buffer,
  pub registration_id: u32,
  pub signed_pre_key: SignedPreKeyBundle,
  pub pre_key: Option<PreKeyBundle>,
}

#[napi(object)]
pub struct SignedPreKeyBundle {
  pub key_id: u32,
  pub public_key: Buffer,
  pub signature: Buffer,
}

#[napi(object)]
pub struct PreKeyBundle {
  pub key_id: u32,
  pub public_key: Buffer,
}

#[napi(object)]
pub struct KeyPairObject {
  pub pub_key: Buffer,
  pub priv_key: Buffer,
}


#[napi(object)]
pub struct EncryptResult {
  pub r#type: u32,
  pub body: Buffer,
  pub registration_id: u32,
}

#[napi(object)]
pub struct PreKeyWhisperMessageObject {
  pub identity_key: Buffer,
  pub registration_id: u32,
  pub base_key: Buffer,
  pub pre_key_id: Option<u32>,
  pub signed_pre_key_id: u32,
}


#[napi(object)]
pub struct BaseKeyTypeEnum {
  pub ours: u8,
  pub theirs: u8,
}

#[napi(object)]
pub struct ChainTypeEnum {
  pub sending: u8,
  pub receiving: u8,
}

#[napi]
pub fn get_base_key_type() -> BaseKeyTypeEnum {
  BaseKeyTypeEnum { ours: 1, theirs: 2 }
}

#[napi]
pub fn get_chain_type() -> ChainTypeEnum {
  ChainTypeEnum {
    sending: 1,
    receiving: 2,
  }
}
