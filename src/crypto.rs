use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use hmac::{Hmac, Mac};
use prost::Message;
use proto_gen::textsecure::WhisperMessage;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::utils::derive_secrets_int;

#[derive(Debug)]
pub enum CryptoError {
  InvalidKeyIv,
  Encrypt,
  Decrypt,
  Mac,
}

pub fn encrypt_int(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
  let cipher =
    Encryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKeyIv)?;
  let msg_len = data.len();

  let mut buf = vec![0u8; msg_len + 16];
  buf[..msg_len].copy_from_slice(data);
  let ct = cipher
    .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
    .map_err(|_| CryptoError::Encrypt)?;
  Ok(ct.to_vec())
}

pub fn decrypt_int(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
  let cipher =
    Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKeyIv)?;

  let mut buf = data.to_vec();
  let decrypted_data = cipher
    .decrypt_padded_mut::<Pkcs7>(&mut buf)
    .map_err(|_| CryptoError::Decrypt)?;

  Ok(decrypted_data.to_vec())
}

pub fn calculate_mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
  let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| CryptoError::Mac)?;

  mac.update(data);
  Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_mac_int(
  key: &[u8],
  data: &[u8],
  expected_mac: &[u8],
  length: usize,
) -> Result<(), CryptoError> {
  let mut calculated = calculate_mac(key, data)?;

  if expected_mac.len() != length || calculated.len() < length {
    return Err(CryptoError::Mac);
  }

  let mut diff = 0u8;
  for i in 0..length {
    diff |= expected_mac[i] ^ calculated[i];
  }

  if diff != 0 {
    return Err(CryptoError::Mac);
  }
  calculated.zeroize();

  Ok(())
}

pub fn hash_int(data: &[u8]) -> Vec<u8> {
  let mut hasher = Sha512::new();
  hasher.update(data);
  hasher.finalize().to_vec()
}

pub fn aes_256_cbc_encrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
  let cipher =
    Encryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKeyIv)?;
  let msg_len = data.len();

  let mut buf = vec![0u8; msg_len + 16];
  buf[..msg_len].copy_from_slice(data);
  let ct = cipher
    .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
    .map_err(|_| CryptoError::Encrypt)?;
  Ok(ct.to_vec())
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_whisper_message_int(
  message_key: &[u8],
  plaintext: &[u8],

  ephemeral_key: &[u8],
  counter: u32,
  previous_counter: Option<u32>,

  our_identity: &[u8],
  remote_identity: &[u8],

  version: u8,
) -> Result<Vec<u8>, CryptoError> {
  let version_byte = ((version & 0x0f) << 4) | (version & 0x0f);

  let keys = derive_secrets_int(message_key, &[0u8; 32], b"WhisperMessageKeys", 3);

  let cipher_key: &[u8] = &keys[0];
  let mac_key: &[u8] = &keys[1];
  let iv: &[u8] = &keys[2][..16];

  let ciphertext = aes_256_cbc_encrypt(cipher_key, plaintext, iv)?;

  let whisper = WhisperMessage {
    ephemeral_key: ephemeral_key.to_vec().into(),
    counter: Some(counter),
    previous_counter: previous_counter,
    ciphertext: Some(ciphertext),
  };

  let msg_buf = whisper.encode_to_vec();

  let mut mac_input =
    Vec::with_capacity(our_identity.len() + remote_identity.len() + 1 + msg_buf.len());

  mac_input.extend_from_slice(our_identity);
  mac_input.extend_from_slice(remote_identity);
  mac_input.push(version_byte);
  mac_input.extend_from_slice(&msg_buf);

  let mac = calculate_mac(mac_key, &mac_input)?;

  let mut result = Vec::with_capacity(msg_buf.len() + 9);

  result.push(version_byte);
  result.extend_from_slice(&msg_buf);
  result.extend_from_slice(&mac[..8]);

  Ok(result)
}
