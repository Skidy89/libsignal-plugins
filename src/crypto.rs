use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

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
  cipher
    .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
    .map_err(|_| CryptoError::Encrypt)?;
  Ok(buf)
}

pub fn decrypt_int(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
  let cipher =
    Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKeyIv)?;

  let mut buf = data.to_vec();
  let len = cipher
    .decrypt_padded_mut::<Pkcs7>(&mut buf)
    .map_err(|_| CryptoError::Decrypt)?
    .len();
  buf.truncate(len);
  Ok(buf)
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
