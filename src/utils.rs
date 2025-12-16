use crate::binding::{curve25519_sign, curve25519_verify};
use curve25519_dalek::{MontgomeryPoint, Scalar};
use hmac::{Hmac, Mac};
use napi::bindgen_prelude::Buffer;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

const BASEPOINT: [u8; 32] = {
  let mut base = [0u8; 32];
  base[0] = 9;
  base
};

pub fn get_basepoint() -> [u8; 32] {
  BASEPOINT
}

// clamping to avoid copies
#[inline(always)]
pub fn clamp_priv_key(priv_key: &mut [u8; 32]) {
  priv_key[0] &= 248;
  priv_key[31] &= 127;
  priv_key[31] |= 64;
}

pub fn create_key_pair_int(mut priv_key: [u8; 32]) -> ([u8; 33], [u8; 32]) {
  clamp_priv_key(&mut priv_key);
  let scalar = Scalar::from_bytes_mod_order(priv_key);
  let pub_key_raw = (scalar * MontgomeryPoint(get_basepoint())).to_bytes();
  let mut pub_key = [0u8; 33];
  pub_key[0] = 5; // version byte
  pub_key[1..33].copy_from_slice(&pub_key_raw);
  (pub_key, priv_key)
}

pub fn shared_secret_int(
  pub_key_bytes: &[u8],
  priv_key: [u8; 32],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
  if pub_key_bytes.len() != 32 && pub_key_bytes.len() != 33 {
    return Err(Box::<dyn std::error::Error>::from(
      "Invalid public key length",
    ));
  }
  let pub_key_32: [u8; 32] = if pub_key_bytes.len() == 33 {
    if pub_key_bytes[0] != 5 {
      return Err(Box::<dyn std::error::Error>::from(
        "Invalid public key version byte",
      ));
    }
    pub_key_bytes[1..33]
      .try_into()
      .map_err(|_| Box::<dyn std::error::Error>::from("Invalid public key"))?
  } else {
    pub_key_bytes
      .try_into()
      .map_err(|_| Box::<dyn std::error::Error>::from("Invalid public key"))?
  };
  let mut clamped_priv = priv_key;
  clamp_priv_key(&mut clamped_priv);
  let scalar = Scalar::from_bytes_mod_order(clamped_priv);
  let shared = (scalar * MontgomeryPoint(pub_key_32)).to_bytes();

  Ok(shared)
}

pub fn generate_key_pair_int() -> ([u8; 33], [u8; 32]) {
  let mut rng = OsRng;
  let mut priv_key = [0u8; 32];
  rng.fill_bytes(&mut priv_key);
  create_key_pair_int(priv_key)
}

pub fn verify_int(
  pub_key_bytes: &[u8],
  message: &[u8],
  sig: &[u8; 64],
) -> Result<bool, Box<dyn std::error::Error>> {
  let mut sig_copy = *sig;

  let ret = unsafe {
    curve25519_verify(
      sig_copy.as_mut_ptr(),
      pub_key_bytes.as_ptr(),
      message.as_ptr(),
      message.len(),
    )
  };

  Ok(ret == 0)
}

pub fn scrub_pub_key(pub_key: &Buffer) -> Result<[u8; 32], &'static str> {
  let slice = match pub_key.len() {
    32 => pub_key,
    33 if pub_key[0] == 5 => &pub_key[1..],
    33 => return Err("Invalid version byte!!"),
    _ => return Err("Invalid public key length, must be 32 or 33 bytes"),
  };

  let mut out = [0u8; 32];
  out.copy_from_slice(slice);
  Ok(out)
}

pub fn curve25519_sign_inner(privkey: &[u8; 32], msg: &[u8]) -> [u8; 64] {
  let mut sig_out = [0u8; 64];
  unsafe {
    curve25519_sign(
      sig_out.as_mut_ptr(),
      privkey.as_ptr(),
      msg.as_ptr(),
      msg.len(),
    );
  }
  sig_out
}

pub fn derive_secrets_int(input: &[u8], salt: &[u8], info: &[u8], chunks: usize) -> Vec<[u8; 32]> {
  assert_eq!(salt.len(), 32);
  assert!(chunks >= 1 && chunks <= 3);

  type HmacSha256 = Hmac<Sha256>;
  let prk = HmacSha256::new_from_slice(salt)
    .unwrap()
    .chain_update(input)
    .finalize()
    .into_bytes();

  let mut prev = Vec::new();
  let mut output = Vec::with_capacity(chunks);

  for i in 1..=chunks {
    let mut hmac = HmacSha256::new_from_slice(&prk).unwrap();
    hmac.update(&prev);
    hmac.update(info);
    hmac.update(&[i as u8]);
    let result = hmac.finalize().into_bytes();
    output.push(result.into());
    prev = result.to_vec();
  }

  output
}
