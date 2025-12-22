use napi::bindgen_prelude::*;
use napi_derive::napi;

extern "C" {
  pub fn curve25519_sign(sig_out: *mut u8, privkey: *const u8, msg: *const u8, msg_len: usize);
  pub fn curve25519_verify(sig: *mut u8, pubkey: *const u8, msg: *const u8, msg_len: usize) -> i32;
}

#[napi(object)]
pub struct JsKeyPair {
  pub pub_key: Buffer,
  pub priv_key: Buffer,
}

#[napi(object)]
pub struct CreateKeyPair {
  pub pub_key: Buffer,
  pub priv_key: Buffer,
}

#[napi(object)]
pub struct GeneratePreKey {
  pub pub_key: Buffer,
  pub priv_key: Buffer,
  pub key_id: u32,
}
