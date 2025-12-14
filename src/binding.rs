extern "C" {
  pub fn curve25519_sign(sig_out: *mut u8, privkey: *const u8, msg: *const u8, msg_len: usize);
  pub fn curve25519_verify(sig: *mut u8, pubkey: *const u8, msg: *const u8, msg_len: usize) -> i32;
}
