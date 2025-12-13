use crate::sender_key_state::SenderKeyState;
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};

#[warn(dead_code)]
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[warn(dead_code)]
pub fn encrypt(state: &mut SenderKeyState, plaintext: &[u8]) -> Vec<u8> {
  let (key, iv) = state.next_message_key();

  let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
  let mut buffer = plaintext.to_vec();

  cipher.apply_keystream(&mut buffer);
  buffer
}
