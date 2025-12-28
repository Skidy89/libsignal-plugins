use crate::crypto::{decrypt_int, encrypt_int};
use crate::groups::{
  message_key::SenderMessageKey, sender_key_message::SenderKeyMessage,
  sender_key_state::SenderKeyState,
};

pub struct GroupCipher;

impl GroupCipher {
  pub fn get_sender_key(
    sender_key_state: &mut SenderKeyState,
    iteration: u32,
  ) -> Result<SenderMessageKey, String> {
    let mut sender_chain_key = sender_key_state.get_sender_chain_key();

    if sender_chain_key.get_iteration() > iteration {
      if sender_key_state.has_sender_message_key(iteration) {
        let message_key = sender_key_state
          .remove_sender_message_key(iteration)
          .ok_or("No sender message key found for iteration")?;
        return Ok(message_key);
      }

      return Err(format!(
        "Received message with old counter: {}, {}",
        sender_chain_key.get_iteration(),
        iteration
      ));
    }

    if iteration - sender_chain_key.get_iteration() > 2000 {
      return Err("Over 2000 messages into the future!".to_string());
    }

    while sender_chain_key.get_iteration() < iteration {
      let message_key = sender_chain_key
        .get_sender_message_key()
        .map_err(|e| format!("Failed to get sender message key: {}", e))?;
      sender_key_state.add_sender_message_key(&message_key);
      sender_chain_key = sender_chain_key
        .get_next()
        .map_err(|e| format!("Failed to get next chain key: {}", e))?;
    }

    let next_chain_key = sender_chain_key
      .get_next()
      .map_err(|e| format!("Failed to get next chain key: {}", e))?;
    sender_key_state.set_sender_chain_key(&next_chain_key);

    sender_chain_key
      .get_sender_message_key()
      .map_err(|e| format!("Failed to get sender message key: {}", e))
  }

  pub fn get_plain_text(iv: &[u8], key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_int(key, ciphertext, iv)
      .map_err(|_| "InvalidMessageException - Decryption failed".to_string())
  }

  pub fn get_cipher_text(iv: &[u8], key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_int(key, plaintext, iv)
      .map_err(|_| "InvalidMessageException - Encryption failed".to_string())
  }

  pub fn encrypt_message(
    sender_key_state: &mut SenderKeyState,
    padded_plaintext: &[u8],
  ) -> Result<Vec<u8>, String> {
    let iteration = sender_key_state.get_sender_chain_key().get_iteration();
    let target_iteration = if iteration == 0 { 0 } else { iteration + 1 };

    let sender_key = Self::get_sender_key(sender_key_state, target_iteration)?;

    let ciphertext = Self::get_cipher_text(
      &sender_key.get_iv(),
      &sender_key.get_cipher_key(),
      padded_plaintext,
    )?;

    let signature_key_private = sender_key_state
      .get_signing_key_private()
      .ok_or("No private signing key available")?;

    let sender_key_message = SenderKeyMessage::new(
      Some(sender_key_state.get_key_id()),
      Some(sender_key.get_iteration()),
      Some(ciphertext),
      Some(signature_key_private),
      None,
    )?;

    Ok(sender_key_message.serialize().to_vec())
  }

  pub fn decrypt_message(
    sender_key_state: &mut SenderKeyState,
    sender_key_message_bytes: &[u8],
  ) -> Result<Vec<u8>, String> {
    let sender_key_message = SenderKeyMessage::new(
      None,
      None,
      None,
      None,
      Some(sender_key_message_bytes.to_vec()),
    )?;

    let signing_key_public = sender_key_state.get_signing_key_public();
    sender_key_message.verify_signature(&signing_key_public)?;

    let sender_key = Self::get_sender_key(sender_key_state, sender_key_message.get_iteration())?;

    let plaintext = Self::get_plain_text(
      &sender_key.get_iv(),
      &sender_key.get_cipher_key(),
      sender_key_message.get_cipher_text(),
    )?;

    Ok(plaintext)
  }
}
