use crate::groups::{
  ciphertext::CipherTextMessage,
  proto::{decode_sender_keys_msg, encode_sender_keys_msg},
};
use crate::utils::{curve25519_sign_inner, verify_int};
use proto_gen::groupproto::SenderKeyMessage as ProtoSenderKeyMessage;

const SIGNATURE_LENGTH: usize = 64;

pub struct SenderKeyMessage {
  message_version: u8,
  key_id: u32,
  iteration: u32,
  ciphertext: Vec<u8>,
  signature: Vec<u8>,
  serialized: Vec<u8>,
  cipher_text_message: CipherTextMessage,
}

impl SenderKeyMessage {
  pub fn new(
    key_id: Option<u32>,
    iteration: Option<u32>,
    ciphertext: Option<Vec<u8>>,
    signature_key: Option<Vec<u8>>,
    serialized: Option<Vec<u8>>,
  ) -> Result<Self, String> {
    let cipher_text_message = CipherTextMessage::new();

    if let Some(serialized) = serialized {
      if serialized.len() <= SIGNATURE_LENGTH {
        return Err("Serialized data too short".to_string());
      }

      let version = serialized[0];
      let message = &serialized[1..serialized.len() - SIGNATURE_LENGTH];
      let signature = serialized[serialized.len() - SIGNATURE_LENGTH..].to_vec();

      let sender_key_message =
        decode_sender_keys_msg(message).map_err(|e| format!("Failed to decode message: {}", e))?;

      Ok(SenderKeyMessage {
        message_version: (version & 0xff) >> 4,
        key_id: sender_key_message.id.ok_or("Missing id")?,
        iteration: sender_key_message.iteration.ok_or("Missing iteration")?,
        ciphertext: sender_key_message.ciphertext.ok_or("Missing ciphertext")?,
        signature,
        serialized,
        cipher_text_message,
      })
    } else {
      let key_id = key_id.ok_or("Missing key_id")?;
      let iteration = iteration.ok_or("Missing iteration")?;
      let ciphertext = ciphertext.ok_or("Missing ciphertext")?;
      let signature_key = signature_key.ok_or("Missing signature_key")?;

      if signature_key.len() != 32 {
        return Err("Signature key must be 32 bytes".to_string());
      }

      let version =
        ((cipher_text_message.current_version << 4) | cipher_text_message.current_version) & 0xff;

      let proto_message = ProtoSenderKeyMessage {
        id: Some(key_id),
        iteration: Some(iteration),
        ciphertext: Some(ciphertext.clone()),
      };

      let message_bytes = encode_sender_keys_msg(&proto_message)
        .map_err(|e| format!("Failed to encode message: {}", e))?;

      // version byte + message
      let mut data_to_sign = Vec::new();
      data_to_sign.push(version);
      data_to_sign.extend_from_slice(&message_bytes);

      let signature_key_array: [u8; 32] = signature_key
        .try_into()
        .map_err(|_| "Invalid signature key length")?;
      let signature = Self::get_signature(&signature_key_array, &data_to_sign);

      let mut serialized = Vec::new();
      serialized.push(version);
      serialized.extend_from_slice(&message_bytes);
      serialized.extend_from_slice(&signature);

      Ok(SenderKeyMessage {
        message_version: cipher_text_message.current_version,
        key_id,
        iteration,
        ciphertext,
        signature: signature.to_vec(),
        serialized,
        cipher_text_message,
      })
    }
  }

  pub fn get_key_id(&self) -> u32 {
    self.key_id
  }

  pub fn get_iteration(&self) -> u32 {
    self.iteration
  }

  pub fn get_message_version(&self) -> u8 {
    self.message_version
  }

  pub fn get_cipher_text(&self) -> &[u8] {
    &self.ciphertext
  }

  pub fn verify_signature(&self, signature_key: &[u8]) -> Result<(), String> {
    if signature_key.len() != 32 {
      return Err("Signature key must be 32 bytes".to_string());
    }

    if self.signature.len() != SIGNATURE_LENGTH {
      return Err("Invalid signature length".to_string());
    }

    let part1 = &self.serialized[0..self.serialized.len() - SIGNATURE_LENGTH];
    let signature_array: [u8; 64] = self.signature[..]
      .try_into()
      .map_err(|_| "Invalid signature length")?;

    let is_valid = verify_int(signature_key, part1, &signature_array)
      .map_err(|e| format!("Verification error: {}", e))?;

    if !is_valid {
      return Err("Invalid signature!".to_string());
    }

    Ok(())
  }

  fn get_signature(signature_key: &[u8; 32], serialized: &[u8]) -> [u8; 64] {
    curve25519_sign_inner(signature_key, serialized)
  }

  pub fn serialize(&self) -> &[u8] {
    &self.serialized
  }

  pub fn get_type(&self) -> u8 {
    self.cipher_text_message.sender_key_type
  }
}
