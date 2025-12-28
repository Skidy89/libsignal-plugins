use crate::groups::{
  ciphertext::CipherTextMessage,
  proto::{decode_sender_distribution_msg, encode_sender_distribution_msg},
};

pub struct SenderKeyDistributionMessage {
  id: u32,
  iteration: u32,
  chain_key: Vec<u8>,
  signature_key: Vec<u8>,
  serialized: Vec<u8>,
  cipher_text_message: CipherTextMessage,
}

impl SenderKeyDistributionMessage {
  pub fn new(
    id: Option<u32>,
    iteration: Option<u32>,
    chain_key: Option<Vec<u8>>,
    signature_key: Option<Vec<u8>>,
    serialized: Option<Vec<u8>>,
  ) -> Result<Self, String> {
    let cipher_text_message = CipherTextMessage::new();

    if let Some(serialized) = serialized {
      if serialized.is_empty() {
        return Err("Serialized data is empty".to_string());
      }

      let message = &serialized[1..];
      let distribution_message = decode_sender_distribution_msg(message)
        .map_err(|e| format!("Failed to decode distribution message: {}", e))?;

      Ok(SenderKeyDistributionMessage {
        id: distribution_message.id.ok_or("Missing id")?,
        iteration: distribution_message.iteration.ok_or("Missing iteration")?,
        chain_key: distribution_message.chain_key.ok_or("Missing chain_key")?,
        signature_key: distribution_message
          .signing_key
          .ok_or("Missing signing_key")?,
        serialized,
        cipher_text_message,
      })
    } else {
      let id = id.ok_or("Missing id")?;
      let iteration = iteration.ok_or("Missing iteration")?;
      let chain_key = chain_key.ok_or("Missing chain_key")?;
      let signature_key = signature_key.ok_or("Missing signature_key")?;

      let version = Self::ints_to_byte_high_and_low(
        cipher_text_message.current_version,
        cipher_text_message.current_version,
      );

      let proto_message =
        encode_sender_distribution_msg(&proto_gen::groupproto::SenderKeyDistributionMessage {
          id: Some(id),
          iteration: Some(iteration),
          chain_key: Some(chain_key.clone()),
          signing_key: Some(signature_key.clone()),
        })
        .map_err(|e| format!("Failed to encode distribution message: {}", e))?;

      let mut serialized = Vec::new();
      serialized.push(version);
      serialized.extend_from_slice(&proto_message);

      Ok(SenderKeyDistributionMessage {
        id,
        iteration,
        chain_key,
        signature_key,
        serialized,
        cipher_text_message,
      })
    }
  }

  fn ints_to_byte_high_and_low(high_value: u8, low_value: u8) -> u8 {
    ((high_value << 4) | low_value) & 0xff
  }

  pub fn serialize(&self) -> &[u8] {
    &self.serialized
  }

  pub fn get_type(&self) -> u8 {
    self.cipher_text_message.sender_key_distribution_type
  }

  pub fn get_iteration(&self) -> u32 {
    self.iteration
  }

  pub fn get_chain_key(&self) -> &[u8] {
    &self.chain_key
  }

  pub fn get_signature_key(&self) -> &[u8] {
    &self.signature_key
  }

  pub fn get_id(&self) -> u32 {
    self.id
  }
}
