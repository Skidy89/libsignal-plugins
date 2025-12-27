pub const WHISPER_GROUP: &[u8; 12] = b"WhisperGroup";

pub struct CipherTextMessage {
  pub unsupported_version: u8,
  pub current_version: u8,
  pub whisper_type: u8,
  pub prekey_type: u8,
  pub sender_key_type: u8,
  pub sender_key_distribution_type: u8,
  pub encrypted_message_overhead: u8,
}

impl CipherTextMessage {
  pub fn new() -> Self {
    CipherTextMessage {
      unsupported_version: 1,
      current_version: 3,
      whisper_type: 2,
      prekey_type: 3,
      sender_key_type: 4,
      sender_key_distribution_type: 5,
      encrypted_message_overhead: 53,
    }
  }
}
