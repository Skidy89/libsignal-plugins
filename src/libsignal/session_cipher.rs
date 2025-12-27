use std::{collections::HashMap, error::Error as StdError};

use proto_gen::textsecure::{PreKeyWhisperMessage, WhisperMessage};

use crate::{
  crypto::{calculate_mac, decrypt_int, encrypt_int, verify_mac_int},
  libsignal::constants::{Chain, ChainKey, ChainType, KeyPair, SessionEntry},
  utils::{derive_secrets_int, generate_key_pair_int, shared_secret_int},
};
use prost::Message;

pub const VERSION: u8 = 3;
pub const WHISPER_MESSAGE_KEYS: &[u8] = b"WhisperMessageKeys";
pub const WHISPER_RATCHET: &[u8] = b"WhisperRatchet";
pub const MAX_MESSAGE_GAP: i32 = 500;

#[derive(Debug)]
pub struct EncryptedMessage {
  pub message_type: u8, // 1 = normal, 3 = prekey
  pub body: Vec<u8>,
  pub registration_id: u32,
}

pub struct SessionCipher {
  our_identity_key: KeyPair,
  our_registration_id: u32,
}

impl SessionCipher {
  pub fn new(our_identity_key: KeyPair, our_registration_id: u32) -> Self {
    Self {
      our_identity_key,
      our_registration_id,
    }
  }

  fn encode_tuple_byte(n1: u8, n2: u8) -> Result<u8, &'static str> {
    if n1 > 15 || n2 > 15 {
      return Err("Numbers must be 4 bits or less");
    }
    Ok((n1 << 4) | n2)
  }

  pub fn decode_tuple_byte(byte: u8) -> (u8, u8) {
    (byte >> 4, byte & 0x0F)
  }

  pub fn encrypt(
    &mut self,
    session: &mut SessionEntry,
    data: &[u8],
  ) -> Result<EncryptedMessage, Box<dyn StdError + Send + Sync>> {
    let chain_key = session.current_ratchet.ephemeral_key_pair.pub_key.clone();
    let chain = session
      .get_chain_mut(&chain_key)
      .ok_or("No sending chain found")?;

    if chain.chain_type != ChainType::Sending {
      return Err("Tried to encrypt on a receiving chain".into());
    }

    Self::fill_message_keys(chain, chain.chain_key.counter + 1)?;

    let counter = chain.chain_key.counter;
    let message_key = chain
      .message_keys
      .remove(&counter)
      .ok_or("Message key not found")?;

    let keys = derive_secrets_int(
      &message_key.encode_to_vec(),
      &[0u8; 32],
      WHISPER_MESSAGE_KEYS,
      3,
    );

    let whisper_msg = WhisperMessage {
      ephemeral_key: Some(session.current_ratchet.ephemeral_key_pair.pub_key.to_vec()),
      counter: Some(counter as u32),
      previous_counter: Some(session.current_ratchet.previous_counter),
      ciphertext: Some(
        encrypt_int(keys[0].as_ref(), data, &keys[2][..16])
          .map_err(|e| format!("Encryption failed: {:?}", e))?,
      ),
    };

    let msg_buf = encode_whisper_message(&whisper_msg)?;

    let mut mc = Vec::with_capacity(msg_buf.len() + 67); // OMG 677777
    mc.extend_from_slice(&self.our_identity_key.pub_key);
    mc.extend_from_slice(&session.index_info.remote_identity_key);
    mc.push(Self::encode_tuple_byte(VERSION, VERSION)?);
    mc.extend_from_slice(&msg_buf);
    let mac = calculate_mac(&keys[1], &mc).map_err(|_| "Failed to calculate MAC")?;

    let mut result = Vec::with_capacity(msg_buf.len() + 9);
    result.push(Self::encode_tuple_byte(VERSION, VERSION)?);
    result.extend_from_slice(&msg_buf);
    result.extend_from_slice(&mac[..8]);

    let (message_type, body) = if let Some(pending) = &session.pending_pre_key {
      let prekey_msg = PreKeyWhisperMessage {
        identity_key: Some(self.our_identity_key.pub_key.to_vec()),
        registration_id: Some(self.our_registration_id),
        base_key: Some(pending.base_key.clone()),
        pre_key_id: pending.pre_key_id,
        signed_pre_key_id: Some(pending.signed_key_id),
        message: Some(result),
      };

      let encoded = encode_prekey_message(&prekey_msg)?;
      let mut body = vec![Self::encode_tuple_byte(VERSION, VERSION)?];
      body.extend_from_slice(&encoded);

      (3u8, body)
    } else {
      (1u8, result)
    };

    Ok(EncryptedMessage {
      message_type,
      body,
      registration_id: session.registration_id,
    })
  }

  pub fn decrypt_whisper_message(
    &self,
    session: &mut SessionEntry,
    message_buffer: &[u8],
  ) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
    if message_buffer.is_empty() {
      return Err("Empty message buffer".into());
    }

    let (max_ver, min_ver) = Self::decode_tuple_byte(message_buffer[0]);
    if min_ver > 3 || max_ver < 3 {
      return Err("Incompatible version number".into());
    }

    if message_buffer.len() < 9 {
      return Err("Message too short".into());
    }

    let message_proto = &message_buffer[1..message_buffer.len() - 8];
    let message = decode_whisper_message(message_proto)?;

    // ratchet
    let ephemeral_key = message
      .ephemeral_key
      .as_ref()
      .ok_or("Missing ephemeral key")?;
    let ephemeral_key_array: &[u8; 33] = ephemeral_key
      .as_slice()
      .try_into()
      .map_err(|_| "Invalid ephemeral key length")?;
    self.maybe_step_ratchet(
      session,
      ephemeral_key_array,
      message.previous_counter.unwrap() as i32,
    )?;

    let chain = session
      .get_chain_mut(&message.ephemeral_key.unwrap())
      .ok_or("Chain not found")?;
    if chain.chain_type == ChainType::Sending {
      return Err("Tried to decrypt on a sending chain".into());
    }

    Self::fill_message_keys(chain, message.counter.unwrap() as i32)?;

    let message_key = chain
      .message_keys
      .remove(&(&(message.counter.unwrap() as i32)))
      .ok_or("Key used already or never filled")?;

    let keys = derive_secrets_int(&Vec::from(message_key), &[0u8; 32], WHISPER_MESSAGE_KEYS, 3);

    let mut mc = Vec::with_capacity(message_proto.len() + 67);
    mc.extend_from_slice(&session.index_info.remote_identity_key);
    mc.extend_from_slice(&self.our_identity_key.pub_key);
    mc.push(Self::encode_tuple_byte(VERSION, VERSION)?);
    mc.extend_from_slice(message_proto);
    let mac_slice = &message_buffer[message_buffer.len() - 8..];
    let d = verify_mac_int(&mc, &keys[1], mac_slice, 8);
    if d.is_err() {
      return Err("MAC verification failed".into());
    }
    let plaintext = decrypt_int(&keys[0], &message.ciphertext.unwrap(), &keys[2][..16])
      .map_err(|e| format!("Decryption failed: {:?}", e))?;

    session.pending_pre_key = None;

    Ok(plaintext)
  }

  fn fill_message_keys(
    chain: &mut Chain,
    counter: i32,
  ) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let current = chain.chain_key.counter;

    if current >= counter {
      return Ok(());
    }

    let gap = counter - current;
    if gap > MAX_MESSAGE_GAP {
      return Err("Over 500 messages into the future!".into());
    }

    let mut key = chain.chain_key.key.clone().ok_or("Chain closed")?;

    let mut next_counter = current;

    while next_counter < counter as i32 {
      next_counter += 1;

      let message_key = calculate_mac(&key, &[1u8]).map_err(|_| "Failed to derive message key")?;
      key = calculate_mac(&key, &[2u8]).map_err(|_| "Failed to derive next chain key")?;

      chain.message_keys.insert(
        next_counter,
        String::from_utf8_lossy(&message_key).to_string(),
      );
    }

    chain.chain_key.counter = next_counter;
    chain.chain_key.key = Some(key);

    Ok(())
  }

  fn maybe_step_ratchet(
    &self,
    session: &mut SessionEntry,
    remote_key: &[u8; 33],
    previous_counter: i32,
  ) -> Result<(), Box<dyn StdError + Send + Sync>> {
    if session.get_chain(remote_key).is_some() {
      return Ok(());
    }

    let last_remote = session.current_ratchet.last_remote_ephemeral_key.clone();
    if let Some(previous_ratchet) = session.get_chain_mut(&last_remote) {
      Self::fill_message_keys(previous_ratchet, previous_counter)?;
      previous_ratchet.chain_key.key = None; // Close chain
    }

    self.calculate_ratchet(session, remote_key, false)?;

    let old_key = session.current_ratchet.ephemeral_key_pair.pub_key.clone();
    if let Some(prev_chain) = session.get_chain(&old_key) {
      session.current_ratchet.previous_counter = prev_chain.chain_key.counter as u32;
      session.delete_chain(&old_key)?;
    }

    let new_keypair = generate_key_pair_int();
    session.current_ratchet.ephemeral_key_pair = KeyPair {
      pub_key: new_keypair.0.clone(),
      priv_key: new_keypair.1.clone(),
    };

    self.calculate_ratchet(session, remote_key, true)?;

    session.current_ratchet.last_remote_ephemeral_key = remote_key.to_vec();

    Ok(())
  }

  fn calculate_ratchet(
    &self,
    session: &mut SessionEntry,
    remote_key: &[u8; 33],
    sending: bool,
  ) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let shared_secret = shared_secret_int(
      remote_key,
      session.current_ratchet.ephemeral_key_pair.priv_key,
    )?;

    let master_key = derive_secrets_int(
      &shared_secret,
      &session.current_ratchet.root_key,
      WHISPER_RATCHET,
      2,
    );

    let chain_key = if sending {
      session.current_ratchet.ephemeral_key_pair.pub_key.clone()
    } else {
      remote_key.clone()
    };

    let chain = Chain {
      message_keys: HashMap::new(),
      chain_key: ChainKey {
        counter: -1,
        key: Some(master_key[1].as_ref().to_vec()),
      },
      chain_type: if sending {
        ChainType::Sending
      } else {
        ChainType::Receiving
      },
    };

    session.add_chain(&chain_key.as_ref(), chain)?;
    session.current_ratchet.root_key = master_key[1].as_ref().to_vec();

    Ok(())
  }
}

pub fn encode_whisper_message(
  msg: &WhisperMessage,
) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
  let mut buf = Vec::new();
  buf.reserve(msg.encoded_len());
  msg.encode(&mut buf)?;
  Ok(buf)
}

pub fn decode_whisper_message(
  data: &[u8],
) -> Result<WhisperMessage, Box<dyn StdError + Send + Sync>> {
  let msg = WhisperMessage::decode(data)?;
  Ok(msg)
}

pub fn encode_prekey_message(
  msg: &PreKeyWhisperMessage,
) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
  let mut buf = Vec::new();
  buf.reserve(msg.encoded_len());
  msg.encode(&mut buf)?;
  Ok(buf)
}
//pub fn decode_prekey_message(data: &[u8]) -> Result<PreKeyWhisperMessage, Box<dyn StdError>> {
////   let msg = PreKeyWhisperMessage::decode(data)?;
//  Ok(msg)
//}
