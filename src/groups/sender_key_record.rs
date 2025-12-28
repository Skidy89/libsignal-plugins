use crate::groups::sender_key_state::{SenderKeyState, SenderSigningKey};
use prost::Message;
use proto_gen::groupproto::{SenderKeyRecordStructure, SenderKeyStateStructure};
use serde::{Deserialize, Serialize};

const MAX_STATES: usize = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyRecord {
  sender_key_states: Vec<SenderKeyState>,
}

impl SenderKeyRecord {
  pub fn new(serialized: Option<Vec<SenderKeyStateStructure>>) -> Result<Self, String> {
    let mut sender_key_states = Vec::new();

    if let Some(structures) = serialized {
      for structure in structures {
        let state = SenderKeyState::new(0, 0, vec![], None, None, None, Some(structure))?;
        sender_key_states.push(state);
      }
    }

    Ok(SenderKeyRecord { sender_key_states })
  }

  pub fn is_empty(&self) -> bool {
    self.sender_key_states.is_empty()
  }

  pub fn get_sender_key_state(&self, key_id: Option<u32>) -> Option<&SenderKeyState> {
    match key_id {
      None => {
        if !self.sender_key_states.is_empty() {
          Some(&self.sender_key_states[self.sender_key_states.len() - 1])
        } else {
          None
        }
      }
      Some(id) => self
        .sender_key_states
        .iter()
        .find(|state| state.get_key_id() == id),
    }
  }

  pub fn add_sender_key_state(
    &mut self,
    id: u32,
    iteration: u32,
    chain_key: Vec<u8>,
    signature_key: Vec<u8>,
  ) -> Result<(), String> {
    let state = SenderKeyState::new(
      id,
      iteration,
      chain_key,
      None,
      Some(signature_key),
      None,
      None,
    )?;
    self.sender_key_states.push(state);

    if self.sender_key_states.len() > MAX_STATES {
      self.sender_key_states.remove(0);
    }

    Ok(())
  }

  pub fn set_sender_key_state(
    &mut self,
    id: u32,
    iteration: u32,
    chain_key: Vec<u8>,
    key_pair: SenderSigningKey,
  ) -> Result<(), String> {
    self.sender_key_states.clear();
    let state = SenderKeyState::new(id, iteration, chain_key, Some(key_pair), None, None, None)?;
    self.sender_key_states.push(state);
    Ok(())
  }

  pub fn serialize(&self) -> Vec<SenderKeyStateStructure> {
    self
      .sender_key_states
      .iter()
      .map(|state| state.get_structure())
      .collect()
  }

  pub fn deserialize(data: &[u8]) -> Result<Self, String> {
    Self::from_protobuf(data)
  }

  pub fn serialize_to_bytes(&self) -> Result<Vec<u8>, String> {
    self.to_protobuf()
  }

  pub fn to_protobuf(&self) -> Result<Vec<u8>, String> {
    let record = SenderKeyRecordStructure {
      sender_key_states: self.serialize(),
    };

    let mut buf = Vec::new();
    record
      .encode(&mut buf)
      .map_err(|e| format!("Protobuf encode error: {}", e))?;
    Ok(buf)
  }

  pub fn from_protobuf(data: &[u8]) -> Result<Self, String> {
    let record = SenderKeyRecordStructure::decode(data)
      .map_err(|e| format!("Protobuf decode error: {}", e))?;
    Self::new(Some(record.sender_key_states))
  }
}
