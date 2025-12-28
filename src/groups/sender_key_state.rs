use crate::groups::{
  message_key::SenderMessageKey as MessageKey, sender_chain_key::SenderChainKey,
};
use proto_gen::groupproto::{
  SenderChainKey as ProtoSenderChainKey, SenderKeyStateStructure,
  SenderMessageKey as ProtoSenderMessageKey, SenderSigningKey as ProtoSenderSigningKey,
};
use serde::{Deserialize, Serialize};

const MAX_MESSAGE_KEYS: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderMessageKeyStructure {
  pub iteration: u32,
  pub seed: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderSigningKey {
  pub public: Vec<u8>,
  pub private: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyState {
  sender_key_id: u32,
  sender_chain_key_iteration: u32,
  sender_chain_key_seed: Vec<u8>,
  sender_signing_key: SenderSigningKey,
  sender_message_keys: Vec<SenderMessageKeyStructure>,
}

impl SenderKeyState {
  pub fn new(
    id: u32,
    iteration: u32,
    chain_key: Vec<u8>,
    key_pair: Option<SenderSigningKey>,
    signature_key_public: Option<Vec<u8>>,
    signature_key_private: Option<Vec<u8>>,
    structure: Option<SenderKeyStateStructure>,
  ) -> Result<Self, String> {
    if let Some(structure) = structure {
      // Create from structure
      let sender_chain_key = structure
        .sender_chain_key
        .ok_or("Missing sender_chain_key")?;
      let sender_signing_key = structure
        .sender_signing_key
        .ok_or("Missing sender_signing_key")?;

      let message_keys = structure
        .sender_message_keys
        .into_iter()
        .map(|mk| SenderMessageKeyStructure {
          iteration: mk.iteration.unwrap_or(0),
          seed: mk.seed.unwrap_or_default(),
        })
        .collect();

      Ok(SenderKeyState {
        sender_key_id: structure.sender_key_id.ok_or("Missing sender_key_id")?,
        sender_chain_key_iteration: sender_chain_key.iteration.ok_or("Missing iteration")?,
        sender_chain_key_seed: sender_chain_key.seed.ok_or("Missing seed")?,
        sender_signing_key: SenderSigningKey {
          public: sender_signing_key.public.ok_or("Missing public key")?,
          private: sender_signing_key.private,
        },
        sender_message_keys: message_keys,
      })
    } else {
      // Create new state
      let signing_key = if let Some(key_pair) = key_pair {
        key_pair
      } else {
        SenderSigningKey {
          public: signature_key_public.unwrap_or_default(),
          private: signature_key_private,
        }
      };

      Ok(SenderKeyState {
        sender_key_id: id,
        sender_chain_key_iteration: iteration,
        sender_chain_key_seed: chain_key,
        sender_signing_key: signing_key,
        sender_message_keys: Vec::new(),
      })
    }
  }

  pub fn get_key_id(&self) -> u32 {
    self.sender_key_id
  }

  pub fn get_sender_chain_key(&self) -> SenderChainKey {
    SenderChainKey::new(
      self.sender_chain_key_iteration,
      self.sender_chain_key_seed.clone(),
    )
  }

  pub fn set_sender_chain_key(&mut self, chain_key: &SenderChainKey) {
    self.sender_chain_key_iteration = chain_key.get_iteration();
    self.sender_chain_key_seed = chain_key.get_seed().to_vec();
  }

  pub fn get_signing_key_public(&self) -> Vec<u8> {
    let public_key = &self.sender_signing_key.public;

    public_key.to_vec()
  }

  pub fn get_signing_key_private(&self) -> Option<Vec<u8>> {
    self.sender_signing_key.private.clone()
  }

  pub fn has_sender_message_key(&self, iteration: u32) -> bool {
    self
      .sender_message_keys
      .iter()
      .any(|key| key.iteration == iteration)
  }

  pub fn add_sender_message_key(&mut self, sender_message_key: &MessageKey) {
    self.sender_message_keys.push(SenderMessageKeyStructure {
      iteration: sender_message_key.get_iteration(),
      seed: sender_message_key.get_seed().to_vec(),
    });

    if self.sender_message_keys.len() > MAX_MESSAGE_KEYS {
      self.sender_message_keys.remove(0);
    }
  }

  pub fn remove_sender_message_key(&mut self, iteration: u32) -> Option<MessageKey> {
    if let Some(index) = self
      .sender_message_keys
      .iter()
      .position(|key| key.iteration == iteration)
    {
      let message_key = self.sender_message_keys.remove(index);
      let seed: [u8; 32] = message_key.seed.try_into().ok()?;
      Some(MessageKey::new(message_key.iteration, seed))
    } else {
      None
    }
  }

  pub fn get_structure(&self) -> SenderKeyStateStructure {
    let message_keys = self
      .sender_message_keys
      .iter()
      .map(|mk| ProtoSenderMessageKey {
        iteration: Some(mk.iteration),
        seed: Some(mk.seed.clone()),
      })
      .collect();

    SenderKeyStateStructure {
      sender_key_id: Some(self.sender_key_id),
      sender_chain_key: Some(ProtoSenderChainKey {
        iteration: Some(self.sender_chain_key_iteration),
        seed: Some(self.sender_chain_key_seed.clone()),
      }),
      sender_signing_key: Some(ProtoSenderSigningKey {
        public: Some(self.sender_signing_key.public.clone()),
        private: self.sender_signing_key.private.clone(),
      }),
      sender_message_keys: message_keys,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_sender_key_state_new() {
    let state =
      SenderKeyState::new(1, 0, vec![1u8; 32], None, Some(vec![2u8; 32]), None, None).unwrap();

    assert_eq!(state.get_key_id(), 1);
  }

  #[test]
  fn test_sender_key_state_from_structure() {
    let structure = SenderKeyStateStructure {
      sender_key_id: Some(5),
      sender_chain_key: Some(ProtoSenderChainKey {
        iteration: Some(10),
        seed: Some(vec![3u8; 32]),
      }),
      sender_signing_key: Some(ProtoSenderSigningKey {
        public: Some(vec![4u8; 32]),
        private: Some(vec![5u8; 32]),
      }),
      sender_message_keys: vec![],
    };

    let state = SenderKeyState::new(0, 0, vec![], None, None, None, Some(structure)).unwrap();

    assert_eq!(state.get_key_id(), 5);
  }

  #[test]
  fn test_get_structure() {
    let state = SenderKeyState::new(
      7,
      15,
      vec![6u8; 32],
      Some(SenderSigningKey {
        public: vec![7u8; 32],
        private: Some(vec![8u8; 32]),
      }),
      None,
      None,
      None,
    )
    .unwrap();

    let structure = state.get_structure();
    assert_eq!(structure.sender_key_id, Some(7));
    assert_eq!(structure.sender_chain_key.unwrap().iteration, Some(15));
  }

  #[test]
  fn test_signing_key_public_with_version() {
    let state =
      SenderKeyState::new(1, 0, vec![1u8; 32], None, Some(vec![2u8; 32]), None, None).unwrap();

    let public_key = state.get_signing_key_public();
    assert_eq!(public_key.len(), 32);
  }

  #[test]
  fn test_has_sender_message_key() {
    let mut state =
      SenderKeyState::new(1, 0, vec![1u8; 32], None, Some(vec![2u8; 32]), None, None).unwrap();

    assert!(!state.has_sender_message_key(5));

    let msg_key = MessageKey::new(5, [3u8; 32]);
    state.add_sender_message_key(&msg_key);

    assert!(state.has_sender_message_key(5));
  }

  #[test]
  fn test_add_and_remove_message_key() {
    let mut state =
      SenderKeyState::new(1, 0, vec![1u8; 32], None, Some(vec![2u8; 32]), None, None).unwrap();

    let msg_key = MessageKey::new(10, [4u8; 32]);
    state.add_sender_message_key(&msg_key);

    assert_eq!(state.sender_message_keys.len(), 1);

    let removed = state.remove_sender_message_key(10);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().get_iteration(), 10);
    assert_eq!(state.sender_message_keys.len(), 0);
  }

  #[test]
  fn test_max_message_keys_limit() {
    let mut state =
      SenderKeyState::new(1, 0, vec![1u8; 32], None, Some(vec![2u8; 32]), None, None).unwrap();

    // Add more than MAX_MESSAGE_KEYS
    for i in 0..2005 {
      let msg_key = MessageKey::new(i, [5u8; 32]);
      state.add_sender_message_key(&msg_key);
    }

    assert_eq!(state.sender_message_keys.len(), MAX_MESSAGE_KEYS);
  }
}
