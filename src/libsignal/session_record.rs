use std::collections::HashMap;

use crate::libsignal::constants::{
  BaseKeyType, Chain, CurrentRatchet, IndexInfo, KeyPair, SessionEntry, SessionRecord,
  CLOSED_SESSIONS_MAX, SESSION_RECORD_VERSION,
};

impl SessionEntry {
  pub fn new() -> Self {
    Self {
      registration_id: 0,
      current_ratchet: CurrentRatchet {
        ephemeral_key_pair: KeyPair {
          pub_key: [0u8; 33],
          priv_key: [0u8; 32],
        },
        last_remote_ephemeral_key: vec![],
        previous_counter: 0,
        root_key: vec![],
      },
      index_info: IndexInfo {
        base_key: vec![],
        base_key_type: BaseKeyType::Theirs,
        closed: -1,
        used: 0,
        created: 0,
        remote_identity_key: vec![],
      },
      chains: HashMap::new(),
      pending_pre_key: None,
    }
  }

  pub fn add_chain(&mut self, key: &[u8], chain: Chain) -> Result<(), String> {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
    if self.chains.contains_key(&id) {
      return Err("Overwrite attempt".to_string());
    }
    self.chains.insert(id, chain);
    Ok(())
  }

  pub fn get_chain(&self, key: &[u8]) -> Option<&Chain> {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
    self.chains.get(&id)
  }

  pub fn get_chain_mut(&mut self, key: &[u8]) -> Option<&mut Chain> {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
    self.chains.get_mut(&id)
  }

  pub fn delete_chain(&mut self, key: &[u8]) -> Result<(), String> {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
    if !self.chains.contains_key(&id) {
      return Err("Not Found".to_string());
    }
    self.chains.remove(&id);
    Ok(())
  }

  pub fn chains_iter(&self) -> impl Iterator<Item = (Vec<u8>, &Chain)> {
    self.chains.iter().filter_map(|(k, v)| {
      base64::Engine::decode(&base64::engine::general_purpose::STANDARD, k)
        .ok()
        .map(|key| (key, v))
    })
  }
}

impl SessionRecord {
  pub fn new() -> Self {
    Self {
      sessions: HashMap::new(),
      version: SESSION_RECORD_VERSION.to_string(),
    }
  }

  pub fn have_open_session(&self) -> bool {
    if let Some(session) = self.get_open_session() {
      session.registration_id > 0
    } else {
      false
    }
  }

  pub fn get_session(&self, key: &[u8]) -> Result<Option<&SessionEntry>, String> {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
    if let Some(session) = self.sessions.get(&id) {
      if session.index_info.base_key_type == BaseKeyType::Ours {
        return Err("Tried to lookup a session using our basekey".to_string());
      }
      Ok(Some(session))
    } else {
      Ok(None)
    }
  }

  pub fn get_session_mut(&mut self, key: &[u8]) -> Result<Option<&mut SessionEntry>, String> {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
    if let Some(session) = self.sessions.get(&id) {
      if session.index_info.base_key_type == BaseKeyType::Ours {
        return Err("Tried to lookup a session using our basekey".to_string());
      }
    }
    Ok(self.sessions.get_mut(&id))
  }

  pub fn get_open_session(&self) -> Option<&SessionEntry> {
    self
      .sessions
      .values()
      .find(|session| !Self::is_closed_session(session))
  }

  pub fn get_open_session_mut(&mut self) -> Option<&mut SessionEntry> {
    self
      .sessions
      .values_mut()
      .find(|session| !Self::is_closed_session(session))
  }

  pub fn set_session(&mut self, session: SessionEntry) {
    let id = base64::Engine::encode(
      &base64::engine::general_purpose::STANDARD,
      &session.index_info.base_key,
    );
    self.sessions.insert(id, session);
  }

  pub fn get_sessions(&self) -> Vec<&SessionEntry> {
    let mut sessions: Vec<&SessionEntry> = self.sessions.values().collect();
    sessions.sort_by(|a, b| {
      let a_used = a.index_info.used;
      let b_used = b.index_info.used;
      b_used.cmp(&a_used) // Descending order
    });
    sessions
  }

  pub fn close_session(&mut self, base_key: &[u8]) {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, base_key);
    if let Some(session) = self.sessions.get_mut(&id) {
      if Self::is_closed_session(session) {
        eprintln!("Session already closed");
        return;
      }
      session.index_info.closed = chrono::Utc::now().timestamp_millis();
    }
  }

  pub fn open_session(&mut self, base_key: &[u8]) {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, base_key);
    if let Some(session) = self.sessions.get_mut(&id) {
      if !Self::is_closed_session(session) {
        eprintln!("Session already open");
      }
      session.index_info.closed = -1;
    }
  }

  pub fn is_closed(&self, base_key: &[u8]) -> bool {
    let id = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, base_key);
    if let Some(session) = self.sessions.get(&id) {
      Self::is_closed_session(session)
    } else {
      false
    }
  }

  fn is_closed_session(session: &SessionEntry) -> bool {
    session.index_info.closed != -1
  }

  pub fn remove_old_sessions(&mut self) {
    while self.sessions.len() > CLOSED_SESSIONS_MAX {
      let oldest_key = self
        .sessions
        .iter()
        .filter(|(_, session)| session.index_info.closed != -1)
        .min_by_key(|(_, session)| session.index_info.closed)
        .map(|(key, _)| key.clone());

      if let Some(key) = oldest_key {
        self.sessions.remove(&key);
      } else {
        panic!("Corrupt sessions object");
      }
    }
  }

  pub fn delete_all_sessions(&mut self) {
    self.sessions.clear();
  }

  pub fn serialize(&self) -> Result<String, serde_json::Error> {
    serde_json::to_string(self)
  }

  pub fn deserialize(data: &str) -> Result<Self, serde_json::Error> {
    serde_json::from_str(data)
  }
}
