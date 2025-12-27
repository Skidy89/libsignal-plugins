use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const CLOSED_SESSIONS_MAX: usize = 40;
pub const SESSION_RECORD_VERSION: &str = "v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum BaseKeyType {
  Ours = 1,
  Theirs = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[repr(u8)]
pub enum ChainType {
  Sending = 1,
  Receiving = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
  #[serde(rename = "pubKey", with = "base64")]
  pub pub_key: [u8; 33],
  #[serde(rename = "privKey", with = "base64")]
  pub priv_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentRatchet {
  #[serde(rename = "ephemeralKeyPair")]
  pub ephemeral_key_pair: KeyPair,
  #[serde(rename = "lastRemoteEphemeralKey", with = "base64")]
  pub last_remote_ephemeral_key: Vec<u8>,
  #[serde(rename = "previousCounter")]
  pub previous_counter: u32,
  #[serde(rename = "rootKey", with = "base64")]
  pub root_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexInfo {
  #[serde(rename = "baseKey", with = "base64")]
  pub base_key: Vec<u8>,
  #[serde(rename = "baseKeyType")]
  pub base_key_type: BaseKeyType,
  pub closed: i64,
  pub used: u64,
  pub created: u64,
  #[serde(rename = "remoteIdentityKey", with = "base64")]
  pub remote_identity_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainKey {
  pub counter: i32,
  #[serde(with = "base64_option")]
  pub key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
  #[serde(rename = "chainKey")]
  pub chain_key: ChainKey,
  #[serde(rename = "chainType")]
  pub chain_type: ChainType,
  #[serde(rename = "messageKeys")]
  pub message_keys: HashMap<i32, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPreKey {
  #[serde(rename = "baseKey", with = "base64_vec")]
  pub base_key: Vec<u8>,
  #[serde(rename = "preKeyId")]
  pub pre_key_id: Option<u32>,
  #[serde(rename = "signedKeyId")]
  pub signed_key_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
  #[serde(rename = "registrationId")]
  pub registration_id: u32,
  #[serde(rename = "currentRatchet")]
  pub current_ratchet: CurrentRatchet,
  #[serde(rename = "indexInfo")]
  pub index_info: IndexInfo,
  #[serde(rename = "_chains")]
  pub chains: HashMap<String, Chain>,
  #[serde(rename = "pendingPreKey", skip_serializing_if = "Option::is_none")]
  pub pending_pre_key: Option<PendingPreKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
  #[serde(rename = "_sessions")]
  pub sessions: HashMap<String, SessionEntry>,
  pub version: String,
}

mod base64 {
  use base64::{engine::general_purpose::STANDARD, Engine as _};
  use serde::{Deserialize, Deserializer, Serializer};

  pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&STANDARD.encode(bytes))
  }

  pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    let vec = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
    vec.try_into().map_err(|_| serde::de::Error::custom(format!("expected array of length {}", N)))
  }
}

mod base64_vec {
  use base64::{engine::general_purpose::STANDARD, Engine as _};
  use serde::{Deserialize, Deserializer, Serializer};

  pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&STANDARD.encode(bytes))
  }

  pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    STANDARD.decode(s).map_err(serde::de::Error::custom)
  }
}

mod base64_option {
  use base64::{engine::general_purpose::STANDARD, Engine as _};
  use serde::{Deserialize, Deserializer, Serializer};

  pub fn serialize<S>(opt: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    match opt {
      Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
      None => serializer.serialize_none(),
    }
  }

  pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
  where
    D: Deserializer<'de>,
  {
    let opt = Option::<String>::deserialize(deserializer)?;
    opt
      .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
      .transpose()
  }
}
