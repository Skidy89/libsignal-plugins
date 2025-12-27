use crate::libsignal::constants::BaseKeyType;
use crate::libsignal::constants::Chain;
use crate::libsignal::constants::ChainKey;
use crate::libsignal::constants::ChainType;
use crate::libsignal::constants::CurrentRatchet;
use crate::libsignal::constants::IndexInfo;
use crate::libsignal::constants::KeyPair;
use crate::libsignal::constants::PendingPreKey;
use crate::libsignal::constants::SessionEntry;
use crate::libsignal::session_cipher::WHISPER_RATCHET;
use crate::utils::derive_secrets_int;
use crate::utils::generate_key_pair_int;
use crate::utils::shared_secret_int;
use crate::utils::verify_int;
use prost::Message;
use proto_gen::textsecure::PreKeyWhisperMessage;

use std::error::Error as StdError;

#[derive(Debug)]
pub struct SignedPreKey {
  pub key_id: u32,
  pub public_key: Vec<u8>,
  pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct PreKey {
  pub key_id: u32,
  pub public_key: Vec<u8>,
}
#[derive(Debug)]
pub struct DeviceBundle {
  pub identity_key: Vec<u8>,
  pub registration_id: u32,
  pub signed_pre_key: SignedPreKey,
  pub pre_key: Option<PreKey>,
}

pub struct SessionBuilder {
  our_identity_key: KeyPair,
}

impl SessionBuilder {
  pub fn new(our_identity_key: KeyPair) -> Self {
    Self { our_identity_key }
  }

  pub fn init_outgoing(
    &self,
    device: &DeviceBundle,
  ) -> Result<SessionEntry, Box<dyn StdError + Send + Sync>> {
    let signature: &[u8; 64] = device
      .signed_pre_key
      .signature
      .as_slice()
      .try_into()
      .map_err(|_| "Invalid signature length: expected 64 bytes")?;
    verify_int(
      &device.identity_key,
      &device.signed_pre_key.public_key,
      signature,
    )?;
    let base_key = generate_key_pair_int();

    let device_pre_key = device.pre_key.as_ref().map(|pk| pk.public_key.clone());

    let mut session = self.init_session(
      true, // is_initiator
      Some(KeyPair {
        pub_key: base_key.0,
        priv_key: base_key.1,
      }), // ourEphemeralKey
      None, // ourSignedKey
      &device.identity_key, // theirIdentityPubKey
      device_pre_key.as_deref(), // theirEphemeralPubKey
      Some(&device.signed_pre_key.public_key), // theirSignedPubKey
      device.registration_id,
    )?;

    session.pending_pre_key = Some(PendingPreKey {
      base_key: base_key.0.to_vec(),
      pre_key_id: device.pre_key.as_ref().map(|pk| pk.key_id),
      signed_key_id: device.signed_pre_key.key_id,
    });

    Ok(session)
  }

  pub fn init_incoming(
    &self,
    message: &PreKeyWhisperMessage,
    pre_key_pair: Option<KeyPair>,
    signed_pre_key_pair: KeyPair,
  ) -> Result<SessionEntry, Box<dyn StdError + Send + Sync>> {
    if message.pre_key_id.is_some() && pre_key_pair.is_none() {
      return Err("Invalid PreKey ID".into());
    }

    let identity_key = message
      .identity_key
      .as_ref()
      .ok_or("Missing identity key")?;
    let base_key = message.base_key.as_ref().ok_or("Missing base key")?;
    let registration_id = message.registration_id.ok_or("Missing registration ID")?;

    let session = self.init_session(
      false,                     // is_initiator
      pre_key_pair,              // ourEphemeralKey (can be None)
      Some(signed_pre_key_pair), // ourSignedKey
      identity_key,              // theirIdentityPubKey
      Some(base_key.as_slice()), // theirEphemeralPubKey
      None,                      // theirSignedPubKey
      registration_id,
    )?;

    Ok(session)
  }

  fn init_session(
    &self,
    is_initiator: bool,
    our_ephemeral_key: Option<KeyPair>,
    our_signed_key: Option<KeyPair>,
    their_identity_pub_key: &[u8],
    their_ephemeral_pub_key: Option<&[u8]>,
    their_signed_pub_key: Option<&[u8]>,
    registration_id: u32,
  ) -> Result<SessionEntry, Box<dyn StdError + Send + Sync>> {
    let our_signed_key = if is_initiator {
      our_ephemeral_key.as_ref().ok_or("Missing ephemeral key")?
    } else {
      our_signed_key.as_ref().ok_or("Missing signed key")?
    };

    let their_signed_pub_key = if is_initiator {
      their_signed_pub_key.ok_or("Missing their signed public key")?
    } else {
      their_ephemeral_pub_key.ok_or("Missing their ephemeral public key")?
    };

    let has_ephemeral = our_ephemeral_key.is_some() && their_ephemeral_pub_key.is_some();
    let secret_len = if has_ephemeral { 32 * 5 } else { 32 * 4 };
    let mut shared_secret = vec![0xFFu8; secret_len];

    let a1 = shared_secret_int(their_signed_pub_key, self.our_identity_key.priv_key)?;
    let a2 = shared_secret_int(their_identity_pub_key, our_signed_key.priv_key)?;
    let a3 = shared_secret_int(their_signed_pub_key, our_signed_key.priv_key)?;
    if is_initiator {
      shared_secret[32..64].copy_from_slice(&a1);
      shared_secret[64..96].copy_from_slice(&a2);
    } else {
      shared_secret[32..64].copy_from_slice(&a2);
      shared_secret[64..96].copy_from_slice(&a1);
    }
    shared_secret[96..128].copy_from_slice(&a3);

    if has_ephemeral {
      let our_eph = our_ephemeral_key.as_ref().unwrap();
      let their_eph = their_ephemeral_pub_key.unwrap();
      let a4 = shared_secret_int(their_eph, our_eph.priv_key)?;
      shared_secret[128..160].copy_from_slice(&a4);
    }

    let master_key = derive_secrets_int(&shared_secret, &[0u8; 32], b"WhisperText", 3);

    let mut session = SessionEntry::new();
    session.registration_id = registration_id;

    let ephemeral_key_pair = if is_initiator {
      generate_key_pair_int()
    } else {
      (our_signed_key.pub_key, our_signed_key.priv_key)
    };

    session.current_ratchet = CurrentRatchet {
      ephemeral_key_pair: KeyPair {
        pub_key: ephemeral_key_pair.0.clone(),
        priv_key: ephemeral_key_pair.1.clone(),
      },
      last_remote_ephemeral_key: their_signed_pub_key.to_vec(),
      previous_counter: 0,
      root_key: master_key[0].to_vec(),
    };

    let base_key = if is_initiator {
      our_ephemeral_key.as_ref().unwrap().pub_key.to_vec()
    } else {
      their_ephemeral_pub_key.unwrap().to_vec()
    };

    let now = chrono::Utc::now().timestamp_millis() as u64;

    session.index_info = IndexInfo {
      base_key,
      base_key_type: if is_initiator {
        BaseKeyType::Ours
      } else {
        BaseKeyType::Theirs
      },
      closed: -1,
      used: now,
      created: now,
      remote_identity_key: their_identity_pub_key.to_vec(),
    };

    if is_initiator {
      self.calculate_sending_ratchet(&mut session, their_signed_pub_key)?;
    }

    Ok(session)
  }

  fn calculate_sending_ratchet(
    &self,
    session: &mut SessionEntry,
    remote_key: &[u8],
  ) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let ratchet = &session.current_ratchet;

    let shared_secret = shared_secret_int(remote_key, ratchet.ephemeral_key_pair.priv_key)?;

    let master_key = derive_secrets_int(&shared_secret, &ratchet.root_key, WHISPER_RATCHET, 2);

    let key_base64 =
      base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &master_key[1]);

    let chain = Chain {
      chain_key: ChainKey {
        counter: -1,
        key: Some(key_base64.encode_to_vec()),
      },
      chain_type: ChainType::Sending,
      message_keys: std::collections::HashMap::new(),
    };

    let ephemeral_pub_key = ratchet.ephemeral_key_pair.pub_key.clone();
    session.add_chain(&ephemeral_pub_key, chain)?;
    session.current_ratchet.root_key = master_key[0].to_vec();

    Ok(())
  }
}
