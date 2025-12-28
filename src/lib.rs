use crate::binding::{CreateKeyPair, GeneratePreKey, JsKeyPair};
use crate::keyhelper::{generate_pre_key_int, generate_registration_id_int};
use crate::libsignal::constants::{KeyPair, SessionEntry, SessionRecord};
use crate::libsignal::session_builder::{SessionBuilder, SignedPreKey};
use crate::libsignal::session_cipher::SessionCipher;
use crate::utils::{
  create_key_pair_int, curve25519_sign_inner, derive_secrets_int, generate_key_pair_int,
  scrub_pub_key, shared_secret_int, verify_int,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use proto_gen::textsecure::PreKeyWhisperMessage;
mod binding;
mod crypto;
pub mod groups;
mod keyhelper;
pub mod libsignal;
mod utils;

// generates a key pair given a private key
// private key is a Buffer of length 32
// returns an object with pubKey and privKey (both Buffers)
// uses
#[napi]
pub fn key_pair<'a>(priv_key: Buffer) -> Result<JsKeyPair> {
  if priv_key.len() != 32 {
    return Err(Error::from_reason("Invalid private key length"));
  }
  let priv_key_array: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid private key"))?;
  let keys = create_key_pair_int(priv_key_array);
  Ok(JsKeyPair {
    pub_key: Buffer::from(keys.0.as_ref()),
    priv_key: Buffer::from(keys.1.as_ref()),
  })
}

#[napi]
pub fn shared_secret(pub_key: Buffer, priv_key: Buffer) -> Result<Buffer> {
  let pub_key = scrub_pub_key(&pub_key).map_err(|e| Error::from_reason(e))?;
  if priv_key.len() != 32 {
    return Err(Error::from_reason("Invalid private key length"));
  }

  let priv_key_array: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid private key"))?;

  let shared = shared_secret_int(pub_key.as_ref(), priv_key_array)
    .map_err(|e| Error::from_reason(format!("Shared secret calculation failed: {}", e)))?;

  Ok(Buffer::from(shared.as_ref()))
}

#[napi]
pub fn verify(sig: Buffer, pub_key: Buffer, message: Buffer) -> Result<bool> {
  if sig.len() != 64 {
    return Err(Error::from_reason("Invalid signature length"));
  }
  let pub_key_scrubbed = scrub_pub_key(&pub_key)
    .map_err(|e| Error::from_reason(format!("Failed to scrub public key: {}", e)))?;

  let sig_array: &[u8; 64] = sig
    .as_ref()
    .try_into()
    .map_err(|_| Error::from_reason("Invalid signature"))?;

  verify_int(pub_key_scrubbed.as_ref(), message.as_ref(), sig_array)
    .map_err(|e| Error::from_reason(format!("Verification failed: {}", e)))
}

#[napi]
pub fn generate_key_pair() -> Result<CreateKeyPair> {
  let (pub_key, priv_key) = generate_key_pair_int();

  let result = CreateKeyPair {
    pub_key: Buffer::from(pub_key.as_ref()),
    priv_key: Buffer::from(priv_key.as_ref()),
  };
  Ok(result)
}

#[napi]
pub fn calculate_agreement(pub_key: Buffer, priv_key: Buffer) -> Result<Buffer> {
  shared_secret(pub_key, priv_key)
}

#[napi]
pub fn verify_signature(
  pub_key: Buffer,
  message: Buffer,
  sig: Buffer,
  is_init: bool,
) -> Result<bool> {
  if is_init {
    return Ok(true);
  }

  verify(sig, pub_key, message)
}

#[napi]
pub fn curve25519_sign(privkey: Buffer, msg: Buffer) -> Result<Buffer> {
  if privkey.len() != 32 {
    return Err(Error::new(Status::InvalidArg, "privkey must be 32 bytes"));
  }

  let pk: [u8; 32] = privkey
    .as_ref()
    .try_into()
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid private key"))?;

  let sig = curve25519_sign_inner(&pk, &msg);

  Ok(Buffer::from(sig.as_ref()))
}

#[napi]
pub fn generate_registration_id() -> Result<u16> {
  Ok(generate_registration_id_int())
}

#[napi]
pub fn generate_pre_key(key_id: u32) -> Result<GeneratePreKey> {
  let pre_key = generate_pre_key_int(key_id);

  let result = GeneratePreKey {
    pub_key: Buffer::from(pre_key.key_pair.pub_key.as_ref()),
    priv_key: Buffer::from(pre_key.key_pair.priv_key.as_ref()),
    key_id: pre_key.key_id,
  };

  Ok(result)
}

#[napi]
pub fn derive_secrets(
  input: Buffer,
  salt: Buffer,
  info: Buffer,
  chunks: u32,
) -> Result<Vec<Buffer>> {
  let secrets = derive_secrets_int(
    input.as_ref(),
    salt.as_ref(),
    info.as_ref(),
    chunks as usize,
  );
  let buffers: Vec<Buffer> = secrets
    .into_iter()
    .map(|arr| Buffer::from(arr.as_ref()))
    .collect();
  Ok(buffers)
}

#[napi]
pub fn encrypt_data(key: Buffer, data: Buffer, iv: Buffer) -> Result<Buffer> {
  if key.len() != 32 {
    return Err(Error::from_reason("Invalid key length"));
  }
  if iv.len() != 16 {
    return Err(Error::from_reason("Invalid IV length"));
  }

  let encrypted = crypto::encrypt_int(key.as_ref(), data.as_ref(), iv.as_ref())
    .map_err(|e| Error::from_reason(format!("Encryption failed: {:?}", e)))?;

  Ok(Buffer::from(encrypted))
}

#[napi]
pub fn decrypt_data(key: Buffer, data: Buffer, iv: Buffer) -> Result<Buffer> {
  if key.len() != 32 {
    return Err(Error::from_reason("Invalid key length"));
  }
  if iv.len() != 16 {
    return Err(Error::from_reason("Invalid IV length"));
  }
  let decrypted = crypto::decrypt_int(key.as_ref(), data.as_ref(), iv.as_ref())
    .map_err(|e| Error::from_reason(format!("Decryption failed: {:?}", e)))?;
  Ok(Buffer::from(decrypted))
}

#[napi]
pub fn verify_mac(key: Buffer, data: Buffer, expected_mac: Buffer, length: u32) -> Result<()> {
  crypto::verify_mac_int(
    key.as_ref(),
    data.as_ref(),
    expected_mac.as_ref(),
    length as usize,
  )
  .map_err(|e| Error::from_reason(format!("MAC verification failed: {:?}", e)))
}

#[napi]
pub fn calculate_mac(key: Buffer, data: Buffer) -> Result<Buffer> {
  let mac = crypto::calculate_mac(key.as_ref(), data.as_ref())
    .map_err(|e| Error::from_reason(format!("MAC calculation failed: {:?}", e)))?;
  Ok(Buffer::from(mac))
}
#[napi]
pub fn hash(data: Buffer) -> Result<Buffer> {
  let hash = crypto::hash_int(data.as_ref());
  Ok(Buffer::from(hash))
}

#[napi]
pub struct SessionRecordWrapper {
  inner: SessionRecord,
}

#[napi]
impl SessionRecordWrapper {
  #[napi(constructor)]
  pub fn new() -> Self {
    SessionRecordWrapper {
      inner: SessionRecord::new(),
    }
  }
  #[napi]
  pub fn serialize(&self) -> String {
    self
      .inner
      .serialize()
      .map_err(|e| Error::from_reason(e.to_string()))
      .unwrap()
  }
  #[napi]
  pub fn deserialize(serialized: String) -> Result<SessionRecordWrapper> {
    let record =
      SessionRecord::deserialize(&serialized).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(SessionRecordWrapper { inner: record })
  }
  #[napi]
  pub fn get_version(&self) -> String {
    self.inner.version.clone()
  }
  #[napi]
  pub fn have_open_session(&self) -> bool {
    self.inner.have_open_session()
  }
  #[napi]
  pub fn remove_old_sessions(&mut self) {
    self.inner.remove_old_sessions()
  }

  #[napi]
  pub fn delete_all_sessions(&mut self) {
    self.inner.delete_all_sessions()
  }

  #[napi]
  pub fn get_open_session(&self) -> Result<Option<String>> {
    match self.inner.get_open_session() {
      Some(session) => {
        let json = serde_json::to_string(session).map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Some(json))
      }
      None => Ok(None),
    }
  }

  #[napi]
  pub fn set_session(&mut self, session_json: String) -> Result<()> {
    let session: SessionEntry =
      serde_json::from_str(&session_json).map_err(|e| Error::from_reason(e.to_string()))?;
    self.inner.set_session(session);
    Ok(())
  }

  #[napi]
  pub fn get_session(&self, base_key: Buffer) -> Result<Option<String>> {
    match self
      .inner
      .get_session(base_key.as_ref())
      .map_err(|e| Error::from_reason(e))?
    {
      Some(session) => {
        let json = serde_json::to_string(session).map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Some(json))
      }
      None => Ok(None),
    }
  }

  #[napi]
  pub fn close_session(&mut self, base_key: Buffer) -> Result<()> {
    self.inner.close_session(base_key.as_ref());
    Ok(())
  }

  #[napi]
  pub fn open_session(&mut self, base_key: Buffer) -> Result<()> {
    self.inner.open_session(base_key.as_ref());
    Ok(())
  }

  pub fn get_inner(&self) -> &SessionRecord {
    &self.inner
  }
  pub fn get_inner_mut(&mut self) -> &mut SessionRecord {
    &mut self.inner
  }
}

#[napi(object)]
pub struct DeviceBundleObject {
  pub identity_key: Buffer,
  pub registration_id: u32,
  pub signed_pre_key: SignedPreKeyBundle,
  pub pre_key: Option<PreKeyBundle>,
}

#[napi(object)]
pub struct SignedPreKeyBundle {
  pub key_id: u32,
  pub public_key: Buffer,
  pub signature: Buffer,
}

#[napi(object)]
pub struct PreKeyBundle {
  pub key_id: u32,
  pub public_key: Buffer,
}

#[napi(object)]
pub struct KeyPairObject {
  pub pub_key: Buffer,
  pub priv_key: Buffer,
}

#[napi]
pub struct SessionBuilderWrapper {
  our_identity_key: KeyPairObject,
}

#[napi]
impl SessionBuilderWrapper {
  #[napi(constructor)]
  pub fn new(our_identity_key: KeyPairObject) -> Self {
    Self {
      our_identity_key: KeyPairObject {
        pub_key: Buffer::from(our_identity_key.pub_key.as_ref()),
        priv_key: Buffer::from(our_identity_key.priv_key.as_ref()),
      },
    }
  }

  #[napi]
  pub fn init_outgoing(&self, device: DeviceBundleObject) -> Result<String> {
    let device_bundle = libsignal::session_builder::DeviceBundle {
      identity_key: device.identity_key.to_vec(),
      registration_id: device.registration_id,
      signed_pre_key: SignedPreKey {
        key_id: device.signed_pre_key.key_id,
        public_key: device.signed_pre_key.public_key.to_vec(),
        signature: device.signed_pre_key.signature.to_vec(),
      },
      pre_key: device.pre_key.map(|pk| libsignal::session_builder::PreKey {
        key_id: pk.key_id,
        public_key: pk.public_key.to_vec(),
      }),
    };

    let pub_key: [u8; 33] = self
      .our_identity_key
      .pub_key
      .as_ref()
      .try_into()
      .map_err(|_| Error::from_reason("Invalid public key length, expected 33 bytes"))?;

    let priv_key: [u8; 32] = self
      .our_identity_key
      .priv_key
      .as_ref()
      .try_into()
      .map_err(|_| Error::from_reason("Invalid private key length, expected 32 bytes"))?;

    let key_pair = KeyPair { pub_key, priv_key };

    let builder = SessionBuilder::new(key_pair);
    let session = builder
      .init_outgoing(&device_bundle)
      .map_err(|e| Error::from_reason(e.to_string()))?;

    serde_json::to_string(&session).map_err(|e| Error::from_reason(e.to_string()))
  }

  #[napi]
  pub fn init_incoming(
    &self,
    message: PreKeyWhisperMessageObject,
    pre_key_pair: Option<KeyPairObject>,
    signed_pre_key_pair: KeyPairObject,
  ) -> Result<String> {
    let msg = PreKeyWhisperMessage {
      identity_key: Some(message.identity_key.to_vec()),
      registration_id: Some(message.registration_id),
      base_key: Some(message.base_key.to_vec()),
      pre_key_id: message.pre_key_id,
      signed_pre_key_id: Some(message.signed_pre_key_id),
      message: None,
    };

    let pre_key = pre_key_pair
      .map(|kp| -> Result<KeyPair> {
        let pub_key: [u8; 33] = kp.pub_key.as_ref().try_into().map_err(|_| {
          Error::from_reason("Invalid pre key public key length, expected 33 bytes")
        })?;

        let priv_key: [u8; 32] = kp.priv_key.as_ref().try_into().map_err(|_| {
          Error::from_reason("Invalid pre key private key length, expected 32 bytes")
        })?;

        Ok(KeyPair { pub_key, priv_key })
      })
      .transpose()?;

    let signed_pub_key: [u8; 33] =
      signed_pre_key_pair
        .pub_key
        .as_ref()
        .try_into()
        .map_err(|_| {
          Error::from_reason("Invalid signed pre key public key length, expected 33 bytes")
        })?;

    let signed_priv_key: [u8; 32] =
      signed_pre_key_pair
        .priv_key
        .as_ref()
        .try_into()
        .map_err(|_| {
          Error::from_reason("Invalid signed pre key private key length, expected 32 bytes")
        })?;

    let signed_key = KeyPair {
      pub_key: signed_pub_key,
      priv_key: signed_priv_key,
    };

    let pub_key: [u8; 33] = self
      .our_identity_key
      .pub_key
      .as_ref()
      .try_into()
      .map_err(|_| Error::from_reason("Invalid public key length, expected 33 bytes"))?;

    let priv_key: [u8; 32] = self
      .our_identity_key
      .priv_key
      .as_ref()
      .try_into()
      .map_err(|_| Error::from_reason("Invalid private key length, expected 32 bytes"))?;

    let key_pair = KeyPair { pub_key, priv_key };

    let builder = SessionBuilder::new(key_pair);
    let session = builder
      .init_incoming(&msg, pre_key, signed_key)
      .map_err(|e| Error::from_reason(e.to_string()))?;

    serde_json::to_string(&session).map_err(|e| Error::from_reason(e.to_string()))
  }
}

#[napi(object)]
pub struct EncryptResult {
  pub message_type: u32,
  pub body: Buffer,
  pub registration_id: u32,
  pub updated_session: String,
}

#[napi(object)]
pub struct DecryptResult {
  pub plaintext: Buffer,
  pub updated_session: String,
}

#[napi(object)]
pub struct PreKeyWhisperMessageObject {
  pub identity_key: Buffer,
  pub registration_id: u32,
  pub base_key: Buffer,
  pub pre_key_id: Option<u32>,
  pub signed_pre_key_id: u32,
}

#[napi]
pub struct SessionCipherWrapper {
  cipher: SessionCipher,
}

#[napi]
impl SessionCipherWrapper {
  #[napi(constructor)]
  pub fn new(our_identity_key: KeyPairObject, our_registration_id: u32) -> Result<Self> {
    let pub_key: [u8; 33] = our_identity_key
      .pub_key
      .as_ref()
      .try_into()
      .map_err(|_| Error::from_reason("Invalid public key length, expected 33 bytes"))?;

    let priv_key: [u8; 32] = our_identity_key
      .priv_key
      .as_ref()
      .try_into()
      .map_err(|_| Error::from_reason("Invalid private key length, expected 32 bytes"))?;

    let key_pair = KeyPair { pub_key, priv_key };

    Ok(Self {
      cipher: SessionCipher::new(key_pair, our_registration_id),
    })
  }

  #[napi]
  pub fn encrypt(&mut self, session_json: String, data: Buffer) -> Result<EncryptResult> {
    let mut session: SessionEntry =
      serde_json::from_str(&session_json).map_err(|e| Error::from_reason(e.to_string()))?;

    let encrypted = self
      .cipher
      .encrypt(&mut session, &data)
      .map_err(|e| Error::from_reason(e.to_string()))?;

    let updated_session =
      serde_json::to_string(&session).map_err(|e| Error::from_reason(e.to_string()))?;

    Ok(EncryptResult {
      message_type: encrypted.message_type as u32,
      body: encrypted.body.into(),
      registration_id: encrypted.registration_id,
      updated_session,
    })
  }

  #[napi]
  pub fn decrypt_whisper_message(
    &mut self,
    session_json: String,
    message: Buffer,
  ) -> Result<DecryptResult> {
    let mut session: SessionEntry =
      serde_json::from_str(&session_json).map_err(|e| Error::from_reason(e.to_string()))?;

    let plaintext = self
      .cipher
      .decrypt_whisper_message(&mut session, &message)
      .map_err(|e| Error::from_reason(e.to_string()))?;

    let updated_session =
      serde_json::to_string(&session).map_err(|e| Error::from_reason(e.to_string()))?;

    Ok(DecryptResult {
      plaintext: plaintext.into(),
      updated_session,
    })
  }
}

#[napi(object)]
pub struct BaseKeyTypeEnum {
  pub ours: u8,
  pub theirs: u8,
}

#[napi(object)]
pub struct ChainTypeEnum {
  pub sending: u8,
  pub receiving: u8,
}

#[napi]
pub fn get_base_key_type() -> BaseKeyTypeEnum {
  BaseKeyTypeEnum { ours: 1, theirs: 2 }
}

#[napi]
pub fn get_chain_type() -> ChainTypeEnum {
  ChainTypeEnum {
    sending: 1,
    receiving: 2,
  }
}

#[napi(object)]
pub struct SenderKeyDistributionMessageResult {
  pub id: u32,
  pub iteration: u32,
  pub chain_key: Buffer,
  pub signing_key: Buffer,
}

#[napi]
pub fn create_sender_key_distribution_message(
  key_id: u32,
  iteration: u32,
  chain_key: Buffer,
  signing_key: Buffer,
) -> Result<Buffer> {
  use crate::groups::sender_key_distribution_message::SenderKeyDistributionMessage;

  let msg = SenderKeyDistributionMessage::new(
    Some(key_id),
    Some(iteration),
    Some(chain_key.to_vec()),
    Some(signing_key.to_vec()),
    None,
  )
  .map_err(|e| Error::from_reason(e))?;

  Ok(Buffer::from(msg.serialize()))
}

#[napi]
pub fn parse_sender_key_distribution_message(
  serialized: Buffer,
) -> Result<SenderKeyDistributionMessageResult> {
  use crate::groups::sender_key_distribution_message::SenderKeyDistributionMessage;

  let msg = SenderKeyDistributionMessage::new(None, None, None, None, Some(serialized.to_vec()))
    .map_err(|e| Error::from_reason(e))?;

  Ok(SenderKeyDistributionMessageResult {
    id: msg.get_id(),
    iteration: msg.get_iteration(),
    chain_key: Buffer::from(msg.get_chain_key()),
    signing_key: Buffer::from(msg.get_signature_key()),
  })
}

#[napi]
pub fn group_encrypt_message(sender_key_record_bytes: Buffer, plaintext: Buffer) -> Result<Buffer> {
  use crate::groups::{group_cipher::GroupCipher, sender_key_record::SenderKeyRecord};

  let record_vec = sender_key_record_bytes.to_vec();
  let record = if record_vec.is_empty() {
    SenderKeyRecord::new(None).map_err(|e| Error::from_reason(e))?
  } else {
    SenderKeyRecord::from_protobuf(&record_vec).map_err(|e| Error::from_reason(e))?
  };

  let mut sender_state = record
    .get_sender_key_state(None)
    .ok_or_else(|| Error::from_reason("No sender key state found"))?
    .clone();

  let ciphertext = GroupCipher::encrypt_message(&mut sender_state, &plaintext)
    .map_err(|e| Error::from_reason(e))?;

  Ok(Buffer::from(ciphertext))
}

#[napi]
pub fn group_decrypt_message(
  sender_key_record_bytes: Buffer,
  ciphertext: Buffer,
) -> Result<Buffer> {
  use crate::groups::{group_cipher::GroupCipher, sender_key_record::SenderKeyRecord};

  let record =
    SenderKeyRecord::from_protobuf(&sender_key_record_bytes).map_err(|e| Error::from_reason(e))?;

  let mut sender_state = record
    .get_sender_key_state(None)
    .ok_or_else(|| Error::from_reason("No sender key state found"))?
    .clone();

  let plaintext = GroupCipher::decrypt_message(&mut sender_state, &ciphertext)
    .map_err(|e| Error::from_reason(e))?;

  Ok(Buffer::from(plaintext))
}

#[napi]
pub fn process_sender_key_distribution(
  existing_record_bytes: Buffer,
  distribution_message: Buffer,
) -> Result<Buffer> {
  use crate::groups::{
    sender_key_distribution_message::SenderKeyDistributionMessage,
    sender_key_record::SenderKeyRecord,
  };

  let dist_msg =
    SenderKeyDistributionMessage::new(None, None, None, None, Some(distribution_message.to_vec()))
      .map_err(|e| Error::from_reason(e))?;

  let mut record = if existing_record_bytes.is_empty() {
    SenderKeyRecord::new(None).map_err(|e| Error::from_reason(e))?
  } else {
    SenderKeyRecord::from_protobuf(&existing_record_bytes).map_err(|e| Error::from_reason(e))?
  };

  record
    .add_sender_key_state(
      dist_msg.get_id(),
      dist_msg.get_iteration(),
      dist_msg.get_chain_key().to_vec(),
      dist_msg.get_signature_key().to_vec(),
    )
    .map_err(|e| Error::from_reason(e))?;

  let bytes = record.to_protobuf().map_err(|e| Error::from_reason(e))?;
  Ok(Buffer::from(bytes))
}

#[napi]
pub fn create_sender_key(
  key_id: u32,
  iteration: u32,
  chain_key: Buffer,
  signing_key_public: Buffer,
  signing_key_private: Option<Buffer>,
) -> Result<Buffer> {
  use crate::groups::{
    sender_key_record::SenderKeyRecord,
    sender_key_state::{SenderKeyState, SenderSigningKey},
  };

  let signing_key = SenderSigningKey {
    public: signing_key_public.to_vec(),
    private: signing_key_private.map(|b| b.to_vec()),
  };

  let state = SenderKeyState::new(
    key_id,
    iteration,
    chain_key.to_vec(),
    Some(signing_key),
    None,
    None,
    None,
  )
  .map_err(|e| Error::from_reason(e))?;

  let structure = state.get_structure();
  let record = SenderKeyRecord::new(Some(vec![structure])).map_err(|e| Error::from_reason(e))?;

  let bytes = record.to_protobuf().map_err(|e| Error::from_reason(e))?;
  Ok(Buffer::from(bytes))
}

#[napi]
pub fn serialize_sender_key_record_json(record_bytes: Buffer) -> Result<String> {
  use crate::groups::sender_key_record::SenderKeyRecord;

  let record = SenderKeyRecord::from_protobuf(&record_bytes).map_err(|e| Error::from_reason(e))?;

  let proto_bytes = record.to_protobuf().map_err(|e| Error::from_reason(e))?;
  let base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &proto_bytes);

  Ok(base64)
}

#[napi]
pub fn deserialize_sender_key_record_json(base64_str: String) -> Result<Buffer> {
  use base64::Engine;

  let bytes = base64::engine::general_purpose::STANDARD
    .decode(&base64_str)
    .map_err(|e| Error::from_reason(e.to_string()))?;

  Ok(Buffer::from(bytes))
}
