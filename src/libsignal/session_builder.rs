use proto_gen::textsecure::PreKeyWhisperMessage;

use crate::utils::{generate_key_pair_int, verify_int};

#[async_trait::async_trait]
pub trait SessionStorage {
  async fn is_trusted_identity(&self, id: &str, key: &[u8]) -> bool;
  async fn load_session(&self, addr: &str) -> Option<SessionRecord>;
  async fn store_session(&self, addr: &str, record: SessionRecord);

  async fn load_pre_key(&self, id: u32) -> Option<KeyPair>;
  async fn load_signed_pre_key(&self, id: u32) -> Option<KeyPair>;

  async fn get_our_identity(&self) -> IdentityKey;
}

#[derive(thiserror::Error, Debug)]
pub enum SignalError {
  #[error("Untrusted identity key")]
  UntrustedIdentityKey,

  #[error("Invalid PreKey ID")]
  InvalidPreKey,

  #[error("Missing SignedPreKey")]
  MissingSignedPreKey,

  #[error("Invalid initSession call")]
  InvalidInitSession,
}

pub struct SessionBuilder<S: SessionStorage> {
  addr: ProtocolAddress,
  storage: std::sync::Arc<S>,
}

impl<S: SessionStorage> SessionBuilder<S> {
  pub fn new(storage: std::sync::Arc<S>, addr: ProtocolAddress) -> Self {
    Self { storage, addr }
  }
  pub async fn init_outgoing(&self, device: Device) -> Result<(), SignalError> {
    let fq_addr = self.addr.to_string();

    if !self
      .storage
      .is_trusted_identity(&self.addr.id, &device.identity_key)
      .await
    {
      return Err(SignalError::UntrustedIdentityKey);
    }
    verify_int(&device.signed_pre_key.public_key, &device.identity_key, &device.signed_pre_key.signature);



    let base_key = generate_key_pair_int();
    let device_pre_key = device.pre_key.as_ref().map(|k| k.public_key.as_slice());

    let mut session = self
      .init_session(
        true,
        Some(&base_key),
        None,
        &device.identity_key,
        device_pre_key,
        Some(&device.signed_pre_key.public_key),
        device.registration_id,
      )
      .await?;

    session.pending_pre_key = Some(PendingPreKey {
      signed_key_id: device.signed_pre_key.key_id,
      base_key: base_key.0.clone(),
      pre_key_id: device.pre_key.map(|k| k.key_id),
    });

    let mut record = self
      .storage
      .load_session(&fq_addr)
      .await
      .unwrap_or_else(SessionRecord::new);

    if let Some(open) = record.get_open_session() {
      record.close_session(open);
    }

    record.set_session(session);
    self.storage.store_session(&fq_addr, record).await;

    Ok(())
  }
  pub async fn init_incoming(
    &self,
    record: &mut SessionRecord,
    message: PreKeyWhisperMessage,
) -> Result<Option<u32>, SignalError> {
    let fq_addr = self.addr.to_string();
    let identity_key = message
    .identity_key
    .as_ref()
    .ok_or(SignalError::InvalidPreKey)?;


    if !self.storage
        .is_trusted_identity(&fq_addr, &identity_key)
        .await
    {
        return Err(SignalError::UntrustedIdentityKey);
    }

    if record.get_session(&message.base_key).is_some() {
        return Ok(None);
    }

    let pre_key_pair = if let Some(id) = message.pre_key_id {
        self.storage
            .load_pre_key(id)
            .await
            .ok_or(SignalError::InvalidPreKey)?
    } else {
        None
    };

    let signed_pre_key = self.storage
        .load_signed_pre_key(message.signed_pre_key_id())
        .await
        .ok_or(SignalError::MissingSignedPreKey)?;

    if let Some(open) = record.get_open_session() {
        record.close_session(open);
    }

    let session = self.init_session(
        false,
        pre_key_pair.as_ref(),
        Some(&signed_pre_key),
        &message.identity_key,
        Some(&message.base_key),
        None,
        message.registration_id,
    ).await?;

    record.set_session(session);

    Ok(message.pre_key_id)
}

}
