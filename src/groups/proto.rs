use prost::Message;
use proto_gen::groupproto::{SenderKeyDistributionMessage, SenderKeyMessage};

pub fn decode_sender_keys_msg(data: &[u8]) -> Result<SenderKeyMessage, prost::DecodeError> {
  let msg = SenderKeyMessage::decode(data)?;
  Ok(msg)
}

pub fn encode_sender_keys_msg(msg: &SenderKeyMessage) -> Result<Vec<u8>, prost::EncodeError> {
  let mut buf = Vec::new();
  msg.encode(&mut buf)?;
  Ok(buf)
}
pub fn encode_sender_distribution_msg(
  msg: &SenderKeyDistributionMessage,
) -> Result<Vec<u8>, prost::EncodeError> {
  let mut buf = Vec::new();
  msg.encode(&mut buf)?;
  Ok(buf)
}
pub fn decode_sender_distribution_msg(
  data: &[u8],
) -> Result<SenderKeyDistributionMessage, prost::DecodeError> {
  let msg = SenderKeyDistributionMessage::decode(data)?;
  Ok(msg)
}
