use std::fmt::{self};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sender {
  pub id: String,
  pub device_id: u32,
}

impl Sender {
  pub fn new(id: String, device_id: u32) -> Self {
    Sender { id, device_id }
  }
}

impl fmt::Display for Sender {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}::{}", self.id, self.device_id)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyName {
  group_id: String,
  sender: Sender,
}

impl SenderKeyName {
  pub fn new(group_id: String, sender: Sender) -> Self {
    SenderKeyName { group_id, sender }
  }

  pub fn get_group_id(&self) -> &str {
    &self.group_id
  }

  pub fn get_sender(&self) -> &Sender {
    &self.sender
  }

  pub fn serialize(&self) -> String {
    format!(
      "{}::{}::{}",
      self.group_id, self.sender.id, self.sender.device_id
    )
  }

  pub fn equals(&self, other: Option<&SenderKeyName>) -> bool {
    match other {
      None => false,
      Some(other) => {
        self.group_id == other.group_id && self.sender.to_string() == other.sender.to_string()
      }
    }
  }

  pub fn hash_code(&self) -> i32 {
    hash_code(&self.group_id) ^ hash_code(&self.sender.to_string())
  }
}

impl fmt::Display for SenderKeyName {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.serialize())
  }
}

impl Hash for SenderKeyName {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.group_id.hash(state);
    self.sender.id.hash(state);
    self.sender.device_id.hash(state);
  }
}

fn is_null(s: &str) -> bool {
  s.is_empty()
}

fn hash_code(str_key: &str) -> i32 {
  let mut hash: i32 = 0;

  if !is_null(str_key) {
    for ch in str_key.chars() {
      hash = hash.wrapping_mul(31).wrapping_add(ch as i32);
    }
  }

  hash
}
