use std::vec;

use crate::{groups::ciphertext::WHISPER_GROUP, sender_key_state, utils::derive_secrets_int};

pub struct SenderMessageKey {
    pub iteration: u32,
    pub seed: [u8; 16],
}

pub struct SenderKeyState {
    iteration: u32,
    iv: [u8; 16],
    cipher_key: [u8; 32],
    seed: [u8; 32],
}


impl SenderMessageKey {
    pub fn new(iteration: u32, seed: [u8; 16]) -> Self {
        let derive = derive_secrets_int(seed.as_ref(), vec![0u8; 32].as_ref(), WHISPER_GROUP, 2);
        let keys = SenderKeyState {
            iteration,
            iv: derive[0][..16].try_into().unwrap(),
            cipher_key: derive[0],
            seed: derive[1],
        };
        SenderMessageKey {
            iteration: keys.iteration,
            seed: keys.seed[..16].try_into().unwrap(),
        }
    }
    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }
    pub fn get_seed(&self) -> [u8; 16] {
        self.seed
    }

}
