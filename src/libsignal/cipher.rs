
use std::collections::HashMap;

use crate::{crypto::calculate_mac, utils::{derive_secrets_int, shared_secret_int}};
#[derive(Clone)]
pub struct ChainKey {
    pub counter: u32,
    pub key: Option<Vec<u8>>, // None = chain closed
}


pub type MessageKey = Vec<u8>;

pub struct Chain {
    pub chain_key: ChainKey,
    pub message_keys: HashMap<u32, MessageKey>,
}
const MESSAGE_KEY_SEED: &[u8; 1] = &[1u8];
const CHAIN_KEY_SEED: &[u8; 1] = &[2u8];
pub fn fill_message_keys_int(chain: &mut Chain, counter: u32) -> Result<(), String> {
    if chain.chain_key.counter >= counter {
        return Ok(()); // No need to fill
    }
    if counter - chain.chain_key.counter > 1000 {
        // posible peer misbehaviour
        return Ok(()); 
    }

    if chain.chain_key.key.is_none() {
        return Ok(()); // Chain is closed
    }
    while chain.chain_key.counter < counter {
        let mut key = chain
        .chain_key
        .key
        .as_ref()
        .ok_or("Chain is closed!")?
        .clone();
    
        let next_counter = chain.chain_key.counter + 1;
        // Derive next chain key and message key
        let data = calculate_mac(&key, MESSAGE_KEY_SEED)
        .map_err(|e| format!("Failed to calculate MAC: {:?}", e)).unwrap();
        // Update chain key
        chain.message_keys.insert(next_counter, data);
        let new_chain_key = calculate_mac(&key, CHAIN_KEY_SEED)
        .map_err(|e| format!("Failed to calculate MAC: {:?}", e)).unwrap();
        chain.chain_key.counter = next_counter;
        chain.chain_key.key = Some(new_chain_key.clone());

        key = new_chain_key;
    }
    Ok(())
}


fn calculate_ratchet(
    ephemeral_priv: &[u8; 32],
    remote_key: &[u8],
    root_key: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error + Send + Sync>> {
    let dh = shared_secret_int(remote_key, *ephemeral_priv)
        .map_err(|e| format!("DH calculation failed: {:?}", e))?;
    let derived_secrets = derive_secrets_int(&dh, root_key, b"WhisperRatchet", 2);
    let root: [u8; 32] = derived_secrets[0]
        .as_slice()
        .try_into()
        .map_err(|_| "invalid derived length")?;

    let chain: [u8; 32] = derived_secrets[1]
        .as_slice()
        .try_into()
        .map_err(|_| "invalid derived length")?;
    Ok((root, chain))
}

pub struct RatchetState {
    pub root_key: [u8; 32],
    pub ephemeral_priv: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub last_remote_ephemeral: Option<[u8; 32]>,
    pub previous_counter: u32,
}

fn maybe_step_ratchet(
    ratchet: &mut RatchetState,
    remote_ephemeral: &[u8],
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    if ratchet
        .last_remote_ephemeral
        .map_or(true, |last| last != remote_ephemeral)
    {
        let (new_root, new_chain) = calculate_ratchet(
            &ratchet.ephemeral_priv,
            remote_ephemeral,
            &ratchet.root_key,
        )?;
        ratchet.root_key = new_root;
        ratchet.previous_counter = 0;
        ratchet.last_remote_ephemeral = Some(
            remote_ephemeral
                .try_into()
                .map_err(|_| "invalid remote ephemeral length")?,
        );

        // Generate new ephemeral key pair
        let (new_ephemeral_pub, new_ephemeral_priv) = crate::utils::generate_key_pair_int();
        ratchet.ephemeral_priv = new_ephemeral_priv;
        ratchet.ephemeral_pub = new_ephemeral_pub[1..33]
            .try_into()
            .map_err(|_| "invalid ephemeral public key length")?;

        Ok(Some(new_chain))
    } else {
        Ok(None)
    }
}