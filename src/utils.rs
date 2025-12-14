use curve25519_dalek::{MontgomeryPoint, Scalar};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

const BASEPOINT: [u8; 32] = {
    let mut base = [0u8; 32];
    base[0] = 9;
    base
};

pub fn get_basepoint() -> [u8; 32] {
    BASEPOINT
}

// clamping to avoid copies
#[inline(always)]
pub fn clamp_priv_key(priv_key: &mut [u8; 32]) {
    priv_key[0] &= 248;
    priv_key[31] &= 127;
    priv_key[31] |= 64;
}

pub fn create_key_pair_int(mut priv_key: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    clamp_priv_key(&mut priv_key);
    let scalar = Scalar::from_bytes_mod_order(priv_key);
    let pub_key = (scalar * MontgomeryPoint(get_basepoint())).to_bytes();
    
    (pub_key, priv_key)
}

pub fn shared_secret_int(pub_key_bytes: &[u8], priv_key: [u8; 32]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if pub_key_bytes.len() != 32 && pub_key_bytes.len() != 33 {
        return Err(Box::<dyn std::error::Error>::from("Invalid public key length"));
    }
    let pub_key_32: [u8; 32] = if pub_key_bytes.len() == 33 {
        if pub_key_bytes[0] != 5 {
            return Err(Box::<dyn std::error::Error>::from("Invalid public key version byte"));
        }
        pub_key_bytes[1..33].try_into()
            .map_err(|_| Box::<dyn std::error::Error>::from("Invalid public key"))?
    } else {
        pub_key_bytes.try_into()
            .map_err(|_| Box::<dyn std::error::Error>::from("Invalid public key"))?
    };
    let mut clamped_priv = priv_key;
    clamp_priv_key(&mut clamped_priv);
    let scalar = Scalar::from_bytes_mod_order(clamped_priv);
    let shared = (scalar * MontgomeryPoint(pub_key_32)).to_bytes();
    
    Ok(shared)
}


pub fn generate_key_pair_int() -> ([u8; 32], [u8; 32]) {
    let mut rng = OsRng;
    let mut priv_key = [0u8; 32];
    rng.fill_bytes(&mut priv_key);
    create_key_pair_int(priv_key)
}

pub fn verify_int(pub_key_bytes: &[u8], message: &[u8], sig: &[u8; 64]) -> Result<bool, Box<dyn std::error::Error>> {
    let pub_key = if pub_key_bytes.len() == 33 {
        if pub_key_bytes[0] != 5 {
            return Ok(false);
        }
        pub_key_bytes[1..33].try_into()
            .map_err(|_| Box::<dyn std::error::Error>::from("Invalid public key"))?
    } else if pub_key_bytes.len() == 32 {
        pub_key_bytes.try_into()
            .map_err(|_| Box::<dyn std::error::Error>::from("Invalid public key"))?
    } else {
        return Ok(false);
    };
    
    match VerifyingKey::from_bytes(pub_key) {
        Ok(ver) => {
            let signature = Signature::from_bytes(sig);
            Ok(ver.verify_strict(message, &signature).is_ok())
        },
        Err(_) => Ok(false)
    }
}