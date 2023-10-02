use std::time::{SystemTime, UNIX_EPOCH};
use dryoc::rng::{copy_randombytes, randombytes_buf};
use crate::utils::sha2::{create_sha256};
use crate::xdr::types::Uint256;
use dryoc::dryocbox::ByteArray;
pub fn generate_secret_key() -> Uint256 {
    let keypair = dryoc::keypair::KeyPair::gen_with_defaults();
    let secretkey = *keypair.secret_key.as_array();
    secretkey
}
pub fn generate_nonce() -> Uint256 {
    let nonce = randombytes_buf(4);
    let mut local_nonce = [0u8; 32];
    local_nonce.copy_from_slice(&create_sha256(&nonce));
    local_nonce
}

pub fn system_time_to_u64_millis(time: &SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        .map(|duration_since_epoch| duration_since_epoch.as_millis())
        .and_then(|millis_since_epoch| millis_since_epoch.try_into().map_err(|e| Box::new(e) as Box<dyn std::error::Error>))
        .unwrap()
}