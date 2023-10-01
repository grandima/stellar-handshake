use std::time::{SystemTime, UNIX_EPOCH};
use rand::random;
use crate::utils::sha2::{create_sha256};
use crate::xdr::types::Uint256;

pub fn generate_nonce() -> Uint256 {
    let nonce = random::<u32>().to_be_bytes();
    //TODO: remove
    // let nonce = [
    //     48u8, 46, 53, 55, 55, 49, 53, 55, 48, 53, 51, 48, 53, 51, 55, 48, 50, 54, 48, 55, 50, 56
    // ];
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