use std::time::{SystemTime, UNIX_EPOCH};
use dryoc::rng::{randombytes_buf};
use crate::sha2::{create_sha256, Uint256};
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

pub fn get_current_u64_milliseconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration|duration.as_millis())
            .unwrap_or(0)
            .try_into()
            .unwrap_or(0)
}

pub fn increase_buffer_by_one(buf: &mut [u8]) {
    for byte in buf.iter_mut().rev() {
        if *byte != 255 {
            *byte += 1;
            break;
        } else {
            *byte = 0;
        }
    }
}