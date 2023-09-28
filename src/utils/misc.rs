use rand::random;
use crate::utils::sha2::{create_sha256, create_sha256_hmac};

pub fn increase_buffer_by_one(buf: &mut [u8]) {
    let mut i = buf.len();
    while i > 0 {
        i -= 1;
        buf[i] = buf[i].wrapping_add(1);
        if buf[i] != 0 {
            break;
        }
    }
}
pub fn generate_nonce() -> [u8; 32] {
    let nonce = random::<u32>().to_be_bytes();
    //TODO: remove
    // let nonce = [
    //     48u8, 46, 53, 55, 55, 49, 53, 55, 48, 53, 51, 48, 53, 51, 55, 48, 50, 54, 48, 55, 50, 56
    // ];
    let mut local_nonce = [0u8; 32];
    local_nonce.copy_from_slice(&create_sha256(&nonce));
    local_nonce
}
