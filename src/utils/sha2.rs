use ring::{digest, hmac};
use std::convert::TryInto;
use ring::digest::{Context, SHA256};
use crate::xdr::types::Uint256;

pub fn create_sha256_hmac(data: &[u8], mac_key: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
    let signature = hmac::sign(&key, data);
    signature.as_ref().to_vec()
}
pub fn create_sha256(data: &[u8]) -> Uint256 {
    let mut context = Context::new(&SHA256);
    context.update(data);
    let digest = context.finish();
    digest.as_ref().to_vec();
    let mut res = [0u8; 32];
    res.copy_from_slice(&digest.as_ref().to_vec());
    res
}

