use ring::{digest, hmac};
use std::convert::TryInto;
use ring::digest::{Context, SHA256};

pub fn create_sha256_hmac(data: &[u8], mac_key: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
    let signature = hmac::sign(&key, data);
    signature.as_ref().to_vec()
}
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut context = Context::new(&SHA256);
    context.update(data);
    let digest = context.finish();
    digest.as_ref().to_vec()
}