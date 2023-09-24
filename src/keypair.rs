use dryoc::classic::crypto_sign::crypto_sign_detached;
use dryoc::sign::{SecretKey, SigningKeyPair};
use crate::xdr::constants::{ED25519_PUBLIC_KEY_BYTE_LENGTH, ED25519_SECRET_KEY_BYTE_LENGTH, ED25519_SECRET_SEED_BYTE_LENGTH};

#[derive(Debug, Clone)]
pub struct Keypair {
    _secret_seed: [u8; ED25519_SECRET_SEED_BYTE_LENGTH],
    _public_key: [u8; ED25519_PUBLIC_KEY_BYTE_LENGTH],
    _secret_key: [u8; ED25519_SECRET_KEY_BYTE_LENGTH]
}

impl Default for Keypair {
    fn default() -> Self {
        Self::from()
    }
}
impl From<[u8; ED25519_SECRET_SEED_BYTE_LENGTH]> for Keypair {
    fn from(_secret_seed: [u8; ED25519_SECRET_SEED_BYTE_LENGTH]) -> Self {
        let mut _public_key = SigningKeyPair::<[u8; ED25519_PUBLIC_KEY_BYTE_LENGTH], SecretKey>::from_seed(&_secret_seed.clone()).public_key;
        let mut _secret_key = [0u8; ED25519_SECRET_KEY_BYTE_LENGTH];
        _secret_key[..ED25519_SECRET_SEED_BYTE_LENGTH].copy_from_slice(&_secret_seed);
        _secret_key[ED25519_SECRET_SEED_BYTE_LENGTH..].copy_from_slice(&_public_key);
        Self { _secret_seed, _public_key, _secret_key }
    }
}

impl Keypair {
    pub fn sign(&self, message: impl AsRef<[u8]>) -> [u8; ED25519_SECRET_KEY_BYTE_LENGTH] {
        let mut signature = [0u8; ED25519_SECRET_KEY_BYTE_LENGTH];
        let arr: [u8; ED25519_SECRET_KEY_BYTE_LENGTH] = self._secret_key.clone();
        crypto_sign_detached(&mut signature, message.as_ref(), &arr).expect("Error");
        signature
    }

    fn key_type(&self) -> &str {
        "ed25519"
    }
    pub fn secret_key(&self) -> &[u8; ED25519_SECRET_KEY_BYTE_LENGTH] {
        &self._secret_key
    }
    pub fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_BYTE_LENGTH] {
        &self._public_key
    }
}
