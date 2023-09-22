use dryoc::classic::crypto_sign::crypto_sign_detached;
use dryoc::sign::{SecretKey, SigningKeyPair};

pub const ED25519_PUBLIC_KEY_BYTE_LENGTH: usize = 32;

pub const ED25519_SECRET_SEED_BYTE_LENGTH: usize = 32;
#[derive(Debug, Clone)]
pub struct Keypair {
    _secret_seed: Vec<u8>,
    _public_key: Vec<u8>,
    _secret_key: Vec<u8>
}

impl From<&[u8]> for Keypair {
    fn from(secret_key: &[u8]) -> Self {
        let mut public_key = (SigningKeyPair::from_seed(&secret_key.to_vec().clone())as SigningKeyPair<Vec<u8>, SecretKey>).public_key.clone();
        let mut _secret_key = vec![];
        _secret_key.extend_from_slice(secret_key);
        _secret_key.append(&mut public_key.clone());
        Self { _secret_seed: secret_key.to_vec().clone(), _public_key: public_key, _secret_key }
    }
}

impl Keypair {
    pub fn sign(&self, message: impl AsRef<[u8]>) -> [u8; 64] {
        let mut signature:[u8; 64] = [0; 64];
        let arr: [u8; 64] = self._secret_key.clone().try_into().unwrap();
        crypto_sign_detached(&mut signature, message.as_ref(), &arr).expect("Error");
        signature
    }

    fn key_type(&self) -> &str {
        "ed25519"
    }
    pub fn secret_key(&self) -> &Vec<u8> {
        &self._secret_key
    }
}
