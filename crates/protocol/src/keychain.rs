use data_encoding::BASE32;
use dryoc::classic::crypto_sign::{crypto_sign_detached, crypto_sign_seed_keypair};
use dryoc::dryocbox::ByteArray;

use utils::misc::generate_secret_key;

use xdr::types::{PublicKey, Uint256};
use crate::constants::{ED25519_SECRET_KEY_BYTE_LENGTH, SEED_LENGTH};

pub type Uint512 = [u8; 64];

#[derive(Debug, Clone)]
pub struct Keychain {
    persistent_public_key: PublicKey,
    signing_key: [u8; ED25519_SECRET_KEY_BYTE_LENGTH]
}

impl Keychain {
    pub fn from_random_seed() -> Self {
        let seed = generate_secret_key();
        Self::from(&seed)
    }
    pub fn sign(&self, message: impl AsRef<[u8]>) -> Uint512 {
        let mut signature = [0u8; ED25519_SECRET_KEY_BYTE_LENGTH];
        crypto_sign_detached(&mut signature, message.as_ref(), &self.signing_key).unwrap_or_default();
        signature
    }
    pub fn persistent_public_key(&self) -> &Uint256 {
        self.persistent_public_key.as_binary()
    }
}

impl TryFrom<&str> for Keychain {
    type Error = KeychainError;
    fn try_from(key: &str) -> Result<Self, Self::Error> {
        let decoded = BASE32.decode(key.as_bytes()).unwrap();
        let _version_byte = decoded[0];
        let payload = &decoded[..decoded.len()-2];
        let data = &payload[1..];
        if data.len() != SEED_LENGTH {
            return Err(KeychainError::WrongLength {
                expected: SEED_LENGTH as u32,
                actual: data.len() as u32
            });
        }
        let mut seed = [0u8; SEED_LENGTH];
        seed.copy_from_slice(data);
        Ok(Keychain::from(&seed))
    }
}

impl From<&[u8; SEED_LENGTH]> for Keychain {
    fn from(seed: &[u8; SEED_LENGTH]) -> Self {
        let public_key = crypto_sign_seed_keypair(seed).0;
        let mut signing_key = [0u8; ED25519_SECRET_KEY_BYTE_LENGTH];
        signing_key[..SEED_LENGTH].copy_from_slice(seed);
        signing_key[SEED_LENGTH..].copy_from_slice(&public_key);
        Self {
            persistent_public_key: PublicKey::PublicKeyTypeEd25519(*public_key.as_array()),
            signing_key
        }
    }
}


#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("Wrong seed: expected {expected}, found {actual}")]
    WrongLength {expected: u32, actual: u32},
}


