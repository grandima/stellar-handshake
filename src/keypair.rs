use data_encoding::BASE32;
use dryoc::classic::crypto_sign::crypto_sign_detached;
use dryoc::dryocbox::ByteArray;
use dryoc::sign::{SecretKey, SigningKeyPair};
use crate::xdr::constants::{ED25519_SECRET_KEY_BYTE_LENGTH, SEED_LENGTH};
use crate::xdr::types::{PublicKey, Uint256, Uint512};
#[derive(Debug, Clone)]
pub struct Keychain {
    public_key: PublicKey,
    signer_key: [u8; ED25519_SECRET_KEY_BYTE_LENGTH]
}

impl Keychain {

    pub fn sign(&self, message: impl AsRef<[u8]>) -> Uint512 {
        let mut signature = [0u8; ED25519_SECRET_KEY_BYTE_LENGTH];
        let secret_key = self.signer_key;
        crypto_sign_detached(&mut signature, message.as_ref(), &secret_key).unwrap();
        signature
    }
    pub fn public_key(&self) -> &Uint256 {
        self.public_key.as_binary()
    }
}


impl TryFrom<&str> for Keychain {
    //todo handle properly
    type Error = &'static str;
    fn try_from(key: &str) -> Result<Self, Self::Error> {
        let decoded = BASE32.decode(key.as_bytes()).unwrap();
        let _version_byte = decoded[0];
        let payload = &decoded[..decoded.len()-2];
        let data = &payload[1..];
        //todo handle properly
        if data.len() != SEED_LENGTH {
            return Err("wrong length")
        }
        let mut seed = [0u8; SEED_LENGTH];
        seed.copy_from_slice(data);
        Ok(Keychain::from(&seed))
    }
}

impl From<&[u8; SEED_LENGTH]> for Keychain {
    fn from(seed: &[u8; SEED_LENGTH]) -> Self {
        let public_key = &SigningKeyPair::<dryoc::sign::PublicKey, SecretKey>::from_seed(&seed.clone()).public_key;
        let mut secret_key = [0u8; ED25519_SECRET_KEY_BYTE_LENGTH];
        secret_key[..SEED_LENGTH].copy_from_slice(seed);
        secret_key[SEED_LENGTH..].copy_from_slice(public_key);
        Self {
            public_key: PublicKey::PublicKeyTypeEd25519(*public_key.as_array()),
            signer_key: secret_key
        }
    }
}

