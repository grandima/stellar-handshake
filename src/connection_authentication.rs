use sha2::{Digest, Sha256};
use crate::keypair::*;
use dryoc::rng::randombytes_buf;
use dryoc::classic::crypto_core::crypto_scalarmult_base;
#[derive(Debug)]
pub struct ConnectionAuthentication {
    keypair: Keypair,
    network_id: Vec<u8>,
    secret_key_ecdh: [u8; ED25519_SECRET_SEED_BYTE_LENGTH],
    public_key_ecdh: [u8; ED25519_PUBLIC_KEY_BYTE_LENGTH],
}

impl ConnectionAuthentication {
    pub fn new(keypair: Keypair, network_id: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(network_id);
        let network_id = hasher.finalize().to_vec();

        // let secret_key_ecdh: [u8; ED25519_SECRET_SEED_BYTE_LENGTH] = randombytes_buf(ED25519_SECRET_SEED_BYTE_LENGTH).into();
        let secret_key_ecdh: [u8; ED25519_SECRET_SEED_BYTE_LENGTH] = [
            36, 15, 196, 238, 139, 200, 81, 214, 184, 101, 133, 6, 129, 121, 28, 202,
            234, 82, 26, 236, 242, 245, 46, 154, 170, 235, 109, 181, 228, 73, 129, 108
        ];
        let mut public_key_ecdh: [u8; ED25519_PUBLIC_KEY_BYTE_LENGTH] = [0; ED25519_PUBLIC_KEY_BYTE_LENGTH];
        crypto_scalarmult_base(&mut public_key_ecdh, &secret_key_ecdh);
        Self {keypair, network_id, public_key_ecdh, secret_key_ecdh }

    }
}
