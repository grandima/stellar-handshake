use std::collections::HashMap;


use super::keychain::Keychain;
use dryoc::classic::crypto_core::crypto_scalarmult_base;
use xdr::types::*;
use dryoc::classic::crypto_sign::crypto_sign_verify_detached;
use thiserror::Error;
use xdr::XdrCodec;
use utils::sha2::{create_sha256, create_sha256_hmac};
use crate::constants::{PUBLIC_KEY_LENGTH, SEED_LENGTH, SHA256_LENGTH};


#[derive(Debug)]
pub struct ConnectionAuthentication {
    keychain: Keychain,
    network_id: xdr::types::Uint256,
    per_connection_seckey: Curve25519Secret,
    per_connection_pubkey: xdr::types::Curve25519Public,
    /// We don't need to store them for handshake process, but if we want to send more and receive more messages, we need to store them.
    we_called_remote_keys: HashMap<Uint256, Vec<u8>>,
    us_called_remote_keys: HashMap<Uint256, Vec<u8>>,
    auth_cert: Option<AuthCert>,
    auth_cert_expiration: u64,
}

impl ConnectionAuthentication {
    // value taken from original code
    const  AUTH_EXPIRATION_LIMIT: u64 = 3600000;
    pub fn new(keypair: Keychain, network_id: impl AsRef<[u8]>, per_connection_secret_key: [u8; SEED_LENGTH]) -> Self {
        let hashed_network_id = create_sha256(network_id.as_ref());
        let mut public_key_ecdh = [0u8; PUBLIC_KEY_LENGTH];
        crypto_scalarmult_base(&mut public_key_ecdh, &per_connection_secret_key);
        Self {
            we_called_remote_keys: Default::default(),
            us_called_remote_keys: Default::default(),
            keychain: keypair,
            network_id: hashed_network_id,
            per_connection_pubkey: Curve25519Public{key: public_key_ecdh},
            per_connection_seckey: Curve25519Secret{key: per_connection_secret_key },
            auth_cert: None,
            auth_cert_expiration: 0
        }
    }
    pub fn auth_cert(&mut self, milisec: u64) -> &AuthCert {
        let cert = match self.auth_cert.take() {
            Some(cert) if self.auth_cert_expiration >= milisec => cert,
            _ => {
                self.create_auth_cert_from_milisec(milisec)
            },
        };
        self.auth_cert = Some(cert);
        self.auth_cert.as_ref().unwrap()
    }
    pub fn verify_cert(&self,
                       time: u64,
                       remote_public_key: &Uint256,
                       cert: &AuthCert
    ) -> Result<(),AuthenticationError> {
        let expiration = cert.expiration;
        if expiration < (time / 1000) {
            return Err(AuthenticationError::VerificationCertExpired)
        }
        let _signature_data = self.network_id.to_vec();
        let signature_data = [self.network_id.as_slice(), EnvelopeType::EnvelopeTypeAuth.encoded().as_slice(), &cert.expiration.to_be_bytes(), &cert.pubkey.key].concat();
        let hashed = create_sha256(&signature_data);

        let mut sig = [0u8; 64];
        sig.copy_from_slice(cert.sig.get_vec());
        crypto_sign_verify_detached(&sig, &hashed, remote_public_key).map_err(|_| AuthenticationError::VerificationSignature)
    }
    /// `we_called_remote` parameter can be replaced with enum for a better readability and data-driven approach
    pub fn mac_key(&mut self,
                          local_nonce: &Uint256,
                          remote_nonce: &Uint256,
                          remote_public_key_ecdh: &Uint256,
        we_called_remote: bool
    ) -> Vec<u8> {
        let message = if we_called_remote {
            [&[0], local_nonce.as_ref(), remote_nonce.as_ref(), &[1]].concat()
        } else {
            [&[1], remote_nonce.as_ref(), local_nonce.as_ref(), &[1]].concat()
        };
        let shared_key = self.shared_key(remote_public_key_ecdh, we_called_remote);
        create_sha256_hmac(&message, &shared_key)
    }
    fn shared_key(&mut self, remote_public_key: &Uint256, we_called_remote: bool) -> Vec<u8> {
        let keys_storage = if we_called_remote {&mut self.we_called_remote_keys} else {&mut self.us_called_remote_keys};
        if let Some(shared_key) = keys_storage.get(remote_public_key.as_ref()) {
            return shared_key.clone();
        }
        let mut shared_secret_key = [0u8; dryoc::constants::CRYPTO_SCALARMULT_BYTES];
        dryoc::classic::crypto_core::crypto_scalarmult(&mut shared_secret_key, &self.per_connection_seckey.key, remote_public_key);
        let message_to_sign = [&shared_secret_key, &self.per_connection_pubkey.key, remote_public_key.as_ref()].concat();
        let zero_salt = [0u8; SHA256_LENGTH];
        let hmac = create_sha256_hmac(&message_to_sign, &zero_salt);
        keys_storage.insert(*remote_public_key, hmac.clone());
        hmac
    }
    fn create_auth_cert_from_milisec(&mut self, milisec: u64) -> AuthCert {
        self.auth_cert_expiration = milisec + Self::AUTH_EXPIRATION_LIMIT;
        let bytes_expiration = self.auth_cert_expiration.to_be_bytes();
        let signature_data = [self.network_id.as_slice(), EnvelopeType::EnvelopeTypeAuth.encoded().as_slice(), &bytes_expiration, &self.per_connection_pubkey.key].concat();
        let hashed_signature_data = create_sha256(&signature_data);
        let signed = self.keychain.sign(hashed_signature_data);
        let sig = Signature::new(signed.to_vec()).unwrap();
        AuthCert {
            pubkey: self.per_connection_pubkey.clone(),
            expiration: self.auth_cert_expiration,
            sig
        }
    }
    pub fn keychain(&self) -> &Keychain {
        &self.keychain
    }
    pub fn network_id(&self) -> Uint256 {
        self.network_id
    }
}



#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Cert expired")]
    VerificationCertExpired,
    #[error("Signature not verified")]
    VerificationSignature
}

