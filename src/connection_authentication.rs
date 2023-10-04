use std::collections::HashMap;

use crate::keypair::*;
//use dryoc::rng::randombytes_buf;
use dryoc::classic::crypto_core::crypto_scalarmult_base;
use crate::xdr::auth_cert::{AuthCert, Curve25519Public};
use std::time::{SystemTime, UNIX_EPOCH};
use dryoc::classic::crypto_sign::crypto_sign_verify_detached;
use thiserror::Error;


use crate::utils::sha2::{create_sha256, create_sha256_hmac};
use crate::xdr::constants::{PUBLIC_KEY_LENGTH, SEED_LENGTH, SHA256_LENGTH};
use crate::xdr::streams::WriteStream;
use crate::xdr::types::{EnvelopeType, Signature, Uint256};
use crate::xdr::xdr_codable::XdrCodable;


//TODO remove
pub enum MacKeyType {
    Sending
}

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Cert expired")]
    VerificationCertExpired,
    #[error("Signature not verified")]
    VerificationSignature
}

#[derive(Debug)]
pub struct ConnectionAuthentication {
    //TODO REMOVE
    called_remote_keys: HashMap<Uint256, Vec<u8>>,
    keychain: Keychain,
    network_id: Uint256,
    pub secret_key_ecdh: [u8; SEED_LENGTH],
    pub public_key_ecdh: Curve25519Public,
    auth_cert: Option<AuthCert>,
    auth_cert_expiration: u64,
}

impl ConnectionAuthentication {
    const  AUTH_EXPIRATION_LIMIT: u64 = 360000; //60 minutes
    pub fn new(keypair: Keychain, network_id: impl AsRef<[u8]>, secret_key_ecdh: [u8; SEED_LENGTH]) -> Self {
        let hashed_network_id = create_sha256(network_id.as_ref());
        let mut public_key_ecdh = [0u8; PUBLIC_KEY_LENGTH];
        crypto_scalarmult_base(&mut public_key_ecdh, &secret_key_ecdh);
        Self {
            called_remote_keys: Default::default(),
            keychain: keypair,
            network_id: hashed_network_id,
            public_key_ecdh: Curve25519Public{key: public_key_ecdh},
            secret_key_ecdh,
            auth_cert: None,
            auth_cert_expiration: 0
        }
    }
    pub fn verify_remote_cert(&self,
                              time: u64,
                              remote_public_key: &Uint256,
                              cert: &AuthCert
    ) -> Result<(),AuthenticationError> {
        let expiration = cert.expiration;
        if expiration < (time / 1000) {
            return Err(AuthenticationError::VerificationCertExpired)
        }
        let mut writer = WriteStream::default();
        EnvelopeType::Auth.encode(&mut writer);
        cert.expiration.encode(&mut writer);
        let envelope = writer.result();
        let mut raw_sig_data = self.network_id.to_vec();
        raw_sig_data.extend(envelope.iter());
        raw_sig_data.extend_from_slice(&cert.pubkey.key);
        let hashed = create_sha256(&raw_sig_data);

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&cert.sig);
        if crypto_sign_verify_detached(&sig, remote_public_key, &hashed).is_err() {
            Ok(())
        } else {
            Err(AuthenticationError::VerificationSignature)
        }
    }

    pub fn mac_key(&mut self,
                          mac_key_type: MacKeyType,
                          local_nonce: &Uint256,
                          remote_nonce: &Uint256,
                          remote_public_key_ecdh: &Uint256
    ) -> Vec<u8> {
        let mut buff = vec![];
        match mac_key_type {
            MacKeyType::Sending => {
                buff.push(0);
                buff.extend_from_slice(local_nonce.as_ref());
                buff.extend_from_slice(remote_nonce.as_ref());
                buff.push(1);
            }
        };
        let shared_key = self.shared_key(remote_public_key_ecdh);
        create_sha256_hmac(&buff, &shared_key)
    }
    fn shared_key(&mut self, remote_public_key_ecdh: &Uint256) -> Vec<u8> {
        if let Some(shared_key) = self.called_remote_keys.get(remote_public_key_ecdh.as_ref()) {
            return shared_key.clone();
        }
        let mut buf = [0u8; dryoc::constants::CRYPTO_SCALARMULT_BYTES];
        dryoc::classic::crypto_core::crypto_scalarmult(&mut buf, &self.secret_key_ecdh, remote_public_key_ecdh);
        let mut message_to_sign = [0u8; 96];
        message_to_sign[..32].copy_from_slice(&buf);
        message_to_sign[32..64].copy_from_slice(&self.public_key_ecdh.key);
        message_to_sign[64..].copy_from_slice(remote_public_key_ecdh);
        let zero_salt = [0u8; SHA256_LENGTH];
        let result_buf = create_sha256_hmac(&message_to_sign, &zero_salt);
        self.called_remote_keys.insert(*remote_public_key_ecdh, result_buf.clone());
        result_buf
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
    fn create_auth_cert_from_milisec(&mut self, milisec: u64) -> AuthCert {
        self.auth_cert_expiration = milisec + Self::AUTH_EXPIRATION_LIMIT;
        let bytes_expiration = self.auth_cert_expiration.to_be_bytes();
        let xdr_envelope_type_result = EnvelopeType::Auth.encoded();
        let mut signature_data = self.network_id.clone().to_vec();
        signature_data.extend(xdr_envelope_type_result.iter());
        signature_data.extend(bytes_expiration.iter());
        signature_data.extend(self.public_key_ecdh.key.iter());
        let hashed_signature_data = create_sha256(&signature_data);
        let signed = self.keychain.sign(hashed_signature_data);
        let sig = Signature::new(signed.to_vec());
        AuthCert {
            pubkey: self.public_key_ecdh.clone(),
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
