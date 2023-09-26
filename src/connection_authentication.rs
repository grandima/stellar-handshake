use std::fmt::format;
use sha2::{Digest, Sha256};
use crate::keypair::*;
//use dryoc::rng::randombytes_buf;
use dryoc::classic::crypto_core::crypto_scalarmult_base;
use crate::xdr::auth_cert;
use crate::xdr::auth_cert::AuthCert;
use std::time::{SystemTime, UNIX_EPOCH};
use dryoc::rng::{copy_randombytes, randombytes_buf};
use rand::random;
use crate::xdr::constants::{ED25519_PUBLIC_KEY_BYTE_LENGTH, ED25519_SECRET_SEED_BYTE_LENGTH};
use crate::xdr::curve25519public::Curve25519Public;
use crate::xdr::streams::WriteStream;
use crate::xdr::types::{EnvelopeType, Signature};
use crate::xdr::xdr_codec::XdrCodec;

#[derive(Debug)]
pub struct ConnectionAuthentication {
    keypair: Keypair,
    pub network_id: [u8; 32],
    secret_key_ecdh: [u8; ED25519_SECRET_SEED_BYTE_LENGTH],
    public_key_ecdh: [u8; ED25519_PUBLIC_KEY_BYTE_LENGTH],
    auth_cert: Option<AuthCert>,
    auth_cert_expiration: u64
}



impl ConnectionAuthentication {
    const  AUTH_EXPIRATION_LIMIT: u64 = 360000; //60 minutes
    pub fn new(keypair: Keypair, network_id: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(network_id);
        let network_id = hasher.finalize().into();
        // let mut secret_key_ecdh = [0u8; ED25519_SECRET_SEED_BYTE_LENGTH];
        // copy_randombytes(&mut secret_key_ecdh);
        let mut secret_key_ecdh = [
            36, 15, 196, 238, 139, 200, 81, 214, 184, 101, 133, 6, 129, 121, 28, 202,
            234, 82, 26, 236, 242, 245, 46, 154, 170, 235, 109, 181, 228, 73, 129, 108
        ];
        let mut public_key_ecdh = [0u8; ED25519_PUBLIC_KEY_BYTE_LENGTH];
        crypto_scalarmult_base(&mut public_key_ecdh, &secret_key_ecdh);
        Self {keypair, network_id, public_key_ecdh, secret_key_ecdh, auth_cert: None, auth_cert_expiration: 0 }
    }
    pub fn get_auth_cert(&mut self, validAt: SystemTime) -> AuthCert {
        let duration_since_epoch = validAt
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let millis_since_epoch = duration_since_epoch.as_millis();
        let millis_as_u64: u64 = millis_since_epoch.try_into().unwrap_or_else(|e| {
            panic!("Failed to convert millis_since_epoch to u64: {}", e);
        });
        let next_expiration = millis_as_u64 + Self::AUTH_EXPIRATION_LIMIT / 2;

        let cert = match self.auth_cert.take() {
            Some(cert) => if self.auth_cert_expiration < next_expiration {
                    self.create_auth_cert(validAt)
                } else {
                    cert
                },
            None => self.create_auth_cert(validAt)
        };
        self.auth_cert = Some(cert.clone());
        cert
    }
    fn create_auth_cert(&mut self, validAt: SystemTime) -> AuthCert {
        let timestamp_with_expiration: u64 = validAt
            .duration_since(UNIX_EPOCH)
            .map(|x|x.as_millis())
            .unwrap()
            .try_into()
            .unwrap();
        self.create_auth_cert_from_milisec(timestamp_with_expiration)
    }

     fn create_auth_cert_from_milisec(&mut self, milisec: u64) -> AuthCert {
         self.auth_cert_expiration = milisec + Self::AUTH_EXPIRATION_LIMIT;
        // self.auth_cert_expiration = 1695728543325 + Self::AUTH_EXPIRATION_LIMIT;
        let bytes_expiration = self.auth_cert_expiration.to_be_bytes();
        let mut writer = WriteStream::new();
        let xdr_envelope_type = EnvelopeType::Auth.to_xdr_buffered(&mut writer);
        let xdr_envelope_type_result = writer.get_result();
        let mut signature_data = self.network_id.clone().to_vec();
        signature_data.extend(xdr_envelope_type_result.iter());
        signature_data.extend(bytes_expiration.iter());
        signature_data.extend(self.public_key_ecdh.iter());
        let mut hasher = Sha256::new();
        hasher.update(signature_data);
        let hashed_signature_data = hasher.finalize().to_vec();
        let signed = self.keypair.sign(hashed_signature_data);
        let sig = Signature::new(signed.to_vec()).unwrap();
        AuthCert{
            pubkey: Curve25519Public {key: self.public_key_ecdh},
            expiration: self.auth_cert_expiration,
            sig
        }
    }
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}
