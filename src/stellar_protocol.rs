
use std::time::SystemTime;
use thiserror::*;

use crate::connection_authentication::{ConnectionAuthentication, MacKeyType, AuthenticationError};
use crate::node_config::{NodeConfig, NodeInfo};
use crate::remote_node_info::RemoteNodeInfo;
use crate::utils::misc::{generate_nonce};
use crate::utils::sha2::{create_sha256_hmac};

use crate::xdr::constants::SHA256_LENGTH;
use crate::xdr::messages::{Auth, AuthenticatedMessage, AuthenticatedMessageV0, Hello, StellarMessage};
use crate::xdr::streams::{ReadStream, WriteStream};
use crate::xdr::types::{XdrSelfCoded, HmacSha256Mac, Uint256, Uint64, NodeId};
use crate::xdr::xdr_codable::XdrCodable;


pub struct StellarProtocol<F: Fn() -> u64> {
    pub node_config: NodeConfig,
    pub authentication: ConnectionAuthentication,
    pub remote_node_info: Option<RemoteNodeInfo>,
    pub local_nonce: Uint256,
    pub local_sequence: Uint64,
    pub sending_mac_key: Option<Vec<u8>>,
    pub time_provider: F
}

#[derive(Debug, Error)]
#[error("Stellar error")]
pub enum StellarError {
    AuthenticationError(#[from] AuthenticationError)
}
pub enum HandshakeMessageExtract {
    Hello(Result<RemoteNodeInfo, StellarError>),
    Auth
}

impl <F: Fn() -> u64> StellarProtocol<F> {
    pub fn new(node_config: NodeConfig, generate_nonce: impl Fn() -> Uint256, authentication: ConnectionAuthentication, time_provider: F) -> Self {
        Self {
            node_config,
            authentication,
            local_nonce: generate_nonce(),
            sending_mac_key: None,
            remote_node_info: None,
            local_sequence: [0u8; 8],
            time_provider
        }
    }

    pub fn handle_message(&self, message: &XdrSelfCoded<AuthenticatedMessage>) -> HandshakeMessageExtract {
        match match &message.0 {
            AuthenticatedMessage::V0(authenticated_message) => &authenticated_message.message
        } {
            StellarMessage::Hello(hello) =>
                match self.authentication.verify_remote_cert((self.time_provider)(), hello.peer_id.as_binary(), &hello.cert) {
                    Ok(_) => HandshakeMessageExtract::Hello(Ok(RemoteNodeInfo::from(hello))),
                    Err(error) => HandshakeMessageExtract::Hello(Err(error.into())),
                },
            StellarMessage::Auth(_) => {HandshakeMessageExtract::Auth}
        }
    }
    pub fn create_hello_message(&mut self) -> XdrSelfCoded<AuthenticatedMessage> {
        let hello = Hello {
            ledger_version: self.node_config.node_info.ledger_version,
            overlay_version: self.node_config.node_info.overlay_version,
            overlay_min_version: self.node_config.node_info.overlay_min_version,
            network_id: self.authentication.network_id(),
            version_str: self.node_config.node_info.version_string.clone(),
            listening_port: self.node_config.listening_port,
            peer_id: NodeId::PublicKeyTypeEd25519(*self.authentication.keychain().public_key()),
            cert: self.authentication.auth_cert((self.time_provider)()).clone(),
            nonce: self.local_nonce,
        };
        XdrSelfCoded(AuthenticatedMessage::V0(AuthenticatedMessageV0{message: StellarMessage::Hello(hello), mac: HmacSha256Mac::default(), sequence: [0u8; 8]}))
    }
    pub fn create_auth_message(&mut self, remote_node_info: RemoteNodeInfo) -> XdrSelfCoded<AuthenticatedMessage> {
        self.sending_mac_key = Some(self.authentication.mac_key(
            MacKeyType::Sending,
            &self.local_nonce,
            &remote_node_info.remote_nonce,
            &remote_node_info.remote_public_key_ecdh
        ));
        self.remote_node_info = Some(remote_node_info);
        let message = StellarMessage::Auth(Auth{flags: 100});
        let mac = self.mac_for_authenticated_message(&message);
        XdrSelfCoded::new(AuthenticatedMessage::V0(AuthenticatedMessageV0{message, sequence: self.local_sequence, mac}))
    }

    fn mac_for_authenticated_message(&self, message: &StellarMessage) -> HmacSha256Mac {
        if self.remote_node_info.as_ref().map(|node|node.remote_public_key_ecdh).is_none() {
            HmacSha256Mac{mac: [0u8; SHA256_LENGTH]}
        } else if let Some(sending_mac_key) = &self.sending_mac_key {
            let mut writer = WriteStream::default();
            message.encode(&mut writer);
            let mut data =  self.local_sequence.to_vec();
            data.extend_from_slice(&writer.result());
            let mut mac = [0u8; SHA256_LENGTH];
            let sha_result = create_sha256_hmac(&data, sending_mac_key);
            mac.copy_from_slice(&sha_result);
            HmacSha256Mac{ mac }
        } else {
            HmacSha256Mac { mac: [0u8; SHA256_LENGTH] }
        }
    }
}

