use std::fmt::Debug;
use std::io;

use thiserror::*;

use crate::protocol::connection_authentication::{ConnectionAuthentication, AuthenticationError};
use crate::node_config::{NodeConfig};
use crate::protocol::remote_node_info::RemoteNodeInfo;
use crate::protocol::stellar_protocol;
use crate::protocol::stellar_protocol::VerificationError::{MacKey, SequenceMismatch};
use crate::utils::misc::increase_buffer_by_one;

use crate::utils::sha2::{create_sha256_hmac, verify_sha256_hmac};

use crate::xdr::constants::SHA256_LENGTH;
use crate::xdr::messages::{Auth, AuthenticatedMessage, AuthenticatedMessageV0, Hello, StellarMessage};
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::{XdrArchive, HmacSha256Mac, Uint256, Uint64, NodeId};
use crate::xdr::xdr_codable::XdrCodable;

pub trait Protocol: Sized {
    type Message: ProtocolMessage;
    type MessageExtract;
    type NodeInfo: Sized;
    fn create_hello_message(&mut self) -> Self::Message;
    fn create_auth_message(&mut self, remote_node_info: Self::NodeInfo) -> Self::Message;
    fn handle_message(&mut self, message: (&Self::Message, Vec<u8>)) -> Result<HandshakeMessageExtract<Self>, StellarError>;
}
pub trait ProtocolMessage: XdrCodable + Sized {
    fn has_complete_message(buf: &[u8]) -> Result<bool, StellarError>;
}

impl <T: XdrCodable> ProtocolMessage for XdrArchive<T> {
    fn has_complete_message(buf: &[u8]) -> std::result::Result<bool, stellar_protocol::StellarError> {
        if buf.len() < 4 {
            return Ok(false);
        }
        let length = ReadStream::new(buf).read_length(true)? ;
        Ok(length + 4 <= buf.len())
    }
}
pub struct StellarProtocol<F: Fn() -> u64> {
    node_config: NodeConfig,
    authentication: ConnectionAuthentication,
    remote_node_info: Option<RemoteNodeInfo>,
    local_nonce: Uint256,
    local_sequence: Uint64,
    remote_sequence: Uint64,
    sending_mac_key: Option<Vec<u8>>,
    receiving_mac_key: Option<Vec<u8>>,
    time_provider: F
}

impl <F: Fn() -> u64> StellarProtocol<F> {
    pub fn new(node_config: NodeConfig, local_nonce: Uint256, authentication: ConnectionAuthentication, time_provider: F) -> Self {
        Self {
            node_config,
            authentication,
            local_nonce,
            sending_mac_key: None,
            remote_node_info: None,
            local_sequence: [0u8; 8],
            remote_sequence: [0u8; 8],
            time_provider,
            receiving_mac_key: None,
        }
    }
    fn mac_for_authenticated_message(&self, message: &StellarMessage) -> HmacSha256Mac {
        if self.remote_node_info.as_ref().map(|node|node.remote_public_key_ecdh.key).is_none() {
            HmacSha256Mac{mac: [0u8; SHA256_LENGTH]}
        } else if let Some(sending_mac_key) = &self.sending_mac_key {
            let mut writer = WriteStream::default();
            message.encode(&mut writer);
            let mut data =  self.local_sequence.to_vec();
            data.extend_from_slice(&writer.result());
            let mut mac = [0u8; SHA256_LENGTH];
            let sha_result = create_sha256_hmac(&data, sending_mac_key);
            mac.copy_from_slice(&sha_result);
            HmacSha256Mac { mac }
        } else {
            HmacSha256Mac { mac: [0u8; SHA256_LENGTH] }
        }
    }

}

impl <F: Fn() -> u64> Protocol for StellarProtocol<F> {
    type Message = XdrArchive<AuthenticatedMessage>;
    type MessageExtract = Result<HandshakeMessageExtract<Self>, StellarError>;
    type NodeInfo = RemoteNodeInfo;
    fn create_hello_message(&mut self) -> XdrArchive<AuthenticatedMessage> {
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
        XdrArchive(AuthenticatedMessage::V0(AuthenticatedMessageV0{message: StellarMessage::Hello(hello), mac: HmacSha256Mac::default(), sequence: [0u8; 8]}))
    }
    fn create_auth_message(&mut self, remote_node_info: RemoteNodeInfo) -> XdrArchive<AuthenticatedMessage> {
        self.sending_mac_key = Some(self.authentication.mac_key(
            &self.local_nonce,
            &remote_node_info.remote_nonce,
            &remote_node_info.remote_public_key_ecdh.key,
            true,
        ));
        self.receiving_mac_key = Some(self.authentication.mac_key(
            &self.local_nonce,
            &remote_node_info.remote_nonce,
            &remote_node_info.remote_public_key_ecdh.key,
            false,
        ));
        self.remote_node_info = Some(remote_node_info);
        let message = StellarMessage::Auth(Auth{flags: 100});
        let mac = self.mac_for_authenticated_message(&message);
        let message = XdrArchive::new(AuthenticatedMessage::V0(AuthenticatedMessageV0{message, sequence: self.local_sequence, mac}));
        self.inc_loc_seq();
        message
    }
    fn handle_message(&mut self, result: (&XdrArchive<AuthenticatedMessage>, Vec<u8>)) -> Result<HandshakeMessageExtract<Self>,StellarError> {
        let AuthenticatedMessage::V0(message) = &result.0.0;
        if let StellarMessage::Hello(hello) = &message.message {
            self.authentication.verify_remote_cert((self.time_provider)(), hello.peer_id.as_binary(), &hello.cert)?;
            Ok(HandshakeMessageExtract::Hello(RemoteNodeInfo::from(hello)))
        } else {
            self.verify_v0_message(message, &result.1[8..&result.1.len() - 32])?;
            self.inc_rem_seq();
            match &message.message {
                StellarMessage::Auth(_) => {Ok(HandshakeMessageExtract::Auth)},
                _ => {unreachable!()}
            }
        }
    }
}

impl<F: Fn() -> u64> StellarProtocol<F> {
    fn inc_loc_seq(&mut self) {
        increase_buffer_by_one(&mut self.local_sequence);
    }
    fn inc_rem_seq(&mut self) {
        increase_buffer_by_one(&mut self.remote_sequence);
    }
    fn verify_v0_message(&self, message: &AuthenticatedMessageV0, body: &[u8]) -> Result<(), VerificationError> {
        if message.sequence != self.remote_sequence {
            Err(SequenceMismatch)
        } else if self.receiving_mac_key.as_ref().map_or(false, |key| verify_sha256_hmac(&message.mac.mac, key, body)) {
            Ok(())
        } else {
            Err(MacKey)
        }
    }
}
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Local and remote sequences do not match")]
    SequenceMismatch,
    #[error("Mac key verification failed")]
    MacKey,
}
#[derive(Debug, Error)]
#[error("Stellar error")]
pub enum StellarError {
    AuthenticationError(#[from] AuthenticationError),
    DecodeError(#[from] DecodeError),
    #[error("IO error: {0}")]
    IOError(#[from] io::Error),
    ConnectionResetByPeer,
    ExpectedMoreMessages,
    Verification(#[from] VerificationError),
}
pub enum HandshakeMessageExtract<P: Protocol> {
    Hello(P::NodeInfo),
    Auth,
}
