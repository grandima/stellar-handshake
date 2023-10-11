
use crate::protocol::connection_authentication::ConnectionAuthentication;
use crate::node_config::NodeConfig;
use crate::protocol::errors::{StellarError, VerificationError};
use crate::protocol::remote_node_info::RemoteNodeInfo;
use crate::protocol::errors::VerificationError::{MacKey, SequenceMismatch};
use crate::protocol::protocol::Protocol;
use crate::utils::misc::increase_buffer_by_one;

use crate::utils::sha2::{create_sha256_hmac, verify_sha256_hmac};

use crate::xdr::constants::SHA256_LENGTH;
use crate::xdr::messages::{Auth, AuthenticatedMessage, AuthenticatedMessageV0, Hello, StellarMessage};

use crate::xdr::types::{HmacSha256Mac, NodeId, Uint256, Uint64, XdrArchive};
use crate::xdr::xdr_codable::XdrCodable;

pub struct StellarProtocol<F: Fn() -> u64> {
    node_config: NodeConfig,
    authentication: ConnectionAuthentication,
    local_nonce: Uint256,
    /// We don't need to store them for handshake process, but if we want to send more and receive more messages, we need to store them
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
            local_sequence: [0u8; 8],
            remote_sequence: [0u8; 8],
            time_provider,
            receiving_mac_key: None,
        }
    }
    fn mac_for_authenticated_message(&self, message: &StellarMessage) -> HmacSha256Mac {
        if let Some(sending_mac_key) = &self.sending_mac_key {
            let data = [&self.local_sequence, message.encoded().as_slice()].concat();
            let mut mac = [0u8; SHA256_LENGTH];
            let sha_result = create_sha256_hmac(&data, sending_mac_key);
            mac.copy_from_slice(&sha_result);
            HmacSha256Mac { mac }
        } else {
            HmacSha256Mac { mac: [0u8; SHA256_LENGTH] }
        }
    }
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

impl <F: Fn() -> u64> Protocol for StellarProtocol<F> {
    type Message = XdrArchive<AuthenticatedMessage>;
    type MessageExtract = Result<HandshakeMessageExtract, StellarError>;
    type NodeInfo = RemoteNodeInfo;
    fn create_hello_message(&mut self) -> XdrArchive<AuthenticatedMessage> {
        let hello = Hello {
            ledger_version: self.node_config.node_info.ledger_version,
            overlay_version: self.node_config.node_info.overlay_version,
            overlay_min_version: self.node_config.node_info.overlay_min_version,
            network_id: self.authentication.network_id(),
            version_str: self.node_config.node_info.version_string.clone(),
            listening_port: self.node_config.listening_port,
            peer_id: NodeId::PublicKeyTypeEd25519(*self.authentication.keychain().persistent_public_key()),
            cert: self.authentication.auth_cert((self.time_provider)()).clone(),
            nonce: self.local_nonce,
        };
        XdrArchive(AuthenticatedMessage::V0(AuthenticatedMessageV0{message: StellarMessage::Hello(hello), mac: HmacSha256Mac::default(), sequence: self.local_sequence}))
    }
    fn create_auth_message(&mut self) -> XdrArchive<AuthenticatedMessage> {
        let message = StellarMessage::Auth(Auth{flags: 100});
        let mac = self.mac_for_authenticated_message(&message);
        let message = XdrArchive::new(AuthenticatedMessage::V0(AuthenticatedMessageV0{message, sequence: self.local_sequence, mac}));
        self.inc_loc_seq();
        message
    }
    fn handle_message(&mut self, result: (&XdrArchive<AuthenticatedMessage>, Vec<u8>)) -> Result<HandshakeMessageExtract,StellarError> {
        let AuthenticatedMessage::V0(message) = &result.0.0;
        if let StellarMessage::Hello(hello) = &message.message {
            self.authentication.verify_remote_cert((self.time_provider)(), hello.peer_id.as_binary(), &hello.cert)?;
            self.local_sequence = [0; 8];
            self.remote_sequence = [0; 8];
            let remote_node_info = RemoteNodeInfo::from(hello);
            self.sending_mac_key = Some(self.authentication.mac_key(
                &self.local_nonce,
                &remote_node_info.nonce,
                &remote_node_info.public_key.key,
                true,
            ));
            self.receiving_mac_key = Some(self.authentication.mac_key(
                &self.local_nonce,
                &remote_node_info.nonce,
                &remote_node_info.public_key.key,
                false,
            ));
            Ok(HandshakeMessageExtract::Hello)
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

pub enum HandshakeMessageExtract {
    Hello,
    Auth,
}
