use std::collections::HashMap;
use rand::random;
use crate::connection_authentication::{ConnectionAuthentication, MacKeyType};
use crate::remote_node_info::RemoteNodeInfo;
use crate::utils::misc::{generate_nonce, increase_buffer_by_one};
use crate::utils::sha2::{create_sha256_hmac};
use crate::xdr::constants::SHA256_LENGTH;
use crate::xdr::stellar_messages::{Auth, Hello};
use crate::xdr::streams::WriteStream;
use crate::xdr::types::{ArchivedMessage, AuthenticatedMessage, AuthenticatedMessageV0, HmacSha256Mac, StellarMessage, Uint256, Uint64};
use crate::xdr::xdr_codec::XdrCodec;

//TODO: do i need this?
const SHA_LENGTH: u32 = 32;

pub struct Connection {
    pub authentication: ConnectionAuthentication,
    pub remote_node: Option<RemoteNodeInfo>,
    pub local_nonce: Uint256,
    pub local_sequence: Uint64,
    pub sending_mac_key: Option<Vec<u8>>,
    pub receiving_mac_key: Option<Vec<u8>>,
}
impl Connection {
    pub fn new(authentication: ConnectionAuthentication) -> Self {
        Self {
            authentication,
            local_nonce: generate_nonce(),
            sending_mac_key: None,
            remote_node: None,
            receiving_mac_key: None,
            local_sequence: [0u8; 8]
        }
    }

    pub fn auth_message(&mut self) -> ArchivedMessage<AuthenticatedMessage> {
        let message = StellarMessage::Auth(Auth{flags: 100});
        let mac = self.mac_for_authenticated_message(&message);
        let messageV0 = ArchivedMessage::new(AuthenticatedMessage::V0(AuthenticatedMessageV0{message: message.clone(), sequence: self.local_sequence, mac}));
        increase_buffer_by_one(&mut self.local_sequence);
        messageV0
    }

    fn mac_for_authenticated_message(&self, message: &StellarMessage) -> HmacSha256Mac {
        if self.remote_node.as_ref().map(|node|node.remote_public_key_ecdh).is_none() {
            HmacSha256Mac{mac: [0u8; SHA256_LENGTH]}
        } else if let Some(sending_mac_key) = &self.sending_mac_key {
            let mut writer = WriteStream::new();
            message.to_xdr_buffered(&mut writer);
            let mut data =  self.local_sequence.to_vec();
            data.extend_from_slice(&writer.get_result());
            let mut mac = [0u8; SHA256_LENGTH];
            let sha_result = create_sha256_hmac(&data, sending_mac_key);
            mac.copy_from_slice(&sha_result);
            HmacSha256Mac{mac}

        } else {
            HmacSha256Mac { mac: [0u8; SHA256_LENGTH] }
        }
    }

    pub fn process_hello(&mut self, hello: Hello) {
        let node_info = RemoteNodeInfo::from(hello);
        self.sending_mac_key = Some(self.authentication.mac_key(
            MacKeyType::Sending,
            &self.local_nonce,
            &node_info.remote_nonce,
            &node_info.remote_public_key_ecdh
        ));
        self.receiving_mac_key = Some(self.authentication.mac_key(
            MacKeyType::Receiving,
            &self.local_nonce,
            &node_info.remote_nonce,
            &node_info.remote_public_key_ecdh
        ));
        self.remote_node = Some(node_info.clone());
    }
    fn increase_local_sequence(&mut self) {
        increase_buffer_by_one(&mut self.local_sequence);
    }
}

