use std::collections::HashMap;
use rand::random;
use crate::connection_authentication::ConnectionAuthentication;
use crate::remote_node_info::RemoteNodeInfo;
use crate::utils::sha2::sha256_hash;
use crate::xdr::stellar_messages::Hello;
use crate::xdr::types::Uint256;

//TODO: do i need this?
const SHA_LENGTH: u32 = 32;

pub struct Connection {
    pub authentication: ConnectionAuthentication,
    pub remote_node: Option<RemoteNodeInfo>,
    pub local_nonce: Uint256
}
impl Connection {
    pub fn new(authentication: ConnectionAuthentication) -> Self {
        Self { authentication, local_nonce: generate_nonce(), remote_node: None}
    }

    pub fn process(&mut self, hello: Hello) {
        self.remote_node = Some(RemoteNodeInfo::from(hello));
    }

    fn sending_mac_key(&mut self, local_nonce: Uint256, remote_nonce: Uint256, remote_public_key_ecdh: Uint256) {

    }

}

pub fn generate_nonce() -> Uint256 {
    let nonce = random::<u32>().to_be_bytes();
    //TODO: remove
    // let nonce = [
    //     48u8, 46, 53, 55, 55, 49, 53, 55, 48, 53, 51, 48, 53, 51, 55, 48, 50, 54, 48, 55, 50, 56
    // ];
    let mut local_nonce = [0u8; 32];
    local_nonce.copy_from_slice(&sha256_hash(&nonce));
    local_nonce
}

