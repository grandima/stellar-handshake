use base64::Engine;

use crate::node_config::NodeInfo;
use crate::public_key::encode_stellar_key;
use crate::xdr::constants::PUBLIC_KEY_VERSION_BYTE;
use crate::xdr::messages::Hello;
use crate::xdr::types::Uint256;

#[derive(Clone)]
pub struct RemoteNodeInfo {
    pub remote_nonce: Uint256,
    pub remote_public_key_ecdh: Uint256,
    pub remote_pubkey: Vec<u8>,
    pub remote_pubkey_raw: Uint256,
    pub node_info: NodeInfo
}

impl From<Hello> for RemoteNodeInfo {
    fn from(hello: Hello) -> Self {
        let remote_nonce = hello.nonce;
        let remote_public_key_ecdh = hello.cert.pubkey.key;
        let remote_pubkey = hello.peer_id.to_encoding();
        let remote_pubkey_raw = hello.peer_id.as_binary().clone();

        let node_info = NodeInfo {
            network_id: Some(base64::prelude::BASE64_STANDARD.encode(hello.peer_id.as_binary())),
            overlay_min_version: hello.overlay_min_version,
            overlay_version: hello.overlay_version,
            ledger_version: hello.ledger_version,
            version_string: hello.version_str
        };
        Self {
            remote_nonce,
            remote_public_key_ecdh,
            remote_pubkey,
            remote_pubkey_raw,
            node_info,
        }
    }
}
