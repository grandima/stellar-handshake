use base64::Engine;

use crate::node_config::NodeInfo;


use crate::xdr::messages::Hello;
use crate::xdr::types::Uint256;

#[derive(Clone)]
pub struct RemoteNodeInfo {
    pub remote_nonce: Uint256,
    pub remote_public_key_ecdh: Uint256,
    pub node_info: NodeInfo
}

impl From<Hello> for RemoteNodeInfo {
    fn from(hello: Hello) -> Self {
        let remote_nonce = hello.nonce;
        let remote_public_key_ecdh = hello.cert.pubkey.key;

        let node_info = NodeInfo {
            network_id: base64::prelude::BASE64_STANDARD.encode(hello.peer_id.as_binary()),
            overlay_min_version: hello.overlay_min_version,
            overlay_version: hello.overlay_version,
            ledger_version: hello.ledger_version,
            version_string: hello.version_str
        };
        Self {
            remote_nonce,
            remote_public_key_ecdh,
            node_info,
        }
    }
}
