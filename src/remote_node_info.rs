




use crate::xdr::messages::Hello;
use crate::xdr::types::Uint256;

#[derive(Clone)]
pub struct RemoteNodeInfo {
    pub remote_nonce: Uint256,
    pub remote_public_key_ecdh: Uint256,
}

impl From<&Hello> for RemoteNodeInfo {
    fn from(hello: &Hello) -> Self {
        let remote_nonce = hello.nonce;
        let remote_public_key_ecdh = hello.cert.pubkey.key;
        Self {
            remote_nonce,
            remote_public_key_ecdh,
        }
    }
}
