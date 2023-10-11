use crate::xdr::auth_cert::Curve25519Public;
use crate::xdr::messages::Hello;
use crate::xdr::types::Uint256;

#[derive(Clone)]
pub struct RemoteNodeInfo {
    pub nonce: Uint256,
    pub public_key: Curve25519Public,
}

impl From<&Hello> for RemoteNodeInfo {
    fn from(hello: &Hello) -> Self {
        let remote_nonce = hello.nonce;
        let remote_public_key = hello.cert.persistent_public_key.key;
        Self {
            nonce: remote_nonce,
            public_key: Curve25519Public{key: remote_public_key }
        }
    }
}
