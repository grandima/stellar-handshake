use xdr::types::*;


#[derive(Clone)]
pub struct RemoteNodeInfo {
    pub nonce: Uint256,
    pub public_key: Curve25519Public,
}

impl From<&Hello> for RemoteNodeInfo {
    fn from(hello: &Hello) -> Self {
        let remote_nonce = hello.nonce;
        let remote_public_key = hello.cert.pubkey.key;
        Self {
            nonce: remote_nonce,
            public_key: Curve25519Public{key: remote_public_key }
        }
    }
}
