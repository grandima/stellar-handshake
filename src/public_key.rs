use crate::xdr::constants::{PUBLIC_KEY_LENGTH};
use crate::xdr::types::PublicKey;
impl PublicKey {
    pub fn as_binary(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        match self {
            PublicKey::PublicKeyTypeEd25519(key) => key,
        }
    }
}
