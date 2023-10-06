
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::{Signature, Uint256};
use crate::xdr::xdr_codable::XdrCodable;
#[derive(Debug, Clone)]
pub struct AuthCert {
    pub pubkey: Curve25519Public,
    pub expiration: u64,
    pub sig: Signature,
}

impl XdrCodable for AuthCert {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.pubkey.encode(write_stream);
        self.expiration.encode(write_stream);
        self.sig.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(AuthCert {
            pubkey: Curve25519Public::decode(read_stream)?,
            expiration: u64::decode(read_stream)?,
            sig: Signature::decode(read_stream)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Curve25519Public {
    pub key: Uint256,
}
impl XdrCodable for Curve25519Public {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.key.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Curve25519Public { key: <Uint256>::decode(read_stream)? })
    }
}
