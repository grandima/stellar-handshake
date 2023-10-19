
use crate::streams::{DecodeError, ReadStream, WriteStream};
use crate::types::{Signature, Uint256};
use crate::xdr_codec::XdrCodec;
#[derive(Debug, Clone)]
pub struct AuthCert {
    pub persistent_public_key: Curve25519Public,
    pub expiration: u64,
    pub sig: Signature,
}

impl XdrCodec for AuthCert {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.persistent_public_key.encode(write_stream);
        self.expiration.encode(write_stream);
        self.sig.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(AuthCert {
            persistent_public_key: Curve25519Public::decode(read_stream)?,
            expiration: u64::decode(read_stream)?,
            sig: Signature::decode(read_stream)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Curve25519Public {
    pub key: Uint256,
}
impl XdrCodec for Curve25519Public {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.key.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Curve25519Public { key: <Uint256>::decode(read_stream)? })
    }
}
