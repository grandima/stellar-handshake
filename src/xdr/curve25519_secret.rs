use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::Uint256;
use crate::xdr::xdr_codec::XdrCodable;
#[derive(Debug, Clone)]
pub struct Curve25519Secret {
    pub key: Uint256,
}

impl XdrCodable for Curve25519Secret {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.key.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Curve25519Secret { key: <Uint256>::decode(read_stream)? })
    }
}
