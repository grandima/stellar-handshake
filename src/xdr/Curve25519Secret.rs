use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::Uint256;
use crate::xdr::xdr_codec::XdrCodec;
#[derive(Debug, Clone)]
pub struct Curve25519Secret {
    pub key: Uint256,
}

impl XdrCodec for Curve25519Secret {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        self.key.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Curve25519Secret { key: <Uint256>::from_xdr_buffered(read_stream)? })
    }
}
