use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::Uint256;
use super::xdr_codec::XdrCodec;
#[derive(Debug, Clone)]
pub struct Curve25519Public {
    pub key: Uint256,
}
impl XdrCodec for Curve25519Public {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        self.key.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Curve25519Public { key: <Uint256>::from_xdr_buffered(read_stream)? })
    }
}