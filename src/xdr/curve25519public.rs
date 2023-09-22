use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use super::xdr_codec::XdrCodec;
#[derive(Debug)]
pub struct Curve25519Public {
    pub key: [u8; 32],
}
impl XdrCodec for Curve25519Public {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        self.key.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Curve25519Public { key: <[u8; 32]>::from_xdr_buffered(read_stream)? })
    }
}