use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::Signature;
use crate::xdr::xdr_codec::XdrCodec;
use super::curve25519public::Curve25519Public;
pub struct AuthCert {
    pub pubkey: Curve25519Public,
    pub expiration: u64,
    pub sig: Signature,
}

impl XdrCodec for AuthCert {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        self.pubkey.to_xdr_buffered(write_stream);
        self.expiration.to_xdr_buffered(write_stream);
        self.sig.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(AuthCert {
            pubkey: Curve25519Public::from_xdr_buffered(read_stream)?,
            expiration: u64::from_xdr_buffered(read_stream)?,
            sig: Signature::from_xdr_buffered(read_stream)?,
        })
    }
}