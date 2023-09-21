use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::xdr_codec::XdrCodec;
use super::compound_types::LimitedVarOpaque;

pub type Uint256 = [u8; 32];
pub enum PublicKey {
    PublicKeyTypeEd25519(Uint256),
}
impl XdrCodec for PublicKey {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        match self {
            PublicKey::PublicKeyTypeEd25519(value) => {
                (0 as i32).to_xdr_buffered(write_stream);
                value.to_xdr_buffered(write_stream)
            },
        }
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let value = i32::from_xdr_buffered(read_stream)?;
        return if value != 0 {
            Ok(PublicKey::PublicKeyTypeEd25519(Uint256::from_xdr_buffered(read_stream)?))
        } else {
            Err(DecodeError::SuddenEnd {actual_length: value as usize, expected_length: 0 })
        }
    }
}
pub type NodeId = PublicKey;
pub type Signature = LimitedVarOpaque<64>;
impl<const N: i32> XdrCodec for LimitedVarOpaque<N> {
    /// The XDR encoder implementation for `LimitedVarOpaque`
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        write_stream.write_next_u32(self.0.len() as u32);
        write_stream.write_next_binary_data(&self.0[..]);
    }

    /// The XDR decoder implementation for `LimitedVarOpaque`
    fn from_xdr_buffered<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let length = read_stream.read_next_u32()? as i32;
        match length > N {
            true => Err(DecodeError::VarOpaqueExceedsMaxLength {
                at_position: read_stream.get_position(),
                max_length: N,
                actual_length: length,
            }),
            false => Ok(LimitedVarOpaque::new(read_stream.read_next_binary_data(length as usize)?).unwrap()),
        }
    }
}

