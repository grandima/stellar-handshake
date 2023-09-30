use crate::xdr::streams::{DecodeError, EncodeError, ReadStream, WriteStream};
use crate::xdr::xdr_codec::XdrCodable;
#[derive(Debug, Clone)]
pub struct LimitedVarOpaque<const N: i32>(Vec<u8>);
impl<const N: i32> LimitedVarOpaque<N> {
    /// Construct a new `LimitedVarOpaque` from a byte vector
    ///
    /// The length of the byte vector must not exceed `N`. Otherwise this function returns
    /// an error.
    pub fn new(vec: Vec<u8>) -> Result<Self, EncodeError> {
        let len = vec.len(); 
        match len > N as usize {
            true => Err(EncodeError::ExceedsMaximumLength {allowed_length: N, requested_length: len}),
            false => Ok(LimitedVarOpaque(vec)),
        }
    }
    pub fn get_vec(&self) -> &Vec<u8> {
        &self.0
    }
}

impl <const N: i32> TryFrom<&str> for LimitedVarOpaque<N> {
    type Error = EncodeError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        LimitedVarOpaque::new(value.as_bytes().into())
    }
}

impl<const N: i32> XdrCodable for LimitedVarOpaque<N> {
    /// The XDR encoder implementation for `LimitedVarOpaque`
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_u32(self.0.len() as u32);
        write_stream.write_binary_data(&self.0[..]);
    }

    /// The XDR decoder implementation for `LimitedVarOpaque`
    fn decode<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let length = read_stream.read_u32()? as i32;
        match length > N {
            true => Err(DecodeError::VarOpaqueExceedsMaxLength {
                at_position: read_stream.get_position(),
                max_length: N,
                actual_length: length,
            }),
            false => Ok(LimitedVarOpaque::new(read_stream.read_binary_data(length as usize)?).unwrap()),
        }
    }
}
