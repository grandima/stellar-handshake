use crate::xdr::streams::{DecodeError, EncodeError, ReadStream, WriteStream};
use crate::xdr::xdr_codec::XdrCodable;
#[derive(Debug, Clone)]
pub struct LimitedLengthedArray<const N: i32>(Vec<u8>);
impl<const N: i32> LimitedLengthedArray<N> {
    pub fn new(vec: Vec<u8>) -> Result<Self, EncodeError> {
        let len = vec.len(); 
        match len > N as usize {
            true => Err(EncodeError::ExceedsMaximumLength {allowed_length: N, requested_length: len}),
            false => Ok(LimitedLengthedArray(vec)),
        }
    }
    pub fn vec(&self) -> &Vec<u8> {
        &self.0
    }
}

impl <const N: i32> TryFrom<&str> for LimitedLengthedArray<N> {
    type Error = EncodeError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        LimitedLengthedArray::new(value.as_bytes().into())
    }
}

impl<const N: i32> XdrCodable for LimitedLengthedArray<N> {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_u32(self.0.len() as u32);
        write_stream.write_binary_data(&self.0[..]);
    }

    fn decode<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let length = read_stream.read_u32()? as i32;
        match length > N {
            true => Err(DecodeError::ArrayExceedsMaxLength {
                at_position: read_stream.get_position(),
                max_length: N,
                actual_length: length,
            }),
            false => Ok(LimitedLengthedArray::new(read_stream.read_binary_data(length as usize)?).unwrap()),
        }
    }
}
