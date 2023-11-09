use crate::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr_codec::XdrCodec;

#[derive(Debug)]
pub struct XdrArchive<T>(Vec<T>);

impl<T: XdrCodec> XdrArchive<T> {
    pub fn new(vec: Vec<T>) -> Self {
        XdrArchive(vec)
    }
    pub fn get_vec(&self) -> &Vec<T> {
        &self.0
    }
}

impl <T: XdrCodec> XdrCodec for XdrArchive<T> {
    fn encode(&self, write_stream: &mut WriteStream) {
        for item in self.0.iter() {
            let item_xdr = item.to_xdr();
            let length = item_xdr.len();
            if length < 0x80_00_00_00 {
                write_stream.write_u32((length as u32) | 0x80_00_00_00);
                write_stream.write_binary_data(&item_xdr);
            }
        }
    }

    fn from_xdr_buffered<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let mut result = Vec::<T>::new();
        while read_stream.no_of_bytes_left_to_read() > 0 {
            let length = read_stream.read_next_u32()? & 0x7f_ff_ff_ff;
            let old_position = read_stream.get_position();

            result.push(T::from_xdr_buffered(read_stream)?);

            if read_stream.get_position() - old_position != length as usize {
                return Err(DecodeError::InvalidXdrArchiveLength { at_position: old_position });
            }
        }

        Ok(XdrArchive::new(result))
    }
}

use std::ops::Deref;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LimitedString<const N: i32>(Vec<u8>);
impl<const N: i32> LimitedString<N> {
    pub fn new(vec: Vec<u8>) -> Result<Self, DecodeError> {
        match vec.len() > N as usize {
            true => Err(DecodeError::ExceedsMaximumLength { requested_length: vec.len(), allowed_length: N }),
            false => Ok(LimitedString(vec)),
        }
    }

    pub fn get_vec(&self) -> &Vec<u8> {
        &self.0
    }
}

impl <const N: i32> Deref for LimitedString<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl <const N: i32>  From<&str> for LimitedString<N> {
    fn from(value: &str) -> Self {
        LimitedString(value.as_bytes().to_vec())
    }
}

impl <const N: i32>  XdrCodec for LimitedString<N> {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_u32(self.0.len() as u32);
        write_stream.write_binary_data(&self.0[..]);
    }

    fn from_xdr_buffered<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let length = read_stream.read_next_u32()? as i32;
        LimitedString::new(read_stream.read_bytes_array(length as usize)?)
    }
}
