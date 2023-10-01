use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::xdr_codec::XdrCodable;
#[derive(Debug, Clone)]
pub struct LengthedArray(Vec<u8>);
impl LengthedArray {
    pub fn new(vec: Vec<u8>) -> Self {
        LengthedArray(vec)
    }
    pub fn vec(&self) -> &Vec<u8> {
        &self.0
    }
}

impl From<&str> for LengthedArray {
    fn from(value: &str) -> Self {
        LengthedArray(value.as_bytes().to_vec())
    }
}

impl XdrCodable for LengthedArray {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_u32(self.0.len() as u32);
        write_stream.write_binary_data(&self.0[..]);
    }

    fn decode<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let length = read_stream.read_u32()? as i32;
        Ok(LengthedArray::new(read_stream.read_bytes_array(length as usize)?))
    }
}
