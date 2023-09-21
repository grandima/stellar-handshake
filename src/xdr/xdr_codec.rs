use super::streams::{DecodeError, ReadStream, WriteStream};

pub trait XdrCodec: Sized {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream);
    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError>;
}

impl<const N: usize> XdrCodec for [u8; N] {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        write_stream.write_next_binary_data(self);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let value = read_stream.read_next_binary_data(N)?;
        value.try_into().map_err(|_| unreachable!())
    }
}

impl XdrCodec for u64 {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        write_stream.write_next_u64(*self);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        read_stream.read_next_u64()
    }
}