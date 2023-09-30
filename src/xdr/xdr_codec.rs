use super::streams::{DecodeError, ReadStream, WriteStream};

pub trait XdrCodec: Sized {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream);
    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError>;
}

impl<const N: usize> XdrCodec for [u8; N] {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        write_stream.write_binary_data(self);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let value = read_stream.read_binary_data(N)?;
        value.try_into().map_err(|_| unreachable!())
    }
}

impl XdrCodec for u32 {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        write_stream.write_u32(*self);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        read_stream.read_u32()
    }
}

impl XdrCodec for u64 {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        write_stream.write_u64(*self);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        read_stream.read_u64()
    }
}

impl<T: XdrCodec, const N: usize> XdrCodec for [T; N] {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        for item in self.iter() {
            item.to_xdr_buffered(write_stream);
        }
    }

    fn from_xdr_buffered<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let mut result = Vec::<T>::with_capacity(N);
        for _ in 0..N {
            result.push(T::from_xdr_buffered(read_stream)?)
        }
        result.try_into().map_err(|_| unreachable!())
    }
}
