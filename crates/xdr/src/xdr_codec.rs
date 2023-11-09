use super::streams::{DecodeError, ReadStream, WriteStream};

pub trait XdrCodec: Sized {
    fn encode(&self, write_stream: &mut WriteStream);
    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError>;

    fn to_xdr(&self) -> Vec<u8> {
        let mut write_stream = WriteStream::new();
        self.encode(&mut write_stream);
        write_stream.result()
    }
    fn decoded<T: AsRef<[u8]>>(bytes: T) -> Result<(Self, usize), DecodeError> {
        let mut read_stream = ReadStream::new(bytes);
        let result = Self::from_xdr_buffered(&mut read_stream);
        result.map(|value|(value, read_stream.get_position()))
    }
}

impl<const N: usize> XdrCodec for [u8; N] {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_binary_data(self);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let value = read_stream.read_bytes_array(N)?;
        value.try_into().map_err(|_| unreachable!())
    }
}

impl XdrCodec for i32 {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_i32(*self);
    }
    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        read_stream.read_i32()
    }
}

impl XdrCodec for u32 {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_u32(*self);
    }
    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        read_stream.read_next_u32()
    }
}

impl XdrCodec for u64 {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_u64(*self);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        read_stream.read_u64()
    }
}

impl<T: XdrCodec, const N: usize> XdrCodec for [T; N] {
    fn encode(&self, write_stream: &mut WriteStream) {
        for item in self.iter() {
            item.encode(write_stream);
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
