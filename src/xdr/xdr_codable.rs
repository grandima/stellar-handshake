use super::streams::{DecodeError, ReadStream, WriteStream};

pub trait XdrCodable: Sized {
    fn encode(&self, write_stream: &mut WriteStream);
    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError>;

    fn encoded(&self) -> Vec<u8> {
        let mut write_stream = WriteStream::new();
        self.encode(&mut write_stream);
        write_stream.result()
    }
}

impl<const N: usize> XdrCodable for [u8; N] {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_binary_data(self);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let value = read_stream.read_bytes_array(N)?;
        value.try_into().map_err(|_| unreachable!())
    }
}

impl XdrCodable for u32 {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_u32(*self);
    }
    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        read_stream.read_u32()
    }
}

impl XdrCodable for u64 {
    fn encode(&self, write_stream: &mut WriteStream) {
        write_stream.write_u64(*self);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        read_stream.read_u64()
    }
}

impl<T: XdrCodable, const N: usize> XdrCodable for [T; N] {
    fn encode(&self, write_stream: &mut WriteStream) {
        for item in self.iter() {
            item.encode(write_stream);
        }
    }

    fn decode<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let mut result = Vec::<T>::with_capacity(N);
        for _ in 0..N {
            result.push(T::decode(read_stream)?)
        }
        result.try_into().map_err(|_| unreachable!())
    }
}
