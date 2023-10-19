
use crate::lengthed_array::LengthedArray;

use crate::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr_codec::XdrCodec;

#[derive(Debug)]
pub struct XdrArchive<T: XdrCodec> (pub T);

impl<T: XdrCodec> XdrArchive<T> {
    pub fn new(value: T) -> Self {
        Self (value)
    }
}

impl <T: XdrCodec> XdrCodec for XdrArchive<T> {
    fn encode(&self, write_stream: &mut WriteStream) {
        let res = self.0.encoded();
        write_stream.write_u32(res.len() as u32 | 0x80_00_00_00);
        write_stream.write_binary_data(&res);
    }

    fn decode<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let length = read_stream.read_length(false)?;
        let buff = read_stream.read_bytes_array(length)?;
        let mut new_read_stream = ReadStream::new(buff);
        Ok(Self(T::decode(&mut new_read_stream)?))
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
    Auth = 2,
    Hello = 13,
}

impl XdrCodec for MessageType {
    fn encode(&self, write_stream: &mut WriteStream) {
        let value = *self as u32;
        value.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = u32::decode(read_stream)?;
        match enum_value {
            2 => Ok(MessageType::Auth),
            13 => Ok(MessageType::Hello),
            _ => Err(DecodeError::InvalidEnumDiscriminator { at_position: read_stream.get_position() }),
        }
    }
}
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct HmacSha256Mac {
    pub mac: Uint256,
}

impl XdrCodec for HmacSha256Mac {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.mac.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(HmacSha256Mac { mac: <Uint256>::decode(read_stream)? })
    }
}
#[derive(Copy, Clone)]
pub enum EnvelopeType {
    Auth = 3,
}

impl XdrCodec for EnvelopeType {
    fn encode(&self, write_stream: &mut WriteStream) {
        let value = *self as u32;
        value.encode(write_stream);
    }
    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = u32::decode(read_stream)?;
        match enum_value {
            3 => Ok(EnvelopeType::Auth),
            _ => Err(DecodeError::InvalidEnumDiscriminator { at_position: read_stream.get_position() }),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PublicKeyType {
    PublicKeyTypeEd25519 = 0,
}

impl XdrCodec for PublicKeyType {
    fn encode(&self, write_stream: &mut WriteStream) {
        let value = *self as u32;
        value.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = u32::decode(read_stream)?;
        match enum_value {
            0 => Ok(PublicKeyType::PublicKeyTypeEd25519),
            _ => Err(DecodeError::InvalidEnumDiscriminator { at_position: read_stream.get_position() }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PublicKey {
    PublicKeyTypeEd25519(Uint256),
}
impl XdrCodec for PublicKey {
    fn encode(&self, write_stream: &mut WriteStream) {
        match self {
            PublicKey::PublicKeyTypeEd25519(value) => {
                PublicKeyType::PublicKeyTypeEd25519.encode(write_stream);
                value.encode(write_stream)
            },
        }
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match PublicKeyType::decode(read_stream)? {
            PublicKeyType::PublicKeyTypeEd25519 =>
                Ok(PublicKey::PublicKeyTypeEd25519(Uint256::decode(read_stream)?)),
        }
    }
}

impl PublicKey {
    pub fn as_binary(&self) -> &Uint256 {
        match self {
            PublicKey::PublicKeyTypeEd25519(key) => key,
        }
    }
}

pub type Uint64 = [u8; 8];
pub type Uint256 = [u8; 32];
pub type Uint512 = [u8; 64];
pub type NodeId = PublicKey;
pub type Signature = LengthedArray;
