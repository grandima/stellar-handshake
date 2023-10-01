use std::fs::read;
use crate::xdr::compound_types::LimitedLengthedArray;
use crate::xdr::messages::{Auth, Hello};
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::xdr_codec::XdrCodable;

#[derive(Debug)]
pub struct XdrSelfCoded<T: XdrCodable> (T);

impl<T: XdrCodable> XdrSelfCoded<T> {
    pub fn new(value: T) -> Self {
        Self (value)
    }
    pub fn value(&self) -> &T {
        &self.0
    }
}

impl <T: XdrCodable> XdrCodable for XdrSelfCoded<T> {
    fn encode(&self, write_stream: &mut WriteStream) {
        let mut internal_stream = WriteStream::new();
        self.0.encode(&mut internal_stream);
        let res = internal_stream.result();
        write_stream.write_u32(res.len() as u32 | 0x80_00_00_00);
        write_stream.write_binary_data(&res);
    }

    fn decode<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let mut length = read_stream.read_u32()? & 0x7f_ff_ff_ff;
        let buff = read_stream.read_binary_data(length as usize)?;
        let mut new_read_stream = ReadStream::new(buff);
        Ok(Self(T::decode(&mut new_read_stream)?))
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
    Auth = 2,
    Hello = 13,
}

impl XdrCodable for MessageType {
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
pub struct HmacSha256Mac {
    pub mac: Uint256,
}
impl Default for HmacSha256Mac {
    fn default() -> Self {
        Self {mac: [0; 32]}
    }
}
impl XdrCodable for HmacSha256Mac {
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

impl XdrCodable for EnvelopeType {
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

impl XdrCodable for PublicKeyType {
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
impl XdrCodable for PublicKey {
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

pub type Uint64 = [u8; 8];
pub type Uint256 = [u8; 32];
pub type Uint512 = [u8; 64];
pub type NodeId = PublicKey;
pub type Signature = LimitedLengthedArray<64>;
