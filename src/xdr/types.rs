use std::fs::read;
use crate::xdr::compound_types::LimitedVarOpaque;
use crate::xdr::messages::{Auth, Hello};
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::xdr_codec::XdrCodable;

pub type Uint512 = [u8; 64];
pub type Uint256 = [u8; 32];
pub type Uint64 = [u8; 8];
#[derive(Debug)]
pub struct XdrCoded<T: XdrCodable> (T);

impl<T: XdrCodable> XdrCoded<T> {
    pub fn new(value: T) -> Self {
        Self (value)
    }
    pub fn value(&self) -> &T {
        &self.0
    }
}

impl <T: XdrCodable> XdrCodable for XdrCoded<T> {
    fn encode(&self, write_stream: &mut WriteStream) {
        let mut internal_stream = WriteStream::new();
        self.0.encode(&mut internal_stream);
        let res = internal_stream.get_result();
        write_stream.write_u32(res.len() as u32);
        write_stream.write_binary_data(&res);
    }

    fn decode<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let mut buffer = read_stream.read_binary_data(4)?;
        let mut length = u32::from_be_bytes([buffer[0] & 0x7f, buffer[1], buffer[2], buffer[3]]);
        let buff = read_stream.read_binary_data(length as usize)?;
        let mut new_read_stream = ReadStream::new(buff);
        Ok(Self(T::decode(&mut new_read_stream)?))
    }
}

#[derive(Debug,Clone)]
pub enum AuthenticatedMessage {
    V0(AuthenticatedMessageV0),
}
impl XdrCodable for AuthenticatedMessage {
    fn encode(&self, write_stream: &mut WriteStream) {
        match self {
            AuthenticatedMessage::V0(value) => {
                0u32.encode(write_stream);
                value.encode(write_stream)
            }
        }
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match u32::decode(read_stream)? {
            0 => Ok(AuthenticatedMessage::V0(AuthenticatedMessageV0::decode(read_stream)?)),
            value => Err(DecodeError::InvalidEnumDiscriminator { at_position: value as usize})
        }
    }

}
impl AuthenticatedMessage where Self: XdrCodable {
    //TODO: remove message
    pub fn compare(&self, vec: &[u8]) -> bool {
        let mut writer = WriteStream::new();
        self.encode(&mut writer);
        writer.get_result() == vec
    }
}
#[derive(Debug, Clone)]
pub struct AuthenticatedMessageV0 {
    pub sequence: Uint64,
    pub message: StellarMessage,
    pub mac: HmacSha256Mac,
}

impl XdrCodable for AuthenticatedMessageV0 {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.sequence.encode(write_stream);
        self.message.encode(write_stream);
        self.mac.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(AuthenticatedMessageV0 {
            sequence: <Uint64>::decode(read_stream)?,
            message: StellarMessage::decode(read_stream)?,
            mac: HmacSha256Mac::decode(read_stream)?,
        })
    }
}
#[derive(Debug, Clone)]
pub enum StellarMessage {
    Hello(Hello),
    Auth(Auth),
}
impl XdrCodable for StellarMessage {
    fn encode(&self, write_stream: &mut WriteStream) {
        match self {
            StellarMessage::Hello(value) => {
                MessageType::Hello.encode(write_stream);
                value.encode(write_stream)
            },
            StellarMessage::Auth(value) => {
                MessageType::Auth.encode(write_stream);
                value.encode(write_stream)
            },
        }
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match MessageType::decode(read_stream)? {
            MessageType::Hello => Ok(StellarMessage::Hello(Hello::decode(read_stream)?)),
            MessageType::Auth => Ok(StellarMessage::Auth(Auth::decode(read_stream)?)),
        }
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
pub type NodeId = PublicKey;

pub type Signature = LimitedVarOpaque<64>;

