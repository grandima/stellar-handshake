use std::fs::read;
use crate::xdr::compound_types::LimitedVarOpaque;
use crate::xdr::stellar_messages::{Auth, Hello};
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::xdr_codec::XdrCodec;

pub type Uint256 = [u8; 32];
#[derive(Debug)]
pub struct ArchivedMessage<T: XdrCodec> {
    pub message: T
}

impl<T: XdrCodec> ArchivedMessage<T> {
    pub fn new(message: T) -> Self {
        Self {message}
    }
}

impl <T: XdrCodec> XdrCodec for ArchivedMessage<T> {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        let mut internal_stream = WriteStream::new();
        self.message.to_xdr_buffered(&mut internal_stream);
        let res = internal_stream.get_result();
        write_stream.write_next_u32(res.len() as u32);
        write_stream.write_next_binary_data(&res);
    }

    fn  from_xdr_buffered<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let mut buffer = read_stream.read_next_binary_data(4)?;
        let mut length = u32::from_be_bytes([buffer[0] & 0x7f, buffer[1], buffer[2], buffer[3]]);
        let buff = read_stream.read_next_binary_data(length as usize)?;
        let mut new_read_stream = ReadStream::new(buff);
        Ok(Self{message: T::from_xdr_buffered(&mut new_read_stream)?})
    }
}

#[derive(Debug,)]
pub enum AuthenticatedMessage {
    V0(AuthenticatedMessageV0),
}
impl XdrCodec for AuthenticatedMessage {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        match self {
            AuthenticatedMessage::V0(value) => {
                0u32.to_xdr_buffered(write_stream);
                value.to_xdr_buffered(write_stream)
            }
        }
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match u32::from_xdr_buffered(read_stream)? {
            0 => Ok(AuthenticatedMessage::V0(AuthenticatedMessageV0::from_xdr_buffered(read_stream)?)),
            value => Err(DecodeError::InvalidEnumDiscriminator { at_position: value as usize})
        }
    }

}
impl AuthenticatedMessage where Self: XdrCodec {
    //TODO: remove message
    pub fn compare(&self, vec: &[u8]) -> bool {
        let mut writer = WriteStream::new();
        self.to_xdr_buffered(&mut writer);
        writer.get_result() == vec
    }
}
#[derive(Debug)]
pub struct AuthenticatedMessageV0 {
    pub sequence: u64,
    pub message: StellarMessage,
    pub mac: HmacSha256Mac,
}

impl AuthenticatedMessageV0 {
    pub fn new(message: StellarMessage) -> Self {
        Self {sequence: 0, message, mac: HmacSha256Mac::default()}
    }
}

impl XdrCodec for AuthenticatedMessageV0 {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        self.sequence.to_xdr_buffered(write_stream);
        self.message.to_xdr_buffered(write_stream);
        self.mac.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(AuthenticatedMessageV0 {
            sequence: u64::from_xdr_buffered(read_stream)?,
            message: StellarMessage::from_xdr_buffered(read_stream)?,
            mac: HmacSha256Mac::from_xdr_buffered(read_stream)?,
        })
    }
}
#[derive(Debug)]
pub enum StellarMessage {
    Hello(Hello),
    Auth(Auth),
}
impl XdrCodec for StellarMessage {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        match self {
            StellarMessage::Hello(value) => {
                MessageType::Hello.to_xdr_buffered(write_stream);
                value.to_xdr_buffered(write_stream)
            },
            StellarMessage::Auth(value) => {
                MessageType::Auth.to_xdr_buffered(write_stream);
                value.to_xdr_buffered(write_stream)
            },
        }
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match MessageType::from_xdr_buffered(read_stream)? {
            MessageType::Hello => Ok(StellarMessage::Hello(Hello::from_xdr_buffered(read_stream)?)),
            MessageType::Auth => Ok(StellarMessage::Auth(Auth::from_xdr_buffered(read_stream)?)),
        }
    }
}
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
    Auth = 2,
    Hello = 13,
}

impl XdrCodec for MessageType {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        let value = *self as i32;
        value.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = i32::from_xdr_buffered(read_stream)?;
        match enum_value {
            2 => Ok(MessageType::Auth),
            13 => Ok(MessageType::Hello),
            _ => Err(DecodeError::InvalidEnumDiscriminator { at_position: read_stream.get_position() }),
        }
    }
}
#[derive(Debug)]
pub struct HmacSha256Mac {
    pub mac: [u8; 32],
}
impl Default for HmacSha256Mac {
    fn default() -> Self {
        Self {mac: [0; 32]}
    }
}
impl XdrCodec for HmacSha256Mac {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        self.mac.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(HmacSha256Mac { mac: <[u8; 32]>::from_xdr_buffered(read_stream)? })
    }
}
#[derive(Copy, Clone)]
pub enum EnvelopeType {
    Auth = 3,
}

impl XdrCodec for EnvelopeType {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        let value = *self as i32;
        value.to_xdr_buffered(write_stream);
    }
    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = i32::from_xdr_buffered(read_stream)?;
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
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        let value = *self as i32;
        value.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = i32::from_xdr_buffered(read_stream)?;
        match enum_value {
            0 => Ok(PublicKeyType::PublicKeyTypeEd25519),
            _ => Err(DecodeError::InvalidEnumDiscriminator { at_position: read_stream.get_position() }),
        }
    }
}

#[derive(Debug)]
pub enum PublicKey {
    PublicKeyTypeEd25519(Uint256),
}
impl XdrCodec for PublicKey {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        match self {
            PublicKey::PublicKeyTypeEd25519(value) => {
                PublicKeyType::PublicKeyTypeEd25519.to_xdr_buffered(write_stream);
                value.to_xdr_buffered(write_stream)
            },
        }
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match PublicKeyType::from_xdr_buffered(read_stream)? {
            PublicKeyType::PublicKeyTypeEd25519 =>
                Ok(PublicKey::PublicKeyTypeEd25519(Uint256::from_xdr_buffered(read_stream)?)),
        }
    }
}
pub type NodeId = PublicKey;

pub type Signature = LimitedVarOpaque<64>;

