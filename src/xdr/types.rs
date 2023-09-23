use crate::xdr::hello::Hello;
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::xdr_codec::XdrCodec;
use super::compound_types::LimitedVarOpaque;

pub type Uint256 = [u8; 32];
#[derive(Debug,)]
pub enum AuthenticatedMessage {
    V0(AuthenticatedMessageV0),
}
impl XdrCodec for AuthenticatedMessage {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        match self {
            AuthenticatedMessage::V0(value) => {
                (0 as u32).to_xdr_buffered(write_stream);
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
#[derive(Debug)]
pub struct AuthenticatedMessageV0 {
    pub sequence: u64,
    pub message: StellarMessage,
    pub mac: HmacSha256Mac,
}

impl AuthenticatedMessageV0 {
    pub fn new(message: StellarMessage) -> Self {
        Self {sequence: 0, message, mac: HmacSha256Mac{mac: [0; 32]}}
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
}
impl XdrCodec for StellarMessage {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        match self {
            StellarMessage::Hello(value) => {
                MessageType::Hello.to_xdr_buffered(write_stream);
                value.to_xdr_buffered(write_stream)
            },
        }
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match MessageType::from_xdr_buffered(read_stream)? {
            MessageType::Hello => Ok(StellarMessage::Hello(Hello::from_xdr_buffered(read_stream)?)),

        }
    }
}
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
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
            13 => Ok(MessageType::Hello),
            _ => Err(DecodeError::InvalidEnumDiscriminator { at_position: read_stream.get_position() }),
        }
    }
}
#[derive(Debug)]
pub struct HmacSha256Mac {
    pub mac: [u8; 32],
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

#[derive(Debug)]
pub enum PublicKey {
    PublicKeyTypeEd25519(Uint256),
}
impl XdrCodec for PublicKey {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        match self {
            PublicKey::PublicKeyTypeEd25519(value) => {
                0i32.to_xdr_buffered(write_stream);
                value.to_xdr_buffered(write_stream)
            },
        }
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let value = i32::from_xdr_buffered(read_stream)?;
        return if value != 0 {
            Ok(PublicKey::PublicKeyTypeEd25519(Uint256::from_xdr_buffered(read_stream)?))
        } else {
            Err(DecodeError::SuddenEnd {actual_length: value as usize, expected_length: 0 })
        }
    }
}
pub type NodeId = PublicKey;

pub type Signature = LimitedVarOpaque<64>;
impl<const N: i32> XdrCodec for LimitedVarOpaque<N> {
    /// The XDR encoder implementation for `LimitedVarOpaque`
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        write_stream.write_next_u32(self.0.len() as u32);
        write_stream.write_next_binary_data(&self.0[..]);
    }

    /// The XDR decoder implementation for `LimitedVarOpaque`
    fn from_xdr_buffered<R: AsRef<[u8]>>(read_stream: &mut ReadStream<R>) -> Result<Self, DecodeError> {
        let length = read_stream.read_next_u32()? as i32;
        match length > N {
            true => Err(DecodeError::VarOpaqueExceedsMaxLength {
                at_position: read_stream.get_position(),
                max_length: N,
                actual_length: length,
            }),
            false => Ok(LimitedVarOpaque::new(read_stream.read_next_binary_data(length as usize)?).unwrap()),
        }
    }
}

