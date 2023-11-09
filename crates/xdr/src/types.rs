
use crate::compound_types::LimitedString;

use crate::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr_codec::XdrCodec;



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

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = u32::from_xdr_buffered(read_stream)?;
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

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(HmacSha256Mac { mac: <Uint256>::from_xdr_buffered(read_stream)? })
    }
}
#[derive(Copy, Clone)]
pub enum EnvelopeType {
    EnvelopeTypeAuth = 3,
}

impl XdrCodec for EnvelopeType {
    fn encode(&self, write_stream: &mut WriteStream) {
        let value = *self as u32;
        value.encode(write_stream);
    }
    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = u32::from_xdr_buffered(read_stream)?;
        match enum_value {
            3 => Ok(EnvelopeType::EnvelopeTypeAuth),
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

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let enum_value = u32::from_xdr_buffered(read_stream)?;
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

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match PublicKeyType::from_xdr_buffered(read_stream)? {
            PublicKeyType::PublicKeyTypeEd25519 =>
                Ok(PublicKey::PublicKeyTypeEd25519(Uint256::from_xdr_buffered(read_stream)?)),
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Curve25519Secret {
    pub key: [u8; 32],
}

impl XdrCodec for Curve25519Secret {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.key.encode(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Curve25519Secret { key: <[u8; 32]>::from_xdr_buffered(read_stream)? })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Curve25519Public {
    pub key: [u8; 32],
}

impl XdrCodec for Curve25519Public {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.key.encode(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Curve25519Public { key: <[u8; 32]>::from_xdr_buffered(read_stream)? })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthCert {
    pub pubkey: Curve25519Public,
    pub expiration: u64,
    pub sig: Signature,
}

impl XdrCodec for AuthCert {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.pubkey.encode(write_stream);
        self.expiration.encode(write_stream);
        self.sig.encode(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(AuthCert {
            pubkey: Curve25519Public::from_xdr_buffered(read_stream)?,
            expiration: u64::from_xdr_buffered(read_stream)?,
            sig: Signature::from_xdr_buffered(read_stream)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Hello {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub network_id: Uint256,
    pub version_str: LimitedString<100>,
    pub listening_port: i32,
    pub peer_id: NodeId,
    pub cert: AuthCert,
    pub nonce: Uint256,
}
impl XdrCodec for Hello {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.ledger_version.encode(write_stream);
        self.overlay_version.encode(write_stream);
        self.overlay_min_version.encode(write_stream);
        self.network_id.encode(write_stream);
        self.version_str.encode(write_stream);
        self.listening_port.encode(write_stream);
        self.peer_id.encode(write_stream);
        self.cert.encode(write_stream);
        self.nonce.encode(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let ledger_version = u32::from_xdr_buffered(read_stream)?;
        let overlay_version = u32::from_xdr_buffered(read_stream)?;
        let overlay_min_version = u32::from_xdr_buffered(read_stream)?;
        let network_id: Uint256 = XdrCodec::from_xdr_buffered(read_stream)?;
        let version_str = LimitedString::from_xdr_buffered(read_stream)?;
        let listening_port =  i32::from_xdr_buffered(read_stream)?;
        let peer_id = NodeId::from_xdr_buffered(read_stream)?;
        Ok(Hello {
            ledger_version,
            overlay_version,
            overlay_min_version,
            network_id,
            version_str,
            listening_port,
            peer_id,
            cert: AuthCert::from_xdr_buffered(read_stream)?,
            nonce: Uint256::from_xdr_buffered(read_stream)?,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Auth {
    pub flags: u32,
}

impl XdrCodec for Auth {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.flags.encode(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Auth { flags: u32::from_xdr_buffered(read_stream)? })
    }
}


#[derive(Debug, Clone)]
pub enum StellarMessage {
    Hello(Hello),
    Auth(Auth),
}
impl XdrCodec for StellarMessage {
    fn encode(&self, write_stream: &mut WriteStream) {
        match self {
            StellarMessage::Hello(value) => {
                MessageType::Hello.encode(write_stream);
                value.encode(write_stream)
            },
            StellarMessage::Auth(value) => {
                MessageType::Auth.encode(write_stream);
                value.encode(write_stream)
            }
        }
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match MessageType::from_xdr_buffered(read_stream)? {
            MessageType::Hello => Ok(StellarMessage::Hello(Hello::from_xdr_buffered(read_stream)?)),
            MessageType::Auth => Ok(StellarMessage::Auth(Auth::from_xdr_buffered(read_stream)?)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedMessageV0 {
    pub sequence: u64,
    pub message: StellarMessage,
    pub mac: HmacSha256Mac,
}

impl XdrCodec for AuthenticatedMessageV0 {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.sequence.encode(write_stream);
        self.message.encode(write_stream);
        self.mac.encode(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(AuthenticatedMessageV0 {
            sequence: <u64>::from_xdr_buffered(read_stream)?,
            message: StellarMessage::from_xdr_buffered(read_stream)?,
            mac: HmacSha256Mac::from_xdr_buffered(read_stream)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum AuthenticatedMessage {
    V0(AuthenticatedMessageV0),
}

impl XdrCodec for AuthenticatedMessage {
    fn encode(&self, write_stream: &mut WriteStream) {
        match self {
            AuthenticatedMessage::V0(value) => {
                (0 as u32).encode(write_stream);
                value.encode(write_stream)
            },
        }
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match u32::from_xdr_buffered(read_stream)? {
            0 => Ok(AuthenticatedMessage::V0(AuthenticatedMessageV0::from_xdr_buffered(read_stream)?)),
            _ => Err(DecodeError::InvalidEnumDiscriminator {at_position: read_stream.get_position()})
        }
    }
}


pub type Uint64 = [u8; 8];
pub type Uint256 = [u8; 32];
pub type Uint512 = [u8; 64];
pub type NodeId = PublicKey;
pub type Signature = LimitedString<100>;
