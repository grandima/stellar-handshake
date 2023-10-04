use crate::xdr::auth_cert::AuthCert;
use crate::xdr::lengthed_array::LengthedArray;
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::{HmacSha256Mac, MessageType, NodeId, Uint256, Uint64};
use crate::xdr::xdr_codable::XdrCodable;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Auth {
    pub flags: u32,
}

impl XdrCodable for Auth {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.flags.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Auth { flags: u32::decode(read_stream)? })
    }
}

#[derive(Debug)]
pub struct Hello {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub network_id: Uint256,
    pub version_str: LengthedArray,
    pub listening_port: u32,
    pub peer_id: NodeId,
    pub cert: AuthCert,
    pub nonce: Uint256,
}
impl XdrCodable for Hello {
    fn encode(&self, write_stream: &mut WriteStream) {
        self.ledger_version.encode(write_stream);
        self.overlay_version.encode(write_stream);
        self.overlay_min_version.encode(write_stream);
        self.network_id.encode(write_stream);
        // println!("{}", String::from_utf8(self.network_id.to_vec().clone()).unwrap());
        self.version_str.encode(write_stream);
        self.listening_port.encode(write_stream);
        self.peer_id.encode(write_stream);
        self.cert.encode(write_stream);
        self.nonce.encode(write_stream);
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let ledger_version = u32::decode(read_stream)?;
        let overlay_version = u32::decode(read_stream)?;
        let overlay_min_version = u32::decode(read_stream)?;
        let network_id: Uint256 = XdrCodable::decode(read_stream)?;
        let version_str = LengthedArray::decode(read_stream)?;
        let listening_port =  u32::decode(read_stream)?;
        let peer_id = NodeId::decode(read_stream)?;
        Ok(Hello {
            ledger_version,
            overlay_version,
            overlay_min_version,
            network_id,
            version_str,
            listening_port,
            peer_id,
            cert: AuthCert::decode(read_stream)?,
            nonce: Uint256::decode(read_stream)?,
        })
    }
}
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
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
            }
        }
    }

    fn decode<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        match MessageType::decode(read_stream)? {
            MessageType::Hello => Ok(StellarMessage::Hello(Hello::decode(read_stream)?)),
            MessageType::Auth => Ok(StellarMessage::Auth(Auth::decode(read_stream)?)),
        }
    }
}


