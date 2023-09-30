use crate::xdr::auth_cert::AuthCert;
use crate::xdr::compound_types::LimitedVarOpaque;
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::{NodeId, Uint256};
use crate::xdr::xdr_codec::XdrCodable;
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

#[derive(Debug, Clone)]
pub struct Hello {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub network_id: Uint256,
    pub version_str: LimitedVarOpaque<100>,
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
        let version_str = LimitedVarOpaque::<100>::decode(read_stream)?;
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