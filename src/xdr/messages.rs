use crate::xdr::auth_cert::AuthCert;
use crate::xdr::compound_types::LimitedVarOpaque;
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::{NodeId, Uint256};
use crate::xdr::xdr_codec::XdrCodec;
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Auth {
    pub flags: u32,
}

impl XdrCodec for Auth {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        self.flags.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Auth { flags: u32::from_xdr_buffered(read_stream)? })
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
impl XdrCodec for Hello {
    fn to_xdr_buffered(&self, write_stream: &mut WriteStream) {
        self.ledger_version.to_xdr_buffered(write_stream);
        self.overlay_version.to_xdr_buffered(write_stream);
        self.overlay_min_version.to_xdr_buffered(write_stream);
        self.network_id.to_xdr_buffered(write_stream);
        // println!("{}", String::from_utf8(self.network_id.to_vec().clone()).unwrap());
        self.version_str.to_xdr_buffered(write_stream);
        self.listening_port.to_xdr_buffered(write_stream);
        self.peer_id.to_xdr_buffered(write_stream);
        self.cert.to_xdr_buffered(write_stream);
        self.nonce.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        let ledger_version = u32::from_xdr_buffered(read_stream)?;
        let overlay_version = u32::from_xdr_buffered(read_stream)?;
        let overlay_min_version = u32::from_xdr_buffered(read_stream)?;
        let network_id: Uint256 = XdrCodec::from_xdr_buffered(read_stream)?;
        let version_str = LimitedVarOpaque::<100>::from_xdr_buffered(read_stream)?;
        let listening_port =  u32::from_xdr_buffered(read_stream)?;
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