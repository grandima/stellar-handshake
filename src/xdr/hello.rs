use crate::xdr::auth_cert::AuthCert;
use crate::xdr::compound_types::LimitedVarOpaque;
use crate::xdr::streams::{DecodeError, ReadStream, WriteStream};
use crate::xdr::types::{NodeId, Uint256};
use crate::xdr::xdr_codec::XdrCodec;

pub struct Hello {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub network_id: [u8; 32],
    pub version_str: LimitedVarOpaque<100>,
    pub listening_port: i32,
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
        self.version_str.to_xdr_buffered(write_stream);
        self.listening_port.to_xdr_buffered(write_stream);
        self.peer_id.to_xdr_buffered(write_stream);
        self.cert.to_xdr_buffered(write_stream);
        self.nonce.to_xdr_buffered(write_stream);
    }

    fn from_xdr_buffered<T: AsRef<[u8]>>(read_stream: &mut ReadStream<T>) -> Result<Self, DecodeError> {
        Ok(Hello {
            ledger_version: u32::from_xdr_buffered(read_stream)?,
            overlay_version: u32::from_xdr_buffered(read_stream)?,
            overlay_min_version: u32::from_xdr_buffered(read_stream)?,
            network_id: XdrCodec::from_xdr_buffered(read_stream)?,
            version_str: LimitedVarOpaque::<100>::from_xdr_buffered(read_stream)?,
            listening_port: i32::from_xdr_buffered(read_stream)?,
            peer_id: NodeId::from_xdr_buffered(read_stream)?,
            cert: AuthCert::from_xdr_buffered(read_stream)?,
            nonce: Uint256::from_xdr_buffered(read_stream)?,
        })
    }
}