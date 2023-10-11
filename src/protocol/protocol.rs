use crate::protocol::errors;
use crate::protocol::errors::StellarError;

use crate::protocol::stellar_protocol::{HandshakeMessageExtract};

use crate::xdr::streams::ReadStream;
use crate::xdr::types::{XdrArchive};
use crate::xdr::xdr_codable::XdrCodable;

pub trait Protocol: Sized {
    type Message: ProtocolMessage;
    type MessageExtract;
    type NodeInfo: Sized;
    fn create_hello_message(&mut self) -> Self::Message;
    fn create_auth_message(&mut self) -> Self::Message;
    fn handle_message(&mut self, message: (&Self::Message, Vec<u8>)) -> Result<HandshakeMessageExtract, StellarError>;
}

pub trait ProtocolMessage: XdrCodable + Sized {
    fn has_complete_message(buf: &[u8]) -> Result<bool, StellarError>;
}

impl <T: XdrCodable> ProtocolMessage for XdrArchive<T> {
    fn has_complete_message(buf: &[u8]) -> std::result::Result<bool, errors::StellarError> {
        if buf.len() < 4 {
            return Ok(false);
        }
        let length = ReadStream::new(buf).read_length(true)? ;
        Ok(length + 4 <= buf.len())
    }
}


