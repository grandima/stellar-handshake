use std::error::Error;
use anyhow::Result;

use xdr::streams::ReadStream;
use xdr::types::{XdrArchive};
use xdr::xdr_codable::XdrCodable;

trait StellarError: Error + Sized {}

pub trait Protocol: Sized {
    type Message: ProtocolMessage;
    type MessageExtract;
    type NodeInfo: Sized;
    fn create_hello_message(&mut self) -> Self::Message;
    fn create_auth_message(&mut self) -> Self::Message;
    fn handle_message(&mut self, message: (&Self::Message, Vec<u8>)) -> Result<HandshakeMessageExtract>;
}

pub trait ProtocolMessage: XdrCodable + Sized {
    fn has_complete_message(buf: &[u8]) -> Result<bool>;
}

impl <T: XdrCodable> ProtocolMessage for XdrArchive<T> {
    fn has_complete_message(buf: &[u8]) -> Result<bool> {
        if buf.len() < 4 {
            return Ok(false);
        }
        let length = ReadStream::new(buf).read_length(true)? ;
        Ok(length + 4 <= buf.len())
    }
}


pub enum HandshakeMessageExtract {
    Hello,
    Auth,
}

