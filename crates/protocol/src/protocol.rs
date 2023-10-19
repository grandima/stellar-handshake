use std::error::Error;
use anyhow::Result;

use xdr::compound_types::XdrArchive;
use xdr::{ReadStream, XdrCodec};
trait StellarError: Error + Sized {}

pub trait Protocol: Sized {
    type Message: ProtocolMessage;
    type MessageExtract;
    type NodeInfo: Sized;
    fn create_hello_message(&mut self) -> Self::Message;
    fn create_auth_message(&mut self) -> Self::Message;
    fn handle_message(&mut self, message: (&Self::Message, Vec<u8>)) -> Result<HandshakeMessageExtract>;
}

pub trait ProtocolMessage: XdrCodec + Sized {
    fn has_complete_message(buf: &[u8]) -> Result<bool>;
    fn decoded<T: AsRef<[u8]>>(bytes: T) -> Result<(Self, usize)> {
        Ok(<Self as XdrCodec>::decoded(bytes).unwrap())
    }
    fn encoded(&self) -> Vec<u8> {
        <Self as XdrCodec>::encoded(self)
    }
}

impl <T: XdrCodec> ProtocolMessage for XdrArchive<T> {
    fn has_complete_message(buf: &[u8]) -> Result<bool> {
        if buf.len() < 4 {
            return Ok(false);
        }
        let length = ReadStream::new(buf).read_length(true).unwrap() ;
        Ok(length + 4 <= buf.len())
    }
}


pub enum HandshakeMessageExtract {
    Hello,
    Auth,
}

