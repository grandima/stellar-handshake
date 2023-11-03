
use anyhow::Result;

use xdr::compound_types::XdrArchive;
use xdr::{ReadStream, XdrCodec};
use crate::errors::StellarError;


pub trait Protocol: Sized {
    type Message: ProtocolMessage;
    type MessageExtract;
    type NodeInfo: Sized;
    fn create_hello_message(&mut self) -> Self::Message;
    fn create_auth_message(&mut self) -> Self::Message;
    fn handle_message(&mut self, message: (&Self::Message, Vec<u8>)) -> Result<HandshakeMessageExtract>;
}

pub trait ProtocolMessage: XdrCodec + Sized {
    fn complete_message_size(buf: &[u8]) -> Option<usize>;
    fn decoded<T: AsRef<[u8]>>(bytes: T) -> Result<(Self, usize), StellarError> {
        let mut read_stream = ReadStream::new(bytes);
        let result = <Self as XdrCodec>::from_xdr_buffered(&mut read_stream)?;
        Ok((result, read_stream.get_position()))
    }
    fn to_xdr(&self) -> Vec<u8> {
        <Self as XdrCodec>::to_xdr(self)
    }
}

impl <T: XdrCodec> ProtocolMessage for XdrArchive<T> {
    fn complete_message_size(buf: &[u8]) -> Option<usize> {
        if buf.len() < 4 {
            return None;
        }
        let length = 4 + (ReadStream::new(buf).read_next_u32().unwrap_or(0) as usize & 0x7f_ff_ff_ff);
        if length <= buf.len() {
            Some(length)
        } else {
            None
        }
    }
}


pub enum HandshakeMessageExtract {
    Hello,
    Auth,
}

