
use std::net::SocketAddr;


use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::stellar_protocol::{MessageTrait, StellarError, StellarProtocolImpl, Protocol};
use crate::xdr::messages::{AuthenticatedMessage};
use crate::xdr::streams::ReadStream;
use crate::xdr::types::XdrSelfCoded;
use crate::xdr::xdr_codable::XdrCodable;

pub struct Connection<P: Protocol> {
    protocol: P,
    socket: TcpStream,
    read_buffer: BytesMut,
}
impl<P: Protocol> Connection<P> {
    pub fn new(
        protocol: P,
        socket: TcpStream,
    ) -> Connection<P> {
        Connection {
            protocol,
            socket,
            read_buffer: BytesMut::with_capacity(0x4000),
        }
    }
    pub fn protocol(&mut self) -> &mut P {
        &mut self.protocol
    }

    pub async fn connect(
        protocol: P,
        addr: SocketAddr,
    ) -> Result<Connection<P>, StellarError> {
        let socket = TcpStream::connect(addr).await?;
        Ok(Connection::new(protocol, socket))
    }

    pub async fn receive(&mut self) -> Result<Option<P::Message>, StellarError> {
        loop {
            match self.parse_message() {
                Ok(Some(message)) => return Ok(Some(message)),
                Ok(None) => {
                    if 0 == self.socket.read_buf(&mut self.read_buffer).await? {
                        return if self.read_buffer.is_empty() {
                            Ok(None)
                        } else {
                            Err(StellarError::ConnectionResetByPeer)
                        };
                    }
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    fn parse_message(&mut self) -> Result<Option<P::Message>, StellarError> {
        if P::Message::has_complete_message(self.read_buffer.as_ref())? {
            let mut stream = ReadStream::new(self.read_buffer.as_ref());
            let message = P::Message::decode(&mut stream)?;
            self.read_buffer.advance(stream.get_position());
            Ok(Some(message))
        } else {
            Ok(None)
        }
    }

    pub async fn send(&mut self, message: P::Message) -> Result<(), StellarError> {
        let encoded = message.encoded();
        if let Err(e) = self.socket.write(&encoded).await {
            return Err(e.into());
        }
        Ok(())
    }
}
