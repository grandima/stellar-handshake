use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::stellar_protocol::StellarError;
use crate::xdr::messages::{Auth, AuthenticatedMessage};
use crate::xdr::streams::ReadStream;
use crate::xdr::types::XdrSelfCoded;
use crate::xdr::xdr_codable::XdrCodable;

pub struct Connection {
    socket: TcpStream,
    read_buffer: BytesMut,
}
impl Connection {
    /// Convenience factory
    pub fn new(
        socket: TcpStream,
    ) -> Connection {
        Connection {
            socket,
            read_buffer: BytesMut::with_capacity(0x4000),
        }
    }


    /// Connect to a peer at a known address
    pub async fn connect(
        addr: SocketAddr,
    ) -> Result<Connection, StellarError> {
        let socket = TcpStream::connect(addr).await?;
        Ok(Connection::new(socket))
    }

    /// Return the next available message - the function is async, so this is non-blocking.
    ///
    /// `Ok(None)` means that the connection was closed gracefully.
    /// `Err(_)` leaves the connection in a potentially inconsistent state, making it illegal to
    ///   use for sending or receiving messages.
    pub async fn receive(&mut self) -> Result<Option<XdrSelfCoded<AuthenticatedMessage>>, StellarError> {
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

    fn parse_message(&mut self) -> Result<Option<XdrSelfCoded<AuthenticatedMessage>>, StellarError> {
        if XdrSelfCoded::<AuthenticatedMessage>::has_complete_message(self.read_buffer.as_ref())? {
            let mut stream = ReadStream::new(self.read_buffer.as_ref());
            let message = XdrSelfCoded::<AuthenticatedMessage>::decode(&mut stream)?;
            self.read_buffer.advance(stream.get_position());
            Ok(Some(message))
        } else {
            Ok(None)
        }
    }

    pub async fn send(&mut self, message: XdrSelfCoded<AuthenticatedMessage>) -> Result<(), StellarError> {
        let encoded = message.encoded();
        if let Err(e) = self.socket.write(&encoded).await {
            return Err(e.into());
        }
        Ok(())
    }
}
