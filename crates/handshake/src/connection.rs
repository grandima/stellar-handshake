
use std::net::SocketAddr;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use protocol::errors::StellarError;
use protocol::protocol::{Protocol, ProtocolMessage};
use anyhow::Result;
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

    pub async fn receive(&mut self) -> Result<Option<(P::Message, Vec<u8>)>> {
        loop {
            match self.parse_message() {
                Ok(Some(result)) => return Ok(Some((result.0, result.1))),
                Ok(None) => {
                    if 0 == self.socket.read_buf(&mut self.read_buffer).await? {
                        return if self.read_buffer.is_empty() {
                            Ok(None)
                        } else {
                            Err(StellarError::ConnectionResetByPeer.into())
                        };
                    }
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    fn parse_message(&mut self) -> Result<Option<(P::Message, Vec<u8>)>> {
        if let Some(size) = P::Message::complete_message_size(self.read_buffer.as_ref()) {
            let (message, size) = P::Message::decoded(self.read_buffer[..size].as_ref())?;
            let raw_message = self.read_buffer.split_to(size);
            Ok(Some((message, raw_message[4..].to_vec())))
        } else {
            Ok(None)
        }
    }

    pub async fn send(&mut self, message: P::Message) -> Result<(), StellarError> {
        let encoded = message.to_xdr();
        if let Err(e) = self.socket.write(&encoded).await {
            return Err(e.into());
        }
        Ok(())
    }
}
