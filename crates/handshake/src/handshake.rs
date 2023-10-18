use crate::connection::Connection;
use protocol::protocol::Protocol;
use protocol::protocol::HandshakeMessageExtract;
use anyhow::Result;
use protocol::errors::StellarError;
pub async fn execute_handshake<P: Protocol>(
    connection: &mut Connection<P>,
) -> Result<bool> {
    let message = connection.protocol().create_hello_message();
    connection.send(message).await?;
    loop {
        match connection.receive().await? {
            Some(result)  => match connection.protocol().handle_message((&result.0, result.1))? {
                HandshakeMessageExtract::Hello => {
                    let auth_message = connection.protocol().create_auth_message();
                    connection.send(auth_message).await?
                }
                HandshakeMessageExtract::Auth => {return Ok(true);}
            },
            None => {
                return Err(StellarError::ExpectedMoreMessages.into());
            }
        }
    }
}
