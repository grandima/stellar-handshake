use crate::connection::Connection;
use crate::protocol::errors::StellarError;
use crate::protocol::protocol::Protocol;
use crate::protocol::stellar_protocol::HandshakeMessageExtract;

pub async fn execute_handshake<P: Protocol>(
    connection: &mut Connection<P>,
) -> Result<bool, StellarError> {
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
                return Err(StellarError::ExpectedMoreMessages);
            }
        }
    }
}
