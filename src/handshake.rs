use crate::connection::Connection;
use crate::protocol::stellar_protocol::{HandshakeMessageExtract, Protocol, StellarError};

pub async fn execute_handshake<P: Protocol>(
    connection: &mut Connection<P>,
) -> Result<bool, StellarError> {
    let message = connection.protocol().create_hello_message();
    connection.send(message).await?;
    loop {
        match connection.receive().await? {
            Some(result)  => match connection.protocol().handle_message((&result.0, result.1))? {
                HandshakeMessageExtract::Hello(node_info) => {
                    let auth_message = connection.protocol().create_auth_message(node_info);
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
