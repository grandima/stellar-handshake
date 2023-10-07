use crate::connection::Connection;
use crate::stellar_protocol::{HandshakeMessageExtract, StellarError, StellarProtocolImpl, StellarProtocolTrait};

pub async fn execute_handshake<P: StellarProtocolTrait>(
    connection: &mut Connection<P>,
) -> Result<bool, StellarError> {
    let message = connection.protocol().create_hello_message();
    connection.send(message).await?;
    loop {
        match connection.receive().await? {
            Some(message)  => match connection.protocol().handle_message(&message) {
                HandshakeMessageExtract::Hello(Ok(node_info)) => {
                    let auth_message = connection.protocol().create_auth_message(node_info);
                    connection.send(auth_message).await?
                }
                HandshakeMessageExtract::Hello(Err(error)) => {return Err(error);}
                HandshakeMessageExtract::Auth => {return Ok(true);}
            },
            None => {
                return Err(StellarError::ExpectedMoreMessages);
            }
        }
    }
}
