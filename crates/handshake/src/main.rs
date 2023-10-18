
mod connection;
mod handshake;

use protocol::node_config::NodeConfig;
use std::error::Error;


use dryoc::rng::copy_randombytes;
use protocol::protocol::Protocol;
use connection::Connection;
use crate::handshake::execute_handshake;
use protocol::connection_authentication::ConnectionAuthentication;
use protocol::keychain::Keychain;
use protocol::stellar_protocol::StellarProtocol;
use utils::misc::{generate_nonce, get_current_u64_milliseconds};


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keychain = Keychain::from_random_seed();
    let node_config = NodeConfig::mainnet();
    let mut per_connection_secret_key = [0u8; 32];
    copy_randombytes(&mut per_connection_secret_key);
    let authentication = ConnectionAuthentication::new(keychain, &node_config.node_info.network_id, per_connection_secret_key);
    let protocol = StellarProtocol::new(node_config.clone(), generate_nonce(), authentication, get_current_u64_milliseconds);
    let mut connection = Connection::connect(protocol, node_config.sock_addr()).await.unwrap();
    on_server_connection(&mut connection).await;
    Ok(())
}

async fn on_server_connection<P: Protocol>(server_connection: &mut Connection<P>) {
    let negotiated = execute_handshake(server_connection).await;
    println!("Handshake result: {:?}", negotiated);
}

