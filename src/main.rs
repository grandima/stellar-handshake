
mod node_config;
mod xdr;
mod utils;
mod connection;
mod handshake;
mod protocol;

use node_config::NodeConfig;
use crate::xdr::constants::SEED_LENGTH;
use std::error::Error;


use dryoc::rng::copy_randombytes;
use protocol::protocol::Protocol;
use crate::connection::Connection;
use crate::handshake::execute_handshake;
use crate::protocol::connection_authentication::ConnectionAuthentication;
use crate::protocol::keychain::Keychain;
use crate::protocol::stellar_protocol::StellarProtocol;
use crate::utils::misc::{generate_nonce, get_current_u64_milliseconds};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keychain = Keychain::from_random_seed();
    let node_config = NodeConfig::mainnet();
    let mut per_connection_secret_key = [0u8; SEED_LENGTH];
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

