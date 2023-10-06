mod keypair_type;
mod keychain;
mod node_config;
mod connection_authentication;
mod xdr;
mod stellar_protocol;
mod remote_node_info;
mod public_key;
mod utils;
mod stellar;
mod connection;
mod handshake;

use keychain::Keychain;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::stellar_protocol::{StellarProtocol};
use crate::xdr::constants::SEED_LENGTH;
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use dryoc::rng::copy_randombytes;
use crate::connection::Connection;
use crate::handshake::execute_handshake;
use crate::utils::misc::{current_u64_milliseconds, generate_nonce};


#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let keychain = Keychain::default();
    let node_config = NodeConfig::default();
    let mut secret_key_ecdh = [0u8; SEED_LENGTH];
    copy_randombytes(&mut secret_key_ecdh);
    let authentication = ConnectionAuthentication::new(keychain, &node_config.node_info.network_id, secret_key_ecdh);
    let protocol = StellarProtocol::new(node_config, generate_nonce,authentication, current_u64_milliseconds);
    let connection = Connection::connect(protocol, SocketAddr::from_str("127.0.0.1:11601").unwrap()).await.unwrap();
    println!("{:?}", on_server_connection(connection).await);
    Ok(())
}

async fn on_server_connection(server_connection: Connection) {
    let mut server_connection = server_connection;
    let negotiated = execute_handshake(&mut server_connection).await.unwrap();
    println!("result: {}", negotiated);
}

