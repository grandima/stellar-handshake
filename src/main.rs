
mod node_config;
mod xdr;
mod utils;
mod connection;
mod handshake;
mod protocol;

use node_config::NodeConfig;
use crate::xdr::constants::SEED_LENGTH;
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use dryoc::rng::copy_randombytes;
use crate::connection::Connection;
use crate::handshake::execute_handshake;
use crate::protocol::connection_authentication::ConnectionAuthentication;
use crate::protocol::keychain::Keychain;
use crate::protocol::stellar_protocol::{Protocol, StellarProtocol};
use crate::utils::misc::{get_current_u64_milliseconds, generate_nonce};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keychain = Keychain::default();
    let node_config = NodeConfig::default();
    let mut secret_key_ecdh = [0u8; SEED_LENGTH];
    copy_randombytes(&mut secret_key_ecdh);
    let authentication = ConnectionAuthentication::new(keychain, &node_config.node_info.network_id, secret_key_ecdh);
    let protocol = StellarProtocol::new(node_config, generate_nonce(), authentication, get_current_u64_milliseconds);
    let mut connection = Connection::connect(protocol, SocketAddr::from_str("127.0.0.1:11625").unwrap()).await.unwrap();
    on_server_connection(&mut connection).await;
    Ok(())
}

async fn on_server_connection<P: Protocol>(server_connection: &mut Connection<P>) {
    let negotiated = execute_handshake(server_connection).await;
    println!("result: {:?}", negotiated);
}

