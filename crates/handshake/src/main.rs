
mod connection;
mod handshake;

use protocol::node_config::{NodeConfig};
use std::error::Error;

use dryoc::rng::copy_randombytes;
use simple_logger::SimpleLogger;
use log::{info, LevelFilter};
use protocol::protocol::Protocol;
use connection::Connection;
use crate::handshake::execute_handshake;
use protocol::connection_authentication::ConnectionAuthentication;
use protocol::keychain::{Keychain, encoded_random_seed};
use protocol::stellar_protocol::StellarProtocol;

use utils::misc::{generate_nonce, get_current_u64_milliseconds};
use serde_aux::field_attributes::deserialize_number_from_string;
#[derive(serde::Deserialize, Clone)]
pub struct Settings {
    pub application: ApplicationSettings,
}
#[derive(serde::Deserialize, Clone)]
pub struct ApplicationSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub host: String,
    pub hmac_secret: String,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let configuration_directory = base_path.join("configuration");
    let settings = config::Config::builder()
        .add_source(config::File::from(
            configuration_directory.join("mainnet.yaml"),
        ))
        .build()?;
    let node_config = settings.try_deserialize::<NodeConfig>().unwrap();


    SimpleLogger::new()
        .with_level(LevelFilter::Trace)
        .with_colors(true)
        .init()
        .unwrap();
    let keychain = Keychain::try_from(encoded_random_seed().as_str()).unwrap();
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
    info!("handshake negotiated: {:#?}", negotiated);
}