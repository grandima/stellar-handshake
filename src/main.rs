mod keypair_type;
mod keypair;
mod node_config;
mod connection_authentication;

use data_encoding::BASE32;
use keypair::Keypair;
use node_config::NodeConfig;
use connection_authentication::*;
fn main() {
    let key = "SCL4SDOGTLHEJ6OMDIMYXRC4JA75P2SY3F2X7ZJ2TMNCXT3FSJVGS2BO";
    let decoded = BASE32.decode(key.as_bytes()).expect("Failed to decode");
    let version_byte = decoded[0];
    let payload = &decoded[..decoded.len()-2];
    let data = &payload[1..];
    println!("Data: {:?}", data);
    let keypair = Keypair::from(data);
    let node_config = NodeConfig::default();
    let authentication = ConnectionAuthentication::new(keypair, node_config.network);
    println!("Keypair: {:?}", authentication);

}
