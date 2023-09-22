mod keypair_type;
mod keypair;
mod node_config;
mod connection_authentication;
mod xdr;
mod connection;

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use data_encoding::BASE32;
use keypair::Keypair;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::xdr::hello::Hello;
use crate::xdr::streams::WriteStream;
use crate::xdr::xdr_codec::XdrCodec;

fn main() {
    let key = "SCL4SDOGTLHEJ6OMDIMYXRC4JA75P2SY3F2X7ZJ2TMNCXT3FSJVGS2BO";
    let decoded = BASE32.decode(key.as_bytes()).expect("Failed to decode");
    let version_byte = decoded[0];
    let payload = &decoded[..decoded.len()-2];
    let data = &payload[1..];
    let keypair = Keypair::from(data);
    let node_config = NodeConfig::default();
    let mut authentication = ConnectionAuthentication::new(keypair, node_config.network);
    let validAt = SystemTime::now();
    let keypair = authentication.keypair.clone();
    println!("keypair {:?}", keypair);
    let cert = authentication.create_auth_cert_from_milisec(1695381410943u64);

    // let hello = Hello{}

    println!("cert {:?}", cert);

}
