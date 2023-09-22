mod keypair_type;
mod keypair;
mod node_config;
mod connection_authentication;
mod xdr;

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use data_encoding::BASE32;
use keypair::Keypair;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::xdr::streams::WriteStream;
use crate::xdr::xdr_codec::XdrCodec;

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
    let validAt = SystemTime::now();
    let since_the_epoch = validAt.duration_since(UNIX_EPOCH)
        .expect("Time went backwards").as_millis();

    let timestamp = 1695381410943u64 + ConnectionAuthentication::AUTH_EXPIRATION_LIMIT as u64;//u64::try_from(since_the_epoch).expect("number is greater");
    println!("timestamp original {:?}", timestamp);
    let mut ws = WriteStream::new();
    let mut bytes = Vec::new();

    bytes.write_all(&timestamp.to_be_bytes()).unwrap();
    timestamp.to_be_bytes().to_xdr_buffered(&mut ws);
    let xdr_result = ws.get_result();
    let cert = authentication.create_auth_cert_from_milisec(1695381410943u64);
    println!("cert {:?}", cert);

}
