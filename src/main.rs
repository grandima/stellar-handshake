mod keypair_type;
mod keypair;
mod node_config;
mod connection_authentication;
mod xdr;
mod connection;

use std::io::Write;

use rand::{random, Rng, thread_rng};
use keypair::Keypair;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::connection::Connection;
use crate::xdr::constants::ED25519_SECRET_SEED_BYTE_LENGTH;
use crate::xdr::compound_types::{LimitedVarOpaque, UnlimitedVarOpaque};
use crate::xdr::hello::Hello;
use crate::xdr::streams::WriteStream;
use crate::xdr::types::{AuthenticatedMessage, AuthenticatedMessageV0, NodeId, StellarMessage};
use crate::xdr::xdr_codec::XdrCodec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::error::Error;
use std::time::SystemTime;
use data_encoding::BASE32;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let key = "SCL4SDOGTLHEJ6OMDIMYXRC4JA75P2SY3F2X7ZJ2TMNCXT3FSJVGS2BO";
    let decoded = BASE32.decode(key.as_bytes()).expect("Failed to decode");
    let version_byte = decoded[0];
    let payload = &decoded[..decoded.len()-2];
    let data = &payload[1..];
    assert_eq!(data.len(), 32);
    let mut seed = [0u8; ED25519_SECRET_SEED_BYTE_LENGTH];
    seed.copy_from_slice(data);
    let keypair = Keypair::from(seed);
    let node_config = NodeConfig::default();
    let mut authentication = ConnectionAuthentication::new(keypair, node_config.network);
    let validAt = SystemTime::now();
    let keypair = authentication.keypair.clone();
    // println!("keypair {:?}", keypair);
    let cert = authentication.get_auth_cert(SystemTime::now());

    let version_str = LimitedVarOpaque::<100>::new("v19.13.0".as_bytes().to_vec()).unwrap();
    let nonce = Connection::new().local_nonce();
    let mut  writer = WriteStream::new();
    let hello = Hello{
        ledger_version: node_config.node_info.ledger_version,
        overlay_version: node_config.node_info.overlay_version,
        overlay_min_version: node_config.node_info.overlay_min_version,
        network_id: authentication.network_id,
        version_str: node_config.node_info.version_string,
        listening_port: node_config.listening_port,
        peer_id: NodeId::PublicKeyTypeEd25519(keypair.public_key().clone()),
        cert,
        nonce
    };
    let authenticated_hello = AuthenticatedMessage::V0(AuthenticatedMessageV0::new(StellarMessage::Hello(hello)));
    // println!("authenticated hello {:?}", authenticated_hello);
    authenticated_hello.to_xdr_buffered(&mut writer);
    let result = writer.get_result();
    println!("authenticated_hello_arr {:?}", result);
    println!("authenticated_hello len {:?}", result.len());
    let message_buff = UnlimitedVarOpaque::new(result).unwrap();
    let mut  writer = WriteStream::new();
    message_buff.to_xdr_buffered(&mut writer);
    let mut tcp_stream = tokio::net::TcpStream::connect("127.0.0.1:11601").await.unwrap();
    tcp_stream.write(&writer.get_result()).await.unwrap();
    Ok(())

}
