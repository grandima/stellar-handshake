mod keypair_type;
mod keypair;
mod node_config;
mod connection_authentication;
mod xdr;
mod connection;
mod remote_node_info;
mod public_key;
mod utils;

use std::io::Write;
use rand::{random, Rng, thread_rng};
use keypair::Keychain;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::connection::Connection;
use crate::xdr::constants::SEED_LENGTH;
use crate::xdr::compound_types::{LimitedVarOpaque};
use crate::xdr::messages::Hello;
use crate::xdr::streams::{ReadStream, WriteStream};
use crate::xdr::types::{XdrCoded, AuthenticatedMessage, AuthenticatedMessageV0, HmacSha256Mac, NodeId, StellarMessage};
use crate::xdr::xdr_codec::XdrCodec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use std::error::Error;
use std::thread;
use std::time::{Duration, SystemTime};
use data_encoding::BASE32;
use tokio::{join, task};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let key = "SCL4SDOGTLHEJ6OMDIMYXRC4JA75P2SY3F2X7ZJ2TMNCXT3FSJVGS2BO";
    let decoded = BASE32.decode(key.as_bytes()).unwrap();
    let version_byte = decoded[0];
    let payload = &decoded[..decoded.len()-2];
    let data = &payload[1..];
    assert_eq!(data.len(), 32);
    let mut seed = [0u8; SEED_LENGTH];
    seed.copy_from_slice(data);
    // let keypair = Keychain::from(&seed);
    let keypair = Keychain::gen();
    let node_config = NodeConfig::default();
    let mut connection = Connection::new(ConnectionAuthentication::new(keypair, node_config.network));
    let hello = Hello{
        ledger_version: node_config.node_info.ledger_version,
        overlay_version: node_config.node_info.overlay_version,
        overlay_min_version: node_config.node_info.overlay_min_version,
        network_id: connection.authentication.network_id,
        version_str: node_config.node_info.version_string,
        listening_port: node_config.listening_port,
        peer_id: NodeId::PublicKeyTypeEd25519(connection.authentication.keychain().public_key().clone()),
        cert: connection.authentication.get_auth_cert(SystemTime::now()).clone(),
        nonce: connection.local_nonce
    };
    let authenticated_message = AuthenticatedMessageV0{message: StellarMessage::Hello(hello), mac: HmacSha256Mac::default(), sequence:[0; 8]};
    let versionized_message = AuthenticatedMessage::V0(authenticated_message);
    let archived_message = XdrCoded::new(versionized_message);
    let mut  writer = WriteStream::new();
    archived_message.to_xdr_buffered(&mut writer);
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:11601").await.unwrap();
    let result = stream.write(&writer.get_result()).await.unwrap();
    let mut buffer: Vec<u8> = Vec::with_capacity(400);
    loop {
        let read_size = stream.read_buf(&mut buffer).await.unwrap();
        if read_size == 0 {
            return Ok(());
        }
        let mut read_stream = ReadStream::new(buffer.clone());
        let message = XdrCoded::<AuthenticatedMessage>::from_xdr_buffered(&mut read_stream).unwrap().value().clone();
        let message = match match message {
            AuthenticatedMessage::V0(message) => message
        }.message {
            StellarMessage::Hello(hello) => {
                hello
            }
            StellarMessage::Auth(_) => {panic!()}
        };
        connection.process_hello(message);
        let auth_message = connection.auth_message();
        let mut  writer = WriteStream::new();
        auth_message.to_xdr_buffered(&mut writer);
        let result = writer.get_result();
        let result = stream.write(&result).await.unwrap();
        buffer.clear();
        let read_result = stream.read_buf(&mut buffer).await.unwrap();
        let mut read_stream = ReadStream::new(buffer.clone());
        let message = XdrCoded::<AuthenticatedMessage>::from_xdr_buffered(&mut read_stream).unwrap().value();

        break;
    }
    Ok(())
}
