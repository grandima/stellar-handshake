mod keypair_type;
mod keypair;
mod node_config;
mod connection_authentication;
mod xdr;
mod connection;
mod remote_node_info;
mod public_key;
mod utils;

use keypair::Keychain;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::connection::Connection;
use crate::xdr::constants::SEED_LENGTH;

use crate::xdr::messages::{AuthenticatedMessage, AuthenticatedMessageV0, Hello, StellarMessage};
use crate::xdr::streams::{ReadStream, WriteStream};
use crate::xdr::types::{XdrSelfCoded, HmacSha256Mac, NodeId};
use crate::xdr::xdr_codec::XdrCodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::error::Error;

use std::time::{SystemTime};
use data_encoding::BASE32;
use dryoc::rng::copy_randombytes;
use crate::utils::misc::generate_secret_key;


#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let key = "SCL4SDOGTLHEJ6OMDIMYXRC4JA75P2SY3F2X7ZJ2TMNCXT3FSJVGS2BO";
    let decoded = BASE32.decode(key.as_bytes()).unwrap();
    let _version_byte = decoded[0];
    let payload = &decoded[..decoded.len()-2];
    let data = &payload[1..];
    assert_eq!(data.len(), 32);
    let mut seed = [0u8; SEED_LENGTH];
    seed.copy_from_slice(data);
    // let keypair = Keychain::from(&seed);
    let keypair = Keychain::from(&generate_secret_key());
    let node_config = NodeConfig::default();
    let mut secret_key_ecdh = [0u8; SEED_LENGTH];
    copy_randombytes(&mut secret_key_ecdh);
    let authentication = ConnectionAuthentication::new(keypair, &node_config.node_info.network_id, secret_key_ecdh);
    let mut connection = Connection::new(node_config, authentication);

    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:11601").await.unwrap();
    let mut write_stream = WriteStream::default();
    connection.create_hello_message().encode(&mut write_stream);
    let _result = stream.write(&write_stream.result()).await.unwrap();
    let mut buffer: Vec<u8> = Vec::with_capacity(0x40000);
    loop {
        let read_size = stream.read_buf(&mut buffer).await.unwrap();
        if read_size == 0 {
            return Ok(());
        }
        let mut read_stream = ReadStream::new(buffer.clone());
        let message = XdrSelfCoded::<AuthenticatedMessage>::decode(&mut read_stream).unwrap().value().clone();
        let message = match match message {
            AuthenticatedMessage::V0(message) => message
        }.message {
            StellarMessage::Hello(hello) => {
                hello
            }
            StellarMessage::Auth(_) => {panic!()}
        };
        connection.process_hello(message, ||SystemTime::now());
        let auth_message = connection.create_auth_message();
        let mut  writer = WriteStream::default();
        auth_message.encode(&mut writer);
        let result = writer.result();
        let _result = stream.write(&result).await.unwrap();
        buffer.clear();
        let _read_result = stream.read_buf(&mut buffer).await.unwrap();
        let mut read_stream = ReadStream::new(buffer.clone());
        let _message = XdrSelfCoded::<AuthenticatedMessage>::decode(&mut read_stream).unwrap().value();
        println!("auth received");
        break;
    }
    Ok(())
}
