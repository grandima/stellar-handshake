mod keypair_type;
mod keypair;
mod node_config;
mod connection_authentication;
mod xdr;
mod stellar_protocol;
mod remote_node_info;
mod public_key;
mod utils;
mod stellar;

use keypair::Keychain;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::stellar_protocol::{HandshakeMessageExtract, StellarProtocol};
use crate::xdr::constants::SEED_LENGTH;

use crate::xdr::messages::{AuthenticatedMessage, StellarMessage};
use crate::xdr::streams::{ReadStream, WriteStream};
use crate::xdr::types::{XdrSelfCoded};
use crate::xdr::xdr_codable::XdrCodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::error::Error;

use std::time::{SystemTime};
use data_encoding::BASE32;
use dryoc::rng::copy_randombytes;
use crate::utils::misc::{current_u64_milliseconds, generate_nonce, generate_secret_key};


#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let keychain = Keychain::from(&generate_secret_key());
    let node_config = NodeConfig::default();
    let mut secret_key_ecdh = [0u8; SEED_LENGTH];
    copy_randombytes(&mut secret_key_ecdh);
    let authentication = ConnectionAuthentication::new(keychain, &node_config.node_info.network_id, secret_key_ecdh);
    let mut protocol = StellarProtocol::new(node_config, generate_nonce,authentication, current_u64_milliseconds);
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:11601").await.unwrap();
    let mut write_stream = WriteStream::default();
    protocol.create_hello_message().encode(&mut write_stream);
    let _result = stream.write(&write_stream.result()).await.unwrap();
    let mut buffer: Vec<u8> = Vec::with_capacity(0x40000);
    let read_size = stream.read_buf(&mut buffer).await.unwrap();
    if read_size == 0 {
        return Ok(());
    }
    let mut read_stream = ReadStream::new(buffer.clone());
    let message = XdrSelfCoded::<AuthenticatedMessage>::decode(&mut read_stream).unwrap();
    match protocol.handle_message(&message) {
        HandshakeMessageExtract::Hello(Ok(remote_node_info)) => {
            protocol.create_auth_message(remote_node_info);
        },
        HandshakeMessageExtract::Hello(Err(_)) => {}
        HandshakeMessageExtract::Auth => {
        }
    }
    // let message = match match message {
    //     AuthenticatedMessage::V0(message) => message
    // }.message {
    //     StellarMessage::Hello(hello) => {
    //         hello
    //     }
    //     StellarMessage::Auth(_) => {panic!()}
    // };
    // connection.process_hello(message, SystemTime::now);
    // let auth_message = connection.create_auth_message();
    // let mut  writer = WriteStream::default();
    // auth_message.encode(&mut writer);
    // let result = writer.result();
    // let _result = stream.write(&result).await.unwrap();
    // buffer.clear();
    // let _read_result = stream.read_buf(&mut buffer).await.unwrap();
    // let mut read_stream = ReadStream::new(buffer.clone());
    // let _message = XdrSelfCoded::<AuthenticatedMessage>::decode(&mut read_stream).unwrap().value();
    // println!("auth received");

    Ok(())
}
