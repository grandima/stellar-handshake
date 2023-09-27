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
use keypair::Keypair;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::connection::Connection;
use crate::xdr::constants::ED25519_SECRET_SEED_BYTE_LENGTH;
use crate::xdr::compound_types::{LimitedVarOpaque, UnlimitedVarOpaque};
use crate::xdr::stellar_messages::Hello;
use crate::xdr::streams::{ReadStream, WriteStream};
use crate::xdr::types::{ArchivedMessage, AuthenticatedMessage, AuthenticatedMessageV0, NodeId, StellarMessage};
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
    let mut seed = [0u8; ED25519_SECRET_SEED_BYTE_LENGTH];
    seed.copy_from_slice(data);
    let keypair = Keypair::from(seed);
    let node_config = NodeConfig::default();
    let mut connection = Connection::new(ConnectionAuthentication::new(keypair, node_config.network));
    let hello = Hello{
        ledger_version: node_config.node_info.ledger_version,
        overlay_version: node_config.node_info.overlay_version,
        overlay_min_version: node_config.node_info.overlay_min_version,
        network_id: connection.authentication.network_id,
        version_str: node_config.node_info.version_string,
        listening_port: node_config.listening_port,
        peer_id: NodeId::PublicKeyTypeEd25519(connection.authentication.keypair().public_key().clone()),
        cert: connection.authentication.get_auth_cert(SystemTime::now()).clone(),
        nonce: connection.local_nonce
    };
    let authenticated_message = AuthenticatedMessageV0::new(StellarMessage::Hello(hello));
    let versionized_message = AuthenticatedMessage::V0(authenticated_message);
    let vec_to_compare = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,13,0,0,0,17,0,0,0,29,0,0,0,17,206,224,48,45,89,132,77,50,189,202,145,92,130,3,221,68,179,63,187,126,220,25,5,30,163,122,190,223,40,236,212,114,0,0,0,8,118,49,57,46,49,51,46,48,0,0,45,82,0,0,0,0,94,185,132,102,34,186,253,6,107,246,184,78,220,234,85,192,79,7,68,232,159,65,86,224,60,38,181,210,114,163,82,96,154,54,113,207,47,196,214,230,242,68,0,142,85,93,76,232,22,114,238,44,53,225,230,200,49,44,16,223,225,87,127,108,0,0,1,138,209,81,164,157,0,0,0,64,180,74,25,218,117,74,93,94,120,20,60,246,51,20,242,13,121,113,141,178,213,249,127,173,27,16,247,43,58,197,193,144,86,195,68,122,47,54,190,140,206,183,56,85,106,104,119,212,79,200,195,20,248,208,95,242,179,179,29,178,175,57,234,8,203,152,39,187,94,33,163,168,66,15,252,122,18,204,94,79,85,172,142,17,209,95,35,107,121,63,197,108,153,198,232,44,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    // assert!(versionized_message.compare(&vec_to_compare));
    let archived_message = ArchivedMessage::new(versionized_message);
    let mut  writer = WriteStream::new();
    archived_message.to_xdr_buffered(&mut writer);
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:11601").await.unwrap();
    let result = stream.write(&writer.get_result()).await.unwrap();
    let mut buffer: Vec<u8> = Vec::with_capacity(400);
    loop {
        let read_size = stream.read_buf(&mut buffer).await.unwrap_or_else(|error| {
            println!("Read error: {:?}", error);
            0
        });
        println!("read size: {:?}", read_size);
        if read_size == 0 {
            return Ok(());
        }
        let mut read_stream = ReadStream::new(buffer.clone());
        println!("read buff start: {:?}", read_stream.get_source());
        // let mut length_buff = read_stream.read_next_binary_data(4).unwrap();
        // let mut length = u32::from_be_bytes([buffer[0] & 0x7f, buffer[1], buffer[2], buffer[3]]);
        let message = ArchivedMessage::<AuthenticatedMessage>::from_xdr_buffered(&mut read_stream).unwrap().message;
        let message = match match message {
            AuthenticatedMessage::V0(message) => message
        }.message {
            StellarMessage::Hello(hello) => {hello}
            StellarMessage::Auth(_) => {panic!()}
        };
        // connection.remoteNonce = Some(message.nonce.clone());

        println!("{:?}", message);
        // let Some(mut message) = message.take() else {
        //     continue
        // };
    }

    Ok(())
}
