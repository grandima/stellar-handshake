mod keypair_type;
mod keypair;
mod node_config;
mod connection_authentication;
mod xdr;
mod connection;

use std::io::Write;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use data_encoding::BASE32;
use rand::{random, Rng, thread_rng};
use keypair::Keypair;
use node_config::NodeConfig;
use connection_authentication::*;
use crate::connection::Connection;
use crate::keypair::ED25519_SECRET_SEED_BYTE_LENGTH;
use crate::xdr::compound_types::LimitedVarOpaque;
use crate::xdr::hello::Hello;
use crate::xdr::streams::WriteStream;
use crate::xdr::types::{AuthenticatedMessage, AuthenticatedMessageV0, NodeId, StellarMessage};
use crate::xdr::xdr_codec::XdrCodec;

fn main() {
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

    let version_str: LimitedVarOpaque<100> = LimitedVarOpaque::new("v19.13.0".as_bytes().to_vec()).unwrap();
    let nonce = Connection{}.local_nonce();
    let mut  writer = WriteStream::new();
    let hello = Hello{ledger_version: 17, overlay_version: 29, overlay_min_version: 17, network_id: authentication.network_id, version_str, listening_port: 11602, peer_id: NodeId::PublicKeyTypeEd25519(keypair.public_key().clone()), cert, nonce };
    let authenticated_hello = AuthenticatedMessage::V0(AuthenticatedMessageV0::new(StellarMessage::Hello(hello)));
    // println!("authenticated hello {:?}", authenticated_hello);
    authenticated_hello.to_xdr_buffered(&mut writer);
    let result = writer.get_result();
    println!("authenticated_hello_arr {:?}", result);
    println!("authenticated_hello len {:?}", result.len());
    let mut  writer = WriteStream::new();
    writer.write_next_u32(result.len() as u32);
    let mut message_buff = writer.get_result();
    message_buff.extend(result.iter());
    let mut tcp_stream = TcpStream::connect("127.0.0.1:11601").unwrap();
    tcp_stream.write(&message_buff);
}
