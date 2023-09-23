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
    let cert = authentication.create_auth_cert_from_milisec(1695381410943u64);

    let version_str: LimitedVarOpaque<100> = LimitedVarOpaque::new("v19.13.0".as_bytes().to_vec()).unwrap();
    let nonce = Connection{}.local_nonce();
    let mut  writer = WriteStream::new();
    let hello = Hello{ledger_version: 17, overlay_version: 29, overlay_min_version: 17, network_id: authentication.network_id, version_str, listening_port: 11625, peer_id: NodeId::PublicKeyTypeEd25519(keypair.public_key().clone()), cert, nonce };
    let authenticated_hello = AuthenticatedMessage::V0(AuthenticatedMessageV0::new(StellarMessage::Hello(hello)));
    // println!("authenticated hello {:?}", authenticated_hello);
    authenticated_hello.to_xdr_buffered(&mut writer);
    let result = writer.get_result();
    println!("authenticated_hello {:?}", result);
    let arr = [0u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,13,0,0,0,17,0,0,0,29,0,0,0,17,206,224,48,45,89,132,77,50,189,202,145,92,130,3,221,68,179,63,187,126,220,25,5,30,163,122,190,223,40,236,212,114,0,0,0,8,118,49,57,46,49,51,46,48,0,0,45,105,0,0,0,0,94,185,132,102,34,186,253,6,107,246,184,78,220,234,85,192,79,7,68,232,159,65,86,224,60,38,181,210,114,163,82,96,154,54,113,207,47,196,214,230,242,68,0,142,85,93,76,232,22,114,238,44,53,225,230,200,49,44,16,223,225,87,127,108,0,0,1,138,188,160,210,191,0,0,0,64,139,252,205,34,5,42,185,53,35,206,135,228,10,90,225,121,57,239,152,204,38,23,12,5,187,192,70,43,204,216,154,110,173,67,81,50,168,239,54,218,28,59,118,30,191,249,145,201,37,161,116,85,158,163,120,131,86,113,83,54,183,82,4,2,203,152,39,187,94,33,163,168,66,15,252,122,18,204,94,79,85,172,142,17,209,95,35,107,121,63,197,108,153,198,232,44,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    assert_eq!(result, arr);
    println!("authenticated_hello len {:?}", result.len());
}
