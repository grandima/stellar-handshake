use crate::xdr::constants::{PUBLIC_KEY_LENGTH, PUBLIC_KEY_VERSION_BYTE};
use crate::xdr::types::PublicKey;
use crate::utils::base32::encode;
impl PublicKey {
    pub fn to_encoding(&self) -> Vec<u8> {
        let key = self.as_binary();
        encode_stellar_key(key, PUBLIC_KEY_VERSION_BYTE)
    }
    pub fn as_binary(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        match self {
            PublicKey::PublicKeyTypeEd25519(key) => key,
        }
    }
}

pub fn encode_stellar_key<const BYTE_LENGTH: usize>(key: &[u8; BYTE_LENGTH], version_byte: u8) -> Vec<u8> {
    let mut unencoded_array = Vec::with_capacity(3 + BYTE_LENGTH);
    unencoded_array.push(version_byte);
    unencoded_array.extend(key.iter());

    let crc_value = crc(&unencoded_array);
    unencoded_array.push((crc_value & 0xff) as u8);
    unencoded_array.push((crc_value >> 8) as u8);

    encode(&unencoded_array)
}
fn crc<T: AsRef<[u8]>>(byte_array: T) -> u16 {
    let mut crc: u16 = 0;
    for byte in byte_array.as_ref().iter() {
        let mut code: u16 = crc >> 8 & 0xff;
        code ^= *byte as u16;
        code ^= code >> 4;
        crc <<= 8;
        crc ^= code;
        code <<= 5;
        crc ^= code;
        code <<= 7;
        crc ^= code;
    }
    crc
}
