use rand::random;
use sha2::{Sha256, Digest};

pub struct Connection {

}
impl Connection {

    //TODO: generate actual nonce
    pub fn local_nonce(&self) -> [u8; 32] {
        let nonce = random::<u32>().to_be_bytes();
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        let mut hashed_nonce = [0u8; 32];
        hashed_nonce.copy_from_slice(&hasher.finalize().to_vec());
        hashed_nonce
    }
}