use rand::random;
use sha2::{Sha256, Digest};

pub struct Connection {

}
impl Connection {

    //TODO: generate actual nonce
    pub fn local_nonce(&self) -> [u8; 32] {
        // let nonce = [48, 46, 53, 55, 55, 49, 53, 55, 48, 53, 51, 48, 53, 51, 55, 48, 50, 54, 48, 55, 50, 56];
        let nonce = random::<u64>().to_be_bytes();
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        let mut hashed_nonce = [0u8; 32];
        hashed_nonce.copy_from_slice(&hasher.finalize().to_vec());
        hashed_nonce
    }
}