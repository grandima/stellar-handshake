use rand::random;
use sha2::{Sha256, Digest};

pub struct Connection {
    local_nonce: [u8; 32]
}
impl Connection {
    pub fn new() -> Self {
        // let nonce = random::<u32>().to_be_bytes();
        let nonce = [
            48, 46, 53, 55, 55, 49, 53, 55, 48, 53, 51, 48, 53, 51, 55, 48, 50, 54, 48, 55, 50, 56
        ];
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        let mut local_nonce = [0u8; 32];
        local_nonce.copy_from_slice(&hasher.finalize().to_vec());
        Self {local_nonce}
    }

    pub fn local_nonce(&self) -> [u8; 32] {
        self.local_nonce.clone()
    }
}