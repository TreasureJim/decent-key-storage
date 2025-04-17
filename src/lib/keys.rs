use base64::Engine;
use sha2::Digest;

pub type Key = Vec<u8>;

pub fn key_fingerprint_b64(key: &Key) -> String {
    let hash = sha2::Sha256::digest(key);
    base64::engine::general_purpose::STANDARD.encode(hash)
}
