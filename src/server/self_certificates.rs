use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertificateErrors {
    #[error("Decoding public key")]
    DecodingPublicKey,
}

pub fn read_certificates(folder: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let folder = PathBuf::from(folder);

    let cert = {
        let mut path = folder.clone();
        path.push("cert.pem");
        std::fs::read_to_string(path)?
    };
    let key = {
        let mut path = folder.clone();
        path.push("key.pem");
        std::fs::read_to_string(path)?
    };
    Ok(())
}
