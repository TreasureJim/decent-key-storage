use std::path::{Path, PathBuf};

use pem::PemError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertificateErrors {
    #[error("Error reading the certificate file: {0:?}")]
    IOError(std::io::Error),
    #[error("Decoding public key")]
    BadKey,
}

pub fn read_certificates(folder: &Path) -> Result<(), CertificateErrors> {
    let folder = PathBuf::from(folder);

    let cert = {
        let mut path = folder.clone();
        path.push("cert.pem");
        std::fs::read_to_string(path).map_err(|e| CertificateErrors::IOError(e))?
    };
    let key = {
        let mut path = folder.clone();
        path.push("key.pem");
        std::fs::read_to_string(path).map_err(|e| CertificateErrors::IOError(e))?
    };

    let cert = x509_parser::pem::parse_x509_pem(cert.as_bytes())
        .map_err(|e| CertificateErrors::BadKey)?
        .1
        .parse_x509()
        .map_err(|e| CertificateErrors::BadKey)?;

    cert.issuer_uid
}
