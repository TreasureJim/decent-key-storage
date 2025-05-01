use std::{ops::Deref, path::PathBuf};

use base64::Engine;
use serde::{Serialize, Deserialize};
use sha2::Digest;
use tonic::transport::CertificateDer;
use uuid::Uuid;

pub fn key_fingerprint_b64(key: impl AsRef<[u8]>) -> String {
    let hash = sha2::Sha256::digest(key);
    base64::engine::general_purpose::STANDARD.encode(hash)
}

#[derive(Debug)]
pub struct CertWithMetadata<'a> {
    pub cert: &'a CertificateData,
    pub metadata: &'a NodeInfo
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub uuid: Uuid,
    #[serde(skip_serializing)]
    pub cert_path: PathBuf,  // Will be derived from uuid
    pub received_at: std::time::SystemTime,
    // signed_by: Option<SignatureInfo>,  // To be implemented later
}

pub trait HasKey {
    fn have_tonic_certificate(&self, cert: &tonic::transport::CertificateDer<'_>) -> bool;
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct CertificateData {
    raw_der: Vec<u8>,
}

impl CertificateData {
    pub fn new(der: &CertificateDer<'_>) -> Result<Self, x509_parser::error::X509Error> {
        Self::validate_certificate_data(&**der)?;
        Ok(Self::new_no_validation(der))
    }

    pub fn new_no_validation(der: &CertificateDer<'_>) -> Self {
        Self {
            raw_der: der.to_vec()
        }
    }

    pub fn to_pem(&self) -> String {
        let pem = pem::Pem::new("CERTIFICATE", self.raw_der.clone());
        pem::encode(&pem)
    }

    pub fn from_pem(s: impl AsRef<[u8]>) -> Result<Self, pem::PemError> {
        let pem = pem::parse(s)?;
        Ok(
            Self {
                raw_der: pem.into_contents()
            }
        )
        
    }

    pub fn to_tonic_cert(&self) -> tonic::transport::Certificate {

        tonic::transport::Certificate::from_pem(&self.to_pem())
    }

    fn validate_certificate_data<'a>(raw_cert: impl Into<&'a [u8]>) -> Result<(), x509_parser::error::X509Error> {
        x509_parser::parse_x509_certificate(raw_cert.into())?;
        Ok(())
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw_der
    }
}

impl<'a> Deref for CertificateData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &*self.raw_der
    }
}
