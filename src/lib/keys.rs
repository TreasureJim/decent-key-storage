use anyhow::Result;
use pem::Pem;
use std::{
    net::SocketAddr,
    ops::Deref,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::Engine;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tonic::transport::CertificateDer;
use uuid::Uuid;

use crate::key_storage::KeyStorage;

pub fn key_fingerprint_b64(key: impl AsRef<[u8]>) -> String {
    let hash = sha2::Sha256::digest(key);
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Represents a private key and X509 certificate.
#[derive(Debug, Clone)]
pub struct Identity {
    pub cert: tonic::transport::Certificate,
    pub key: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Self {
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(&[]).unwrap();

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        Self::from_pem(cert_pem, key_pem)
    }

    const KEY_FILE_NAME: &str = "key.pem";
    const CERT_FILE_NAME: &str = "cert.pem";

    pub fn save_to_folder(&self, folder: &Path) -> anyhow::Result<()> {
        // Ensure folder exists (or create it)
        std::fs::create_dir_all(folder)?;

        {
            // Write private key (with restricted permissions)
            let secret_path = folder.join(Self::KEY_FILE_NAME);
            std::fs::write(&secret_path, &self.key)?;
            #[cfg(unix)]
            std::fs::set_permissions(secret_path, std::fs::Permissions::from_mode(0o600))?;
        }

        {
            // Write public key
            std::fs::write(folder.join(Self::CERT_FILE_NAME), Pem::new("CERTIFICATE", self.cert.as_ref()).to_string())?;
        }

        Ok(())
    }

    pub fn read_from_folder(folder: &Path) -> Result<Identity, std::io::Error> {
        let cert = {
            let path = folder.join(Self::CERT_FILE_NAME);
            std::fs::read_to_string(path)?
        };
        let key = {
            let path = folder.join(Self::KEY_FILE_NAME);
            std::fs::read_to_string(path)?
        };

        Ok(Identity::from_pem(cert, key))
    }

    /// Parse a PEM encoded certificate and private key.
    ///
    /// The provided cert must contain at least one PEM encoded certificate.
    pub fn from_pem(cert: impl AsRef<[u8]>, key: impl AsRef<[u8]>) -> Self {
        let cert = tonic::transport::Certificate::from_pem(cert);
        let key = key.as_ref().into();
        Self { cert, key }
    }
}

impl Into<tonic::transport::Identity> for Identity {
    fn into(self) -> tonic::transport::Identity {
        tonic::transport::Identity::from_pem(self.cert, self.key)
    }
}

#[derive(Debug)]
pub struct CertWithMetadata<'a> {
    pub cert: &'a Arc<CertificateData>,
    pub metadata: &'a NodeInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub uuid: Uuid,
    #[serde(skip)]
    pub cert_path: PathBuf, // Will be derived from uuid
    pub received_at: std::time::SystemTime,
    pub sock_addr: SocketAddr,
    // signed_by: Option<SignatureInfo>,  // To be implemented later
}

impl NodeInfo {
    pub fn new(
        uuid: Uuid,
        cert_path: PathBuf,
        received_at: std::time::SystemTime,
        sock_addr: SocketAddr,
    ) -> Self {
        Self {
            uuid,
            cert_path,
            received_at,
            sock_addr,
        }
    }
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
            raw_der: der.to_vec(),
        }
    }

    pub fn to_pem(&self) -> String {
        let pem = pem::Pem::new("CERTIFICATE", self.raw_der.clone());
        pem::encode(&pem)
    }

    pub fn from_pem(s: impl AsRef<[u8]>) -> Result<Self, pem::PemError> {
        let pem = pem::parse(s)?;
        Ok(Self {
            raw_der: pem.into_contents(),
        })
    }

    pub fn to_tonic_cert(&self) -> tonic::transport::Certificate {
        tonic::transport::Certificate::from_pem(&self.to_pem())
    }

    fn validate_certificate_data<'a>(
        raw_cert: impl Into<&'a [u8]>,
    ) -> Result<(), x509_parser::error::X509Error> {
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

impl TryFrom<Vec<u8>> for CertificateData {
    type Error = x509_parser::error::X509Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::validate_certificate_data(&*value)?;
        Ok(Self { raw_der: value })
    }
}

pub fn save_tonic_certificate(
    key_storage: &mut KeyStorage,
    cert: crate::protocol::proto::share_cert::response_certificates::Certificate,
) -> anyhow::Result<()> {
    key_storage.add_certificate(
        cert.uuid.parse()?,
        cert.cert.try_into()?,
        std::time::SystemTime::now(),
        cert.socket.parse()?,
    )?;
    Ok(())
}
