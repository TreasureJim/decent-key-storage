use anyhow::Context;
use base64::Engine;
use pkcs8::der::pem::PemLabel;
use pkcs8::der::{Encode, EncodePem};
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tonic::transport::{CertificateDer, Identity};
use uuid::Uuid;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::X509Certificate;

use crate::keys::{NodeInfo, CertWithMetadata, CertificateData};

#[derive(Debug)]
pub struct KeyStorage {
    storage_dir: PathBuf,
    node_info: HashMap<uuid::Uuid, NodeInfo>,
    cert_data: HashMap<uuid::Uuid, CertificateData>,
    // Used for quickly checking if the store includes a certificate
    cert_map: HashMap<CertificateData, uuid::Uuid>,
}

#[derive(Debug, Error)]
pub enum KeyStorageError {
    #[error("Storage directory error: {0}")]
    DirectoryError(#[from] std::io::Error),

    #[error("Certificate {0} not found")]
    CertificateNotFound(Uuid),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid pem certificate file: {0:?}")]
    InvalidPemFile(#[from] pem::PemError),

    #[error("Invalid certificate data from {0}: {1}")]
    InvalidCertificateData(Uuid, x509_parser::error::X509Error),

    #[error("Certificate already exists: {0}")]
    DuplicateCertificate(Uuid),

    #[error("Certificate file missing for {0}")]
    MissingCertificateFile(Uuid),
}

impl KeyStorage {
    /// Initialize and load all certificate data
    pub fn new(storage_dir: impl AsRef<Path>) -> Result<Self, KeyStorageError> {
        let storage_dir = storage_dir.as_ref().to_path_buf();

        // Create directories if they don't exist
        fs::create_dir_all(&storage_dir)?;
        fs::create_dir_all(storage_dir.join("certs"))?;

        // Load metadata
        let certificates = if storage_dir.join("certs.json").exists() {
            Self::load_metadata(&storage_dir)?
        } else {
            HashMap::new()
        };

        // Pre-load all certificate data
        let mut cert_data = HashMap::new();
        let mut cert_map = HashMap::new();
        for (uuid, _) in &certificates {
            let data = Self::load_cert_file(&storage_dir, *uuid)?;
            cert_map.insert(data.clone(), *uuid);
            cert_data.insert(*uuid, data);
        }

        Ok(Self {
            storage_dir,
            node_info: certificates,
            cert_data,
            cert_map,
        })
    }

    /// Add a new certificate (saves to disk immediately)
    pub fn add_certificate(
        &mut self,
        uuid: Uuid,
        raw_cert: CertificateData,
        received_at: std::time::SystemTime,
    ) -> Result<(), KeyStorageError> {
        if self.node_info.contains_key(&uuid) {
            return Err(KeyStorageError::DuplicateCertificate(uuid));
        }

        let cert_path = self.cert_path(uuid);

        // Store to disk first
        {
            fs::write(&cert_path, raw_cert.to_pem())?;
        }

        // Update in-memory state
        let cert = NodeInfo {
            uuid,
            cert_path,
            received_at,
        };

        self.node_info.insert(uuid, cert);
        self.cert_data.insert(uuid, raw_cert);
        self.save_metadata()?;

        Ok(())
    }

    // Get certificate data (already loaded)
    pub fn get_cert_data(&self, uuid: Uuid) -> Result<&CertificateData, KeyStorageError> {
        self.cert_data
            .get(&uuid)
            .ok_or(KeyStorageError::CertificateNotFound(uuid))
    }

    // List all certificate UUIDs
    pub fn list_certificates(&self) -> Vec<Uuid> {
        self.node_info.keys().cloned().collect()
    }

    pub fn get_certificates(&self) -> Vec<CertWithMetadata> {
        self.cert_map.iter().map(|(cert, uuid)| {
            let metadata = self
                .node_info
                .get(uuid)
                .expect("Cert store had metadata loaded but not cert");

            CertWithMetadata {
                cert,
                metadata
            }
        }).collect()
    }

    // Confirm existence of certificate
    pub fn have_tonic_certificate(&self, cert: &tonic::transport::CertificateDer<'_>) -> bool {
        self.cert_map
            .contains_key(&CertificateData::new_no_validation(cert))
    }

    // Private helpers

    fn cert_path(&self, uuid: Uuid) -> PathBuf {
        self.storage_dir.join("certs").join(format!("{}.pem", uuid))
    }

    fn load_metadata(storage_dir: &Path) -> Result<HashMap<Uuid, NodeInfo>, KeyStorageError> {
        let metadata_path = storage_dir.join("certs.json");
        if !metadata_path.exists() {
            return Ok(HashMap::new());
        }

        let file = fs::File::open(metadata_path)?;
        let mut certs: HashMap<Uuid, NodeInfo> = serde_json::from_reader(file)?;

        // Rebuild paths for loaded certificates
        for (uuid, cert) in certs.iter_mut() {
            cert.cert_path = storage_dir.join("certs").join(format!("{}.pem", uuid));
        }

        Ok(certs)
    }

    fn load_cert_file(storage_dir: &Path, uuid: Uuid) -> Result<CertificateData, KeyStorageError> {
        let cert_path = storage_dir.join("certs").join(format!("{}.pem", uuid));
        if !cert_path.exists() {
            return Err(KeyStorageError::MissingCertificateFile(uuid));
        }

        let pem_string = fs::read(&cert_path)?;
        Ok(CertificateData::from_pem(pem_string)?)
    }

    fn save_metadata(&self) -> Result<(), KeyStorageError> {
        let metadata_path = self.storage_dir.join("certs.json");
        let file = fs::File::create(metadata_path)?;
        serde_json::to_writer_pretty(file, &self.node_info)?;
        Ok(())
    }
}

const KEY_FILE_NAME: &str = "key.pem";
const CERT_FILE_NAME: &str = "cert.pem";

pub fn create_self_signed_keys(folder: &Path) -> anyhow::Result<Identity> {
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(&[]).unwrap();

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Ensure folder exists (or create it)
    std::fs::create_dir_all(folder)?;

    {
        // Write private key (with restricted permissions)
        let secret_path = folder.join(KEY_FILE_NAME);
        std::fs::write(&secret_path, &key_pem)?;
        #[cfg(unix)]
        std::fs::set_permissions(secret_path, std::fs::Permissions::from_mode(0o600))?;
    }

    {
        // Write public key
        std::fs::write(folder.join(CERT_FILE_NAME), &cert_pem)?;
    }

    Ok(Identity::from_pem(cert_pem, key_pem))
}

pub fn read_self_signed_keys(folder: &Path) -> Result<Identity, std::io::Error> {
    let cert = {
        let path = folder.join(CERT_FILE_NAME);
        std::fs::read_to_string(path)?
    };
    let key = {
        let path = folder.join(KEY_FILE_NAME);
        std::fs::read_to_string(path)?
    };

    Ok(Identity::from_pem(cert, key))
}
