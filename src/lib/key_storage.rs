use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::{
    collections::HashMap, fs, path::{Path, PathBuf}
};
use thiserror::Error;
use tonic::transport::{CertificateDer, Identity};
use x509_parser::prelude::X509Certificate;

use crate::keys::{CertificateData, NodeCertificate};


#[derive(Debug)]
pub struct KeyStorage {
    storage_dir: PathBuf,
    certificates: HashMap<uuid::Uuid, NodeCertificate>,
    cert_data: HashMap<uuid::Uuid, CertificateData>,
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
        for (uuid, _) in &certificates {
            let data = Self::load_cert_file(&storage_dir, *uuid)?;
            cert_data.insert(*uuid, data);
        }
        
        Ok(Self {
            storage_dir,
            certificates,
            cert_data,
        })
    }
    
    /// Add a new certificate (saves to disk immediately)
    pub fn add_certificate(
        &mut self,
        uuid: Uuid,
        raw_cert: CertificateData,
        received_at: std::time::SystemTime,
    ) -> Result<(), KeyStorageError> {
        if self.certificates.contains_key(&uuid) {
            return Err(KeyStorageError::DuplicateCertificate(uuid));
        }
        
        let cert_path = self.cert_path(uuid);

        // Store to disk first
        {
            fs::write(&cert_path, raw_cert.to_pem())?;
        }
        
        // Update in-memory state
        let cert = NodeCertificate {
            uuid,
            cert_path,
            received_at,
        };
        
        self.certificates.insert(uuid, cert);
        self.cert_data.insert(uuid, raw_cert);
        self.save_metadata()?;
        
        Ok(())
    }
    
    // Get certificate metadata
    pub fn get_certificate(&self, uuid: Uuid) -> Result<&NodeCertificate, KeyStorageError> {
        self.certificates.get(&uuid)
            .ok_or(KeyStorageError::CertificateNotFound(uuid))
    }
    
    // Get certificate data (already loaded)
    pub fn get_cert_data(&self, uuid: Uuid) -> Result<&CertificateData, KeyStorageError> {
        self.cert_data.get(&uuid)
            .ok_or(KeyStorageError::CertificateNotFound(uuid))
    }
    
    // List all certificate UUIDs
    pub fn list_certificates(&self) -> Vec<Uuid> {
        self.certificates.keys().cloned().collect()
    }

    // Private helpers
    
    fn cert_path(&self, uuid: Uuid) -> PathBuf {
        self.storage_dir.join("certs").join(format!("{}.pem", uuid))
    }
    
    fn load_metadata(storage_dir: &Path) -> Result<HashMap<Uuid, NodeCertificate>, KeyStorageError> {
        let metadata_path = storage_dir.join("certs.json");
        if !metadata_path.exists() {
            return Ok(HashMap::new());
        }
        
        let file = fs::File::open(metadata_path)?;
        let mut certs: HashMap<Uuid, NodeCertificate> = serde_json::from_reader(file)?;
        
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
        serde_json::to_writer_pretty(file, &self.certificates)?;
        Ok(())
    }
}

const KEY_FILE_NAME: &str = "key.pem";
const CERT_FILE_NAME: &str = "cert.pem";

pub fn create_self_signed_keys(folder: &Path) -> anyhow::Result<Identity> {
    let mut csprng = rand_core::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let key_bytes = key.to_keypair_bytes();

    // confirm folder exists
    if !std::fs::exists(folder).unwrap_or(false) {
        return Err(anyhow::anyhow!("Folder {:?} does not exist.", &folder));
    }

    let secret_bytes = &key_bytes[..ed25519_dalek::SECRET_KEY_LENGTH];
    {
        let path = folder.join(KEY_FILE_NAME);

        let secret_pem = pem::Pem::new("PRIVATE KEY", secret_bytes);
        std::fs::write(path, pem::encode(&secret_pem))?;
    }

    let public_bytes = &key_bytes[ed25519_dalek::SECRET_KEY_LENGTH..];
    {
        let path = folder.join(CERT_FILE_NAME);

        let public_pem = pem::Pem::new("CERTIFICATE", public_bytes);
        std::fs::write(path, pem::encode(&public_pem))?;
    }

    Ok(Identity::from_pem(public_bytes, secret_bytes))
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
