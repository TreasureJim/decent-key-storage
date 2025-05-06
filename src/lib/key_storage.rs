use anyhow::Context;
use arc_swap::ArcSwap;
use base64::Engine;
use path_absolutize::Absolutize;
use pkcs8::der::pem::PemLabel;
use pkcs8::der::{Encode, EncodePem};
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::sync::RwLock;
use tonic::transport::{CertificateDer, Identity};
use uuid::Uuid;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::X509Certificate;

use crate::custom_tls::DebugHasKey;
use crate::keys::{CertWithMetadata, CertificateData, HasKey, NodeInfo};

pub fn canonicalize_path(path: &str) -> Result<PathBuf, anyhow::Error> {
    let expanded = expanduser::expanduser(path)?;
    Ok(expanded.absolutize()?.into_owned())
}


#[derive(Debug)]
struct UuidCertBiMap {
    uuid_to_cert: HashMap<Uuid, Arc<CertificateData>>,
    cert_to_uuid: HashMap<Arc<CertificateData>, Uuid>,
}

impl UuidCertBiMap {
    pub fn new() -> Self {
        Self {
            uuid_to_cert: HashMap::new(),
            cert_to_uuid: HashMap::new(),
        }
    }

    pub fn get_cert(&self, uuid: &Uuid) -> Option<&Arc<CertificateData>> {
        self.uuid_to_cert.get(uuid)
    }

    pub fn get_uuid(&self, cert: &CertificateData) -> Option<&Uuid> {
        self.cert_to_uuid.get(cert)
    }

    /// Returns true if map already contained certicate
    pub fn insert(&mut self, uuid: Uuid, cert: CertificateData)  {
        let rc = Arc::new(cert);
        self.uuid_to_cert.insert(uuid, rc.clone());
        self.cert_to_uuid.insert(rc, uuid);
    }

    pub fn get_all_certificates(&self) -> Vec<&Arc<CertificateData>> {
        self.cert_to_uuid.keys().collect()
    }

    pub fn get_all_uuids(&self) -> Vec<&Uuid> {
        self.uuid_to_cert.keys().collect()
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, Uuid, Arc<CertificateData>> {
        self.uuid_to_cert.iter()
    }
}


#[derive(Debug)]
pub struct KeyStorage {
    storage_dir: PathBuf,
    node_info: HashMap<Uuid, NodeInfo>,
    // Used for quickly checking if the store includes a certificate
    uuid_cert_bimap: UuidCertBiMap,

    snapshot: arc_swap::ArcSwap<HashSet<CertificateData>>,
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
        let cert_metadata = if storage_dir.join("certs.json").exists() {
            Self::load_metadata(&storage_dir)?
        } else {
            HashMap::new()
        };

        // Pre-load all certificate data
        let mut uuid_cert_bimap = UuidCertBiMap::new();
        let mut cert_list = HashSet::new();
        cert_list.reserve(cert_metadata.len());
        for (uuid, _) in &cert_metadata {
            let data = Self::load_cert_file(&storage_dir, *uuid)?;
            cert_list.insert(data.clone());
            uuid_cert_bimap.insert(*uuid, data.clone());
        }

        Ok(Self {
            snapshot: ArcSwap::from_pointee(cert_list),
            storage_dir,
            node_info: cert_metadata,
            uuid_cert_bimap,
        })
    }

    /// Add a new certificate (saves to disk immediately)
    pub fn add_certificate(
        &mut self,
        uuid: Uuid,
        raw_cert: CertificateData,
        received_at: std::time::SystemTime,
        sock_addr: SocketAddr,
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
        let cert = NodeInfo::new(uuid, cert_path, received_at, sock_addr);

        self.node_info.insert(uuid, cert);
        self.uuid_cert_bimap.insert(uuid, raw_cert);
        self.save_metadata()?;

        self.update_snapshot();

        Ok(())
    }

    /// Returns the amount of nodes and certificates it has.
    pub fn amount_of_nodes(&self) -> usize {
        self.node_info.len()
    }

    // Get certificate data (already loaded)
    pub fn get_cert_data<'a>(&'a self, uuid: &Uuid) -> Option<&'a Arc<CertificateData>> {
        self.uuid_cert_bimap
            .get_cert(uuid)
    }

    // List all certificate UUIDs
    pub fn list_certificates(&self) -> Vec<Uuid> {
        self.node_info.keys().cloned().collect()
    }

    pub fn get_certificates(&self) -> Vec<CertWithMetadata> {
        self.uuid_cert_bimap
            .iter()
            .map(|(uuid, cert)| {
                let metadata = self
                    .node_info
                    .get(uuid)
                    .expect("Cert store had metadata loaded but not cert");

                CertWithMetadata { cert, metadata }
            })
            .collect()
    }

    pub fn get_certificate_uuid<'a>(&'a self, uuid: &Uuid) -> Option<CertWithMetadata<'a>> {
        Some(CertWithMetadata {
            cert: self.uuid_cert_bimap.get_cert(uuid)?,
            metadata: self.node_info.get(uuid)?
        })
    }

    pub fn snapshot(&self) -> Arc<HashSet<CertificateData>> {
        self.snapshot.load_full()
    }

    // Private helpers

    fn update_snapshot(&self) {
        self.snapshot
            .swap(Arc::new(self.uuid_cert_bimap.get_all_certificates().into_iter().map(|c| (**c).clone()).collect()));
    }

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

impl HasKey for KeyStorage {
    // Confirm existence of certificate
    fn have_tonic_certificate(&self, cert: &tonic::transport::CertificateDer<'_>) -> bool {
        self.uuid_cert_bimap
            .get_uuid(&CertificateData::new_no_validation(cert)).is_some()
    }
}

impl DebugHasKey for KeyStorage {}

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
