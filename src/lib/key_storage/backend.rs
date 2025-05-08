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
use std::sync::Mutex;
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::sync::RwLock;
use tonic::transport::CertificateDer;
use uuid::Uuid;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::X509Certificate;

use super::KeyStorageError;
use crate::keys::{CertWithMetadata, CertificateData, HasKey, Identity, NodeInfo};

pub trait StorageBackend: std::fmt::Debug + Send + Sync {
    fn save_cert(&self, uuid: Uuid, cert: &CertificateData) -> Result<(), std::io::Error>;
    fn load_cert(&self, uuid: Uuid) -> Result<CertificateData, KeyStorageError>;
    fn save_metadata(&self, metadata: &HashMap<Uuid, NodeInfo>) -> Result<(), KeyStorageError>;
    fn load_metadata(&self) -> Result<HashMap<Uuid, NodeInfo>, std::io::Error>;
}

#[derive(Debug)]
pub struct FileStorageBackend {
    base_path: PathBuf,
}

impl FileStorageBackend {
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }

    fn cert_path(&self, uuid: Uuid) -> PathBuf {
        self.base_path.join("certs").join(format!("{}.pem", uuid))
    }

    fn metadata_path(&self) -> PathBuf {
        self.base_path.join("certs.json")
    }
}

impl StorageBackend for FileStorageBackend {
    fn save_cert(&self, uuid: Uuid, cert: &CertificateData) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(self.base_path.join("certs"))?;
        std::fs::write(self.cert_path(uuid), cert.to_pem())
    }

    fn load_cert(&self, uuid: Uuid) -> Result<CertificateData, KeyStorageError> {
        let cert_path = self.base_path.join("certs").join(format!("{}.pem", uuid));
        if !cert_path.exists() {
            return Err(KeyStorageError::MissingCertificateFile(uuid));
        }

        let pem_string = fs::read(&cert_path)?;
        Ok(CertificateData::from_pem(pem_string)?)
    }

    fn save_metadata(&self, metadata: &HashMap<Uuid, NodeInfo>) -> Result<(), KeyStorageError> {
        let file = std::fs::File::create(self.metadata_path())?;
        serde_json::to_writer_pretty(file, metadata)?;
        Ok(())
    }

    fn load_metadata(&self) -> Result<HashMap<Uuid, NodeInfo>, std::io::Error> {
        if !self.metadata_path().exists() {
            return Ok(HashMap::new());
        }
        let file = std::fs::File::open(self.metadata_path())?;
        Ok(serde_json::from_reader(file)?)
    }
}

#[derive(Debug)]
pub struct FakeStorageBackend {}

impl FakeStorageBackend {
    pub fn new() -> Self {
        Self {}
    }
}

impl StorageBackend for FakeStorageBackend {
    fn save_cert(&self, uuid: Uuid, cert: &CertificateData) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn load_cert(&self, uuid: Uuid) -> Result<CertificateData, KeyStorageError> {
        Err(KeyStorageError::CertificateNotFound(uuid))
    }

    fn save_metadata(&self, metadata: &HashMap<Uuid, NodeInfo>) -> Result<(), KeyStorageError> {
        Ok(())
    }

    fn load_metadata(&self) -> Result<HashMap<Uuid, NodeInfo>, std::io::Error> {
        Ok(HashMap::new())
    }
}
