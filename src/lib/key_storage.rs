mod bimap;
pub mod backend;

use anyhow::Context;
use arc_swap::ArcSwap;
use base64::Engine;
use bimap::UuidCertBiMap;
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
use tonic::transport::CertificateDer;
use uuid::Uuid;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::X509Certificate;

use crate::keys::{CertWithMetadata, CertificateData, HasKey, Identity, NodeInfo};

pub fn canonicalize_path(path: &str) -> Result<PathBuf, anyhow::Error> {
    let expanded = expanduser::expanduser(path)?;
    Ok(expanded.absolutize()?.into_owned())
}


#[derive(Debug)]
pub struct KeyStorage {
    backend: Box<dyn backend::StorageBackend>,
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
    pub fn create_with_backend(backend: Box<dyn backend::StorageBackend>) -> Result<Self, KeyStorageError> {
        let cert_metadata = backend.load_metadata()?;

        // Pre-load all certificate data
        let mut uuid_cert_bimap = UuidCertBiMap::new();
        let mut cert_list = HashSet::new();
        cert_list.reserve(cert_metadata.len());
        for (uuid, _) in &cert_metadata {
            let data = backend.load_cert(*uuid)?;
            cert_list.insert(data.clone());
            uuid_cert_bimap.insert(*uuid, data.clone());
        }

        Ok(Self {
            backend,
            snapshot: ArcSwap::from_pointee(cert_list),
            node_info: cert_metadata,
            uuid_cert_bimap,
        })
    }

    pub fn add_certificate(
        &mut self,
        uuid: Uuid,
        raw_cert: CertificateData,
        received_at: std::time::SystemTime,
        sock_addr: SocketAddr,
    ) -> Result<(), KeyStorageError> {
        /* if self.node_info.contains_key(&uuid) {
            return Err(KeyStorageError::DuplicateCertificate(uuid));
        } */

        let cert = NodeInfo::new(uuid, received_at, sock_addr);

        self.backend.save_metadata(&self.node_info)?;
        self.backend.save_cert(uuid, &raw_cert)?;

        self.node_info.insert(uuid, cert);
        self.uuid_cert_bimap.insert(uuid, raw_cert);

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

    pub fn get_all_node_info(&self) -> std::collections::hash_map::Values<'_, Uuid, NodeInfo> {
        self.node_info.values()
    }

    // Private helpers

    fn update_snapshot(&self) {
        self.snapshot
            .swap(Arc::new(self.uuid_cert_bimap.get_all_certificates().into_iter().map(|c| (**c).clone()).collect()));
    }
}

impl HasKey for KeyStorage {
    // Confirm existence of certificate
    fn have_tonic_certificate(&self, cert: &tonic::transport::CertificateDer<'_>) -> bool {
        self.uuid_cert_bimap
            .get_uuid(&CertificateData::new_no_validation(cert)).is_some()
    }
}
