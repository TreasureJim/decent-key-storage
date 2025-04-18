use base64::Engine;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tonic::transport::{CertificateDer, Identity};
use x509_parser::prelude::X509Certificate;

/*
* certicates.json
*
* -------------
* {
*   nodes: [
*       {
*           uiud: Uuid,
*           cert_file: Path,
*           received: TimeStamp,
*           signed_by: VerificationSignature (bytes)
*       }
*   ]
* }
*/

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct NodeCertContainer {
    uuid: uuid::Uuid,
    cert_file: PathBuf,

    #[serde(skip_serializing)]
    raw_cert: Option<Vec<u8>>,

    received_at: std::time::SystemTime,
    signed_by: Option<(uuid::Uuid, Vec<u8>)>,
}

#[derive(Debug, Error)]
pub enum KeyStorageError {
    #[error("Could not access folder containing data")]
    FolderAccess,
    #[error("IO error for certs.json file: {0:?}")]
    CertJsonIO(std::io::Error),
    #[error("Parsing certs.json file")]
    CertJsonParsing
}

#[derive(Debug)]
pub struct KeyStorage {
    folder: PathBuf,
    hosts: HashMap<uuid::Uuid, NodeCertContainer>,
}

impl KeyStorage {
    pub fn empty_hosts(folder: &Path) -> Result<Self, KeyStorageError> {
        if !folder.exists() {
            return Err(KeyStorageError::FolderAccess);
        }

        Ok(Self {
            folder: folder.to_path_buf(),
            hosts: HashMap::new(),
        })
    }

    pub fn read_certs(&mut self) -> Result<KeyStorage, KeyStorageError> {
        

        for line in s.lines() {
            let mut words = line.split_whitespace();

            let Some(host_name) = words.next() else {
                continue;
            };

            let host = Certificate {
                encryption_scheme: words
                    .next()
                    .ok_or(KeyStorageError::ParsingMissingEncryptionScheme)?
                    .to_string(),
                public_key: base64::engine::general_purpose::STANDARD
                    .decode(
                        words
                            .next()
                            .ok_or(KeyStorageError::ParsingMissingPublicKey)?,
                    )
                    .map_err(|_| KeyStorageError::DecodingPublicKey)?,
            };

            known_hosts.add_host(host_name.to_string(), host);
        }

        Ok(known_hosts)
    }

    pub fn save_certs(&self) -> Result<(), KeyStorageError> {
        let cert_containers: Vec<_> = self.hosts.values().collect();

        // certs.json
        {
            let cert_json_str = serde_json::to_string(&cert_containers).unwrap();
            std::fs::write(self.folder.join("certs.json"), &cert_json_str).map_err(|e| KeyStorageError::CertJsonIO(e))?;
        }

        // pem cert files

        Ok(())
    }
}

impl KeyStorage<'a> {
    pub fn add_host(&mut self, host_name: String, host: Certificate) {
        self.hosts.insert(host_name, host);
    }

    pub fn get_host_key(&self, host_name: String) -> Option<&Certificate> {
        self.hosts.get(&host_name)
    }

    pub fn get_host_keys(&self, host_name: String) -> Vec<Vec<u8>> {
        if let Some(host) = self.hosts.get(&host_name) {
            vec![host.public_key.clone()]
        } else {
            vec![]
        }
    }
}

pub static DEFAULT_DATA_LOCATION: &str = "~/.local/decent-key-storage";
pub static HOSTS_FILE_NAME: &str = "known_hosts";
pub static KEY_FILE_NAME: &str = "key.pem";
pub static CERT_FILE_NAME: &str = "cert.pem";

/// Finds the default location of the known_hosts. If it doesn't exist, it creates it.
pub fn default_storage_file() -> Result<PathBuf, std::io::Error> {
    let mut path = PathBuf::new();
    path.push(DEFAULT_DATA_LOCATION);
    path.push(HOSTS_FILE_NAME);

    let exists = std::fs::exists(&path)?;
    if !exists {
        std::fs::create_dir_all(
            path.parent()
                .expect("Default location should always be able to get the parent directory."),
        )
        .expect("Couldn't create default storage folder");
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)?;
    }

    Ok(path.clone())
}

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
        let path = folder.join(KEY_FILE_NAME);

        let public_pem = pem::Pem::new("CERTIFICATE", public_bytes);
        std::fs::write(path, pem::encode(&public_pem))?;
    }

    Ok(Identity::from_pem(public_bytes, secret_bytes))
}

pub fn read_self_signed_keys(folder: &Path) -> Option<Identity> {
    let cert = {
        let path = folder.join("cert.pem");
        std::fs::read_to_string(path).ok()?
    };
    let key = {
        let path = folder.join("key.pem");
        std::fs::read_to_string(path).ok()?
    };

    Some(Identity::from_pem(cert, key))
}
