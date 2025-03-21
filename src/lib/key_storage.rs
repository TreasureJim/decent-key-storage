use base64::Engine;
use rustls::sign::SigningKey;
use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyStorageError {
    #[error("Encryption scheme was missing in the line during parsing")]
    ParsingMissingEncryptionScheme,
    #[error("Public key was missing in the line during parsing")]
    ParsingMissingPublicKey,
    #[error("Decoding public key")]
    DecodingPublicKey,
}

#[derive(Debug)]
pub struct KeyStorage {
    hosts: HashMap<String, Host>,
}

#[derive(Debug)]
pub struct Host {
    pub encryption_scheme: String,
    pub public_key: Vec<u8>,
}

impl KeyStorage {
    pub fn empty_hosts() -> Self {
        Self {
            hosts: HashMap::new(),
        }
    }

    pub fn deserialise_hosts(s: String) -> Result<KeyStorage, KeyStorageError> {
        let mut known_hosts = KeyStorage::empty_hosts();

        for line in s.lines() {
            let mut words = line.split_whitespace();

            let Some(host_name) = words.next() else {
                continue;
            };

            let host = Host {
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

    pub fn serialise_hosts(&self) -> String {
        let mut file_string = String::new();

        for (
            host_name,
            Host {
                encryption_scheme,
                public_key,
            },
        ) in &self.hosts
        {
            file_string.push_str(&format!(
                "{} {} {}\n",
                host_name,
                encryption_scheme,
                base64::engine::general_purpose::STANDARD.encode(public_key)
            ));
        }

        file_string
    }
}

impl KeyStorage {
    pub fn add_host(&mut self, host_name: String, host: Host) {
        self.hosts.insert(host_name, host);
    }

    pub fn get_host_key(&self, host_name: String) -> Option<&Host> {
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

// TODO: Create custom PEM serialization
struct PublicKey([u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);
struct PrivateKey([u8; ed25519_dalek::SECRET_KEY_LENGTH]);

pub fn create_self_signed_keys(path: Option<&Path>) {
    let mut csprng = rand_core::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut csprng);
    // key.serialize()
}
